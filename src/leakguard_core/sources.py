"""Bounded byte acquisition and version-pinned contextual proof readers."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

from . import models as m


class AcquisitionError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def content_identity(data):
    return m.ContentIdentity('sha256', hashlib.sha256(data).hexdigest(), len(data))


def _bounded_file(path, maximum):
    try:
        if not stat.S_ISREG(os.stat(path, follow_symlinks=False).st_mode):
            raise AcquisitionError('input-nonregular')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise AcquisitionError('input-nonregular')
            if before.st_size > maximum:
                raise AcquisitionError('input-limit')
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        observed = os.stat(path, follow_symlinks=False)
        if len(data) > maximum:
            raise AcquisitionError('input-limit')
        if _signature(before) != _signature(after) or _signature(after) != _signature(observed):
            raise AcquisitionError('input-changed')
        return data
    except AcquisitionError:
        raise
    except FileNotFoundError:
        raise AcquisitionError('input-missing') from None
    except OSError:
        raise AcquisitionError('input-unreadable') from None


def _signature(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _reference_names(data):
    if len(data) > 1_000_000:
        return ()
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError()
            value[key] = item
        return value
    try:
        value = json.loads(data.decode('utf-8-sig'), object_pairs_hook=unique)
        if not isinstance(value, dict):
            return ()
        names = set()
        fingerprints = value.get('source_fingerprints')
        if isinstance(fingerprints, dict):
            names.update(fingerprints)
        for key, item in value.items():
            if isinstance(item, dict) and isinstance(item.get('function_ast_sha256'), dict):
                names.add(key)
        return tuple(sorted(name for name in names if isinstance(name, str)))
    except (ValueError, UnicodeError, RecursionError):
        return ()


class ProofContext:
    """A bounded reader memoizes exact sibling versions and missing sentinels."""
    def __init__(self, reader, *, validator=None):
        self._reader = reader
        self._validator = validator
        self.dependencies = {}
        self.truncated = False
        self._total_bytes = 0
        self.max_dependencies = 1000
        self.max_dependency_bytes = 12_000_000

    def read(self, name):
        reference = PurePosixPath(name.replace('\\', '/'))
        if reference.is_absolute() or '..' in reference.parts or ':' in str(reference):
            return None
        key = str(reference)
        if self.truncated:
            return None
        if key not in self.dependencies:
            if len(self.dependencies) >= self.max_dependencies:
                self.truncated = True
                return None
            try:
                data = self._reader(key)
            except (OSError, AcquisitionError):
                data = None
            if data is not None and len(data) > 1_000_000:
                data = None
            if data is not None and self._total_bytes + len(data) > self.max_dependency_bytes:
                self.truncated = True
                return None
            self._total_bytes += len(data) if data is not None else 0
            self.dependencies[key] = data
        return self.dependencies[key]

    def prepare(self, data, path):
        if Path(path).suffix.lower() == '.json':
            for name in _reference_names(data):
                self.read(name)
                if self.truncated:
                    break

    @property
    def identity(self):
        values = [(name, hashlib.sha256(data).hexdigest() if data is not None else 'missing')
                  for name, data in sorted(self.dependencies.items())]
        return hashlib.sha256(json.dumps(['proof-context-v2', self.truncated, values], separators=(',', ':')).encode()).hexdigest()

    def detach_validator(self):
        # Keep only digests after classification; raw sibling/source bytes must
        # not accumulate across an entire bounded batch.
        expected = {name: hashlib.sha256(data).digest() if data is not None else None
                    for name, data in self.dependencies.items()}
        reader = self._validator
        if reader is None:
            return lambda: True

        def valid():
            for name, original in expected.items():
                try:
                    current = reader(name)
                except (OSError, AcquisitionError):
                    current = None
                actual = hashlib.sha256(current).digest() if current is not None else None
                if actual != original:
                    return False
            return True
        return valid

    def valid(self):
        return self.detach_validator()()


@dataclass(frozen=True)
class SnapshotInput:
    source: m.SourceRef
    data: bytes
    context: ProofContext
    revalidate: object = None
    anchor: object = None

    @property
    def content(self):
        return content_identity(self.data)

    def detach_validator(self):
        context_check = self.context.detach_validator()
        primary_check = self.revalidate
        return lambda: context_check() and (primary_check is None or primary_check())

    def valid(self):
        return self.detach_validator()()


def acquire_file(path: Path, *, max_bytes: int):
    path = path.absolute()
    source = m.SourceRef(m.SourceKind.FILESYSTEM, str(path))
    if path.is_symlink():
        raise AcquisitionError('input-nonregular')
    data = _bounded_file(path, max_bytes)
    root = path.parent.resolve()

    def sibling(name):
        candidate = path.parent / name
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            return None
        return _bounded_file(candidate, 1_000_000)

    context = ProofContext(sibling, validator=sibling)
    context.prepare(data, str(path))

    expected_digest = hashlib.sha256(data).digest()
    def valid():
        try:
            return hashlib.sha256(_bounded_file(path, max_bytes)).digest() == expected_digest
        except AcquisitionError:
            return False

    try:
        anchor = capture_anchor(path)
        if anchor.source_path != str(path):
            anchor = None
    except AcquisitionError:
        anchor = None
    return SnapshotInput(source, data, context, valid, anchor)


def acquire_bytes(data, logical_path, *, max_bytes):
    if len(data) > max_bytes:
        raise AcquisitionError('input-limit')
    # Caller-supplied bytes never receive a filesystem or Git proof capability.
    return SnapshotInput(m.SourceRef(m.SourceKind.BYTES, logical_path), data, ProofContext(lambda name: None))


@dataclass(frozen=True)
class DirectoryIdentity:
    path: str
    device: int
    inode: int
    mode: int


def _directory_identity(path):
    try:
        value = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400 or not value.st_ino:
            raise AcquisitionError('source-unavailable')
        return DirectoryIdentity(str(path), value.st_dev, value.st_ino, value.st_mode)
    except OSError:
        raise AcquisitionError('source-unavailable') from None


@dataclass(frozen=True)
class FilesystemAnchor:
    source_path: str
    directories: tuple[DirectoryIdentity, ...]

    def valid(self):
        source = Path(self.source_path)
        expected = tuple(str(parent) for parent in reversed((source.parent, *source.parent.parents)))
        if not source.is_absolute() or not 1 <= len(expected) <= 128 or tuple(item.path for item in self.directories) != expected:
            return False
        try:
            return all(_directory_identity(Path(item.path)) == item for item in self.directories)
        except AcquisitionError:
            return False


def capture_anchor(path):
    path = Path(os.path.abspath(path))
    parents = tuple(reversed((path.parent, *path.parent.parents)))
    if len(parents) > 128:
        raise AcquisitionError('input-limit')
    return FilesystemAnchor(str(path), tuple(_directory_identity(parent) for parent in parents))


@dataclass(frozen=True)
class AbsenceProof:
    anchor: FilesystemAnchor
    root: str
    observed_at: object

    def valid(self):
        source = Path(self.anchor.source_path)
        root = Path(self.root)
        if str(root) not in {item.path for item in self.anchor.directories} or source == root or not source.is_relative_to(root):
            return False
        if not self.anchor.valid():
            return False
        try:
            os.stat(self.anchor.source_path, follow_symlinks=False)
        except FileNotFoundError:
            # A missing intermediate/unmounted/replaced directory cannot authorize
            # a negative. The same recorded traversal must still be available.
            return self.anchor.valid()
        except OSError:
            return False
        return False


def confirm_absence(path, root, anchor):
    from datetime import datetime, timezone
    if '..' in Path(path).parts or '..' in Path(root).parts:
        raise AcquisitionError('source-unavailable')
    path = Path(os.path.abspath(path))
    root = Path(os.path.abspath(root))
    if type(anchor) is not FilesystemAnchor or anchor.source_path != str(path) or path == root or not path.is_relative_to(root):
        raise AcquisitionError('source-unavailable')
    if str(root) not in {item.path for item in anchor.directories}:
        raise AcquisitionError('source-unavailable')
    proof = AbsenceProof(anchor, str(root), datetime.now(timezone.utc))
    if not proof.valid():
        raise AcquisitionError('source-unavailable')
    return proof
