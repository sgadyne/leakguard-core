"""Bounded byte acquisition and version-pinned contextual proof readers."""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
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


class FilesystemBoundary:
    """A selected directory identity with no linked descendants.

    Aliases above the selected root (including macOS /var) remain usable. POSIX
    descriptor-relative opens prevent a renamed ancestor from redirecting reads
    between persisted work slices or during acquisition.
    """

    def __init__(self, root):
        self.root = Path(os.path.abspath(root))
        self.physical_root = self.root.resolve(strict=True)
        self.identity = _directory_identity(self.root)
        self.check(self.root, directory=True)

    def check(self, path, *, directory=False):
        path = Path(os.path.abspath(path))
        try:
            relative = path.relative_to(self.root)
            if '..' in relative.parts or len(relative.parts) > 128 or _directory_identity(self.root) != self.identity:
                raise AcquisitionError('source-unavailable')
            current = self.root
            for index, part in enumerate(('', *relative.parts)):
                if part:
                    current = current / part
                value = os.stat(current, follow_symlinks=False)
                if stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400:
                    raise AcquisitionError('input-nonregular')
                if (directory or index < len(relative.parts)) and not stat.S_ISDIR(value.st_mode):
                    raise AcquisitionError('input-nonregular')
            if self.root.resolve(strict=True) != self.physical_root:
                raise AcquisitionError('source-unavailable')
            return relative
        except (ValueError, OSError, RuntimeError):
            raise AcquisitionError('source-unavailable') from None

    def directory_fd(self, path):
        relative = self.check(path, directory=True)
        if os.open not in os.supports_dir_fd:
            return None
        flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = None
        try:
            descriptor = os.open(self.root, flags)
            root = os.fstat(descriptor)
            if (root.st_dev, root.st_ino, root.st_mode) != (self.identity.device, self.identity.inode, self.identity.mode):
                raise AcquisitionError('source-unavailable')
            for part in relative.parts:
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except (OSError, ValueError):
            if descriptor is not None:
                os.close(descriptor)
            raise AcquisitionError('source-unavailable') from None
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise

    def open_file(self, path, flags):
        self.check(path)
        parent = self.directory_fd(Path(path).parent)
        if parent is not None:
            try:
                return os.open(Path(path).name, flags, dir_fd=parent)
            finally:
                os.close(parent)
        descriptor = os.open(path, flags)
        try:
            self.check(path)
            if os.name == 'nt':
                # Windows lacks openat(). Verify the actual opened file before
                # reading; a replaced ancestor cannot redirect bytes outside
                # the selected physical root. Native validation is separate.
                import ctypes
                from ctypes import wintypes
                import msvcrt
                function = ctypes.WinDLL('kernel32', use_last_error=True).GetFinalPathNameByHandleW
                function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
                function.restype = wintypes.DWORD
                buffer = ctypes.create_unicode_buffer(32768)
                length = function(msvcrt.get_osfhandle(descriptor), buffer, len(buffer), 0)
                if not 0 < length < len(buffer):
                    raise AcquisitionError('source-unavailable')
                actual = buffer.value
                if actual.startswith('\\\\?\\UNC\\'):
                    actual = '\\\\' + actual[8:]
                elif actual.startswith('\\\\?\\'):
                    actual = actual[4:]
                if not Path(actual).is_relative_to(self.physical_root):
                    raise AcquisitionError('source-unavailable')
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise


@dataclass(frozen=True, slots=True)
class ScopedFileInput(m.FileInput):
    boundary: FilesystemBoundary


@contextmanager
def scoped_scandir(path, boundary=None, *, navigation=None, deadline=None,
                   cancel=None, same_file_system=False):
    """The one directory-navigation seam, with the same acquisition boundary."""
    from .navigation import Navigation
    owned = navigation is None
    navigator = Navigation() if owned else navigation
    try:
        with navigator.scandir(path, boundary=boundary, deadline=deadline,
                               cancel=cancel, same_file_system=same_file_system) as entries:
            yield entries
    finally:
        if owned:
            navigator.close()


def _bounded_file(path, maximum, *, boundary=None):
    try:
        if boundary is not None:
            boundary.check(path)
        if not stat.S_ISREG(os.stat(path, follow_symlinks=False).st_mode):
            raise AcquisitionError('input-nonregular')
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = boundary.open_file(path, flags) if boundary is not None else os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise AcquisitionError('input-nonregular')
            if before.st_size > maximum:
                raise AcquisitionError('input-limit')
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        observed = os.stat(path, follow_symlinks=False)
        if boundary is not None:
            boundary.check(path)
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
    data: bytes = field(repr=False)
    context: ProofContext
    revalidate: object = None
    anchor: object = None
    _content: m.ContentIdentity = field(init=False, repr=False)

    def __post_init__(self):
        if type(self.data) is not bytes:
            raise TypeError('immutable-input-required')
        object.__setattr__(self, '_content', content_identity(self.data))

    @property
    def content(self):
        return self._content

    def detach_validator(self):
        context_check = self.context.detach_validator()
        primary_check = self.revalidate
        return lambda: context_check() and (primary_check is None or primary_check())

    def valid(self):
        return self.detach_validator()()


def acquire_file(path: Path, *, max_bytes: int, boundary=None):
    path = path.absolute()
    source = m.SourceRef(m.SourceKind.FILESYSTEM, str(path))
    if path.is_symlink():
        raise AcquisitionError('input-nonregular')
    boundary = boundary or FilesystemBoundary(path.parent)
    boundary.check(path)
    anchor = capture_anchor(path)
    data = _bounded_file(path, max_bytes, boundary=boundary)
    if not anchor.valid():
        raise AcquisitionError('input-changed')
    root = path.parent.resolve()

    def sibling(name):
        candidate = path.parent / name
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            return None
        return _bounded_file(candidate, 1_000_000, boundary=boundary)

    context = ProofContext(sibling, validator=sibling)
    context.prepare(data, str(path))

    expected_digest = None
    def valid():
        try:
            return anchor.valid() and hashlib.sha256(_bounded_file(path, max_bytes, boundary=boundary)).digest() == expected_digest
        except AcquisitionError:
            return False

    snapshot = SnapshotInput(source, data, context, valid, anchor)
    # The validator retains only the already-computed digest, not the snapshot
    # or its source bytes. Avoid hashing acquired content a second time here.
    expected_digest = bytes.fromhex(snapshot.content.digest)
    return snapshot


def acquire_bytes(data, logical_path, *, max_bytes):
    if len(data) > max_bytes:
        raise AcquisitionError('input-limit')
    # Caller-supplied bytes never receive a filesystem or Git proof capability.
    return SnapshotInput(m.SourceRef(m.SourceKind.BYTES, logical_path), data, ProofContext(lambda name: None))


def directory_signature(path, boundary=None):
    """A change detector for one traversal, never an atomic tree snapshot."""
    try:
        descriptor = boundary.directory_fd(path) if boundary is not None else None
        try:
            value = os.fstat(descriptor) if descriptor is not None else os.stat(path, follow_symlinks=False)
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if not stat.S_ISDIR(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400 or not value.st_ino:
            raise AcquisitionError('source-unavailable')
        signature = (value.st_dev, value.st_ino, value.st_mode, value.st_mtime_ns, value.st_ctime_ns)
        if any(type(item) is not int for item in signature):
            raise AcquisitionError('source-unavailable')
        return signature
    except (OSError, AttributeError):
        raise AcquisitionError('source-unavailable') from None


@dataclass(frozen=True)
class DirectoryIdentity:
    path: str
    device: int
    inode: int
    mode: int


def _directory_identity(path):
    try:
        # Ancestor aliases such as macOS /var -> /private/var are legitimate
        # provenance spellings. Bind them to the actual directory inode so
        # retargeting/replacing a parent invalidates a proof. Enumeration still
        # refuses symlink entries and acquisition still refuses linked files.
        value = os.stat(path, follow_symlinks=True)
        if not stat.S_ISDIR(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400 or not value.st_ino:
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
        descriptor = None
        try:
            boundary = FilesystemBoundary(root)
            descriptor = boundary.directory_fd(source.parent)
            try:
                if descriptor is None:
                    boundary.check(source.parent, directory=True)
                    os.stat(source, follow_symlinks=False)
                else:
                    os.stat(source.name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                # Bind the negative to the same nofollow traversal as acquisition.
                # A moved directory linked back to its original inode must not
                # turn an out-of-scope deletion into an in-scope absence proof.
                boundary.check(source.parent, directory=True)
                return self.anchor.valid()
        except (AcquisitionError, OSError):
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)
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
