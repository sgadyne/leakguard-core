"""Bounded snapshots of explicitly selected Gitleaks rule configuration.

Relative extend.path entries use the caller's working directory, as in pinned
Gitleaks 8.30.1. They are staged in a private directory so an unrelated repository
.gitleaksignore cannot change required scan policy. External inheritance remains
uncacheable; its bytes still participate in the observed runtime identity.

https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/config.go
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import tomllib


class RuleConfigError(RuntimeError):
    code = 'configuration-invalid'

    def __init__(self):
        super().__init__(self.code)


@dataclass(frozen=True, repr=False)
class RuleClosure:
    files: tuple[tuple[str, bytes], ...] = field(repr=False)
    relative_files: tuple[tuple[str, bytes], ...] = field(repr=False)
    external: bool = False

    @property
    def identity(self):
        return tuple((path, hashlib.sha256(data).hexdigest()) for path, data in self.files)


def _field(value, name, default=None):
    if type(value) is not dict:
        raise RuleConfigError()
    matches = [item for key, item in value.items() if key.lower() == name]
    if len(matches) > 1:
        raise RuleConfigError()
    return matches[0] if matches else default


def _resolved(path):
    # Explicit config symlinks may select regular rule files. A symlink loop
    # raises RuntimeError on Python 3.11, whose message contains the local path;
    # isolate that resolution error without swallowing caller budget failures.
    try:
        return Path(path).resolve()
    except (OSError, ValueError, RuntimeError):
        raise RuleConfigError() from None


def inspect(path, *, cwd=None, check=None):
    from .sources import _bounded_file, AcquisitionError
    files = []
    relative_files = []
    external = False
    relative_name = None
    try:
        base = Path(cwd) if cwd is not None else Path.cwd()
        current = _resolved(path)
        # The pinned backend follows at most two external inheritance edges.
        for depth in range(3):
            if check is not None:
                check()
            raw = _bounded_file(current, 1_000_000)
            files.append((str(current), raw))
            if relative_name is not None:
                relative_files.append((relative_name, raw))
            value = tomllib.loads(raw.decode('utf-8-sig'))
            extension = _field(value, 'extend', {})
            reference = _field(extension, 'path', '')
            if _field(extension, 'url', ''):
                external = True
            if type(reference) is not str or len(reference) > 4096 or '\x00' in reference:
                raise RuleConfigError()
            if not reference:
                break
            external = True
            if depth == 2:
                break
            relative = Path(reference)
            current = _resolved(relative if relative.is_absolute() else base / relative)
            relative_name = None
            if not relative.is_absolute():
                if relative.drive or sum(part == '..' for part in relative.parts) > 32:
                    raise RuleConfigError()
                relative_name = reference
        return RuleClosure(tuple(files), tuple(relative_files), external)
    except (AcquisitionError, OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise RuleConfigError() from None


def stage(closure, scratch):
    """Return a private cwd preserving bounded relative rule-file references."""
    scratch = _resolved(scratch)
    depth = max((sum(part == '..' for part in Path(name).parts)
                 for name, _ in closure.relative_files), default=0) + 1
    directory = scratch.joinpath(*(['work'] * depth))
    directory.mkdir(mode=0o700, parents=True)
    for name, data in closure.relative_files:
        raw_destination = directory / name
        destination = _resolved(raw_destination)
        if not destination.is_relative_to(scratch) or destination == directory / '.gitleaksignore':
            raise RuleConfigError()
        raw_destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists():
            if destination.read_bytes() != data:
                raise RuleConfigError()
            continue
        with destination.open('xb') as stream:
            stream.write(data)
        destination.chmod(0o600)
    return directory
