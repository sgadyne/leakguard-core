"""Private, bounded file I/O. Only ciphertext and empty lock files reach disk."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat

from .errors import VaultError


def _parent(path: Path) -> None:
    if not isinstance(path, Path):
        raise VaultError("vault-path-invalid")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink() or not path.parent.is_dir():
            raise VaultError("vault-path-invalid")
    except OSError:
        raise VaultError("vault-io-failed") from None


def read_bounded(path: Path, maximum: int) -> bytes:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise VaultError("vault-format-invalid")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise VaultError("vault-format-invalid")
        return value
    except FileNotFoundError:
        raise VaultError("vault-not-created") from None
    except OSError:
        raise VaultError("vault-io-failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def atomic_write(path: Path, value: bytes, *, replace: bool = True) -> None:
    _parent(path)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(12) + ".tmp")
    descriptor = None
    try:
        if not replace and path.exists():
            raise VaultError("vault-already-created")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        # The owner holds FileLock for primary files. Backups use hard-link
        # publication for exclusive creation, so a racing writer is not replaced.
        if replace:
            if path.is_symlink():
                raise VaultError("vault-path-invalid")
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError:
                raise VaultError("vault-already-created") from None
            temporary.unlink()
        if os.name == "posix":
            parent_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
    except OSError:
        raise VaultError("vault-io-failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


class FileLock:
    """Single owner across processes; never removes another owner's lock inode."""

    def __init__(self, path: Path):
        self._descriptor = None
        _parent(path)
        lock_path = path.with_name(path.name + ".lock")
        try:
            descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                raise VaultError("vault-path-invalid")
            self._descriptor = descriptor
            if os.name == "nt":
                import msvcrt
                # msvcrt.locking can lock a byte beyond EOF without writing it.
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.close()
            raise VaultError("vault-busy") from None

    def close(self):
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            os.close(descriptor)
