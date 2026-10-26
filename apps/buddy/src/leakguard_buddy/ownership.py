"""Nonblocking process ownership, independent of either encrypted store."""
from __future__ import annotations

import os
from pathlib import Path
import stat


class ProfileInUse(RuntimeError):
    code = "profile-in-use"


class ProfileOwnership:
    """Hold an OS lock, never delete its inode or infer ownership from a PID."""

    def __init__(self, path: Path):
        self._descriptor: int | None = None
        descriptor = None
        try:
            if path.is_symlink():
                raise OSError()
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise OSError()
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise OSError()
            if os.name == "nt":
                import msvcrt
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._descriptor = descriptor
            descriptor = None
        except OSError:
            raise ProfileInUse("profile-in-use") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def close(self) -> None:
        descriptor, self._descriptor = self._descriptor, None
        if descriptor is not None:
            os.close(descriptor)
