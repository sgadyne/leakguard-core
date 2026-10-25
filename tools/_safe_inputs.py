"""Small, bounded readers and source identity helpers for validation tools."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess


MAX_CONFIG_BYTES = 1_000_000


def read_empty_json_object(path: Path) -> None:
    """Admit only a regular, bounded, unique-key JSON empty object.

    O_NONBLOCK prevents a FIFO from stalling a validation command; fstat then
    rejects it before any read. O_NOFOLLOW is used where supported, in addition
    to the explicit symlink check, to keep the preflight path stable.
    """
    path = Path(path)
    if path.is_symlink():
        raise ValueError("config-invalid")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > MAX_CONFIG_BYTES:
            raise ValueError("config-invalid")
        chunks = bytearray()
        while len(chunks) <= MAX_CONFIG_BYTES:
            block = os.read(descriptor, min(65_536, MAX_CONFIG_BYTES + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > MAX_CONFIG_BYTES:
            raise ValueError("config-invalid")
    finally:
        os.close(descriptor)

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("config-invalid")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("config-invalid")

    try:
        value = json.loads(bytes(chunks).decode("utf-8-sig"),
                           object_pairs_hook=unique_pairs,
                           parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("config-invalid") from error
    if type(value) is not dict or value:
        raise ValueError("config-invalid")


def _update_file_digest(digest, path: Path, root: Path) -> None:
    """Hash a path entry without following an untracked symlink's target."""
    try:
        original_stat = path.lstat()
    except OSError:
        digest.update(b"entry-unavailable\0")
        return

    if stat.S_ISLNK(original_stat.st_mode):
        try:
            target = os.readlink(path)
            target_bytes = os.fsencode(target) if isinstance(target, str) else target
        except OSError:
            target_bytes = b"<unreadable-link>"
        digest.update(b"symlink\0" + target_bytes + b"\0")
        return

    if not stat.S_ISREG(original_stat.st_mode):
        digest.update(b"non-regular\0" + str(stat.S_IFMT(original_stat.st_mode)).encode("ascii") + b"\0")
        return

    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            digest.update(b"outside-root-file-not-read\0")
            return
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                digest.update(b"non-regular-after-open\0")
                return
            digest.update(b"regular-file\0")
            while block := stream.read(1_048_576):
                digest.update(block)
    except (OSError, RuntimeError):
        digest.update(b"file-read-failed\0")


def source_identity(root: Path) -> tuple[str, str]:
    """Return HEAD plus a digest of the patch and all safely observed untracked entries."""
    root = Path(root).resolve(strict=True)

    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True,
                              check=True, timeout=15).stdout

    revision = git("rev-parse", "HEAD").decode("ascii").strip()
    digest = hashlib.sha256()
    digest.update(b"worktree-diff\0")
    digest.update(git("diff", "--binary", "HEAD"))
    for relative in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if not relative:
            continue
        relative_text = os.fsdecode(relative)
        candidate = root / relative_text
        # Reject lexical escape paths before path resolution.
        if Path(relative_text).is_absolute() or ".." in Path(relative_text).parts:
            digest.update(relative + b"\0outside-root-entry\0")
            continue
        digest.update(relative + b"\0")
        _update_file_digest(digest, candidate, root)
    return revision, digest.hexdigest()
