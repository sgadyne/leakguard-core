"""Current-user filesystem navigation; no mounting or privilege escalation."""
from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import time

from .errors import HostError

MAX_PAGE = 500
MAX_ENUMERATION = 20_000


def _path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)) or not str(value) or len(str(value)) > 4096 or "\x00" in str(value):
        raise HostError("path-invalid")
    if os.name != "nt" and (str(value).startswith("\\\\") or len(str(value)) > 1 and str(value)[1] == ":"):
        raise HostError("platform-unavailable")
    return Path(value).expanduser().absolute()


def bounded_path(value: str | Path, root: str | Path | None = None) -> Path:
    target = _path(value)
    try:
        resolved = target.resolve()
        if root is not None:
            base = _path(root).resolve()
            if not resolved.is_relative_to(base):
                raise HostError("outside-root")
        return resolved
    except HostError:
        raise
    except (OSError, RuntimeError):
        raise HostError("unreadable") from None


def path_status(path: Path) -> str:
    try:
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode):
            return "not-directory"
        with os.scandir(path):
            pass
        return "available"
    except PermissionError:
        return "permission-denied"
    except FileNotFoundError:
        return "offline"
    except OSError as error:
        return "offline" if error.errno in {errno.ENODEV, errno.ENXIO, errno.ESTALE, errno.ENETDOWN, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EIO} else "unreadable"


def _mounts() -> list[dict]:
    """Discover mount metadata without probing every remote filesystem."""
    values = []
    if platform.system() == "Linux":
        try:
            with open("/proc/self/mountinfo", encoding="utf-8") as stream:
                for line in stream:
                    before, after = line.rstrip().split(" - ", 1)
                    fields, extra = before.split(), after.split()
                    decode = lambda item: item.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
                    target, filesystem = decode(fields[4]), extra[0]
                    if target == "/" or filesystem in {"nfs", "nfs4", "cifs", "smb3", "fuse.sshfs"} or target.startswith(("/mnt/", "/media/", "/run/media/")):
                        # Mount/device IDs change on a legitimate reconnect.
                        # Bind to the selected endpoint/root instead, so an
                        # unmounted local fallback is rejected and the SAME
                        # share can reconnect without a new source selection.
                        marker = hashlib.sha256((extra[1] + "|" + decode(fields[3]) + "|" + target + "|" + filesystem).encode()).hexdigest()
                        values.append({"path": target, "filesystem": filesystem, "marker": marker})
        except (OSError, ValueError, IndexError):
            pass
    elif platform.system() == "Darwin":
        try:
            # Native mount output is metadata only, bounded and never a shell.
            result = subprocess.run(["/sbin/mount", "-p"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=False)
            if len(result.stdout) <= 1_000_000:
                for line in result.stdout.decode("utf-8", "replace").splitlines():
                    fields = line.split()
                    if len(fields) >= 3:
                        target = fields[1].replace("\\040", " ")
                        if target == "/" or target.startswith("/Volumes/"):
                            marker = hashlib.sha256((fields[0] + "|" + target + "|" + fields[2]).encode()).hexdigest()
                            values.append({"path": target, "filesystem": fields[2], "marker": marker})
        except (OSError, subprocess.SubprocessError):
            pass
    elif os.name == "nt":
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for index in range(26):
            if mask & (1 << index):
                target = chr(65 + index) + ":\\"
                values.append({"path": target, "filesystem": "windows-drive", "marker": target})
    return values


def mount_marker(path: str | Path) -> str | None:
    target = _path(path)
    matches = [item for item in _mounts() if target.is_relative_to(Path(item["path"]))]
    if not matches:
        return None
    return max(enumerate(matches), key=lambda value: (len(value[1]["path"]), value[0]))[1]["marker"]


def capabilities() -> dict:
    system = platform.system()
    return {"platform": system.lower(), "native_platform": system, "navigation": True,
            "mounted_shares": True, "mount_management": False, "unc": os.name == "nt",
            "reveal": system in {"Darwin", "Windows"} or shutil.which("xdg-open") is not None,
            "ssh": shutil.which("ssh") is not None, "service": system in {"Linux", "Darwin", "Windows"},
            "platform_validation": "native-runtime-only"}


def roots(*, supplied_unc: tuple[str, ...] = ()) -> list[dict]:
    home = Path.home()
    candidates = [(str(home), "Home", "home")]
    for name in ("Desktop", "Documents", "Downloads"):
        if (home / name).is_dir():
            candidates.append((str(home / name), name, "common"))
    for item in _mounts():
        candidates.append((item["path"], Path(item["path"]).name or item["path"], "mounted"))
    for value in supplied_unc:
        if not isinstance(value, str) or not value.startswith("\\\\") or len(value) > 4096:
            raise HostError("path-invalid")
        candidates.append((value, value, "unc"))
    seen, rows = set(), []
    for value, label, kind in candidates:
        if value in seen:
            continue
        seen.add(value)
        # Remote roots are probed only when the user browses them.
        status = "unverified" if kind == "mounted" or kind == "unc" and os.name == "nt" else "available"
        if kind == "unc" and os.name != "nt":
            status = "platform-unavailable"
        rows.append({"name": label, "path": value, "kind": kind, "status": status, "selectable": status != "platform-unavailable"})
    return rows


def browse(path: str | Path, *, root: str | Path | None = None, cursor: str | None = None, limit: int = 100) -> dict:
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise HostError("page-invalid")
    target = bounded_path(path, root)
    base = str(bounded_path(root)) if root is not None else None
    response = {"path": str(target), "root": base, "status": "available", "entries": [], "next_cursor": None, "truncated": False}
    position = 0
    try:
        info = target.stat()
        signature = [info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns]
        fingerprint = hashlib.sha256(json.dumps([str(target), base, signature]).encode()).hexdigest()
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor.startswith("lgh1.") or len(cursor) > 512:
                raise HostError("cursor-invalid")
            try:
                encoded = cursor[5:]
                value = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True))
                if type(value) is not list or len(value) != 2 or value[0] != fingerprint or type(value[1]) is not int or not 0 <= value[1] <= MAX_ENUMERATION:
                    raise ValueError()
                position = value[1]
            except (ValueError, TypeError, UnicodeError):
                raise HostError("cursor-invalid") from None
        deadline = time.monotonic() + 2
        with os.scandir(target) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_ENUMERATION or time.monotonic() > deadline:
                    response.update(truncated=True, status="listing-limit")
                    break
                if index < position:
                    continue
                if len(response["entries"]) >= limit:
                    response["next_cursor"] = "lgh1." + base64.urlsafe_b64encode(json.dumps([fingerprint, index]).encode()).decode().rstrip("=")
                    break
                try:
                    kind = "symlink" if entry.is_symlink() else "directory" if entry.is_dir(follow_symlinks=False) else "file" if entry.is_file(follow_symlinks=False) else "other"
                    status = "symlink-not-followed" if kind == "symlink" else "available"
                except PermissionError:
                    kind, status = "unknown", "permission-denied"
                except OSError:
                    kind, status = "unknown", "unreadable"
                response["entries"].append({"name": entry.name, "path": entry.path, "kind": kind, "status": status, "selectable": kind == "directory" and status == "available"})
        after = target.stat()
        if signature != [after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns]:
            response.update(status="directory-changed", next_cursor=None, truncated=True)
    except HostError:
        raise
    except PermissionError:
        response["status"] = "permission-denied"
    except FileNotFoundError:
        response["status"] = "offline"
    except NotADirectoryError:
        response["status"] = "not-directory"
    except OSError:
        response["status"] = "unreadable"
    return response


def reveal(path: str | Path, *, root: str | Path) -> dict:
    target = bounded_path(path, root)
    if not target.exists():
        return {"supported": False, "path": str(target), "status": "offline"}
    system = platform.system()
    if system == "Darwin":
        argv = ["/usr/bin/open", "-R", str(target)]
    elif os.name == "nt":
        argv = ["explorer.exe", "/select,", str(target)]
    elif shutil.which("xdg-open"):
        argv = [shutil.which("xdg-open"), str(target if target.is_dir() else target.parent)]
    else:
        return {"supported": False, "path": str(target), "status": "copy-path"}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Reap the child without blocking the local API.
        import threading
        threading.Thread(target=process.wait, daemon=True).start()
        return {"supported": True, "path": str(target), "status": "requested"}
    except OSError:
        return {"supported": False, "path": str(target), "status": "copy-path"}
