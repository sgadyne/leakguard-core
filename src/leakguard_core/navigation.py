"""Bounded, no-follow directory enumeration with an explicit Rust helper option.

The default implementation uses Python's descriptor-relative scandir path. A
requested native helper is never replaced by Python after startup or protocol
failure. The helper receives the already-open directory descriptor for each
request, so traversal remains rooted in the same directory object as the core
filesystem boundary.
"""
from __future__ import annotations

import array
import base64
from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import threading
import time
from typing import Callable, Iterator


_MAX_ENTRIES = 100_000
_MAX_LINE_BYTES = 64 * 1024
_MAX_REQUEST_BYTES = 4 * 1024
_MAX_TIMEOUT_SECONDS = 120.0
_HANDSHAKE_SECONDS = 5.0
_CANCEL_DRAIN_SECONDS = 5.0


class NavigationError(OSError):
    """Sanitized traversal error carrying a stable, path-free code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class NavigationStat:
    """Stat-like values retaining the helper's exact nanosecond timestamps."""

    st_mode: int
    st_ino: int
    st_dev: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_atime_ns: int
    st_mtime_ns: int
    st_ctime_ns: int

    @property
    def st_atime(self):
        return self.st_atime_ns / 1_000_000_000

    @property
    def st_mtime(self):
        return self.st_mtime_ns / 1_000_000_000

    @property
    def st_ctime(self):
        return self.st_ctime_ns / 1_000_000_000

    def __iter__(self):
        return iter((self.st_mode, self.st_ino, self.st_dev, self.st_nlink,
                     self.st_uid, self.st_gid, self.st_size,
                     self.st_atime, self.st_mtime, self.st_ctime))


@dataclass(frozen=True, slots=True)
class NavigationEntry:
    """A no-follow metadata snapshot shaped like ``os.DirEntry``."""

    name: str
    path: Path
    kind: str
    mode: int
    size: int
    atime_ns: int
    mtime_ns: int
    ctime_ns: int
    device: int
    inode: int
    nlink: int
    uid: int
    gid: int

    def is_symlink(self) -> bool:
        return self.kind == "symlink"

    def is_dir(self, *, follow_symlinks: bool = False) -> bool:
        if follow_symlinks:
            raise NavigationError("follow-links-disabled")
        return self.kind == "directory"

    def is_file(self, *, follow_symlinks: bool = False) -> bool:
        if follow_symlinks:
            raise NavigationError("follow-links-disabled")
        return self.kind == "file"

    def stat(self, *, follow_symlinks: bool = False) -> NavigationStat:
        if follow_symlinks:
            raise NavigationError("follow-links-disabled")
        return NavigationStat(self.mode, self.inode, self.device, self.nlink,
                              self.uid, self.gid, self.size, self.atime_ns,
                              self.mtime_ns, self.ctime_ns)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate-field")
        result[key] = value
    return result


def _loads(line: bytes) -> dict:
    try:
        value = json.loads(line, object_pairs_hook=_unique_object,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise NavigationError("helper-response-invalid") from None
    if type(value) is not dict:
        raise NavigationError("helper-response-invalid")
    return value


def _signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode),
            info.st_mtime_ns, info.st_ctime_ns)


def _component_from_wire(value: dict, parent: Path) -> NavigationEntry:
    fields = {"name_b64", "kind", "mode", "size", "atime_ns", "mtime_ns",
              "ctime_ns", "device", "inode", "nlink", "uid", "gid"}
    if type(value) is not dict or set(value) != fields:
        raise NavigationError("helper-response-invalid")
    if (type(value["name_b64"]) is not str or len(value["name_b64"]) > 16_384
            or type(value["kind"]) is not str
            or value["kind"] not in {"directory", "file", "symlink", "other"}
            or any(type(value[key]) is not int or value[key] < 0
                   for key in ("mode", "size", "device", "inode", "nlink", "uid", "gid"))
            or any(type(value[key]) is not int for key in ("atime_ns", "mtime_ns", "ctime_ns"))):
        raise NavigationError("helper-response-invalid")
    try:
        raw_name = base64.b64decode(value["name_b64"], validate=True)
        name = os.fsdecode(raw_name)
    except (ValueError, UnicodeError):
        raise NavigationError("helper-response-invalid") from None
    if (not name or name in {".", ".."} or "\x00" in name or "/" in name
            or os.name == "nt" and "\\" in name or len(name) > 4096):
        raise NavigationError("helper-path-invalid")
    return NavigationEntry(name, parent / name, value["kind"], value["mode"],
                           value["size"], value["atime_ns"], value["mtime_ns"],
                           value["ctime_ns"], value["device"], value["inode"],
                           value["nlink"], value["uid"], value["gid"])


class _PythonEntries:
    def __init__(self, entries, *, maximum: int,
                 deadline: float, cancel: Callable[[], bool] | None):
        self._entries = iter(entries)
        self._maximum = maximum
        self._deadline = deadline
        self._cancel = cancel
        self._count = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._cancel is not None and self._cancel():
            raise NavigationError("cancelled")
        if time.monotonic() >= self._deadline:
            raise NavigationError("deadline-exhausted")
        try:
            entry = next(self._entries)
        except StopIteration:
            raise
        self._count += 1
        if self._count > self._maximum:
            raise NavigationError("entry-limit")
        return entry


class _HelperEntries:
    def __init__(self, navigation: "Navigation", request_id: int, parent: Path,
                 *, deadline: float, cancel: Callable[[], bool] | None):
        self._navigation = navigation
        self._request_id = request_id
        self._parent = parent
        self._deadline = deadline
        self._cancel = cancel
        self._count = 0
        self._finished = False
        self._aborted: str | None = None

    def __iter__(self):
        return self

    def __next__(self):
        if self._finished:
            raise StopIteration
        while True:
            if self._aborted is None:
                if self._cancel is not None and self._cancel():
                    self._abort("cancelled")
                elif time.monotonic() >= self._deadline:
                    self._abort("deadline-exhausted")
            response = self._navigation._read_response(self._deadline if self._aborted is None
                                                       else time.monotonic() + _CANCEL_DRAIN_SECONDS)
            if (type(response.get("schema_version")) is not int
                    or response["schema_version"] != 1
                    or type(response.get("request_id")) is not int
                    or response["request_id"] != self._request_id):
                self._navigation._poison()
                raise NavigationError("helper-response-invalid")
            kind = response.get("kind")
            if kind == "entry":
                if set(response) != {"schema_version", "request_id", "kind", "entry"}:
                    self._navigation._poison()
                    raise NavigationError("helper-response-invalid")
                try:
                    entry = _component_from_wire(response["entry"], self._parent)
                except NavigationError:
                    self._navigation._poison()
                    self._finished = True
                    raise
                self._count += 1
                if self._count > self._navigation.max_entries:
                    self._abort("entry-limit")
                if self._aborted is not None:
                    continue
                return entry
            if kind == "done":
                if set(response) != {"schema_version", "request_id", "kind", "count"} or type(response["count"]) is not int or response["count"] != self._count:
                    self._navigation._poison()
                    raise NavigationError("helper-response-invalid")
                self._finished = True
                if self._aborted is not None:
                    raise NavigationError(self._aborted)
                raise StopIteration
            if kind == "error":
                if (set(response) != {"schema_version", "request_id", "kind", "code"}
                        or type(response["code"]) is not str
                        or response["code"] not in {"cancelled", "deadline-exhausted", "entry-limit", "directory-changed", "directory-unavailable", "filesystem-boundary", "walk-failed", "worker-protocol"}):
                    self._navigation._poison()
                    raise NavigationError("helper-response-invalid")
                self._finished = True
                raise NavigationError(self._aborted or response["code"])
            self._navigation._poison()
            raise NavigationError("helper-response-invalid")

    def _abort(self, code: str):
        if self._aborted is not None:
            return
        self._aborted = code
        self._navigation._send_cancel(self._request_id)

    def drain(self):
        if self._finished:
            return
        self._abort("cancelled")
        try:
            while True:
                next(self)
        except (StopIteration, NavigationError):
            return


class Navigation:
    """A reusable enumeration service with a pure-Python default backend.

    Supplying ``helper`` explicitly requests the native worker. Startup, protocol,
    or worker errors are returned to the caller; they never silently switch to
    the Python implementation. ``same_file_system`` is explicit on every walk.
    """

    def __init__(self, helper: str | os.PathLike[str] | None = None, *,
                 max_entries: int = _MAX_ENTRIES):
        if type(max_entries) is not int or not 1 <= max_entries <= _MAX_ENTRIES:
            raise ValueError("max_entries")
        self.max_entries = max_entries
        self._helper_path = Path(helper).absolute() if helper is not None else None
        self._lock = threading.RLock()
        self._process: subprocess.Popen | None = None
        self._socket: socket.socket | None = None
        self._buffer = bytearray()
        self._request_id = 0
        self._closed = False
        self._poisoned = False
        self._native_info: dict | None = None
        if self._helper_path is not None:
            self._start_helper()

    @contextmanager
    def scandir(self, path: str | os.PathLike[str], *, boundary=None,
                deadline: float | None = None, cancel: Callable[[], bool] | None = None,
                same_file_system: bool = False) -> Iterator[Iterator[NavigationEntry]]:
        """Yield a deterministic direct-entry listing with links left unopened."""
        if type(same_file_system) is not bool:
            raise ValueError("same_file_system")
        target = Path(path).absolute()
        if "\x00" in str(target) or len(str(target)) > 4096:
            raise NavigationError("path-invalid")
        end = deadline if deadline is not None else time.monotonic() + _MAX_TIMEOUT_SECONDS
        if (type(end) not in {int, float}
                or type(end) is float and not math.isfinite(end)
                or end <= time.monotonic()):
            raise NavigationError("deadline-exhausted")
        end = min(end, time.monotonic() + _MAX_TIMEOUT_SECONDS)
        if self._closed:
            raise NavigationError("navigation-closed")
        with self._lock:
            descriptor = None
            expected = None
            try:
                if boundary is not None:
                    boundary.check(target, directory=True)
                    if self._helper_path is not None:
                        descriptor = boundary.directory_fd(target)
                        if descriptor is None:
                            raise NavigationError("secure-fd-unavailable")
                        expected = os.fstat(descriptor)
                        filesystem_device = boundary.identity.device
                        if same_file_system and expected.st_dev != filesystem_device:
                            raise NavigationError("filesystem-boundary")
                    else:
                        filesystem_device = boundary.identity.device
                elif self._helper_path is not None:
                    descriptor, expected = self._open_directory(target)
                    filesystem_device = expected.st_dev
                else:
                    filesystem_device = None
                if self._helper_path is None:
                    with self._python_listing(target, boundary, maximum=self.max_entries,
                                              deadline=float(end), cancel=cancel,
                                              same_file_system=same_file_system,
                                              filesystem_device=filesystem_device) as entries:
                        yield entries
                else:
                    with self._native_listing(target, descriptor, expected,
                                              same_file_system=same_file_system,
                                              filesystem_device=filesystem_device,
                                              deadline=float(end), cancel=cancel) as entries:
                        yield entries
            finally:
                if descriptor is not None:
                    os.close(descriptor)
                if boundary is not None:
                    boundary.check(target, directory=True)

    def capabilities(self) -> dict:
        if self._helper_path is None:
            return {"backend": "python", "native": False,
                    "descriptor_relative": os.name == "posix",
                    "hidden_entries": True, "ignore_filters": False,
                    "follow_links": False, "same_file_system": True,
                    "fallback_reason": (None if os.name == "posix" else
                                        "secure-fd-native-bridge-unsupported")}
        if self._native_info is None:
            return {"backend": "rust-ignore", "native": True,
                    "status": "unavailable"}
        return {"backend": "rust-ignore", "native": True, **self._native_info}

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            process, stream = self._process, self._socket
            if stream is not None and process is not None and process.poll() is None:
                try:
                    line = b'{"schema_version":1,"kind":"close"}\n'
                    stream.sendall(line)
                    process.wait(timeout=1.0)
                except Exception:
                    try:
                        process.terminate()
                        process.wait(timeout=0.5)
                    except Exception:
                        try:
                            process.kill()
                            process.wait(timeout=0.5)
                        except Exception:
                            pass
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
            self._process = None
            self._socket = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    @staticmethod
    def _open_directory(path: Path):
        descriptor = None
        try:
            before = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise NavigationError("not-directory")
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(path, flags)
            after = os.fstat(descriptor)
            if _signature(before) != _signature(after):
                raise NavigationError("directory-changed")
            result = descriptor, after
            descriptor = None
            return result
        except NavigationError:
            raise
        except OSError:
            raise NavigationError("directory-unavailable") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _python_listing(self, target, boundary, *, maximum, deadline, cancel,
                        same_file_system, filesystem_device):
        @contextmanager
        def listing():
            descriptor = boundary.directory_fd(target) if boundary is not None else None
            if boundary is None and os.name == "posix":
                try:
                    descriptor = os.open(
                        target,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    )
                except OSError:
                    raise NavigationError("directory-unavailable") from None
            try:
                scan_target = descriptor if descriptor is not None else target
                with os.scandir(scan_target) as entries:
                    root_info = os.fstat(descriptor) if descriptor is not None else os.stat(
                        target, follow_symlinks=False)
                    if not stat.S_ISDIR(root_info.st_mode):
                        raise NavigationError("not-directory")
                    anchor_device = (filesystem_device if filesystem_device is not None
                                     else root_info.st_dev)
                    if same_file_system and root_info.st_dev != anchor_device:
                        raise NavigationError("filesystem-boundary")
                    # Directory sizes are bounded before materializing or sorting.
                    values = []
                    for entry in entries:
                        if cancel is not None and cancel():
                            raise NavigationError("cancelled")
                        if time.monotonic() >= deadline:
                            raise NavigationError("deadline-exhausted")
                        if len(values) >= maximum:
                            raise NavigationError("entry-limit")
                        try:
                            # Windows DirEntry.stat() has zero device/inode
                            # fields; no-follow os.stat retains boundary identity.
                            info = (os.stat(target / entry.name, follow_symlinks=False)
                                    if os.name == "nt" else entry.stat(follow_symlinks=False))
                            if same_file_system and info.st_dev != anchor_device:
                                raise NavigationError("filesystem-boundary")
                            kind = ("symlink" if entry.is_symlink() else
                                    "directory" if stat.S_ISDIR(info.st_mode) else
                                    "file" if stat.S_ISREG(info.st_mode) else "other")
                            values.append((os.fsencode(entry.name), NavigationEntry(
                                entry.name, target / entry.name, kind, info.st_mode,
                                info.st_size, info.st_atime_ns, info.st_mtime_ns,
                                info.st_ctime_ns, info.st_dev, info.st_ino,
                                info.st_nlink, info.st_uid, info.st_gid)))
                        except NavigationError:
                            raise
                        except OSError:
                            raise NavigationError("entry-unavailable") from None
                    values.sort(key=lambda pair: pair[0])
                    yield _PythonEntries([entry for _, entry in values],
                                         maximum=maximum, deadline=deadline,
                                         cancel=cancel)
            except NavigationError:
                raise
            except OSError:
                raise NavigationError("directory-unavailable") from None
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        return listing()

    def _start_helper(self):
        if os.name != "posix" or not hasattr(socket, "SCM_RIGHTS") or not hasattr(socket, "AF_UNIX"):
            raise NavigationError("secure-fd-unavailable")
        if not self._helper_path.is_file() or not os.access(self._helper_path, os.X_OK):
            raise NavigationError("helper-unavailable")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            process = subprocess.Popen(
                [str(self._helper_path), "--control-fd", str(child.fileno())],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True,
                pass_fds=(child.fileno(),), start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
            )
        except OSError:
            parent.close()
            child.close()
            raise NavigationError("helper-unavailable") from None
        child.close()
        parent.setblocking(True)
        self._process, self._socket = process, parent
        try:
            response = self._read_response(time.monotonic() + _HANDSHAKE_SECONDS)
            fields = {"schema_version", "kind", "helper_version", "ignore_version",
                      "secure_fd", "hidden_entries", "ignore_filters", "follow_links",
                      "same_file_system", "direct_entries_only"}
            if (set(response) != fields
                    or type(response.get("schema_version")) is not int
                    or response["schema_version"] != 1
                    or response.get("kind") != "ready"
                    or response.get("helper_version") != "0.1.0"
                    or response.get("ignore_version") != "0.4.33"
                    or response.get("secure_fd") is not True
                    or response.get("hidden_entries") is not True
                    or response.get("ignore_filters") is not False
                    or response.get("follow_links") is not False
                    or response.get("same_file_system") is not True
                    or response.get("direct_entries_only") is not True):
                raise NavigationError("helper-handshake-invalid")
            self._native_info = {"helper_version": response["helper_version"],
                                 "ignore_version": response["ignore_version"],
                                 "secure_fd": True, "hidden_entries": True,
                                 "ignore_filters": False, "follow_links": False,
                                 "same_file_system": True, "direct_entries_only": True}
        except Exception as error:
            self._poison()
            if isinstance(error, NavigationError):
                raise
            raise NavigationError("helper-handshake-invalid") from None

    def _native_listing(self, target, descriptor, info, *, same_file_system,
                        filesystem_device, deadline, cancel):
        @contextmanager
        def listing():
            self._ensure_helper()
            self._request_id += 1
            request_id = self._request_id
            remaining = min(_MAX_TIMEOUT_SECONDS, max(0.001, deadline - time.monotonic()))
            request = {"schema_version": 1, "kind": "scan", "request_id": request_id,
                       "same_file_system": same_file_system,
                       "filesystem_device": int(filesystem_device),
                       "max_entries": self.max_entries,
                       "timeout_ms": max(1, int(remaining * 1000)),
                       "device": int(info.st_dev), "inode": int(info.st_ino),
                       "mode": int(info.st_mode), "mtime_ns": int(info.st_mtime_ns),
                       "ctime_ns": int(info.st_ctime_ns)}
            self._send_fd_message(request, descriptor)
            entries = _HelperEntries(self, request_id, target,
                                     deadline=deadline, cancel=cancel)
            try:
                yield entries
                # Drain the protocol even when a caller stops consuming early.
                if not entries._finished:
                    entries.drain()
            except Exception:
                entries.drain()
                raise
        return listing()

    def _ensure_helper(self):
        if self._closed:
            raise NavigationError("navigation-closed")
        if self._poisoned or self._process is None or self._process.poll() is not None:
            raise NavigationError("helper-failed")

    def _send_fd_message(self, value: dict, descriptor: int):
        self._ensure_helper()
        line = json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii") + b"\n"
        if len(line) > _MAX_REQUEST_BYTES:
            raise NavigationError("helper-request-limit")
        fds = array.array("i", [descriptor])
        try:
            sent = self._socket.sendmsg([line], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
            if sent <= 0:
                raise OSError()
            if sent < len(line):
                self._socket.sendall(line[sent:])
        except OSError:
            self._poison()
            raise NavigationError("helper-failed") from None

    def _send_message(self, value: dict):
        line = json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii") + b"\n"
        if len(line) > _MAX_REQUEST_BYTES or self._socket is None:
            raise NavigationError("helper-request-limit")
        try:
            self._socket.sendall(line)
        except OSError:
            self._poison()
            raise NavigationError("helper-failed") from None

    def _send_cancel(self, request_id: int):
        try:
            self._send_message({"schema_version": 1, "kind": "cancel",
                                "request_id": request_id})
        except NavigationError:
            self._poison()

    def _read_response(self, deadline: float) -> dict:
        if self._socket is None:
            raise NavigationError("helper-failed")
        while b"\n" not in self._buffer:
            self._ensure_helper()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._poison()
                raise NavigationError("helper-timeout")
            readable, _, _ = select.select([self._socket], [], [], min(0.05, remaining))
            if not readable:
                continue
            try:
                chunk = self._socket.recv(8192)
            except OSError:
                self._poison()
                raise NavigationError("helper-failed") from None
            if not chunk:
                self._poison()
                raise NavigationError("helper-failed")
            self._buffer.extend(chunk)
            if len(self._buffer) > _MAX_LINE_BYTES:
                self._poison()
                raise NavigationError("helper-response-limit")
        end = self._buffer.index(b"\n")
        line = bytes(self._buffer[:end])
        del self._buffer[:end + 1]
        return _loads(line)

    def _poison(self):
        self._poisoned = True
        process, stream = self._process, self._socket
        self._process = None
        self._socket = None
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=0.5)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=0.5)
                except Exception:
                    pass
