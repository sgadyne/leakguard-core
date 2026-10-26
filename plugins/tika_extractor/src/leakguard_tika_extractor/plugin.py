"""Bounded local Apache Tika 4.1.0 extractor.

The session-owned adapter starts one loopback server and keeps it warm for the
owning core worker. It emits only body text under a fixed part label; Tika
metadata and parser messages are treated as private and never returned.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
from typing import Mapping
import zipfile

from leakguard_core.extraction import Extraction, ExtractedPart, ExtractionContext
from leakguard_core.plugins import OptionSchema, OptionSpec, PluginManifest


API_VERSION = 2
TIKA_VERSION = "4.1.0"
TIKA_ARCHIVE_SHA512 = (
    "c932f84c569fb02df4f72ab060d6f2cf77b6797417040202401bc256e18a8f6f0"
    "ebc25d12d6dce222cb9328abfcb388cfa6511d7382c765a45687240a8a4bd7e"
)
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 5000
MAX_RESPONSE_OVERHEAD = 1024 * 1024
MAX_TIKA_IPC_BYTES = 80_000_000
_SUPPORTED_FORMATS = ("pdf-text", "office-word", "office-sheet", "office-slides", "outlook-msg")
_OPTION_FIELDS = (
    OptionSpec("artifact-path", "string", required=True, max_length=4096),
    OptionSpec("artifact-sha512", "string", required=True, max_length=128),
    OptionSpec("java-path", "string", required=True, max_length=4096),
    OptionSpec("temp-root", "string", default=None, max_length=4096),
    OptionSpec("max-file-bytes", "int", default=20_971_520, min_value=1,
               max_value=20_971_520),
    OptionSpec("max-text-bytes", "int", default=12_000_000, min_value=1,
               max_value=12_000_000),
    OptionSpec("startup-timeout-ms", "int", default=30_000, min_value=1_000,
               max_value=60_000),
    OptionSpec("request-timeout-ms", "int", default=25_000, min_value=1_000,
               max_value=120_000),
)

MANIFEST = PluginManifest(
    id="tika-extractor",
    implementation_version="0.1.0a1",
    kind="extractor",
    formats=_SUPPORTED_FORMATS,
    part_kinds=("body",),
    options_schema=OptionSchema(fields=_OPTION_FIELDS),
    dependencies=(),
    deterministic=True,
    external_state="declared",
    worker_lifetime="session",
)


class _TikaUnavailable(Exception):
    pass


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int


def _file_identity(path: Path) -> _FileIdentity:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise _TikaUnavailable()
    return _FileIdentity(info.st_dev, info.st_ino, info.st_size,
                         getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)))


def _java_version(java: Path) -> tuple[str, int]:
    try:
        process = subprocess.run([str(java), "-version"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=5, check=False, close_fds=True,
                                 env={"PATH": str(java.parent)})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _TikaUnavailable() from error
    text = (process.stdout + process.stderr).decode("utf-8", "replace")[:4096]
    match = re.search(r'(?:openjdk|java)\s+version\s+["\']?(\d+)(?:\.(\d+))?', text, re.I)
    if process.returncode != 0 or not match:
        # Some vendors print "openjdk 21.0.1" without the word version.
        match = re.search(r'\bopenjdk\s+(\d+)(?:\.(\d+))?', text, re.I)
    if process.returncode != 0 or not match:
        raise _TikaUnavailable()
    major = int(match.group(1))
    if major == 1 and match.group(2):
        major = int(match.group(2))
    if major < 17:
        raise _TikaUnavailable()
    first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return first_line[:200], major


def _copy_verified_archive(source: Path, destination: Path, expected_sha512: str) -> _FileIdentity:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise _TikaUnavailable() from error
    digest = hashlib.sha512()
    out_fd = None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_ARCHIVE_BYTES:
            raise _TikaUnavailable()
        out_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        copied = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            copied += len(block)
            if copied > MAX_ARCHIVE_BYTES:
                raise _TikaUnavailable()
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(out_fd, view)
                view = view[written:]
        os.fsync(out_fd)
        after = os.fstat(descriptor)
        identity = _FileIdentity(after.st_dev, after.st_ino, after.st_size,
                                  getattr(after, "st_mtime_ns", int(after.st_mtime * 1_000_000_000)))
        if (copied != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                digest.hexdigest() != expected_sha512):
            raise _TikaUnavailable()
        return identity
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    finally:
        if out_fd is not None:
            os.close(out_fd)
        os.close(descriptor)


def _safe_extract_archive(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(mode=0o700)
    root = destination.resolve(strict=True)
    seen: set[str] = set()
    expanded = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_ARCHIVE_ENTRIES:
                raise _TikaUnavailable()
            for item in entries:
                name = item.filename
                if (not name or "\\" in name or name.startswith("/") or
                        PureWindowsPath(name).drive or name in seen):
                    raise _TikaUnavailable()
                seen.add(name)
                pure = PurePosixPath(name)
                if any(piece in {"", ".", ".."} for piece in pure.parts):
                    raise _TikaUnavailable()
                mode = (item.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode) or mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                    raise _TikaUnavailable()
                if item.flag_bits & 1:
                    raise _TikaUnavailable()
                if item.is_dir():
                    continue
                if item.file_size < 0 or item.file_size > MAX_EXPANDED_BYTES:
                    raise _TikaUnavailable()
                expanded += item.file_size
                if expanded > MAX_EXPANDED_BYTES:
                    raise _TikaUnavailable()
                target = root.joinpath(*pure.parts)
                if os.path.commonpath((str(root), str(target.resolve(strict=False)))) != str(root):
                    raise _TikaUnavailable()
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                file_descriptor = os.open(target, flags, 0o600)
                written = 0
                try:
                    with archive.open(item) as source:
                        while True:
                            block = source.read(1024 * 1024)
                            if not block:
                                break
                            written += len(block)
                            if written > item.file_size or written > MAX_EXPANDED_BYTES:
                                raise _TikaUnavailable()
                            view = memoryview(block)
                            while view:
                                count = os.write(file_descriptor, view)
                                view = view[count:]
                    if written != item.file_size:
                        raise _TikaUnavailable()
                    os.fsync(file_descriptor)
                finally:
                    os.close(file_descriptor)
        jar = root / f"tika-server-standard-{TIKA_VERSION}.jar"
        lib = root / "lib"
        if (not jar.is_file() or jar.is_symlink() or not lib.is_dir() or lib.is_symlink()
                or not any(lib.glob("*.jar"))):
            raise _TikaUnavailable()
        # The extracted closure is immutable for its lifetime. Tika's worker
        # process can be restarted by the server without re-reading the source.
        for current, directories, files in os.walk(root, topdown=False, followlinks=False):
            for file_name in files:
                os.chmod(Path(current) / file_name, 0o400)
            for directory_name in directories:
                os.chmod(Path(current) / directory_name, 0o500)
        os.chmod(root, 0o500)
        return root
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError) as error:
        if isinstance(error, _TikaUnavailable):
            raise
        raise _TikaUnavailable() from error


def _mime_for(context: ExtractionContext) -> str | None:
    suffix = Path(context.logical_path).suffix.lower()
    formats = {
        ".pdf": ("pdf-text", "application/pdf"),
        ".docx": ("office-word", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ".xlsx": ("office-sheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ".xlsm": ("office-sheet", "application/vnd.ms-excel.sheet.macroEnabled.12"),
        ".pptx": ("office-slides", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        ".msg": ("outlook-msg", "application/vnd.ms-outlook"),
    }
    selected = formats.get(suffix)
    if selected is None or selected[0] != context.format_id:
        return None
    return selected[1]


def _matches_format(data: bytes, context: ExtractionContext) -> bool:
    if context.format_id == "pdf-text":
        return data.startswith(b"%PDF-")
    if context.format_id == "outlook-msg":
        return data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    if context.format_id not in {"office-word", "office-sheet", "office-slides"}:
        return False
    expected = {
        "office-word": "word/document.xml",
        "office-sheet": "xl/workbook.xml",
        "office-slides": "ppt/presentation.xml",
    }[context.format_id]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            return (len(names) <= context.limits.max_archive_members
                    and "[Content_Types].xml" in names and expected in names)
    except (OSError, zipfile.BadZipFile, ValueError):
        return False


def _truthy_metadata(value: object) -> bool:
    if type(value) is bool:
        return value
    if type(value) is str:
        return value.strip().lower() == "true"
    if type(value) is list:
        return any(_truthy_metadata(item) for item in value)
    return False


class TikaExtractor:
    """One warmed, loopback-only Tika service owned by a v2 session worker."""

    def __init__(self, options: Mapping[str, object]):
        self._lock = threading.RLock()
        self._closed = False
        self._failure: str | None = None
        self._server: subprocess.Popen | None = None
        self._temp: tempfile.TemporaryDirectory | None = None
        self._port: int | None = None
        self._artifact_path = Path(str(options["artifact-path"]))
        self._expected_sha512 = str(options["artifact-sha512"]).lower()
        self._java_path = Path(str(options["java-path"]))
        self._temp_root = options.get("temp-root")
        self._max_file_bytes = int(options.get("max-file-bytes", 20_971_520))
        self._max_text_bytes = int(options.get("max-text-bytes", 12_000_000))
        self._startup_timeout = int(options.get("startup-timeout-ms", 30_000)) / 1000
        self._request_timeout = int(options.get("request-timeout-ms", 25_000)) / 1000
        self._artifact_identity: _FileIdentity | None = None
        self._java_identity: _FileIdentity | None = None
        self._java_version_text = ""
        self._java_major: int | None = None
        self._distribution: Path | None = None
        self._identity: dict[str, object] = {
            "component": "tika-extractor",
            "version": "0.1.0a1",
            "tika_version": TIKA_VERSION,
            "tika_archive_sha512": self._expected_sha512,
            "status": "unavailable",
        }
        if (self._expected_sha512 != TIKA_ARCHIVE_SHA512 or
                not self._artifact_path.is_absolute() or not self._java_path.is_absolute()):
            self._failure = "dependency-unavailable"
            return
        try:
            if self._artifact_path.is_symlink() or self._java_path.resolve(strict=True).is_dir():
                raise _TikaUnavailable()
            self._java_path = self._java_path.resolve(strict=True)
            if not os.access(self._java_path, os.X_OK):
                raise _TikaUnavailable()
            self._java_identity = _file_identity(self._java_path)
            self._java_version_text, self._java_major = _java_version(self._java_path)
            self._prepare_and_start()
            self._identity = self._build_identity()
        except Exception:
            self._failure = "dependency-unavailable"
            self._stop_server()
            self._remove_temp()

    def _private_temp(self) -> tempfile.TemporaryDirectory:
        parent = self._temp_root
        if parent is not None:
            candidate = Path(str(parent))
            if not candidate.is_absolute() or not candidate.is_dir() or candidate.is_symlink():
                raise _TikaUnavailable()
            parent = str(candidate)
        return tempfile.TemporaryDirectory(prefix="leakguard-tika-", dir=parent)

    def _prepare_and_start(self) -> None:
        self._temp = self._private_temp()
        private = Path(self._temp.name)
        os.chmod(private, 0o700)
        archive_copy = private / "tika-server-standard.zip"
        # Copy and hash into the private directory, so the jar/lib
        # closure comes only from the verified archive bytes.
        self._artifact_identity = _copy_verified_archive(
            self._artifact_path, archive_copy, self._expected_sha512)
        self._distribution = _safe_extract_archive(archive_copy, private / "distribution")
        archive_copy.unlink()
        home = private / "home"
        work = private / "work"
        tika_tmp = work / "tmp"
        home.mkdir(mode=0o700)
        tika_tmp.mkdir(mode=0o700, parents=True)
        config_path = work / "tika-config.json"
        config = self._server_config()
        with config_path.open("x", encoding="utf-8") as stream:
            json.dump(config, stream, separators=(",", ":"))
        os.chmod(config_path, 0o600)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            self._port = listener.getsockname()[1]
        jar = self._distribution / f"tika-server-standard-{TIKA_VERSION}.jar"
        command = [str(self._java_path), "-Xms32m", "-Xmx128m",
                   "-XX:+DisableAttachMechanism", "-Djava.net.useSystemProxies=false",
                   f"-Djava.io.tmpdir={tika_tmp}", f"-Duser.home={home}",
                   "-jar", str(jar), "--host", "127.0.0.1", "--port", str(self._port),
                   "--config", str(config_path)]
        env = {
            "PATH": str(self._java_path.parent),
            "HOME": str(home),
            "TMPDIR": str(tika_tmp),
            "TMP": str(tika_tmp),
            "TEMP": str(tika_tmp),
            "LANG": "C.UTF-8",
        }
        for key in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"):
            if os.name == "nt" and key in os.environ:
                env[key] = os.environ[key]
        self._server = subprocess.Popen(
            command, cwd=str(self._distribution), stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
            close_fds=True,
        )
        self._wait_until_ready()

    def _server_config(self) -> dict[str, object]:
        timeout_ms = int(self._request_timeout * 1000)
        return {
            "server": {
                "endpoints": ["tika", "version"],
                "allowPipes": False,
                "allowPerRequestConfig": False,
                "cors": "",
                "maxRequestSizeBytes": self._max_file_bytes,
            },
            "pipes": {
                "numClients": 1,
                "useSharedServer": False,
                "maxFilesProcessedPerProcess": 10_000,
                "maxWaitForClientMillis": 1_000,
                "maxInlineBytes": self._max_file_bytes,
                "maxIpcPayloadBytes": MAX_TIKA_IPC_BYTES,
                "maxTotalTaskTimeoutMillis": timeout_ms,
                "socketTimeoutMillis": timeout_ms + 2_000,
                "javaPath": str(self._java_path),
                "forkedJvmArgs": ["-Xms16m", "-Xmx256m"],
            },
            "parse-context": {
                "output-limits": {
                    "writeLimit": self._max_text_bytes,
                    # Tika reports a bounded write-limit flag in structured
                    # metadata when false. The adapter discards any partial
                    # body and returns an explicit output-limit issue.
                    "throwOnWriteLimit": False,
                    "maxXmlDepth": 100,
                    "maxPackageEntryDepth": 10,
                    "zipBombThreshold": 1_000_000,
                    "zipBombRatio": 100,
                },
                "embedded-limits": {
                    "maxDepth": 10,
                    "throwOnMaxDepth": True,
                    "maxCount": 1000,
                    "throwOnMaxCount": True,
                },
                "timeout-limits": {
                    "totalTaskTimeoutMillis": timeout_ms,
                    "progressTimeoutMillis": max(1_000, timeout_ms - 1_000),
                },
                "standard-metadata-limiter-factory": {
                    "maxTotalBytes": 4096,
                    "maxFieldSize": 1024,
                    "maxKeySize": 128,
                    "maxValuesPerField": 8,
                },
            },
            # These empty lists disable local OCR and inference engines. No
            # cloud endpoint or command-line OCR process is configured.
            "text-recognizers": [],
            "inference": [],
        }

    def _wait_until_ready(self) -> None:
        if self._port is None or self._server is None:
            raise _TikaUnavailable()
        deadline = time.monotonic() + self._startup_timeout
        while time.monotonic() < deadline:
            if self._server.poll() is not None:
                raise _TikaUnavailable()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", self._port, timeout=0.5)
                connection.request("GET", "/version", headers={"Connection": "close"})
                response = connection.getresponse()
                body = response.read(512)
                connection.close()
                if response.status == 200 and TIKA_VERSION.encode("ascii") in body:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise _TikaUnavailable()

    def _assert_runtime_unchanged(self) -> bool:
        try:
            return (_file_identity(self._artifact_path) == self._artifact_identity and
                    _file_identity(self._java_path) == self._java_identity)
        except (OSError, _TikaUnavailable):
            return False

    def _build_identity(self) -> dict[str, object]:
        config = self._server_config()
        serial = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        fingerprint = hashlib.sha256(
            (TIKA_ARCHIVE_SHA512 + "|" + self._java_version_text + "|").encode() + serial
        ).hexdigest()
        return {
            "component": "tika-extractor",
            "version": "0.1.0a1",
            "tika_version": TIKA_VERSION,
            "tika_archive_sha512": TIKA_ARCHIVE_SHA512,
            "java_runtime": self._java_version_text,
            "java_major": self._java_major,
            "config_sha256": hashlib.sha256(serial).hexdigest(),
            "runtime_fingerprint": fingerprint,
            "service": "loopback-session",
            "status": "ready",
        }

    def identity(self) -> dict[str, object]:
        return dict(self._identity)

    def capabilities(self) -> dict[str, object]:
        ready = (self._failure is None and not self._closed and self._server is not None
                 and self._server.poll() is None and self._assert_runtime_unchanged())
        return {
            "component": "tika-extractor",
            "tika_version": TIKA_VERSION,
            "formats": list(_SUPPORTED_FORMATS),
            "ocr": False,
            "remote_services": False,
            "ready": ready,
            "service": "warm-loopback-server",
        }

    def extract(self, data: bytes, context: ExtractionContext) -> Extraction:
        if type(data) is not bytes:
            return Extraction("no-text", issues=("unsupported-format",))
        mime_type = _mime_for(context)
        if mime_type is None or not _matches_format(data, context):
            return Extraction("unsupported", issues=("unsupported-format",))
        if len(data) > min(context.limits.max_file_bytes, self._max_file_bytes):
            return Extraction("no-text", issues=("extract-output-limit",))
        if context.limits.max_text_bytes < 1 or context.limits.max_parts < 1:
            return Extraction("no-text", issues=("extract-output-limit",))
        with self._lock:
            if self._closed or self._failure is not None or self._server is None:
                return Extraction("no-text", issues=(self._failure or "dependency-unavailable",))
            if not self._assert_runtime_unchanged() or self._server.poll() is not None:
                return Extraction("no-text", issues=("dependency-unavailable",))
            return self._parse(data, mime_type, context)

    def _parse(self, data: bytes, mime_type: str, context: ExtractionContext) -> Extraction:
        if self._port is None:
            return Extraction("no-text", issues=("dependency-unavailable",))
        connection = http.client.HTTPConnection("127.0.0.1", self._port,
                                                timeout=self._request_timeout)
        try:
            connection.request(
                # BODY excludes parser metadata that the TEXT handler may emit
                # alongside extracted content (for example a PDF title).
                "PUT", "/tika/json/body", body=data,
                headers={"Content-Type": mime_type, "Accept": "application/json",
                         "Connection": "close"},
            )
            response = connection.getresponse()
            max_response = min(
                context.limits.max_ipc_bytes,
                self._max_text_bytes * 6 + MAX_RESPONSE_OVERHEAD,
            )
            raw = response.read(max_response + 1)
            status = response.status
        except (OSError, http.client.HTTPException, TimeoutError):
            return Extraction("no-text", issues=("extract-timeout",))
        finally:
            connection.close()
        if len(raw) > max_response or status == 413:
            return Extraction("no-text", issues=("extract-output-limit",))
        if status in {408, 504}:
            return Extraction("no-text", issues=("extract-timeout",))
        if status < 200 or status >= 300:
            return Extraction("no-text", issues=("extract-failed",))
        try:
            metadata = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeError, ValueError, TypeError):
            return Extraction("no-text", issues=("extract-failed",))
        if type(metadata) is not dict:
            return Extraction("no-text", issues=("extract-failed",))
        if any(type(key) is not str for key in metadata):
            return Extraction("no-text", issues=("extract-failed",))
        if _truthy_metadata(metadata.get("pdf:encrypted")):
            return Extraction("encrypted", issues=("encrypted",))
        for key, value in metadata.items():
            normalized = key.lower()
            if "deadline-reached" in normalized and _truthy_metadata(value):
                return Extraction("no-text", issues=("extract-timeout",))
            if "write-limit" in normalized and _truthy_metadata(value):
                return Extraction("no-text", issues=("extract-output-limit",))
            if normalized.startswith("tk:exception") or normalized.startswith("tika:exception"):
                return Extraction("no-text", issues=("extract-failed",))
        content = metadata.get("tk:content")
        if content is None:
            return Extraction("no-text", issues=("no-text",))
        if type(content) is list:
            if any(type(item) is not str for item in content):
                return Extraction("no-text", issues=("extract-failed",))
            text = "\n".join(content)
        elif type(content) is str:
            text = content
        else:
            return Extraction("no-text", issues=("extract-failed",))
        if not text.strip():
            return Extraction("no-text", issues=("no-text",))
        try:
            output_size = len(text.encode("utf-8", "strict"))
        except UnicodeError:
            return Extraction("no-text", issues=("decode-failed",))
        if output_size > min(context.limits.max_text_bytes, self._max_text_bytes):
            return Extraction("no-text", issues=("extract-output-limit",))
        return Extraction("extracted", parts=(ExtractedPart("body", 1, text),))

    def _descendants(self, root_pid: int) -> set[int]:
        if os.name == "nt":
            return set()
        try:
            result = subprocess.run(["pgrep", "-P", str(root_pid)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=1, check=False,
                                    close_fds=True, env={"PATH": os.defpath})
        except (OSError, subprocess.TimeoutExpired):
            return set()
        found = set()
        if result.returncode in {0, 1}:
            for line in result.stdout.splitlines():
                try:
                    child = int(line)
                except ValueError:
                    continue
                if child > 0 and child != root_pid:
                    found.add(child)
                    found.update(self._descendants(child))
        return found

    def _stop_server(self) -> None:
        process = self._server
        if process is None:
            return
        self._server = None
        if process.poll() is not None:
            return
        if os.name == "nt":
            try:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            return
        children = self._descendants(process.pid)
        try:
            process.terminate()
        except OSError:
            pass
        deadline = time.monotonic() + 2
        while process.poll() is None and time.monotonic() < deadline:
            children.update(self._descendants(process.pid))
            time.sleep(0.05)
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        for child in sorted(children, reverse=True):
            try:
                os.kill(child, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                continue
        time.sleep(0.05)
        for child in children:
            try:
                os.kill(child, 0)
                os.kill(child, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    def _remove_temp(self) -> None:
        temp = self._temp
        self._temp = None
        if temp is None:
            return
        root = Path(temp.name)
        for current, directories, files in os.walk(root, topdown=False, followlinks=False):
            for name in files:
                try:
                    os.chmod(Path(current) / name, 0o600)
                except OSError:
                    pass
            for name in directories:
                try:
                    os.chmod(Path(current) / name, 0o700)
                except OSError:
                    pass
        try:
            os.chmod(root, 0o700)
            temp.cleanup()
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop_server()
            self._remove_temp()


def create_plugin(options: Mapping[str, object]) -> TikaExtractor:
    if type(options) is not dict or any(key not in {field.name for field in _OPTION_FIELDS} for key in options):
        raise ValueError("invalid options")
    for required in ("artifact-path", "artifact-sha512", "java-path"):
        if required not in options or type(options[required]) is not str:
            raise ValueError("invalid options")
    return TikaExtractor(options)
