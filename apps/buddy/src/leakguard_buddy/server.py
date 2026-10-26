"""Authenticated loopback HTTP server for Buddy's bundled browser client.

The bootstrap credential is delivered in the URL fragment, which browsers do
not send in HTTP requests. It is exchanged once for an HttpOnly session cookie
and an in-memory CSRF token. API bodies and exceptions are never logged.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import http.server
import json
import os
import re
import secrets
import signal
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

_JSON_LIMIT = 70_000_000
_SESSION_SECONDS = 8 * 60 * 60
_SESSION_LIMIT = 8
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,160}\Z")
_SAFE_BACKEND_ERRORS = {
    "vault-locked", "vault-authentication-failed", "vault-already-created",
    "vault-not-created", "vault-already-unlocked", "vault-busy",
    "vault-passphrase-invalid", "vault-capacity-limit", "vault-entry-invalid",
    "vault-entry-not-found", "vault-format-invalid", "vault-io-failed",
    "vault-crypto-unavailable", "observation-keyring-unavailable",
    "observation-keyring-not-enabled", "observation-keyring-invalid",
    "state-locked", "state-checkpoint-failed", "state-capacity-limit",
    "state-query-invalid", "state-cycle-busy", "plugin-invalid",
    "plugin-crashed", "plugin-timeout", "dependency-unavailable",
    "source-not-found", "source-unavailable", "source-disabled", "job-not-found", "job-busy",
    "scan-incomplete", "observation-store-exists", "observation-store-locked",
    "credential-vault-locked", "extension-invalid", "extension-not-found",
    "hook-configuration-invalid", "hook-directory-shared", "hook-target-changed",
    "hook-target-nonregular", "hook-write-failed", "hook-import-path-limit",
    "git-command-failed", "git-path-invalid", "repository-not-found", "hook-operation-failed",
    "plugin-review-required",
}
_STATIC = Path(__file__).with_name("static")


class ApiError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class Session:
    token_digest: bytes
    csrf: str
    expires_at: float


class BuddyHTTPServer(http.server.ThreadingHTTPServer):
    # Wait for in-flight API requests before Buddy locks or closes encrypted
    # stores during shutdown.
    daemon_threads = False
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], backend: object, *, bootstrap: str):
        if address[0] != "127.0.0.1":
            raise ValueError("Buddy may bind only to IPv4 loopback")
        self.backend = backend
        self.bootstrap_digest = hashlib.sha256(bootstrap.encode("ascii")).digest()
        self.bootstrap_used = False
        self.sessions: dict[bytes, Session] = {}
        self.session_lock = threading.RLock()
        self.bootstrap_rotator = None
        super().__init__(address, BuddyRequestHandler)
        self.expected_host = f"127.0.0.1:{self.server_address[1]}"
        self.origin = f"http://{self.expected_host}"


class BuddyRequestHandler(http.server.BaseHTTPRequestHandler):
    server: BuddyHTTPServer
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, format: str, *args: Any) -> None:
        # Request targets, form values and exception text can contain secrets.
        return

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PATCH(self) -> None:
        self._handle("PATCH")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        try:
            if self.headers.get("Host") != self.server.expected_host:
                raise ApiError(421, "host-rejected")
            origin = self.headers.get("Origin")
            if origin is not None and origin != self.server.origin:
                raise ApiError(403, "origin-rejected")
            if self.headers.get("Sec-Fetch-Site") in {"cross-site", "same-site"}:
                raise ApiError(403, "request-site-rejected")
            parsed = urlsplit(self.path)
            if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or "#" in self.path:
                raise ApiError(400, "request-invalid")
            if parsed.path == "/" and method == "GET":
                self._serve_static("index.html", "text/html; charset=utf-8")
                return
            if parsed.path in {"/app.js", "/app.css"} and method == "GET":
                name = "app.js" if parsed.path == "/app.js" else "app.css"
                mime = "text/javascript; charset=utf-8" if name.endswith(".js") else "text/css; charset=utf-8"
                self._serve_static(name, mime)
                return
            if parsed.path == "/__bootstrap" and method == "POST":
                if origin != self.server.origin:
                    raise ApiError(403, "origin-required")
                body = self._read_json()
                if set(body) != {"token"} or type(body["token"]) is not str or not _TOKEN_RE.fullmatch(body["token"]):
                    raise ApiError(400, "request-invalid")
                candidate = hashlib.sha256(body["token"].encode("ascii")).digest()
                with self.server.session_lock:
                    if self.server.bootstrap_used or not hmac.compare_digest(candidate, self.server.bootstrap_digest):
                        raise ApiError(403, "bootstrap-rejected")
                    self.server.bootstrap_used = True
                    now = time.monotonic()
                    for expired in [key for key, value in self.server.sessions.items() if value.expires_at <= now]:
                        self.server.sessions.pop(expired, None)
                    if len(self.server.sessions) >= _SESSION_LIMIT:
                        oldest = min(self.server.sessions, key=lambda key: self.server.sessions[key].expires_at)
                        self.server.sessions.pop(oldest, None)
                    session_id = secrets.token_bytes(32)
                    csrf = secrets.token_urlsafe(32)
                    self.server.sessions[hashlib.sha256(session_id).digest()] = Session(
                        hashlib.sha256(session_id).digest(), csrf, now + _SESSION_SECONDS
                    )
                    if callable(self.server.bootstrap_rotator):
                        replacement = self.server.bootstrap_rotator()
                        self.server.bootstrap_digest = hashlib.sha256(replacement.encode("ascii")).digest()
                        self.server.bootstrap_used = False
                self._send_json(200, {"csrf": csrf}, cookie="buddy_session=" + session_id.hex() + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + str(_SESSION_SECONDS))
                return
            if parsed.path.startswith("/api/"):
                session = self._require_session(mutating=method != "GET", origin=origin)
                if self.headers.get("Transfer-Encoding") is not None:
                    raise ApiError(400, "request-invalid")
                body = self._read_json() if method in {"POST", "PATCH", "DELETE"} else {}
                query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True) if parsed.query else {}
                payload, status = self._api(method, parsed.path, query, body, session)
                self._send_json(status, payload)
                return
            raise ApiError(404, "not-found")
        except ApiError as error:
            self._send_json(error.status, {"error": error.code})
        except (ValueError, TypeError, KeyError):
            self._send_json(400, {"error": "request-invalid"})
        except Exception as error:
            # Do not serialize exception text or request values.
            code = getattr(error, "code", None)
            safe_code = code if type(code) is str and code in _SAFE_BACKEND_ERRORS else "request-failed"
            conflict = {"vault-already-created", "vault-already-unlocked", "vault-busy", "source-not-found", "source-disabled", "job-not-found", "job-busy", "observation-store-exists", "extension-not-found"}
            client = {"vault-passphrase-invalid", "vault-entry-invalid", "state-query-invalid", "plugin-invalid", "plugin-review-required", "extension-invalid"}
            unavailable = {"vault-crypto-unavailable", "observation-keyring-unavailable", "observation-keyring-not-enabled", "observation-keyring-invalid", "state-checkpoint-failed", "state-capacity-limit"}
            status = 409 if safe_code in conflict else 401 if safe_code == "vault-authentication-failed" else 400 if safe_code in client else 503 if safe_code in unavailable else 500
            self._send_json(status, {"error": safe_code})

    def _require_session(self, *, mutating: bool, origin: str | None) -> Session:
        if mutating and origin != self.server.origin:
            raise ApiError(403, "origin-required")
        cookie = self.headers.get("Cookie", "")
        match = re.search(r"(?:^|;\s*)buddy_session=([0-9a-f]{64})(?:;|$)", cookie)
        if not match:
            raise ApiError(401, "session-required")
        digest = hashlib.sha256(bytes.fromhex(match.group(1))).digest()
        with self.server.session_lock:
            session = self.server.sessions.get(digest)
            if session is None or session.expires_at <= time.monotonic():
                self.server.sessions.pop(digest, None)
                raise ApiError(401, "session-expired")
            session.expires_at = time.monotonic() + _SESSION_SECONDS
        if mutating and not hmac.compare_digest(self.headers.get("X-Buddy-CSRF", ""), session.csrf):
            raise ApiError(403, "csrf-rejected")
        return session

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get_content_type() != "application/json":
            raise ApiError(415, "content-type-required")
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            raise ApiError(400, "request-invalid") from None
        if not 0 <= length <= _JSON_LIMIT:
            raise ApiError(413, "request-too-large")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ApiError(400, "request-invalid")

        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result

        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError, RecursionError):
            raise ApiError(400, "request-invalid") from None
        if type(value) is not dict:
            raise ApiError(400, "request-invalid")
        return value

    def _api(self, method: str, path: str, query: dict[str, list[str]], body: dict[str, Any], session: Session) -> tuple[Any, int]:
        app = self.server.backend
        if method == "GET":
            if path == "/api/status":
                return app.status(), 200
            if path == "/api/roots":
                return app.roots(), 200
            if path == "/api/sources":
                return app.sources(), 200
            if path == "/api/jobs":
                return app.jobs(), 200
            if path == "/api/findings":
                return app.findings(_query(query, {"state", "profile", "rule", "severity", "source", "category", "annotation", "cursor", "limit"})), 200
            match = re.fullmatch(r"/api/findings/([A-Za-z0-9_-]{1,160})", path)
            if match:
                return app.finding(match.group(1)), 200
            if path == "/api/observations/status":
                return app.observation_status(), 200
            if path == "/api/vault/status":
                return app.credential_status(), 200
            if path == "/api/vault/entries":
                return {"entries": app.credential_entries()}, 200
            if path == "/api/plugins":
                return app.plugins(), 200
            if path == "/api/settings":
                return app.settings(), 200
            if path == "/api/hooks/status":
                values = _query(query, {"repository"})
                if "repository" not in values or not values["repository"] or "\x00" in values["repository"]:
                    raise ApiError(400, "request-invalid")
                return app.git_hooks_status(values["repository"]), 200
            if path == "/api/browse":
                values = _query(query, {"path", "root", "cursor", "limit"})
                return app.browse(values), 200
        if method == "POST":
            if path == "/api/observations/create":
                _keys(body, {"passphrase"}); _passphrase(body, "passphrase")
                return app.observation_create(body["passphrase"]), 201
            if path == "/api/observations/unlock":
                _keys(body, {"passphrase"}); _passphrase(body, "passphrase")
                return app.observation_unlock(body["passphrase"]), 200
            if path == "/api/observations/lock":
                _keys(body, set()); app.observation_lock(); return {"locked": True}, 200
            if path == "/api/observations/keyring":
                _keys(body, {"enabled"}, {"enabled"})
                if type(body["enabled"]) is not bool: raise ApiError(400, "request-invalid")
                return app.observation_keyring(body["enabled"]), 200
            match = re.fullmatch(r"/api/findings/([A-Za-z0-9_-]{1,160})/annotation", path)
            if match:
                _keys(body, {"state"}); _text(body, "state", 16)
                if body["state"] not in {"unreviewed", "reviewed", "dismissed"}: raise ApiError(400, "request-invalid")
                return app.annotate_finding(match.group(1), body["state"]), 200
            if path == "/api/sources":
                _keys(body, {"root", "label", "kind", "exclusions", "schedule_seconds"}, {"root"})
                _text(body, "root", 4096); _optional_text(body, "label", 200)
                if body.get("kind", "local") not in {"local", "mounted", "unc"}: raise ApiError(400, "request-invalid")
                if "exclusions" in body: _text_list(body, "exclusions", 256, 4096)
                if body.get("schedule_seconds") is not None: _positive_int(body, "schedule_seconds", maximum=31_536_000)
                return app.add_source(body), 201
            match = re.fullmatch(r"/api/sources/([A-Za-z0-9_-]{1,160})/reveal", path)
            if match:
                _keys(body, {"path"}); _text(body, "path", 4096)
                return app.reveal_path(match.group(1), body["path"]), 200
            if path == "/api/scans":
                _keys(body, {"source_id"}); _id(body, "source_id")
                return app.submit(body["source_id"]), 202
            if path == "/api/vault/create":
                _keys(body, {"passphrase"}); _passphrase(body, "passphrase")
                return app.credential_create(body["passphrase"]), 201
            if path == "/api/vault/unlock":
                _keys(body, {"passphrase"}); _passphrase(body, "passphrase")
                return app.credential_unlock(body["passphrase"]), 200
            if path == "/api/vault/lock":
                _keys(body, set()); app.credential_lock(); return {"locked": True}, 200
            if path == "/api/vault/entries":
                _keys(body, {"title", "secret", "username", "location", "notes", "finding_id"}, {"title", "secret"})
                _text(body, "title", 256); _secret(body, "secret", maximum=65_536)
                _optional_text(body, "username", 2048); _optional_text(body, "location", 4096); _optional_text(body, "notes", 65_536)
                if "finding_id" in body: _id(body, "finding_id")
                return app.credential_save(body), 201
            if path == "/api/vault/backup":
                _keys(body, {"passphrase"}); _passphrase(body, "passphrase")
                return app.credential_backup(body["passphrase"]), 200
            if path == "/api/vault/restore":
                _keys(body, {"backup", "backup_passphrase", "new_passphrase", "replace"}, {"backup", "backup_passphrase", "new_passphrase"})
                _text(body, "backup", 24_000_000); _passphrase(body, "backup_passphrase"); _passphrase(body, "new_passphrase")
                if "replace" in body and type(body["replace"]) is not bool: raise ApiError(400, "request-invalid")
                return app.credential_restore(body), 200
            if path == "/api/plugins/install":
                _keys(body, {"wheel", "reviewed"}, {"wheel", "reviewed"}); _text(body, "wheel", 68_000_000)
                if body["reviewed"] is not True: raise ApiError(400, "request-invalid")
                return app.plugin_install(body), 201
            if path == "/api/plugins/conformance":
                _keys(body, {"id"}); _text(body, "id", 80)
                return app.plugin_conformance(body), 200
            if path == "/api/hooks/install":
                _keys(body, {"repository", "profile"}, {"repository", "profile"})
                _text(body, "repository", 4096); _text(body, "profile", 32)
                if body["profile"] not in {"credentials", "sensitive", "firm"}:
                    raise ApiError(400, "request-invalid")
                return app.git_hooks_install(body["repository"], body["profile"]), 200
            if path == "/api/hooks/uninstall":
                _keys(body, {"repository"}, {"repository"})
                _text(body, "repository", 4096)
                return app.git_hooks_uninstall(body["repository"]), 200
        if method == "PATCH":
            match = re.fullmatch(r"/api/vault/entries/([A-Za-z0-9_-]{1,160})", path)
            if match:
                _keys(body, {"title", "secret", "username", "location", "notes", "finding_id"}, {"title"})
                _text(body, "title", 256)
                if "secret" in body: _secret(body, "secret", maximum=65_536)
                _optional_text(body, "username", 2048); _optional_text(body, "location", 4096); _optional_text(body, "notes", 65_536)
                if "finding_id" in body and body["finding_id"] is not None: _id(body, "finding_id")
                return app.credential_update(match.group(1), body), 200
            match = re.fullmatch(r"/api/sources/([A-Za-z0-9_-]{1,160})", path)
            if match:
                _keys(body, {"enabled", "schedule_seconds"})
                if "enabled" in body and type(body["enabled"]) is not bool: raise ApiError(400, "request-invalid")
                if body.get("schedule_seconds") is not None: _positive_int(body, "schedule_seconds", maximum=31_536_000)
                return app.update_source(match.group(1), body), 200
        if method == "DELETE":
            match = re.fullmatch(r"/api/vault/entries/([A-Za-z0-9_-]{1,160})", path)
            if match:
                _keys(body, set()); app.credential_delete(match.group(1)); return {"deleted": True}, 200
            match = re.fullmatch(r"/api/sources/([A-Za-z0-9_-]{1,160})", path)
            if match:
                _keys(body, set()); app.remove_source(match.group(1)); return {"deleted": True}, 200
        match = re.fullmatch(r"/api/(?:jobs|scans)/([A-Za-z0-9_-]{1,160})/(pause|resume|cancel)", path)
        if method == "POST" and match:
            _keys(body, set())
            action = match.group(2)
            return getattr(app, action)(match.group(1)), 200
        match = re.fullmatch(r"/api/vault/entries/([A-Za-z0-9_-]{1,160})/(reveal|copy)", path)
        if method == "POST" and match:
            _keys(body, set())
            # This is the only route that returns a credential value, following
            # a user click and a same-origin, CSRF-protected request.
            return app.credential_reveal(match.group(1)), 200
        match = re.fullmatch(r"/api/plugins/(enable|disable)", path)
        if method == "POST" and match:
            _keys(body, {"id", "profile"}); _text(body, "id", 80); _text(body, "profile", 80)
            return app.plugin_set_enabled(body, match.group(1) == "enable"), 200
        if method == "POST" and path == "/api/settings":
            _keys(body, {"active_profile", "scan_workers"})
            return app.save_settings(body), 200
        raise ApiError(404, "not-found")

    def _serve_static(self, name: str, content_type: str) -> None:
        try:
            data = (_STATIC / name).read_bytes()
        except OSError:
            raise ApiError(404, "not-found") from None
        self.send_response(200)
        self._security_headers(content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def _send_json(self, status: int, value: Any, *, cookie: str | None = None) -> None:
        try:
            data = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            status, data = 500, b'{"error":"response-invalid"}'
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.close_connection = True
        self.wfile.write(data)

    def _security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")


def _query(query: dict[str, list[str]], allowed: set[str]) -> dict[str, str]:
    if set(query) - allowed or any(len(values) != 1 for values in query.values()):
        raise ApiError(400, "request-invalid")
    result = {key: values[0] for key, values in query.items()}
    if len(result) > 8 or any(len(key) > 40 or len(value) > 4096 for key, value in result.items()):
        raise ApiError(400, "request-invalid")
    return result


def _keys(value: dict[str, Any], allowed: set[str], required: set[str] | None = None) -> None:
    if type(value) is not dict or set(value) - allowed or not (required or set()) <= set(value):
        raise ApiError(400, "request-invalid")


def _text(value: dict[str, Any], key: str, maximum: int) -> None:
    if type(value.get(key)) is not str or not 1 <= len(value[key]) <= maximum or "\x00" in value[key]:
        raise ApiError(400, "request-invalid")


def _secret(value: dict[str, Any], key: str, maximum: int = 4096) -> None:
    _text(value, key, maximum)


def _passphrase(value: dict[str, Any], key: str) -> None:
    if type(value.get(key)) is not str or not 12 <= len(value[key]) <= 1024 or "\x00" in value[key]:
        raise ApiError(400, "vault-passphrase-invalid")


def _optional_text(value: dict[str, Any], key: str, maximum: int) -> None:
    if key in value and value[key] is not None and (type(value[key]) is not str or len(value[key]) > maximum or "\x00" in value[key]):
        raise ApiError(400, "request-invalid")


def _text_list(value: dict[str, Any], key: str, count: int, size: int) -> None:
    rows = value[key]
    if type(rows) is not list or len(rows) > count or any(type(item) is not str or not item or len(item) > size or "\x00" in item for item in rows):
        raise ApiError(400, "request-invalid")


def _positive_int(value: dict[str, Any], key: str, maximum: int) -> None:
    if type(value.get(key)) is not int or not 1 <= value[key] <= maximum:
        raise ApiError(400, "request-invalid")


def _id(value: dict[str, Any], key: str) -> None:
    if type(value.get(key)) is not str or not _ID_RE.fullmatch(value[key]):
        raise ApiError(400, "request-invalid")


class LocalBuddy:
    """Own the runtime integration; a backend adapter supplies app operations."""

    def __init__(self, backend: object, *, bootstrap_file: Path | None = None):
        self.backend = backend
        self.bootstrap = secrets.token_urlsafe(32)
        if not _TOKEN_RE.fullmatch(self.bootstrap):
            raise RuntimeError("secure token generation failed")
        self.server = BuddyHTTPServer(("127.0.0.1", 0), backend, bootstrap=self.bootstrap)
        self.server.bootstrap_rotator = self._rotate_bootstrap
        self.thread = threading.Thread(target=self.server.serve_forever, name="leakguard-buddy-http", daemon=True)
        self.bootstrap_file = bootstrap_file
        self._bootstrap_url: str | None = None

    @property
    def url(self) -> str:
        return self.server.origin + "/#bootstrap=" + self.bootstrap

    def start(self) -> None:
        if self.bootstrap_file is not None:
            self._write_bootstrap_file(self.bootstrap)
        self.thread.start()

    def _rotate_bootstrap(self) -> str:
        token = secrets.token_urlsafe(32)
        if not _TOKEN_RE.fullmatch(token):
            raise RuntimeError("secure token generation failed")
        if self.bootstrap_file is not None:
            self._write_bootstrap_file(token)
        self.bootstrap = token
        return token

    def _write_bootstrap_file(self, token: str) -> None:
        assert self.bootstrap_file is not None
        self.bootstrap_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try: os.chmod(self.bootstrap_file.parent, 0o700)
        except OSError: pass
        value = self.server.origin + "/#bootstrap=" + token
        descriptor, temporary_name = tempfile.mkstemp(prefix=".buddy-launch-", dir=self.bootstrap_file.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.bootstrap_file)
            try:
                parent = os.open(self.bootstrap_file.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try: os.fsync(parent)
                finally: os.close(parent)
            except OSError:
                pass
            self._bootstrap_url = value
        finally:
            try: os.close(descriptor)
            except OSError: pass
            try: temporary.unlink()
            except OSError: pass

    def close(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        finally:
            if self.bootstrap_file is not None:
                try:
                    if self.bootstrap_file.read_text(encoding="utf-8") == self._bootstrap_url:
                        self.bootstrap_file.unlink()
                except OSError:
                    pass
            close = getattr(self.backend, "close", None)
            if callable(close):
                close()


def serve_forever(backend: object, *, open_browser: bool = True, bootstrap_file: Path | None = None) -> None:
    import webbrowser

    app = LocalBuddy(backend, bootstrap_file=bootstrap_file)
    app.start()
    url = app.url
    print(f"Password Buddy listening at {app.server.origin}", flush=True)
    if open_browser:
        webbrowser.open(url, new=1, autoraise=True)
    stopping = threading.Event()
    prior_handlers: dict[int, Any] = {}
    if threading.current_thread() is threading.main_thread():
        for signum in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
            if signum is None: continue
            try:
                prior_handlers[signum] = signal.signal(signum, lambda _signum, _frame: stopping.set())
            except (ValueError, OSError):
                pass
    try:
        stopping.wait()
    finally:
        app.close()
        for signum, handler in prior_handlers.items():
            try: signal.signal(signum, handler)
            except (ValueError, OSError): pass


def open_existing(state_dir: Path | None = None) -> bool:
    """Consume the one-time browser bootstrap written by a service process."""
    import webbrowser

    if state_dir is None:
        from leakguard_core import settings
        state_dir = settings.state_directory()
    path = Path(state_dir).expanduser().absolute() / "buddy-launch.url"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return False
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or observed.st_size > 4096 or observed.st_mode & 0o077:
            return False
        if hasattr(os, "getuid") and observed.st_uid != os.getuid():
            return False
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as stream:
            value = stream.read(4097)
    finally:
        os.close(descriptor)
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.path != "/" or parsed.query or not _TOKEN_RE.fullmatch(parse_qs(parsed.fragment).get("bootstrap", [""])[0])):
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return bool(webbrowser.open(value, new=1, autoraise=True))
