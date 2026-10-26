#!/usr/bin/env python3
"""Exercise an installed Buddy runtime through its real loopback HTTP API.

The scenario creates one synthetic source and credential under a new owned
work directory. The emitted receipt contains only status codes, counts, IDs,
hashes, artifact sizes, and boolean checks. Runtime files are inspected and
removed before the receipt is written. This script uses only the standard
library and can run on the Linux or macOS native bridge.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, quote, urlencode, urlsplit
import uuid


ROOT = Path(__file__).resolve().parents[1]
LABELS = ROOT / "tests" / "fixtures" / "independent_literal_labels.json"
_READY = re.compile(r"Password Buddy listening at (http://127\.0\.0\.1:[0-9]{1,5})\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
_MAX_HTTP_BODY = 2_000_000
_MAX_LOG_BYTES = 256_000
_PACKAGES = ("leakguard-core", "leakguard-host", "leakguard-vault", "leakguard-buddy")


class JourneyFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class BuddyProcess:
    def __init__(self, process: subprocess.Popen[bytes]):
        self.process = process
        self.lines: queue.Queue[bytes | None] = queue.Queue()
        self.stdout = bytearray()
        self.stderr = bytearray()
        self._lock = threading.Lock()
        self._threads = [
            threading.Thread(target=self._read_lines, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _read_lines(self) -> None:
        stream = self.process.stdout
        try:
            assert stream is not None
            for line in iter(stream.readline, b""):
                with self._lock:
                    if len(self.stdout) < _MAX_LOG_BYTES:
                        self.stdout.extend(line[:_MAX_LOG_BYTES - len(self.stdout)])
                self.lines.put(line[:4096])
        finally:
            self.lines.put(None)

    def _read_stderr(self) -> None:
        stream = self.process.stderr
        try:
            assert stream is not None
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    return
                with self._lock:
                    if len(self.stderr) < _MAX_LOG_BYTES:
                        self.stderr.extend(chunk[:_MAX_LOG_BYTES - len(self.stderr)])
        finally:
            pass

    def readiness(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise JourneyFailure("buddy-exited-before-ready")
            try:
                line = self.lines.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if line is None:
                raise JourneyFailure("buddy-readiness-missing")
            match = _READY.fullmatch(line.decode("utf-8", "replace").strip())
            if match:
                return match.group(1)
        raise JourneyFailure("buddy-readiness-timeout")

    def stop(self, timeout: float = 20.0) -> bool:
        if self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=timeout)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self.process.kill()
                    self.process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    return False
        for thread in self._threads:
            thread.join(timeout=2)
        return self.process.poll() is not None

    def logs(self) -> bytes:
        with self._lock:
            return bytes(self.stdout + b"\n" + self.stderr)


class BuddyClient:
    def __init__(self, origin: str, *, timeout: float):
        parsed = urlsplit(origin)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.path:
            raise JourneyFailure("buddy-origin-invalid")
        self.origin = origin
        self.host = parsed.netloc
        self.port = parsed.port
        self.timeout = timeout
        self.cookie: str | None = None
        self.csrf: str | None = None
        self.bodies: list[tuple[str, bytes, bool]] = []
        self.status_codes: dict[str, int] = {}

    def request(self, method: str, path: str, payload: dict | None = None, *,
                auth: bool = True, origin: str | None = None,
                csrf: bool = True, host: str | None = None,
                deliberate_reveal: bool = False, protected_backup: bool = False) -> tuple[int, dict, http.client.HTTPMessage]:
        headers = {"Host": self.host if host is None else host, "Connection": "close"}
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if auth and self.cookie is not None:
            headers["Cookie"] = self.cookie
        if origin is not None:
            headers["Origin"] = origin
        elif auth and method in {"POST", "PATCH", "DELETE"}:
            headers["Origin"] = self.origin
        if auth and csrf and self.csrf is not None and method in {"POST", "PATCH", "DELETE"}:
            headers["X-Buddy-CSRF"] = self.csrf
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        try:
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read(_MAX_HTTP_BODY + 1)
            if len(raw) > _MAX_HTTP_BODY:
                raise JourneyFailure("http-response-too-large")
            status = response.status
            response_headers = response.headers
        except JourneyFailure:
            raise
        except (OSError, http.client.HTTPException, TimeoutError):
            raise JourneyFailure("http-request-failed") from None
        finally:
            connection.close()
        classified = deliberate_reveal or protected_backup
        self.bodies.append((path, raw, classified))
        try:
            value = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeError, RecursionError):
            raise JourneyFailure("http-json-invalid") from None
        if type(value) is not dict and type(value) is not list:
            raise JourneyFailure("http-json-invalid")
        self.status_codes[f"{method} {path.split('?', 1)[0]}"] = status
        return status, value, response_headers

    def exchange(self, token: str) -> dict:
        status, value, headers = self.request(
            "POST", "/__bootstrap", {"token": token}, auth=False,
            origin=self.origin, csrf=False,
        )
        if status != 200 or type(value) is not dict or type(value.get("csrf")) is not str:
            raise JourneyFailure("bootstrap-rejected")
        cookie_header = headers.get("Set-Cookie", "")
        match = re.match(r"buddy_session=([0-9a-f]{64})(?:;|$)", cookie_header)
        if not match:
            raise JourneyFailure("session-cookie-invalid")
        self.cookie = "buddy_session=" + match.group(1)
        self.csrf = value["csrf"]
        return value


def _load_fixture() -> tuple[str, str, str]:
    try:
        raw = LABELS.read_bytes()
        value = json.loads(raw)
        case = next(item for item in value["cases"] if item.get("expected") == "finding")
        text = case["text"]
        rule = case["expected_rule"]
        case_id = case["case_id"]
    except Exception:
        raise JourneyFailure("synthetic-fixture-invalid") from None
    if (type(text) is not str or "\n" in text or "\r" in text
            or type(rule) is not str or type(case_id) is not str):
        raise JourneyFailure("synthetic-fixture-invalid")
    return text, rule, case_id


def _runtime_probe(python: Path, buddy: Path, timeout: float) -> dict:
    probe = """
import importlib.metadata as metadata
import json
import sys
names = ('leakguard-core', 'leakguard-host', 'leakguard-vault', 'leakguard-buddy')
versions = {}
for name in names:
    try:
        versions[name] = metadata.version(name)
    except metadata.PackageNotFoundError:
        versions[name] = None
print(json.dumps({'prefix': sys.prefix, 'executable': sys.executable, 'versions': versions}))
"""
    try:
        result = subprocess.run([str(python), "-c", probe], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False, env=_child_env())
        data = json.loads(result.stdout.decode("utf-8")) if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
        raise JourneyFailure("installed-runtime-probe-failed") from None
    if type(data) is not dict or type(data.get("versions")) is not dict:
        raise JourneyFailure("installed-runtime-probe-failed")
    # A venv's Python executable is commonly a symlink to its base interpreter;
    # the interpreter's sys.prefix and installed console entry points bind the
    # private runtime, while resolving sys.executable may legitimately escape.
    prefix = Path(os.path.abspath(data.get("prefix", "")))
    executable = Path(os.path.abspath(data.get("executable", "")))
    try:
        if not executable.is_relative_to(prefix) or not python.absolute().is_relative_to(prefix) or not buddy.absolute().is_relative_to(prefix):
            raise JourneyFailure("runtime-not-private")
    except (OSError, RuntimeError, ValueError):
        raise JourneyFailure("runtime-not-private") from None
    versions = data["versions"]
    if any(type(versions.get(name)) is not str for name in _PACKAGES):
        raise JourneyFailure("installed-package-missing")
    return {"python": Path(data["executable"]).name,
            "versions": {name: versions[name] for name in _PACKAGES}}


def _child_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    for name in ("LEAKGUARD_CONFIG", "LEAKGUARD_STATE_DIR", "LEAKGUARD_GITLEAKS"):
        env.pop(name, None)
    return env


def _start_buddy(buddy: Path, *, state: Path, config: Path, backend: Path,
                 cwd: Path, timeout: float) -> tuple[BuddyProcess, str]:
    env = _child_env()
    env.update({"LEAKGUARD_CONFIG": str(config), "LEAKGUARD_STATE_DIR": str(state),
                "LEAKGUARD_GITLEAKS": str(backend)})
    try:
        process = subprocess.Popen([str(buddy), "--no-browser", "--state-dir", str(state),
                                     "--config", str(config)], cwd=cwd, env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, bufsize=0)
    except OSError:
        raise JourneyFailure("buddy-launch-failed") from None
    wrapped = BuddyProcess(process)
    try:
        return wrapped, wrapped.readiness(timeout)
    except BaseException:
        wrapped.stop()
        raise


def _token_from_launch(path: Path, origin: str) -> str:
    try:
        value = path.read_text(encoding="utf-8")
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        raise JourneyFailure("bootstrap-file-missing") from None
    if os.name != "nt" and mode & 0o077:
        raise JourneyFailure("bootstrap-file-permissions")
    parsed = urlsplit(value)
    params = parse_qs(parsed.fragment, strict_parsing=True)
    token = params.get("bootstrap", [""])[0]
    if (parsed.scheme != "http" or parsed.netloc != urlsplit(origin).netloc
            or parsed.path != "/" or parsed.query or not _TOKEN.fullmatch(token)):
        raise JourneyFailure("bootstrap-file-invalid")
    return token


def _expect_status(actual: int, expected: int, code: str) -> None:
    if actual != expected:
        raise JourneyFailure(code)


def _dict(value, code: str) -> dict:
    if type(value) is not dict:
        raise JourneyFailure(code)
    return value


def _locked_request_rejected(status: int, value: object, *expected_errors: str) -> bool:
    if status < 400 or type(value) is not dict:
        return False
    error = value.get("error")
    return type(error) is str and error in {*expected_errors, "request-failed"}


def _jobs(value) -> list[dict]:
    if type(value) is not list or any(type(item) is not dict for item in value):
        raise JourneyFailure("jobs-response-invalid")
    return value


def _run_scan(client: BuddyClient, source_id: str, expected_rule: str,
              timeout: float, checks: dict, details: dict) -> tuple[str, dict]:
    status, submitted, _ = client.request("POST", "/api/scans", {"source_id": source_id})
    _expect_status(status, 202, "scan-submit-failed")
    submitted = _dict(submitted, "scan-submit-invalid")
    job_id = submitted.get("id")
    if type(job_id) is not str:
        raise JourneyFailure("scan-job-id-missing")
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        status, rows, _ = client.request("GET", "/api/jobs")
        _expect_status(status, 200, "jobs-query-failed")
        observed = next((item for item in _jobs(rows) if item.get("id") == job_id), None)
        if observed is None:
            raise JourneyFailure("scan-job-missing")
        if observed.get("state") in {"completed", "failed", "backoff", "cancelled", "paused"}:
            break
        time.sleep(0.1)
    if observed is None or observed.get("state") != "completed" or observed.get("coverage") != "complete":
        raise JourneyFailure("scan-incomplete")
    details["files_scanned"] = int(observed.get("files_scanned") or 0)
    checks["bounded_scan_completed"] = details["files_scanned"] >= 1
    status, findings, _ = client.request(
        "GET", "/api/findings?" + urlencode({"state": "current", "rule": expected_rule, "limit": "20"}),
    )
    _expect_status(status, 200, "findings-query-failed")
    findings = _dict(findings, "findings-response-invalid")
    rows = findings.get("findings")
    if type(rows) is not list or not rows or any(type(row) is not dict for row in rows):
        raise JourneyFailure("expected-finding-missing")
    row = next((item for item in rows if item.get("rule") == expected_rule), None)
    if row is None or type(row.get("id")) is not str:
        raise JourneyFailure("expected-rule-missing")
    finding_id = row["id"]
    details["finding_id"] = finding_id
    details["finding_rule"] = row.get("rule")
    checks["finding_redacted"] = "value" not in row and "secret" not in row and "match" not in row
    status, annotation, _ = client.request(
        "POST", f"/api/findings/{quote(finding_id, safe='')}/annotation", {"state": "reviewed"},
    )
    _expect_status(status, 200, "finding-annotation-failed")
    status, filtered, _ = client.request(
        "GET", "/api/findings?" + urlencode({"state": "current", "rule": expected_rule,
                                              "annotation": "reviewed", "limit": "20"}),
    )
    _expect_status(status, 200, "finding-filter-failed")
    filtered = _dict(filtered, "finding-filter-invalid")
    checks["finding_filter_and_annotation"] = any(
        type(item) is dict and item.get("id") == finding_id
        and (item.get("annotation") or {}).get("state") == "reviewed"
        for item in filtered.get("findings", [])
    )
    if not checks["finding_filter_and_annotation"]:
        raise JourneyFailure("finding-annotation-not-visible")
    details["findings"] = len(rows)
    return finding_id, row


def _artifact_review(product: Path, logs: bytes, bodies: list[tuple[str, bytes, bool]],
                     source_fixture: Path, sensitive_values: tuple[bytes, ...]) -> dict:
    if any(value and value in logs for value in sensitive_values):
        raise JourneyFailure("synthetic-value-in-service-log")
    for path, body, protected in bodies:
        if protected:
            continue
        if any(value and value in body for value in sensitive_values):
            raise JourneyFailure("synthetic-value-in-http-response")
    rows = []
    encrypted = {"observations.lgo", "credentials.lgv"}
    total = 0
    for path in sorted(product.rglob("*")):
        if path.is_symlink():
            raise JourneyFailure("state-symlink-unexpected")
        if not path.is_file():
            continue
        if path == source_fixture:
            continue  # This one declared synthetic file is the scan input.
        try:
            data = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            raise JourneyFailure("state-artifact-unreadable") from None
        total += len(data)
        if total > 32_000_000:
            raise JourneyFailure("state-artifact-limit")
        is_encrypted = path.name in encrypted
        if path.name not in encrypted:
            if any(value and value in data for value in sensitive_values):
                raise JourneyFailure("synthetic-value-in-plaintext-state")
            if path.name.endswith((".sqlite", ".sqlite3", ".db", ".db-wal", ".db-shm")):
                raise JourneyFailure("plaintext-database-present")
        elif any(value and value in data for value in sensitive_values):
            raise JourneyFailure("synthetic-value-in-encrypted-store")
        if os.name != "nt" and mode & 0o077:
            raise JourneyFailure("product-artifact-permissions-invalid")
        rows.append({"name": str(path.relative_to(product)), "size_bytes": len(data),
                     "encrypted": is_encrypted,
                     "private_mode": os.name == "nt" or mode & 0o077 == 0})
    names = {Path(row["name"]).name for row in rows}
    if not {"observations.lgo", "credentials.lgv"} <= names:
        raise JourneyFailure("encrypted-store-missing")
    return {"files": rows, "total_bytes": total}


def _do_journey(*, python: Path, buddy: Path, backend: Path, work: Path,
                timeout: float, worker_policy: str) -> dict:
    runtime = _runtime_probe(python, buddy, min(timeout, 30))
    fixture, expected_rule, fixture_id = _load_fixture()
    product = work / "product"
    product.mkdir(mode=0o700)
    state = product / "state"
    state.mkdir(mode=0o700)
    source = product / "source"
    source.mkdir(mode=0o700)
    fixture_path = source / "synthetic-case.txt"
    fixture_bytes = (fixture + "\n").encode("utf-8")
    fixture_path.write_bytes(fixture_bytes)
    try:
        os.chmod(fixture_path, 0o600)
    except OSError:
        pass
    original_stat = fixture_path.stat()
    fixture_digest = hashlib.sha256(fixture_bytes).hexdigest()
    config = product / "config.json"
    config_values = {
        "worker_policy": worker_policy,
        "scan_workers": 2,
        "gitleaks_executable": str(backend),
        "observation_backend": "encrypted",
        "observation_path": str((state / "observations.lgo").absolute()),
    }
    config.write_text(json.dumps(config_values, sort_keys=True) + "\n", encoding="utf-8")
    try:
        os.chmod(config, 0o600)
    except OSError:
        pass

    credential_value = "Synthetic-only Buddy credential 7a5f1f20c98545199a37"
    observation_phrase = "Synthetic observation passphrase 2026!"
    backup_phrase = "Synthetic backup passphrase 2026!"
    restored_phrase = "Synthetic restored passphrase 2026!"
    credentials = credential_value.encode("utf-8")
    sensitive_values: list[bytes] = [
        fixture.encode("utf-8"), credentials, observation_phrase.encode("utf-8"),
        backup_phrase.encode("utf-8"), restored_phrase.encode("utf-8"),
        b"Synthetic initial vault passphrase 2026!",
    ]
    checks: dict[str, bool] = {}
    details: dict = {"synthetic_case_id": fixture_id, "expected_rule": expected_rule,
                     "fixture_sha256": fixture_digest, "worker_policy": worker_policy,
                     "runtime": runtime}
    log_buffers: list[bytes] = []
    http_bodies: list[tuple[str, bytes, bool]] = []
    active: BuddyProcess | None = None
    client: BuddyClient | None = None

    def start_and_authenticate() -> tuple[BuddyProcess, BuddyClient, str]:
        nonlocal active
        active, ready = _start_buddy(buddy, state=state, config=config, backend=backend,
                                     cwd=product, timeout=timeout)
        log_buffers.append(active.logs())
        client_here = BuddyClient(ready, timeout=min(15.0, timeout))
        # Bootstrap is read only from this run's private opener file, never logged.
        token = _token_from_launch(state / "buddy-launch.url", ready)
        return active, client_here, token

    try:
        active, client, token = start_and_authenticate()
        status, _, _ = client.request("GET", "/api/status", auth=False)
        _expect_status(status, 401, "unauthenticated-api-accepted")
        checks["unauthenticated_rejected"] = True
        status, _, _ = client.request("GET", "/api/status", auth=False, host="127.0.0.1:1")
        _expect_status(status, 421, "incorrect-host-accepted")
        checks["host_header_enforced"] = True
        status, _, _ = client.request("POST", "/__bootstrap", {"token": token}, auth=False,
                                      origin="http://localhost", csrf=False)
        _expect_status(status, 403, "incorrect-bootstrap-origin-accepted")
        checks["origin_enforced"] = True
        status, _, _ = client.request("POST", "/api/observations/create",
                                      {"passphrase": observation_phrase}, origin=client.origin,
                                      csrf=False, auth=False)
        _expect_status(status, 401, "unauthenticated-mutation-accepted")
        client.exchange(token)
        sensitive_values.append(token.encode("ascii"))
        checks["bootstrap_authenticated"] = True
        rotated = _token_from_launch(state / "buddy-launch.url", client.origin)
        sensitive_values.append(rotated.encode("ascii"))
        checks["bootstrap_rotated"] = rotated != token
        if rotated == token:
            raise JourneyFailure("bootstrap-not-rotated")
        status, _, _ = client.request("POST", "/__bootstrap", {"token": token}, auth=False,
                                      origin=client.origin, csrf=False)
        _expect_status(status, 403, "bootstrap-replay-accepted")
        status, _, _ = client.request("POST", "/api/observations/create",
                                      {"passphrase": observation_phrase}, csrf=False)
        _expect_status(status, 403, "csrf-not-required")
        checks["csrf_enforced"] = True
        status, _, _ = client.request("POST", "/api/observations/create",
                                      {"passphrase": observation_phrase}, origin="http://localhost")
        _expect_status(status, 403, "mutation-origin-not-bound")

        status, observations, _ = client.request(
            "POST", "/api/observations/create", {"passphrase": observation_phrase},
        )
        _expect_status(status, 201, "observations-create-failed")
        observations = _dict(observations, "observations-response-invalid")
        if observations.get("created") is not True or observations.get("unlocked") is not True:
            raise JourneyFailure("observations-create-invalid")
        checks["encrypted_observations_created"] = True

        status, vault, _ = client.request("POST", "/api/vault/create", {"passphrase": "Synthetic initial vault passphrase 2026!"})
        _expect_status(status, 201, "vault-create-failed")
        checks["credential_vault_created_separately"] = True

        status, added_source, _ = client.request("POST", "/api/sources", {
            "root": str(source), "label": "Synthetic owned acceptance source", "kind": "local",
        })
        _expect_status(status, 201, "source-add-failed")
        added_source = _dict(added_source, "source-add-invalid")
        source_id = added_source.get("id")
        if type(source_id) is not str:
            raise JourneyFailure("source-id-missing")
        checks["explicit_source_added"] = True

        finding_id, _ = _run_scan(client, source_id, expected_rule, timeout, checks, details)
        details["source_id"] = source_id

        status, saved, _ = client.request("POST", "/api/vault/entries", {
            "title": "Synthetic manually saved credential", "secret": credential_value,
            "username": "synthetic-user", "location": "synthetic-only", "notes": "manual save",
        })
        _expect_status(status, 201, "credential-save-failed")
        saved = _dict(saved, "credential-save-invalid")
        entry_id = saved.get("id")
        if type(entry_id) is not str or "secret" in saved:
            raise JourneyFailure("credential-save-not-redacted")
        details["credential_entry_id"] = entry_id
        status, entries, _ = client.request("GET", "/api/vault/entries")
        _expect_status(status, 200, "credential-list-failed")
        entries = _dict(entries, "credential-list-invalid")
        entry_rows = entries.get("entries")
        if type(entry_rows) is not list or not any(type(row) is dict and row.get("id") == entry_id for row in entry_rows):
            raise JourneyFailure("credential-not-listed")
        if any("secret" in row or "username" in row or "notes" in row for row in entry_rows if type(row) is dict):
            raise JourneyFailure("credential-list-not-redacted")
        checks["manual_save_redacted"] = True
        status, revealed, _ = client.request("POST", f"/api/vault/entries/{quote(entry_id, safe='')}/reveal",
                                              {}, deliberate_reveal=True)
        _expect_status(status, 200, "credential-reveal-failed")
        revealed = _dict(revealed, "credential-reveal-invalid")
        if revealed.get("secret") != credential_value:
            raise JourneyFailure("credential-explicit-reveal-invalid")
        checks["explicit_reveal_only"] = True
        del revealed

        status, backup, _ = client.request("POST", "/api/vault/backup", {"passphrase": backup_phrase},
                                            protected_backup=True)
        _expect_status(status, 200, "credential-backup-failed")
        backup = _dict(backup, "credential-backup-invalid")
        backup_b64 = backup.get("backup_base64")
        if type(backup_b64) is not str:
            raise JourneyFailure("credential-backup-invalid")
        try:
            backup_bytes = base64.b64decode(backup_b64, validate=True)
        except (ValueError, TypeError):
            raise JourneyFailure("credential-backup-invalid") from None
        if not backup_bytes or len(backup_bytes) > 16_000_000:
            raise JourneyFailure("credential-backup-size-invalid")
        details["credential_backup_bytes"] = len(backup_bytes)
        status, _, _ = client.request("POST", "/api/vault/lock", {})
        _expect_status(status, 200, "credential-lock-failed")
        status, locked_rows, _ = client.request("GET", "/api/vault/entries")
        checks["credential_lock_revoked_session"] = _locked_request_rejected(
            status, locked_rows, "credential-vault-locked", "vault-locked",
        )
        if not checks["credential_lock_revoked_session"]:
            raise JourneyFailure("credential-lock-not-enforced")
        status, restored, _ = client.request("POST", "/api/vault/restore", {
            "backup": backup_b64, "backup_passphrase": backup_phrase,
            "new_passphrase": restored_phrase, "replace": True,
        }, protected_backup=True)
        _expect_status(status, 200, "credential-restore-failed")
        restored = _dict(restored, "credential-restore-invalid")
        if restored.get("unlocked") is not True:
            raise JourneyFailure("credential-restore-not-unlocked")
        status, after_restore, _ = client.request("POST", f"/api/vault/entries/{quote(entry_id, safe='')}/reveal",
                                                   {}, deliberate_reveal=True)
        _expect_status(status, 200, "restored-credential-reveal-failed")
        after_restore = _dict(after_restore, "restored-credential-invalid")
        if after_restore.get("secret") != credential_value:
            raise JourneyFailure("restored-credential-mismatch")
        checks["credential_backup_restore"] = True
        del after_restore
        status, _, _ = client.request("POST", "/api/vault/lock", {})
        _expect_status(status, 200, "credential-lock-before-restart-failed")

        status, findings_before_lock, _ = client.request(
            "GET", "/api/findings?" + urlencode({"state": "current", "rule": expected_rule,
                                                  "annotation": "reviewed", "limit": "20"}),
        )
        _expect_status(status, 200, "findings-lost-when-credential-locked")
        checks["scan_evidence_independent_of_credential_lock"] = bool(
            _dict(findings_before_lock, "findings-before-restart-invalid").get("findings")
        )
        status, _, _ = client.request("POST", "/api/observations/lock", {})
        _expect_status(status, 200, "observations-lock-failed")
        status, locked_findings, _ = client.request("GET", "/api/findings", auth=True)
        checks["observation_lock_hides_findings"] = _locked_request_rejected(
            status, locked_findings, "observation-store-locked", "state-locked",
        )
        if not checks["observation_lock_hides_findings"]:
            raise JourneyFailure("observation-lock-not-enforced")
        if active is not None:
            if not active.stop():
                raise JourneyFailure("buddy-stop-timeout")
            log_buffers.append(active.logs())
            active = None
        if (state / "buddy-launch.url").exists():
            raise JourneyFailure("bootstrap-file-not-removed-on-stop")
        checks["buddy_stopped_cleanly"] = True
        http_bodies.extend(client.bodies)

        active, client, token2 = start_and_authenticate()
        sensitive_values.append(token2.encode("ascii"))
        client.exchange(token2)
        rotated2 = _token_from_launch(state / "buddy-launch.url", client.origin)
        sensitive_values.append(rotated2.encode("ascii"))
        checks["bootstrap_rotated_after_restart"] = rotated2 != token2
        if rotated2 == token2:
            raise JourneyFailure("bootstrap-not-rotated-after-restart")
        status, observation_status, _ = client.request("GET", "/api/observations/status")
        _expect_status(status, 200, "observation-status-after-restart-failed")
        observation_status = _dict(observation_status, "observation-status-invalid")
        if observation_status.get("created") is not True or observation_status.get("unlocked") is not False:
            raise JourneyFailure("observations-not-locked-after-restart")
        status, _, _ = client.request("POST", "/api/observations/unlock", {"passphrase": observation_phrase})
        _expect_status(status, 200, "observations-unlock-after-restart-failed")
        status, persisted, _ = client.request(
            "GET", "/api/findings?" + urlencode({"state": "current", "rule": expected_rule,
                                                  "annotation": "reviewed", "limit": "20"}),
        )
        _expect_status(status, 200, "persisted-findings-query-failed")
        persisted = _dict(persisted, "persisted-findings-invalid")
        persisted_rows = persisted.get("findings")
        checks["scan_evidence_survives_restart"] = type(persisted_rows) is list and any(
            type(row) is dict and row.get("id") == finding_id for row in persisted_rows
        )
        if not checks["scan_evidence_survives_restart"]:
            raise JourneyFailure("scan-evidence-not-persisted")
        status, locked_entries, _ = client.request("GET", "/api/vault/entries")
        checks["credential_session_separate_after_restart"] = _locked_request_rejected(
            status, locked_entries, "credential-vault-locked", "vault-locked",
        )
        if not checks["credential_session_separate_after_restart"]:
            raise JourneyFailure("credential-session-restored-implicitly")
        status, vault_status, _ = client.request("GET", "/api/vault/status")
        _expect_status(status, 200, "vault-status-after-restart-failed")
        if _dict(vault_status, "vault-status-invalid").get("created") is not True:
            raise JourneyFailure("restored-vault-not-persisted")
        status, _, _ = client.request("POST", "/api/vault/unlock", {"passphrase": restored_phrase})
        _expect_status(status, 200, "restored-vault-unlock-failed")
        status, persisted_entries, _ = client.request("GET", "/api/vault/entries")
        _expect_status(status, 200, "restored-vault-list-failed")
        rows = _dict(persisted_entries, "restored-vault-list-invalid").get("entries")
        if type(rows) is not list or not any(type(row) is dict and row.get("id") == entry_id for row in rows):
            raise JourneyFailure("restored-vault-entry-missing")
        status, final_reveal, _ = client.request("POST", f"/api/vault/entries/{quote(entry_id, safe='')}/reveal",
                                                  {}, deliberate_reveal=True)
        _expect_status(status, 200, "restored-vault-reveal-failed")
        final_reveal = _dict(final_reveal, "restored-vault-reveal-invalid")
        if final_reveal.get("secret") != credential_value:
            raise JourneyFailure("restored-vault-value-mismatch")
        del final_reveal
        checks["vault_relocked_and_reopened_after_restart"] = True
        status, _, _ = client.request("POST", "/api/vault/lock", {})
        _expect_status(status, 200, "final-credential-lock-failed")

        if active is not None:
            if not active.stop():
                raise JourneyFailure("buddy-stop-timeout")
            log_buffers.append(active.logs())
            active = None
        if (state / "buddy-launch.url").exists():
            raise JourneyFailure("bootstrap-file-not-removed-on-final-stop")
        http_bodies.extend(client.bodies)
        all_logs = b"\n".join(log_buffers)
        artifact_rows = _artifact_review(product, all_logs, http_bodies,
                                         fixture_path, tuple(sensitive_values))
        checks["no_synthetic_values_in_plaintext_state_or_logs"] = True
        checks["encrypted_observation_and_credential_files_private"] = all(
            row["encrypted"] and row["private_mode"] for row in artifact_rows["files"]
            if row["name"] in {"observations.lgo", "credentials.lgv"}
        )
        if not checks["encrypted_observation_and_credential_files_private"]:
            raise JourneyFailure("encrypted_store_permissions_invalid")
        before = fixture_path.stat()
        checks["source_unchanged"] = (hashlib.sha256(fixture_path.read_bytes()).hexdigest() == fixture_digest
                                       and before.st_size == original_stat.st_size
                                       and before.st_mtime_ns == original_stat.st_mtime_ns)
        if not checks["source_unchanged"]:
            raise JourneyFailure("source-modified")
        details["encrypted_artifacts"] = [row for row in artifact_rows["files"] if row["encrypted"]]
        details["state_artifact_bytes"] = artifact_rows["total_bytes"]
        details["http_status_codes"] = dict(sorted(client.status_codes.items()))
        details["status_codes_recorded"] = len(client.status_codes)
        return {"outcome": "passed", "checks": checks, "details": details}
    finally:
        if active is not None:
            active.stop()
            log_buffers.append(active.logs())
        # Read and inspect artifacts above, then remove only this script's
        # freshly-created child beneath the explicitly-owned work directory.
        if product.exists() and not product.is_symlink():
            shutil.rmtree(product, ignore_errors=True)
        if product.exists():
            raise JourneyFailure("owned-work-cleanup-failed")


def _safe_path(value: str, *, label: str, executable: bool = False) -> Path:
    path = Path(value).expanduser().absolute()
    try:
        if path.is_symlink() and label != "python":
            raise JourneyFailure(f"{label}-symlink")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except JourneyFailure:
        raise
    except (OSError, RuntimeError):
        raise JourneyFailure(f"{label}-missing") from None
    if not stat.S_ISREG(info.st_mode) or (executable and os.name != "nt" and not os.access(resolved, os.X_OK)):
        raise JourneyFailure(f"{label}-invalid")
    return path if label == "python" else resolved


def run(args) -> dict:
    work = Path(args.work).expanduser().absolute()
    if work.is_symlink():
        raise JourneyFailure("work-path-symlink")
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(work.iterdir()):
        raise JourneyFailure("work-directory-not-empty")
    try:
        os.chmod(work, 0o700)
    except OSError:
        pass
    output = Path(args.output).expanduser().absolute() if args.output else work / "product-journey.json"
    if output.exists() or output.is_symlink():
        raise JourneyFailure("receipt-path-exists")
    try:
        if not output.absolute().is_relative_to(work.absolute()):
            raise JourneyFailure("receipt-outside-work-directory")
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not output.parent.resolve(strict=True).is_relative_to(work.resolve(strict=True)):
            raise JourneyFailure("receipt-outside-work-directory")
    except (OSError, RuntimeError, ValueError):
        raise JourneyFailure("receipt-outside-work-directory") from None
    python = _safe_path(args.python, label="python", executable=True)
    buddy = _safe_path(args.buddy, label="buddy", executable=True)
    backend = _safe_path(args.gitleaks, label="backend", executable=True)
    if args.worker_policy not in {"strict", "supervised-alpha"}:
        raise JourneyFailure("worker-policy-invalid")
    started = dt.datetime.now(dt.timezone.utc)
    before = time.monotonic()
    try:
        result = _do_journey(python=python, buddy=buddy, backend=backend, work=work,
                             timeout=float(args.timeout_seconds), worker_policy=args.worker_policy)
    finally:
        product = work / "product"
        if product.exists() and not product.is_symlink():
            shutil.rmtree(product, ignore_errors=True)
        if product.exists():
            raise JourneyFailure("owned-work-cleanup-failed")
    result.update({"schema_version": 1, "lane": "evidence", "platform": platform.system().lower(),
                   "machine": platform.machine(), "started_utc": started.isoformat(),
                   "elapsed_seconds": round(time.monotonic() - before, 3),
                   "gitleaks_sha256": hashlib.sha256(backend.read_bytes()).hexdigest()})
    result["checks"] = dict(sorted(result["checks"].items()))
    return result


def _write_receipt(path: Path, value: dict) -> None:
    payload = (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise JourneyFailure("receipt-write-failed") from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, help="Python executable in the installed private runtime")
    parser.add_argument("--buddy", required=True, help="Installed leakguard-buddy executable")
    parser.add_argument("--gitleaks", required=True, help="Pinned Gitleaks backend executable")
    parser.add_argument("--work", required=True, help="New, empty, explicitly-owned work directory")
    parser.add_argument("--output", help="Redacted JSON receipt path inside --work")
    parser.add_argument("--worker-policy", choices=("strict", "supervised-alpha"),
                        default="supervised-alpha" if sys.platform == "darwin" else "strict")
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args(argv)
    started = dt.datetime.now(dt.timezone.utc)
    work_path = Path(args.work).expanduser().absolute()
    output: Path | None
    try:
        if work_path.is_symlink():
            output = None
        else:
            work_root = work_path.resolve(strict=False)
            requested = (Path(args.output).expanduser().absolute() if args.output
                         else work_path / "product-journey.json")
            candidate = requested.resolve(strict=False)
            output = (candidate if candidate.is_relative_to(work_root)
                      else work_root / "product-journey.json")
    except (OSError, RuntimeError, ValueError):
        output = None
    try:
        if not 10 <= args.timeout_seconds <= 180:
            raise JourneyFailure("timeout-invalid")
        value = run(args)
        exit_code = 0 if value.get("outcome") == "passed" else 1
    except JourneyFailure as error:
        value = {"schema_version": 1, "lane": "evidence", "outcome": "failed",
                 "error_code": error.code, "checks": {}, "platform": platform.system().lower(),
                 "machine": platform.machine(), "started_utc": started.isoformat(),
                 "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
        exit_code = 1
    except Exception:
        value = {"schema_version": 1, "lane": "evidence", "outcome": "failed",
                 "error_code": "journey-failed", "checks": {}, "platform": platform.system().lower(),
                 "machine": platform.machine(), "started_utc": started.isoformat(),
                 "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
        exit_code = 2
    if "finished_utc" not in value:
        value["finished_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        if output is None:
            raise JourneyFailure("receipt-path-invalid")
        _write_receipt(output, value)
    except JourneyFailure:
        # Output remains a compact failure marker; never print child output or
        # exception strings, even if the requested receipt path is unusable.
        value = {"schema_version": 1, "lane": "evidence", "outcome": "failed",
                 "error_code": "receipt-write-failed", "checks": {},
                 "platform": platform.system().lower(), "machine": platform.machine()}
        exit_code = 2
    print(json.dumps(value, sort_keys=True, ensure_ascii=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
