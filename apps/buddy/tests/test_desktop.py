"""Focused desktop auth, ownership and safe-stop boundary checks."""
import http.client
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from leakguard_buddy.backend import BuddyBackend
from leakguard_buddy.desktop import _request
from leakguard_buddy.ownership import ProfileInUse, ProfileOwnership
from leakguard_buddy.server import LocalBuddy


class StubBackend:
    def __init__(self):
        self.fail_stop = False
        self.closed = False
        self.released = False
    def status(self):
        return {"ready": True}
    def prepare_close(self):
        if self.fail_stop:
            raise RuntimeError("worker-still-running")
        self.closed = True
    def release_ownership(self):
        self.released = True


def request_http(app, method, path, *, token=None, cookie=None, origin=None, csrf=None, payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", app.server.server_address[1], timeout=5)
    headers = {}
    body = None
    if token is not None:
        payload = {"token": token}
    if payload is not None:
        body = json.dumps(payload)
        headers.update({"Content-Type": "application/json", "Origin": origin or app.server.origin})
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-Buddy-CSRF"] = csrf
    connection.request(method, path, body, headers)
    response = connection.getresponse()
    value = response.read()
    result = response.status, dict(response.getheaders()), value
    connection.close()
    return result


class DesktopBoundaryTests(unittest.TestCase):
    def test_session_recovery_requires_auth_and_bootstrap_is_rotatable(self):
        app = LocalBuddy(StubBackend())
        app.start()
        try:
            self.assertEqual(request_http(app, "GET", "/api/session")[0], 401)
            initial = app.bootstrap
            replacement = app.fresh_bootstrap()
            self.assertNotEqual(initial, replacement)
            self.assertEqual(request_http(app, "POST", "/__bootstrap", token=initial)[0], 403)
            code, headers, body = request_http(app, "POST", "/__bootstrap", token=replacement)
            self.assertEqual(code, 200)
            cookie = headers["Set-Cookie"].split(";", 1)[0]
            csrf = json.loads(body)["csrf"]
            code, _, body = request_http(app, "GET", "/api/session", cookie=cookie)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body), {"csrf": csrf, "api_version": 1})
            self.assertEqual(request_http(app, "POST", "/__bootstrap", token=replacement)[0], 403)
            self.assertEqual(request_http(app, "POST", "/__bootstrap", token=app.fresh_bootstrap(), cookie=cookie)[0], 200)
        finally:
            app.close()

    def test_nonce_injected_per_index_only_and_static_allowlist_stays_flat(self):
        app = LocalBuddy(StubBackend())
        app.start()
        try:
            with tempfile.TemporaryDirectory() as name:
                folder = Path(name)
                (folder / "index.html").write_text('<meta name="buddy-style-nonce" content="__BUDDY_STYLE_NONCE__">')
                (folder / "private.txt").write_text("not public")
                with patch("leakguard_buddy.server._STATIC", folder):
                    first = request_http(app, "GET", "/")
                    second = request_http(app, "GET", "/")
                    self.assertEqual(first[0], 200)
                    self.assertNotEqual(first[2], second[2])
                    self.assertNotIn(b"__BUDDY_STYLE_NONCE__", first[2])
                    nonce = first[2].decode().split('content="', 1)[1].split('"', 1)[0]
                    csp = first[1]["Content-Security-Policy"]
                    self.assertIn("'nonce-" + nonce + "'", csp)
                    self.assertIn("script-src 'self'", csp)
                    self.assertNotIn("unsafe-eval", csp)
                    self.assertEqual(request_http(app, "GET", "/private.txt")[0], 404)
                    self.assertEqual(request_http(app, "GET", "/../private.txt")[0], 404)
        finally:
            app.close()

    def test_failed_stop_keeps_http_and_owner_then_retry_releases(self):
        backend = StubBackend()
        app = LocalBuddy(backend)
        app.start()
        token = app.bootstrap
        code, headers, body = request_http(app, "POST", "/__bootstrap", token=token)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        csrf = json.loads(body)["csrf"]
        backend.fail_stop = True
        with self.assertRaisesRegex(RuntimeError, "worker-still-running"):
            app.close()
        self.assertFalse(backend.closed)
        self.assertFalse(backend.released)
        self.assertEqual(request_http(app, "GET", "/api/status", cookie=cookie)[0], 200)
        self.assertEqual(request_http(app, "POST", "/api/vault/lock", cookie=cookie, csrf=csrf, payload={})[0], 503)
        backend.fail_stop = False
        app.close()
        self.assertTrue(backend.closed)
        self.assertTrue(backend.released)

    def test_profile_lock_survives_locked_stores_and_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as name:
            lock_path = Path(name) / ".buddy-owner.lock"
            first = ProfileOwnership(lock_path)
            try:
                with self.assertRaises(ProfileInUse):
                    ProfileOwnership(lock_path)
                self.assertTrue(lock_path.exists())
            finally:
                first.close()
            second = ProfileOwnership(lock_path)
            second.close()
            self.assertTrue(lock_path.exists())

    def test_backend_failed_stop_retains_store_and_ownership(self):
        class Host:
            def stop(self):
                raise RuntimeError("worker-still-running")
        class Store:
            def close(self):
                raise AssertionError("must retain store")
        class Vault:
            def lock(self):
                pass
        with tempfile.TemporaryDirectory() as name:
            backend = object.__new__(BuddyBackend)
            backend._lock = threading.RLock()
            backend._ownership = ProfileOwnership(Path(name) / ".buddy-owner.lock")
            backend._host = Host()
            backend._observation_store = Store()
            backend._vault = Vault()
            backend._credential_session = None
            with self.assertRaisesRegex(RuntimeError, "worker-still-running"):
                backend.close()
            with self.assertRaises(ProfileInUse):
                ProfileOwnership(Path(name) / ".buddy-owner.lock")
            backend.release_ownership()

    def test_control_schema_rejects_unknown_fields_and_duplicate_keys(self):
        self.assertEqual(_request(b'{"id":1,"op":"status"}')["op"], "status")
        for line in (b'{"id":1,"op":"eval"}', b'{"id":1,"op":"status","args":[]}',
                     b'{"id":1,"id":2,"op":"status"}', b'{"id":true,"op":"status"}', b" " * 16385):
            with self.subTest(line=line[:50]), self.assertRaises(ValueError):
                _request(line)


class DesktopProtocolSmoke(unittest.TestCase):
    def test_real_backend_ready_bootstrap_status_and_safe_shutdown(self):
        with tempfile.TemporaryDirectory(prefix="buddy-desktop-smoke-") as name:
            state = Path(name) / "profile" / "state"
            state.mkdir(parents=True)
            config = state / "config.json"
            config.write_text("{}")
            env = dict(os.environ)
            source = str(Path(__file__).parents[1] / "src")
            env["PYTHONPATH"] = source
            process = subprocess.Popen([sys.executable, "-m", "leakguard_buddy.desktop",
                "--state-dir", str(state), "--config", str(config)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            messages = queue.Queue()
            def read():
                for line in process.stdout:
                    messages.put(json.loads(line))
            thread = threading.Thread(target=read, daemon=True)
            thread.start()
            def request(identifier, operation):
                process.stdin.write(json.dumps({"id": identifier, "op": operation}).encode() + b"\n")
                process.stdin.flush()
                result = messages.get(timeout=10)
                self.assertEqual(result["id"], identifier)
                self.assertTrue(result["ok"], result.get("error"))
                return result["result"]
            try:
                ready = messages.get(timeout=10)
                self.assertEqual(ready["type"], "ready", ready)
                self.assertEqual(ready["pid"], process.pid)
                self.assertEqual(ready["protocol"], 1)
                self.assertNotIn("token", ready)
                self.assertNotIn("#", ready["origin"])
                first = request(1, "bootstrap")
                fake_app = type("App", (), {"server": type("Server", (), {
                    "origin": ready["origin"],
                    "server_address": ("127.0.0.1", int(ready["origin"].rsplit(":", 1)[1]))
                })()})()
                code, headers, body = request_http(fake_app, "POST", "/__bootstrap", token=first["token"])
                self.assertEqual(code, 200)
                cookie = headers["Set-Cookie"].split(";", 1)[0]
                self.assertEqual(request_http(fake_app, "GET", "/api/session", cookie=cookie)[0], 200)
                status = request(2, "status")
                self.assertFalse(status["observations"]["unlocked"])
                self.assertFalse(status["vault"]["unlocked"])
                self.assertTrue(request(3, "lock-credentials")["locked"])
                self.assertTrue(request(4, "shutdown")["stopped"])
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertEqual(process.stderr.read(), b"")
                self.assertFalse((state / "buddy-launch.url").exists())
            finally:
                process.stdin.close()
                process.wait(timeout=15)
                process.stdout.close()
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
