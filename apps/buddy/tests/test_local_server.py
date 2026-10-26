import http.client
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from leakguard_buddy.server import LocalBuddy, open_existing


class StubBackend:
    def status(self):
        return {"ready": True}

    def close(self):
        pass

    def git_hooks_install(self, repository, profile):
        return {"repository": repository, "profile": profile}

    def plugin_install(self, payload):
        return {"filename": payload["filename"]}


class LocalServerTests(unittest.TestCase):
    def test_bootstrap_rotates_after_exchange_and_next_open_works(self):
        with tempfile.TemporaryDirectory(prefix="buddy-http-test-") as name:
            launch_file = Path(name) / "buddy-launch.url"
            app = LocalBuddy(StubBackend(), bootstrap_file=launch_file)
            app.start()
            try:
                initial = app.bootstrap
                with patch("webbrowser.open", return_value=True) as browser_open:
                    self.assertTrue(open_existing(Path(name)))
                    browser_open.assert_called_once_with(app.url, new=1, autoraise=True)
                self.assertFalse(launch_file.exists())
                first = self._exchange(app, initial)
                self.assertEqual(first.status, 200)
                self.assertNotEqual(app.bootstrap, initial)
                self.assertIn(app.bootstrap, launch_file.read_text(encoding="utf-8"))
                self.assertEqual(self._exchange(app, initial).status, 403)

                cookie = first.getheader("Set-Cookie").split(";", 1)[0]
                self.assertEqual(self._request(app, "GET", "/api/status", cookie=cookie)[0], 200)
                next_token = app.bootstrap
                with patch("webbrowser.open", return_value=True) as browser_open:
                    self.assertTrue(open_existing(Path(name)))
                    browser_open.assert_called_once_with(app.url, new=1, autoraise=True)
                second = self._exchange(app, next_token)
                self.assertEqual(second.status, 200)
                self.assertNotEqual(first.getheader("Set-Cookie"), second.getheader("Set-Cookie"))
            finally:
                app.close()
            self.assertFalse(launch_file.exists())

    def test_mutating_api_requires_csrf_and_exact_origin(self):
        app = LocalBuddy(StubBackend())
        app.start()
        try:
            response = self._exchange(app, app.bootstrap)
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            csrf = json.loads(response._buddy_body)["csrf"]
            payload = {"repository": "/synthetic/repo", "profile": "firm"}
            status, _ = self._request(app, "POST", "/api/hooks/install", cookie=cookie, payload=payload, origin=app.server.origin)
            self.assertEqual(status, 403)
            status, response = self._request(app, "POST", "/api/hooks/install", cookie=cookie, payload=payload, origin="http://localhost")
            self.assertEqual(status, 403)
            status, response = self._request(app, "POST", "/api/hooks/install", cookie=cookie, payload=payload, origin=app.server.origin, csrf=csrf)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(response._buddy_body), payload)
        finally:
            app.close()

    def test_plugin_upload_requires_and_preserves_wheel_filename(self):
        app = LocalBuddy(StubBackend())
        app.start()
        try:
            response = self._exchange(app, app.bootstrap)
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            csrf = json.loads(response._buddy_body)["csrf"]
            status, _ = self._request(
                app, "POST", "/api/plugins/install", cookie=cookie,
                payload={"wheel": "AAAA", "reviewed": True},
                origin=app.server.origin, csrf=csrf,
            )
            self.assertEqual(status, 400)
            filename = "firm_checker-1.2.3-py3-none-any.whl"
            status, response = self._request(
                app, "POST", "/api/plugins/install", cookie=cookie,
                payload={"wheel": "AAAA", "filename": filename, "reviewed": True},
                origin=app.server.origin, csrf=csrf,
            )
            self.assertEqual(status, 201)
            self.assertEqual(json.loads(response._buddy_body), {"filename": filename})
        finally:
            app.close()

    @staticmethod
    def _request(app, method, path, *, token=None, cookie=None, payload=None, origin=None, csrf=None):
        connection = http.client.HTTPConnection("127.0.0.1", app.server.server_address[1], timeout=5)
        headers = {"Host": app.server.expected_host}
        if token is not None:
            headers.update({"Origin": app.server.origin, "Content-Type": "application/json"})
            body = json.dumps({"token": token})
        elif payload is not None:
            headers["Content-Type"] = "application/json"
            headers["Origin"] = origin or app.server.origin
            if csrf is not None:
                headers["X-Buddy-CSRF"] = csrf
            body = json.dumps(payload)
        else:
            body = None
        if cookie is not None:
            headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response._buddy_body = response.read()
        connection.close()
        return response.status, response

    def _exchange(self, app, token):
        path = urlsplit(app.url).path + "__bootstrap"
        _, response = self._request(app, "POST", path, token=token)
        return response


if __name__ == "__main__":
    unittest.main()
