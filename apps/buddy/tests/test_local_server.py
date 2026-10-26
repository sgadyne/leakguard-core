import http.client
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlsplit

from leakguard_buddy.server import LocalBuddy


class StubBackend:
    def status(self):
        return {"ready": True}

    def close(self):
        pass


class LocalServerTests(unittest.TestCase):
    def test_bootstrap_rotates_after_exchange_and_next_open_works(self):
        with tempfile.TemporaryDirectory(prefix="buddy-http-test-") as name:
            launch_file = Path(name) / "buddy-launch.url"
            app = LocalBuddy(StubBackend(), bootstrap_file=launch_file)
            app.start()
            try:
                initial = app.bootstrap
                first = self._exchange(app, initial)
                self.assertEqual(first.status, 200)
                self.assertNotEqual(app.bootstrap, initial)
                self.assertIn(app.bootstrap, launch_file.read_text(encoding="utf-8"))
                self.assertEqual(self._exchange(app, initial).status, 403)

                cookie = first.getheader("Set-Cookie").split(";", 1)[0]
                self.assertEqual(self._request(app, "GET", "/api/status", cookie=cookie)[0], 200)
                second = self._exchange(app, app.bootstrap)
                self.assertEqual(second.status, 200)
                self.assertNotEqual(first.getheader("Set-Cookie"), second.getheader("Set-Cookie"))
            finally:
                app.close()
            self.assertFalse(launch_file.exists())

    @staticmethod
    def _request(app, method, path, *, token=None, cookie=None):
        connection = http.client.HTTPConnection("127.0.0.1", app.server.server_address[1], timeout=5)
        headers = {"Host": app.server.expected_host}
        if token is not None:
            headers.update({"Origin": app.server.origin, "Content-Type": "application/json"})
            body = json.dumps({"token": token})
        else:
            body = None
        if cookie is not None:
            headers["Cookie"] = cookie
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        connection.close()
        return response.status, response

    def _exchange(self, app, token):
        path = urlsplit(app.url).path + "__bootstrap"
        _, response = self._request(app, "POST", path, token=token)
        return response


if __name__ == "__main__":
    unittest.main()
