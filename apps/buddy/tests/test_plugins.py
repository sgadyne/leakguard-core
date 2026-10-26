import unittest
from pathlib import Path
import tempfile

from leakguard_buddy.backend import BuddyBackend, BuddyOperationError, _safe_wheel_filename


class PluginUploadTests(unittest.TestCase):
    def test_accepts_supported_wheel_basenames(self):
        self.assertEqual(
            _safe_wheel_filename("firm_checker-1.2.3-py3-none-any.whl"),
            "firm_checker-1.2.3-py3-none-any.whl",
        )
        self.assertEqual(
            _safe_wheel_filename("firm_checker-1.2.3-1-py3-none-manylinux_2_28_x86_64.whl"),
            "firm_checker-1.2.3-1-py3-none-manylinux_2_28_x86_64.whl",
        )

    def test_rejects_paths_and_non_wheel_names(self):
        for filename in (
            "../firm_checker-1.2.3-py3-none-any.whl",
            "folder/firm_checker-1.2.3-py3-none-any.whl",
            r"folder\firm_checker-1.2.3-py3-none-any.whl",
            "firm_checker.whl",
            "firm_checker-1.2.3-py3-none-any.zip",
            "firm_checker-1.2.3-py3-none-any.whl\x00",
        ):
            with self.subTest(filename=filename), self.assertRaises(BuddyOperationError) as raised:
                _safe_wheel_filename(filename)
            self.assertEqual(raised.exception.code, "plugin-invalid")


class ObservationStatusTests(unittest.TestCase):
    def test_status_exposes_active_checkpoint_capacity(self):
        class Store:
            def status(self):
                return {
                    "unlocked": True,
                    "healthy": True,
                    "serialized_bytes": 1024,
                    "capacity_bytes": 64 * 1024 * 1024,
                }

        with tempfile.TemporaryDirectory(prefix="buddy-status-test-") as name:
            backend = object.__new__(BuddyBackend)
            backend.observation_path = Path(name) / "absent-observations.lgo"
            backend._observation_store = Store()
            backend._startup_observation_error = None
            status = backend.observation_status()
        self.assertTrue(status["healthy"])
        self.assertEqual(status["serialized_bytes"], 1024)
        self.assertEqual(status["capacity_bytes"], 64 * 1024 * 1024)


class CredentialUpdateTests(unittest.TestCase):
    def test_combined_edit_uses_one_atomic_vault_operation(self):
        class Session:
            def __init__(self):
                self.calls = []

            def update_entry(self, entry_id, **fields):
                self.calls.append((entry_id, fields))
                return {"id": entry_id, "title": fields["title"]}

            def update_secret(self, *args, **kwargs):
                raise AssertionError("legacy two-write path must not run")

            def update_metadata(self, *args, **kwargs):
                raise AssertionError("legacy two-write path must not run")

        session = Session()
        backend = object.__new__(BuddyBackend)
        backend._credential_session = session
        result = backend.credential_update("entry_1", {"title": "Updated", "secret": "new-secret", "finding_id": None})
        self.assertEqual(result, {"id": "entry_1", "title": "Updated"})
        self.assertEqual(session.calls, [("entry_1", {"title": "Updated", "secret": "new-secret", "finding_id": None})])


class ScanConfigRefreshTests(unittest.TestCase):
    def test_config_change_restarts_host_without_closing_observation_store(self):
        class Host:
            def __init__(self):
                self.stopped = False

            def stop(self):
                self.stopped = True

        old_host = Host()
        store = object()
        backend = object.__new__(BuddyBackend)
        backend._host = old_host
        backend._observation_store = store
        backend._config_values = {"detection_profile": "credentials"}
        backend._config = "old-config"
        backend._startup_observation_error = "old-error"
        writes = []

        def start_host(candidate_store):
            self.assertIs(candidate_store, store)
            backend._host = Host()
            backend._observation_store = candidate_store

        backend._write_config = lambda values: writes.append(dict(values))
        backend._start_host = start_host
        values = {"detection_profile": "firm"}
        restarted = backend._replace_scan_config(values, "new-config")
        self.assertTrue(restarted)
        self.assertTrue(old_host.stopped)
        self.assertIsNot(backend._host, old_host)
        self.assertIs(backend._observation_store, store)
        self.assertEqual(backend._config_values, values)
        self.assertEqual(backend._config, "new-config")
        self.assertIsNone(backend._startup_observation_error)
        self.assertEqual(writes, [values])


if __name__ == "__main__":
    unittest.main()
