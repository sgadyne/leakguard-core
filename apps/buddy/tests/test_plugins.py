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


if __name__ == "__main__":
    unittest.main()
