#!/usr/bin/env python3
"""Focused stdlib checks for immutable closure and retained desktop profiles."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bootstrap", ROOT / "deploy/desktop/bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class ResourceBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.resources = self.root / "resources"
        self.resources.mkdir()
        (self.resources / "python/bin").mkdir(parents=True)
        (self.resources / "python/bin/python3").write_bytes(b"synthetic interpreter")
        system = {"Darwin": "macos", "Windows": "windows", "Linux": "linux"}[platform.system()]
        machine = "arm64" if platform.machine().lower() in {"aarch64", "arm64"} else "x86_64"
        self.manifest = {"schemaVersion": 1, "desktopVersion": "0.1.0-alpha.1", "protocolVersion": 1,
                         "target": f"{system}-{machine}", "pythonVersion": platform.python_version(),
                         "pythonExecutable": "python/bin/python3", "backendBundle": "backend/LeakGuard",
                         "backendRelease": "desktop-0.1.0-alpha.1", "sourceCommit": "0" * 40}
        self.seal()

    def seal(self):
        self.manifest["files"] = bootstrap.records(self.resources)
        self.manifest["runtimeId"] = bootstrap.runtime_identity(self.manifest)
        self.write_manifest()

    def write_manifest(self):
        (self.resources / "desktop-manifest.json").write_text(json.dumps(self.manifest))

    def rejected(self, function, code):
        with self.assertRaisesRegex(bootstrap.PreparationError, "^" + code + "$"):
            function()

    def test_tampering_and_unlisted_files_rejected(self):
        bootstrap.verify_resources(self.resources)
        executable = self.resources / "python/bin/python3"
        executable.write_bytes(b"changed interpreter")
        self.rejected(lambda: bootstrap.verify_resources(self.resources), "resource-integrity-failed")
        self.seal()
        (self.resources / "extra.py").write_text("unlisted")
        self.rejected(lambda: bootstrap.verify_resources(self.resources), "resource-integrity-failed")

    def test_relative_links_preserved_escaping_links_rejected(self):
        if os.name == "nt":
            self.skipTest("Windows symlink privileges are not assumed")
        link = self.resources / "python/bin/python"
        link.symlink_to("python3")
        self.seal()
        bootstrap.verify_resources(self.resources)
        link.unlink()
        link.symlink_to(self.root)
        self.rejected(lambda: bootstrap.records(self.resources), "payload-symlink-escape")

    def test_macos_symlink_mode_normalization_preserves_regular_modes(self):
        if os.name == "nt":
            self.skipTest("Windows symlink privileges are not assumed")
        link = self.resources / "python/bin/python"
        link.symlink_to("python3")
        expected = bootstrap.records(self.resources)
        original = Path.lstat
        def macos_lstat(path):
            info = original(path)
            return os.stat_result((stat.S_IFLNK | 0o755, *tuple(info)[1:])) if path == link else info
        with patch.object(Path, "lstat", macos_lstat):
            self.assertEqual(bootstrap.records(self.resources), expected)
        self.assertEqual(next(row for row in expected if row["path"].endswith("/python"))["mode"], 0o777)

    def test_unsafe_manifest_and_duplicate_paths_rejected(self):
        self.manifest["pythonExecutable"] = "../outside"
        self.write_manifest()
        self.rejected(lambda: bootstrap.verify_resources(self.resources), "manifest-path-invalid")
        self.manifest["pythonExecutable"] = "python/bin/python3"
        self.manifest["files"].append(self.manifest["files"][0])
        self.write_manifest()
        self.rejected(lambda: bootstrap.verify_resources(self.resources), "manifest-invalid")

    def test_runtime_mismatch_preserves_state(self):
        profile = self.root / "desktop/profile"
        (profile / "state").mkdir(parents=True)
        marker = profile / "desktop-runtime.json"
        marker.write_text(json.dumps({"runtimeId": "f" * 64, "status": "ready"}))
        state = profile / "state/credentials.lgv"
        state.write_bytes(b"synthetic retained ciphertext")
        self.rejected(lambda: bootstrap.prepare(self.resources, profile.parent), "runtime-migration-required")
        self.assertEqual(state.read_bytes(), b"synthetic retained ciphertext")
        self.assertEqual(json.loads(marker.read_text())["runtimeId"], "f" * 64)

    def test_unclaimed_state_and_symlink_root_refused(self):
        data = self.root / "desktop"
        (data / "profile/state").mkdir(parents=True)
        (data / "profile/state/config.json").write_text("retained")
        self.rejected(lambda: bootstrap.prepare(self.resources, data), "unclaimed-profile-state")
        if os.name != "nt":
            link = self.root / "profile-link"
            link.symlink_to(data)
            self.rejected(lambda: bootstrap.prepare(self.resources, link), "profile-path-invalid")

    def test_prepare_lock_is_exclusive(self):
        lock = bootstrap.PreparationLock(self.root / "lock")
        try:
            self.rejected(lambda: bootstrap.PreparationLock(self.root / "lock"), "runtime-preparation-in-use")
        finally:
            lock.close()

    def test_preparation_respects_backend_ownership_before_receipt_write(self):
        data = self.root / "desktop"
        state = data / "profile/state"
        state.mkdir(parents=True)
        marker = data / "profile/desktop-runtime.json"
        marker.write_text(json.dumps({"runtimeId": self.manifest["runtimeId"], "status": "preparing"}))
        before = marker.read_bytes()
        ownership = bootstrap.PreparationLock(state / ".buddy-owner.lock", "profile-in-use")
        try:
            self.rejected(lambda: bootstrap.prepare(self.resources, data), "profile-in-use")
            self.assertEqual(marker.read_bytes(), before)
            self.assertFalse((data / "runtimes").exists())
        finally:
            ownership.close()

    def test_installer_environment_hides_uv_and_not_yet_created_config(self):
        with patch.dict(os.environ, {"LEAKGUARD_CONFIG": "/legacy/config", "PYTHONPATH": "/checkout"}):
            environment = bootstrap.clean_environment(self.root / "python/bin/python3", self.root / "state")
        self.assertEqual(environment["PATH"], str(self.root / "python/bin"))
        self.assertNotIn("LEAKGUARD_CONFIG", environment)
        self.assertNotIn("LEAKGUARD_STATE_DIR", environment)
        self.assertNotIn("PYTHONPATH", environment)


if __name__ == "__main__":
    unittest.main()
