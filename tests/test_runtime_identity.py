"""Behavior-bearing bytes must change runtime identity even when labels stay put."""
from __future__ import annotations

import importlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

from leakguard_core import scan_policy
from leakguard_core.sources import acquire_file


class RuntimeIdentityTests(unittest.TestCase):
    def preserve_mtime_write(self, path: Path, value: bytes) -> None:
        previous = path.stat()
        path.write_bytes(value)
        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))

    def test_script_bytes_change_identity_when_version_and_path_stay_fixed(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-script-identity-") as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            rules = root / "rules.toml"
            script = root / "check.py"
            binary.write_bytes(b"synthetic backend bytes")
            rules.write_text("title = 'fixture'\n", encoding="utf-8")
            first = b'__version__ = "1"\nVALUE = 1\n'
            second = b'__version__ = "1"\nVALUE = 2\n'
            self.assertEqual(len(first), len(second))
            script.write_bytes(first)
            spec = {"id": "fixture", "implementation_version": "1",
                    "argv": [sys.executable, str(script)], "rules": []}
            config = {"gitleaks_config": str(rules), "script_checks": [spec]}

            before, _ = scan_policy.runtime_identity(config, binary)
            self.preserve_mtime_write(script, second)
            after, _ = scan_policy.runtime_identity(config, binary)

        self.assertNotEqual(before, after)

    def test_module_bytes_change_identity_without_importing_the_module(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-module-identity-") as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            rules = root / "rules.toml"
            module = root / "fixture_extension.py"
            binary.write_bytes(b"synthetic backend bytes")
            rules.write_text("title = 'fixture'\n", encoding="utf-8")
            first = b'__version__ = "1"\nVALUE = 1\n'
            second = b'__version__ = "1"\nVALUE = 2\n'
            self.assertEqual(len(first), len(second))
            module.write_bytes(first)
            sys.path.insert(0, temporary)
            importlib.invalidate_caches()
            try:
                config = {"gitleaks_config": str(rules)}
                specs = [{"module": "fixture_extension", "options": {}}]
                before, _ = scan_policy.runtime_identity(config, binary, specs)
                self.preserve_mtime_write(module, second)
                after, _ = scan_policy.runtime_identity(config, binary, specs)
            finally:
                sys.path.remove(temporary)
                sys.path_importer_cache.pop(temporary, None)

        self.assertNotEqual(before, after)

    def test_binary_bytes_change_identity_even_if_path_and_mtime_are_fixed(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-binary-identity-") as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            rules = root / "rules.toml"
            rules.write_text("title = 'fixture'\n", encoding="utf-8")
            first = b"synthetic backend version 1"
            second = b"synthetic backend version 2"
            self.assertEqual(len(first), len(second))
            binary.write_bytes(first)
            before, _ = scan_policy.runtime_identity({"gitleaks_config": str(rules)}, binary)
            self.preserve_mtime_write(binary, second)
            after, _ = scan_policy.runtime_identity({"gitleaks_config": str(rules)}, binary)

        self.assertNotEqual(before, after)

    def test_input_content_identity_and_snapshot_validation_ignore_size_mtime_cache(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-input-identity-") as temporary:
            path = Path(temporary) / "input.txt"
            path.write_bytes(b"first")
            original = path.stat()
            snapshot = acquire_file(path, max_bytes=1024)

            self.preserve_mtime_write(path, b"other")
            changed = path.stat()
            self.assertEqual(changed.st_size, original.st_size)
            self.assertEqual(changed.st_mtime_ns, original.st_mtime_ns)
            self.assertFalse(snapshot.valid())
            refreshed = acquire_file(path, max_bytes=1024)

        self.assertNotEqual(snapshot.content.digest, refreshed.content.digest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
