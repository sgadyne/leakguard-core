from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HELPER = ROOT / "tools" / "_safe_inputs.py"
if not HELPER.is_file():
    HELPER = HERE / "_safe_inputs.py"
spec = importlib.util.spec_from_file_location("evidence_safe_inputs", HELPER)
safe_inputs = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(safe_inputs)


class SafeInputTests(unittest.TestCase):
    def test_config_requires_unique_bounded_empty_regular_object(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / "config.json"
            config.write_text("{}\n", encoding="utf-8")
            safe_inputs.read_empty_json_object(config)
            for content in ('{"x":1}', '{"x":1,"x":1}', '{"x":NaN}'):
                config.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    safe_inputs.read_empty_json_object(config)
            config.write_bytes(b" " * (safe_inputs.MAX_CONFIG_BYTES + 1))
            with self.assertRaises(ValueError):
                safe_inputs.read_empty_json_object(config)

    @unittest.skipIf(os.name == "nt", "POSIX FIFO admission check")
    def test_config_fifo_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as folder:
            fifo = Path(folder) / "config.fifo"
            os.mkfifo(fifo)
            script = (
                "import sys; from _safe_inputs import read_empty_json_object; "
                "read_empty_json_object(sys.argv[1])"
            )
            result = subprocess.run(
                [sys.executable, "-c", script, str(fifo)], cwd=HERE,
                env={**os.environ, "PYTHONPATH": str(HELPER.parent)},
                capture_output=True, timeout=2, check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink unavailable")
    def test_source_identity_hashes_symlink_target_without_reading_external_file(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / "checkout"
            root.mkdir()
            outside = base / "external-file"
            outside.write_bytes(b"synthetic outside content")
            link = root / "outside-link"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            digest = hashlib.sha256()
            with patch.object(safe_inputs.os, "open", side_effect=AssertionError("must not follow symlink")):
                safe_inputs._update_file_digest(digest, link, root.resolve())
            expected = hashlib.sha256(
                b"symlink\0" + os.fsencode(str(outside)) + b"\0"
            ).digest()
            self.assertEqual(digest.digest(), expected)


if __name__ == "__main__":
    unittest.main()
