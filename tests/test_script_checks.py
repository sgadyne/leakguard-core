"""Synthetic fixed-argv script protocol and redaction regressions."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from leakguard_core import models, plugins
from leakguard_core.plugins import PluginError


class ScriptCheckTests(unittest.TestCase):
    def make_detector(self, script: Path, *, maximum_severity="review"):
        return plugins.load_scripts([{
            "id": "fixture-script",
            "argv": [sys.executable, str(script.resolve())],
            "rules": [{"id": "firm-demo-marker", "minimum_severity": maximum_severity}],
        }])[0]

    def write_script(self, directory: Path, source: str) -> Path:
        script = directory / "check.py"
        script.write_text(source, encoding="utf-8")
        return script

    def test_published_example_round_trips_through_the_supervised_adapter(self):
        example = Path(__file__).resolve().parents[1] / "examples" / "script_checks" / "check.py"
        detector = self.make_detector(example)
        findings = tuple(plugins.detect(
            [detector], "ordinary\nFIRM-DEMO-MARKER\n", "space/é\nfixture.txt", "text",
            format_id="text", timeout=5,
        ))
        self.assertEqual([(item.rule, item.line, item.severity) for item in findings],
                         [("firm-demo-marker", 2, "review")])
        self.assertEqual(tuple(plugins.detect(
            [detector], "ordinary fixture", "fixture.txt", "text", timeout=5,
        )), ())

    def test_severity_downgrade_and_unknown_fields_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-script-test-") as temporary:
            script = self.write_script(Path(temporary), '''
import json, sys
request = json.load(sys.stdin)
assert request["schema_version"] == 1
assert request["logical_path"] == "fixture.txt"
print(json.dumps({"schema_version": 1, "findings": [
    {"rule": "firm-demo-marker", "line": 1, "severity": "review"}
]}))
''')
            detector = self.make_detector(script, maximum_severity="block")
            with self.assertRaises(PluginError) as error:
                tuple(plugins.detect([detector], "FIRM-DEMO-MARKER", "fixture.txt", "text", timeout=5))
            self.assertEqual(error.exception.code, "detector-output-invalid")
            self.assertEqual(str(error.exception), "detector-output-invalid")

    def test_bad_stdout_and_nonzero_exit_are_fixed_codes_without_raw_values(self):
        marker = "SyntheticOnly~ScriptFailure8b3f"
        with tempfile.TemporaryDirectory(prefix="leakguard-script-test-") as temporary:
            bad = self.write_script(Path(temporary), "print('not-json')\n")
            with self.assertRaises(PluginError) as error:
                tuple(plugins.detect([self.make_detector(bad)], marker, "fixture.txt", "text", timeout=5))
            self.assertEqual(error.exception.code, "detector-output-invalid")
            self.assertNotIn(marker, str(error.exception))

            crashed = self.write_script(Path(temporary),
                                        "import sys\nsys.stderr.write(" + repr(marker) + ")\nsys.exit(9)\n")
            with self.assertRaises(PluginError) as error:
                tuple(plugins.detect([self.make_detector(crashed)], marker, "fixture.txt", "text", timeout=5))
            self.assertEqual(error.exception.code, "plugin-crashed")
            self.assertNotIn(marker, str(error.exception))

    def test_timeout_and_output_bounds_fail_safely(self):
        marker = "SyntheticOnly~ScriptTimeout2d6a"
        with tempfile.TemporaryDirectory(prefix="leakguard-script-test-") as temporary:
            hangs = self.write_script(Path(temporary), "import time\ntime.sleep(30)\n")
            detector = self.make_detector(hangs)
            started = time.monotonic()
            with self.assertRaises(PluginError) as error:
                tuple(plugins.detect([detector], marker, "fixture.txt", "text", timeout=0.15))
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(error.exception.code, "plugin-timeout")
            self.assertNotIn(marker, str(error.exception))

            flood = self.write_script(Path(temporary), "print('x' * 4096)\n")
            detector = self.make_detector(flood)
            limits = models.ScanLimits(5, 1, max_ipc_bytes=512)
            with self.assertRaises(PluginError) as error:
                tuple(plugins.detect([detector], "short", "fixture.txt", "text", timeout=5, limits=limits))
            self.assertEqual(error.exception.code, "detector-output-limit")
            self.assertNotIn(marker, str(error.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
