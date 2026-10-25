from __future__ import annotations

import hashlib
import importlib.util
import json
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

BENCHMARK = ROOT / "tools" / "benchmark_scan.py"
sys.path.insert(0, str(ROOT / "tools"))
benchmark_spec = importlib.util.spec_from_file_location("evidence_benchmark_scan", BENCHMARK)
benchmark_scan = importlib.util.module_from_spec(benchmark_spec)
assert benchmark_spec and benchmark_spec.loader
benchmark_spec.loader.exec_module(benchmark_scan)


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


class BenchmarkAggregationTests(unittest.TestCase):
    def test_benchmark_module_uses_its_copied_tool_root(self):
        self.assertEqual(Path(benchmark_scan.__file__).resolve(), BENCHMARK.resolve())
        self.assertEqual(benchmark_scan.ROOT.resolve(), ROOT.resolve())
        self.assertIn(str(benchmark_scan.ROOT / "src"), sys.path)

    def test_report_aggregation_uses_backend_metric_and_case_local_identities(self):
        def case(files, policy_id):
            rows = {}
            for mode in ("cold", "warm", "uncached"):
                rows[mode] = {
                    "backend_worker_launches": 0 if mode == "warm" else files,
                    "coverage_complete": True,
                    "policy_id": policy_id,
                    "runtime_id": "runtime-fixed",
                }
            return {
                "files": files, "content": "clean", "repetition": 0,
                "measurements": rows, "warm_reused_results": files,
                "equivalence": {"warm_matches_cold": True,
                                "uncached_matches_cold": True},
            }

        benchmarks = [case(10, "policy-small-limit"), case(50, "policy-large-limit")]
        part_curve = [{"covered_text_surfaces_complete": True}]
        hooks = [{"clean_exit_code": 0, "positive_blocked": True,
                  "positive_output_redacted": True}]
        checks, identities = benchmark_scan._aggregate_checks(benchmarks, part_curve, hooks)

        self.assertEqual(checks, {
            "equivalence_failures": 0, "cache_reuse_failures": 0,
            "coverage_failures": 0, "installed_hook_failures": 0,
            "scan_identity_failures": 0,
        })
        self.assertTrue(all(row["consistent_within_case"] for row in identities))
        self.assertEqual(identities[0]["policy_ids"]["cold"], "policy-small-limit")
        self.assertEqual(identities[1]["policy_ids"]["cold"], "policy-large-limit")

    def test_mocked_benchmark_result_reaches_redacted_receipt(self):
        measurements = {
            mode: {"backend_worker_launches": 0, "coverage_complete": True,
                   "policy_id": "policy-limit-10", "runtime_id": "runtime-stable"}
            for mode in ("cold", "warm", "uncached")
        }
        checks, identities = benchmark_scan._aggregate_checks([{
            "files": 10, "content": "clean", "repetition": 0,
            "measurements": measurements, "warm_reused_results": 10,
            "equivalence": {"warm_matches_cold": True,
                            "uncached_matches_cold": True},
        }], [{"covered_text_surfaces_complete": True}], [{
            "clean_exit_code": 0, "positive_blocked": True,
            "positive_output_redacted": True,
        }])
        details = {"checks": checks, "scan_identity_cases": identities,
                   "scan_identities_consistent": True}

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / "empty.json"
            config.write_text("{}\n", encoding="utf-8")
            backend = root / "backend"
            backend.write_text("synthetic backend placeholder\n", encoding="ascii")
            backend.chmod(0o700)
            output = root / "receipt.json"
            source = ("a" * 40, "b" * 64)
            with patch.object(benchmark_scan, "run_benchmark", return_value=details), \
                    patch.object(benchmark_scan, "source_identity", return_value=source):
                status = benchmark_scan.main([
                    "--output", str(output), "--state", str(root / "state"),
                    "--config", str(config), "--gitleaks", str(backend),
                    "--repetitions", "3",
                ])
            self.assertEqual(status, 0)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["outcome"], "passed")
            self.assertEqual(receipt["details"]["checks"]["cache_reuse_failures"], 0)
            self.assertEqual(receipt["details"]["scan_identity_cases"][0]["policy_ids"]["warm"],
                             "policy-limit-10")


if __name__ == "__main__":
    unittest.main()
