from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
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
CORPUS_TOOL = ROOT / "tools" / "run_corpus.py"
corpus_spec = importlib.util.spec_from_file_location("evidence_run_corpus", CORPUS_TOOL)
run_corpus = importlib.util.module_from_spec(corpus_spec)
assert corpus_spec and corpus_spec.loader
corpus_spec.loader.exec_module(run_corpus)
ACCEPTANCE = ROOT / "tools" / "run_acceptance.py"
acceptance_spec = importlib.util.spec_from_file_location("evidence_run_acceptance", ACCEPTANCE)
run_acceptance = importlib.util.module_from_spec(acceptance_spec)
assert acceptance_spec and acceptance_spec.loader
acceptance_spec.loader.exec_module(run_acceptance)
INDEPENDENT_LABELS = ROOT / "tools" / "run_independent_labels.py"
independent_spec = importlib.util.spec_from_file_location("evidence_independent_labels", INDEPENDENT_LABELS)
run_independent_labels = importlib.util.module_from_spec(independent_spec)
assert independent_spec and independent_spec.loader
independent_spec.loader.exec_module(run_independent_labels)
PRODUCT_JOURNEY = ROOT / "tools" / "check_product_journey.py"
product_spec = importlib.util.spec_from_file_location("evidence_product_journey", PRODUCT_JOURNEY)
check_product_journey = importlib.util.module_from_spec(product_spec)
assert product_spec and product_spec.loader
product_spec.loader.exec_module(check_product_journey)


class IndependentLabelTests(unittest.TestCase):
    def test_independent_set_keeps_six_short_literal_positives(self):
        catalog, _raw = run_independent_labels._catalog()
        positive = [item for item in catalog["cases"] if item["expected"] == "finding"]
        negative = [item for item in catalog["cases"] if item["expected"] == "none"]
        self.assertEqual(len(catalog["cases"]), 12)
        self.assertEqual(len(positive), 6)
        self.assertEqual(len(negative), 6)
        self.assertEqual(
            {item["expected_rule"] for item in positive},
            {"literal-client-secret", "literal-password"},
        )

    def test_scoring_calls_detector_once_per_isolated_case(self):
        from leakguard_core import backends

        catalog, _raw = run_independent_labels._catalog()
        cases = catalog["cases"]

        def detect(text, **_kwargs):
            case = next(item for item in cases if item["text"] == text)
            if case["expected"] == "finding":
                return [SimpleNamespace(rule=case["expected_rule"])]
            return []

        with tempfile.TemporaryDirectory() as folder:
            backend = Path(folder) / "gitleaks"
            backend.write_bytes(b"synthetic backend placeholder")
            backend.chmod(0o700)
            with patch.object(backends, "detect", side_effect=detect) as detector, \
                    patch.object(run_independent_labels, "source_identity",
                                 return_value=("a" * 40, "b" * 64)):
                receipt = run_independent_labels.run(backend, timeout=2)

        self.assertEqual(detector.call_count, 12)
        self.assertEqual([call.args[0] for call in detector.call_args_list],
                         [item["text"] for item in cases])
        self.assertEqual(receipt["evaluation_boundary"], "isolated-input")
        self.assertTrue(all(row["boundary"] == "isolated-input" for row in receipt["cases"]))
        self.assertEqual(receipt["outcome"], "passed")


class ProductJourneyArtifactTests(unittest.TestCase):
    def test_artifact_review_allows_only_declared_source_and_encrypted_payloads(self):
        with tempfile.TemporaryDirectory() as folder:
            product = Path(folder) / "product"
            state = product / "state"
            source = product / "source"
            state.mkdir(parents=True)
            source.mkdir()
            fixture = source / "case.txt"
            fixture.write_bytes(b"synthetic labeled source line")
            (product / "config.json").write_text('{"worker_policy":"strict"}\n', encoding="ascii")
            (product / "config.json").chmod(0o600)
            for name in ("observations.lgo", "credentials.lgv"):
                (state / name).write_bytes(b"opaque encrypted synthetic payload")
                (state / name).chmod(0o600)
            rows = check_product_journey._artifact_review(
                product, b"ready\n", [], fixture,
                (b"synthetic labeled source line", b"synthetic vault value"),
            )
            self.assertEqual({Path(row["name"]).name for row in rows["files"]},
                             {"config.json", "observations.lgo", "credentials.lgv"})
            (product / "config.json").write_bytes(b"leaked synthetic vault value")
            with self.assertRaises(check_product_journey.JourneyFailure) as caught:
                check_product_journey._artifact_review(
                    product, b"ready\n", [], fixture,
                    (b"synthetic labeled source line", b"synthetic vault value"),
                )
            self.assertEqual(caught.exception.code, "synthetic-value-in-plaintext-state")

    def test_artifact_review_rejects_synthetic_values_in_normal_http_responses(self):
        with tempfile.TemporaryDirectory() as folder:
            product = Path(folder) / "product"
            state = product / "state"
            source = product / "source"
            state.mkdir(parents=True)
            source.mkdir()
            fixture = source / "case.txt"
            fixture.write_bytes(b"synthetic labeled source line")
            (state / "observations.lgo").write_bytes(b"opaque encrypted payload")
            (state / "credentials.lgv").write_bytes(b"opaque encrypted payload")
            (state / "observations.lgo").chmod(0o600)
            (state / "credentials.lgv").chmod(0o600)
            with self.assertRaises(check_product_journey.JourneyFailure) as caught:
                check_product_journey._artifact_review(
                    product, b"ready\n", [("/api/findings", b"synthetic vault value", False)],
                    fixture, (b"synthetic labeled source line", b"synthetic vault value"),
                )
            self.assertEqual(caught.exception.code, "synthetic-value-in-http-response")


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
    def test_file_curve_honors_requested_repetitions_at_every_size(self):
        cases = list(benchmark_scan._file_curve_cases(3))
        self.assertEqual(len(cases), 4 * 2 * 3)
        for count in (1, 10, 50, 200):
            for content_kind in ("clean", "positive"):
                rows = [case for case in cases
                        if case[0] == count and case[1] == content_kind]
                self.assertEqual(rows, [
                    (count, content_kind, repetition) for repetition in range(3)
                ])

    def test_file_curve_supports_bounded_50_and_500_file_cases(self):
        cases = list(benchmark_scan._file_curve_cases(1, counts=(50, 500)))
        self.assertEqual(cases, [
            (count, content_kind, 0)
            for count in (50, 500) for content_kind in ("clean", "positive")
        ])

    def test_benchmark_module_uses_its_copied_tool_root(self):
        self.assertEqual(Path(benchmark_scan.__file__).resolve(), BENCHMARK.resolve())
        self.assertEqual(benchmark_scan.ROOT.resolve(), ROOT.resolve())
        self.assertIn(str(benchmark_scan.ROOT / "src"), sys.path)

    def test_corpus_tool_validates_catalog_from_copied_test_tree(self):
        self.assertEqual(Path(run_corpus.__file__).resolve(), CORPUS_TOOL.resolve())
        self.assertEqual(run_corpus.ROOT.resolve(), ROOT.resolve())
        self.assertEqual(run_corpus.CATALOG.resolve(),
                         (ROOT / "tests" / "fixtures" / "corpus_catalog.json").resolve())
        catalog = json.loads(run_corpus.CATALOG.read_text(encoding="utf-8"))
        self.assertEqual(catalog["schema_version"], 3)
        self.assertEqual(len(catalog["cases"]), 48)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config = root / "config.json"
            config.write_text("{}\n", encoding="utf-8")
            backend = root / "synthetic-backend"
            backend.write_text("private validation placeholder\n", encoding="ascii")
            backend.chmod(0o700)
            args = SimpleNamespace(config=config, gitleaks=backend,
                                   state=root / "state", output=root / "receipt.json")
            resolved = run_corpus._validate(args)
            self.assertEqual(resolved[-1], args.output.with_suffix(".json.manifest.json"))

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

    def test_report_aggregation_keeps_serial_and_parallel_identities_separate(self):
        def measurements(policy_id, runtime_id):
            return {
                mode: {"backend_worker_launches": 0 if mode == "warm" else 50,
                       "coverage_complete": True, "policy_id": policy_id,
                       "runtime_id": runtime_id}
                for mode in ("cold", "warm", "uncached")
            }

        benchmark = {
            "files": 50, "content": "positive", "repetition": 0,
            "measurements": measurements("policy-workers-2", "runtime-workers-2"),
            "reference_measurements": measurements("policy-workers-1", "runtime-workers-1"),
            "warm_reused_results": 50, "reference_warm_reused_results": 50,
            "equivalence": {
                "warm_matches_cold": True, "uncached_matches_cold": True,
                "reference_warm_matches_cold": True,
                "reference_uncached_matches_cold": True,
                "serial_matches_parallel": True,
                "serial_warm_matches_parallel_warm": True,
                "serial_uncached_matches_parallel_uncached": True,
            },
        }
        checks, identities = benchmark_scan._aggregate_checks(
            [benchmark], [{"covered_text_surfaces_complete": True}],
            [{"clean_exit_code": 0, "positive_blocked": True,
              "positive_output_redacted": True}],
        )
        self.assertEqual(sum(checks.values()), 0)
        self.assertTrue(identities[0]["consistent_within_case"])
        self.assertEqual(identities[0]["worker_identities"]["1"]["policy_ids"]["cold"],
                         "policy-workers-1")
        self.assertEqual(identities[0]["worker_identities"]["2"]["policy_ids"]["cold"],
                         "policy-workers-2")

    def test_hook_latency_summary_uses_median_and_nearest_rank_p95(self):
        summary = benchmark_scan._hook_latency_summary([
            {"clean_seconds": 0.1, "positive_seconds": 0.4},
            {"clean_seconds": 0.2, "positive_seconds": 0.5},
            {"clean_seconds": 0.3, "positive_seconds": 0.6},
        ])
        self.assertEqual(summary["clean_commit"], {
            "samples": 3, "median_seconds": 0.2, "p95_nearest_rank_seconds": 0.3,
        })
        self.assertEqual(summary["positive_blocked_commit"], {
            "samples": 3, "median_seconds": 0.5, "p95_nearest_rank_seconds": 0.6,
        })

    def test_live_process_tree_sampler_labels_platform_availability(self):
        sampler = benchmark_scan._ProcessTreeRssSampler(interval_seconds=0.01)
        sampler.start()
        time.sleep(0.025)
        row = sampler.stop()
        if sys.platform.startswith("linux"):
            self.assertTrue(row["process_tree_rss_sampling_available"])
            self.assertGreater(row["sampled_process_tree_peak_bytes"], 0)
            self.assertGreaterEqual(row["process_tree_sample_count"], 2)
        else:
            self.assertFalse(row["process_tree_rss_sampling_available"])
            self.assertIsNone(row["sampled_process_tree_peak_bytes"])

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


class AcceptanceSummaryTests(unittest.TestCase):
    def test_unittest_summary_reports_counts_and_only_fixed_skip_ids(self):
        output = (
            "test_native_only (test_runtime_identity.RuntimeIdentityTests) ... skipped 'Windows only'\n"
            "test_pdf_optional (test_corpus.CorpusTests) ... skipped 'parser extra unavailable'\n"
            "test_regular_case (test_corpus.CorpusTests) ... ok\n\n"
            "Ran 3 tests in 0.012s\n\nOK (skipped=2)\n"
        )
        summary = run_acceptance._parse_unittest_summary(
            output, "harmless plugin stdout after the unittest summary")
        self.assertEqual(summary, {
            "total": 3, "passed": 1, "skipped": 2, "failures": 0, "errors": 0,
            "skip_test_ids": [
                "test_corpus.CorpusTests.test_pdf_optional",
                "test_runtime_identity.RuntimeIdentityTests.test_native_only",
            ],
            "failed_test_ids": [], "error_test_ids": [], "failure_types": [],
        })
        self.assertNotIn("parser extra unavailable", json.dumps(summary))

    def test_unittest_failure_summary_keeps_test_ids_and_exception_types_only(self):
        output = (
            "test_path_case (test_paths.PathTests) ... FAIL\n"
            "test_policy_case (test_policy.PolicyTests) ... ERROR\n\n"
            "FAIL: test_path_case (test_paths.PathTests)\n"
            "Traceback (most recent call last):\n"
            "AssertionError: synthetic fixture path detail\n\n"
            "ERROR: test_policy_case (test_policy.PolicyTests)\n"
            "Traceback (most recent call last):\n"
            "ValueError: synthetic policy detail\n\n"
            "Ran 2 tests in 0.012s\n\nFAILED (failures=1, errors=1)\n"
        )
        summary = run_acceptance._parse_unittest_summary(output)
        self.assertEqual(summary["failed_test_ids"], ["test_paths.PathTests.test_path_case"])
        self.assertEqual(summary["error_test_ids"], ["test_policy.PolicyTests.test_policy_case"])
        self.assertEqual(summary["failure_types"], [
            {"test_id": "test_paths.PathTests.test_path_case", "result": "fail",
             "exception_type": "AssertionError"},
            {"test_id": "test_policy.PolicyTests.test_policy_case", "result": "error",
             "exception_type": "ValueError"},
        ])
        self.assertNotIn("synthetic fixture path detail", json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
