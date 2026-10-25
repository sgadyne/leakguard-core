"""Public API contract, import, serialization and CLI adapter checks."""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core.api import ConfigurationError, ScanConfig, Scanner
from leakguard_core.cli import _parser, main
from leakguard_core import manage, presentation
from leakguard_core.models import (
    BytesInput,
    ContentIdentity,
    CoverageIssue,
    CoverageState,
    CoverageSummary,
    DecisionVerdict,
    DetectorSeverity,
    ErrorCode,
    FindingClassification,
    FindingRecord,
    FindingSeverity,
    FileInput,
    PolicyDecision,
    RuntimeIdentity,
    ScanLimits,
    ScanOutcome,
    ScanPolicy,
    ScanReport,
    ScanResult,
    SourceKind,
    SourceRef,
    report_to_dict,
)


def _report(*, verdict=DecisionVerdict.ALLOW, severity=FindingSeverity.REVIEW):
    now = dt.datetime.now(dt.timezone.utc)
    source = SourceRef(SourceKind.FILESYSTEM, "sample.txt")
    finding = FindingRecord(
        id="f" * 64,
        source=source,
        part_id="text",
        start_line=2,
        end_line=3,
        rule="fixture-rule",
        detector_id="builtin",
        detector_severity=DetectorSeverity.REVIEW,
        severity=severity,
        classification=FindingClassification.CREDENTIAL_CANDIDATE,
    )
    result = ScanResult(
        source=source,
        content=ContentIdentity("sha256", "a" * 64, 10),
        identity=RuntimeIdentity("policy-1", "runtime-1", "context-1", True),
        outcome=ScanOutcome.SCANNED,
        coverage=CoverageState.COMPLETE,
        findings=(finding,),
        issues=(),
        observed_at=now,
        last_executed_at=now,
        last_verified_at=now,
    )
    return ScanReport(
        schema_version=1,
        run_id="run-1",
        started_at=now,
        finished_at=now,
        policy_id="policy-1",
        results=(result,),
        coverage=CoverageSummary(True, True, 0),
        decision=PolicyDecision(verdict, (), "policy-1"),
    )


class PublicApiTests(unittest.TestCase):
    def test_import_is_inert_even_with_invalid_operator_environment(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-public-") as directory:
            root = Path(directory)
            state = root / "must-not-exist"
            config = root / "invalid.json"
            config.write_text("not json", encoding="utf-8")
            environment = dict(os.environ)
            environment["LEAKGUARD_CONFIG"] = str(config)
            environment["LEAKGUARD_STATE_DIR"] = str(state)
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            process = subprocess.run(
                [sys.executable, "-c", "import leakguard_core.api, leakguard_core.models"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertFalse(state.exists())

    def test_manage_import_does_not_initialize_scan_engine_or_state(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-manage-import-") as directory:
            root = Path(directory)
            state = root / "must-not-exist"
            config = root / "invalid.json"
            config.write_text("not json", encoding="utf-8")
            environment = dict(os.environ)
            environment["LEAKGUARD_CONFIG"] = str(config)
            environment["LEAKGUARD_STATE_DIR"] = str(state)
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            process = subprocess.run(
                [sys.executable, "-c", "import leakguard_core.manage, sys; assert 'leakguard_core.engine' not in sys.modules"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertFalse(state.exists())

    def test_config_is_validated_copied_and_safe_to_repr(self):
        config = ScanConfig.from_mapping({"plugins": [{"module": "example", "options": {"marker": "PRIVATE-MARKER"}}]})
        values = config.to_mapping()
        values["plugins"][0]["options"]["marker"] = "changed"
        self.assertEqual(config.to_mapping()["plugins"][0]["options"]["marker"], "PRIVATE-MARKER")
        self.assertNotIn("PRIVATE-MARKER", repr(config))
        with self.assertRaises(ConfigurationError) as error:
            ScanConfig.from_mapping({"unknown-private-key": "PRIVATE-MARKER"})
        self.assertEqual(error.exception.code, "configuration-invalid")
        self.assertNotIn("PRIVATE-MARKER", str(error.exception))
        self.assertNotIn("unknown-private-key", str(error.exception))

    def test_bytes_input_repr_does_not_expose_input_content(self):
        value = BytesInput(b"PRIVATE-BYTES-MARKER", "fixture.bin")
        self.assertNotIn("PRIVATE-BYTES-MARKER", repr(value))

    def test_source_refs_validate_git_object_identity_without_requiring_nullable_fields(self):
        git = SourceRef(SourceKind.GIT_COMMIT, "fixture.txt", commit="a" * 40, blob_oid="b" * 64)
        index = SourceRef(SourceKind.GIT_INDEX, "fixture.txt", index_tree_oid="c" * 40)
        partial_git = SourceRef(SourceKind.GIT_COMMIT, "fixture.txt")
        self.assertEqual(git.commit, "a" * 40)
        self.assertEqual(index.index_tree_oid, "c" * 40)
        self.assertIsNone(partial_git.commit)
        with self.assertRaises(ValueError):
            SourceRef(SourceKind.GIT_COMMIT, "fixture.txt", commit="short")
        with self.assertRaises(ValueError):
            SourceRef(SourceKind.FILESYSTEM, "fixture.txt", blob_oid="a" * 40)
        with self.assertRaises(ValueError):
            SourceRef(SourceKind.GIT_COMMIT, "fixture.txt", index_tree_oid="a" * 40)

    def test_config_file_rejects_duplicate_keys_without_echoing_values(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-public-") as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"plugins":[],"plugins":[{"marker":"PRIVATE-MARKER"}]}', encoding="utf-8")
            with self.assertRaises(ConfigurationError) as error:
                ScanConfig.from_file(path)
            self.assertEqual(error.exception.code, "configuration-invalid")
            self.assertNotIn("PRIVATE-MARKER", str(error.exception))

    def test_config_file_read_is_bounded_and_invalid_numeric_values_are_safe(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-public-") as directory:
            path = Path(directory) / "oversize.json"
            path.write_bytes(b" " * 1_000_001)
            with self.assertRaises(ConfigurationError) as error:
                ScanConfig.from_file(path)
            self.assertEqual(error.exception.code, "configuration-invalid")
            self.assertNotIn("1000001", str(error.exception))
        with self.assertRaises(ConfigurationError) as error:
            ScanConfig.from_mapping({"max_file_bytes": 2**100})
        self.assertEqual(error.exception.code, "configuration-invalid")
        self.assertEqual(error.exception.field, "max_file_bytes")
        self.assertNotIn(str(2**100), str(error.exception))

    def test_report_serializer_is_closed_and_counts_derive_from_results(self):
        report = _report()
        payload = report_to_dict(report)
        self.assertEqual(
            set(payload),
            {"schema_version", "run_id", "started_at", "finished_at", "policy_id", "results", "coverage", "decision", "counts", "issues"},
        )
        self.assertEqual(payload["counts"]["findings"], 1)
        self.assertEqual(payload["counts"]["review_findings"], 1)
        self.assertEqual(set(payload["results"][0]["findings"][0]), {
            "id", "source", "part_id", "start_line", "end_line", "rule", "detector_id",
            "detector_severity", "severity", "classification", "proof_id",
        })
        self.assertEqual(json.loads(report.to_json()), payload)

    def test_typed_scan_summary_does_not_claim_a_git_operation_was_blocked(self):
        text = presentation.render(_report(
            verdict=DecisionVerdict.BLOCK, severity=FindingSeverity.BLOCK,
        ))
        self.assertIn("BLOCKING FINDINGS", text)
        self.assertIn("Blocking findings are present", text)
        self.assertNotIn("blocked this Git operation", text)

    def test_typed_scan_summary_does_not_claim_a_git_operation_was_blocked(self):
        text = presentation.render(_report(
            verdict=DecisionVerdict.BLOCK, severity=FindingSeverity.BLOCK,
        ))
        self.assertIn("BLOCKING FINDINGS", text)
        self.assertIn("Blocking findings are present", text)
        self.assertNotIn("blocked this Git operation", text)

    def test_report_json_preserves_surrogateescaped_paths_as_utf8_safe_json(self):
        report = _report()
        invalid_path = "bad-" + bytes([0xff]).decode("utf-8", "surrogateescape") + ".txt"
        source = SourceRef(SourceKind.GIT_COMMIT, invalid_path)
        original = report.results[0]
        finding = replace(original.findings[0], source=source)
        result = replace(original, source=source, findings=(finding,))
        report = replace(report, results=(result,))
        encoded = report.to_json()
        encoded.encode("utf-8")
        self.assertEqual(json.loads(encoded)["results"][0]["source"]["path"], source.path)
        self.assertIn("\\udcff", presentation.clean(source.path))

    def test_manage_current_history_uses_closed_store_report_without_raw_fields(self):
        stamp = "2026-10-25X18:00:00+00:00"
        row = {
            "id": "a" * 64,
            "source": {"kind": "filesystem", "path": "fixture.txt", "repository": None,
                       "commit": None, "blob_oid": None, "index_tree_oid": None,
                       "extra": "PRIVATE-SOURCE"},
            "part_id": "text", "start_line": 4, "end_line": 5, "rule": "fixture-rule",
            "detector_id": "builtin", "detector_severity": "review", "severity": "review",
            "classification": "credential-candidate", "state": "unknown",
            "first_seen": stamp, "last_seen": stamp, "last_verified": None,
            "resolved_at": None, "state_reason": "source-unavailable",
            "matched_value": "PRIVATE-VALUE", "policy_id": "internal-policy-id",
        }

        class FakeStore:
            def __init__(self):
                self.closed = False
                self.query = None

            def query_findings_page(self, *, state, profile, limit, cursor):
                self.query = (state, profile, limit, cursor)
                return type("Page", (), {"rows": (row,), "has_more": False, "next_cursor": None})()

            def close(self):
                self.closed = True

        store = FakeStore()
        for state in ("current", "history"):
            stdout = __import__("io").StringIO()
            stderr = __import__("io").StringIO()
            with patch("leakguard_core.manage._open_scan_store", return_value=store):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = manage.main(["report", "general", "--state", state, "--format", "json"])
            self.assertEqual(code, 0)
            self.assertEqual(store.query, (state, "general", 1000, None))
            payload = json.loads(stdout.getvalue())
            self.assertEqual(set(payload), {
                "schema_version", "report_type", "state", "profile", "page_count",
                "has_more", "next_cursor", "findings",
            })
            self.assertEqual((payload["schema_version"], payload["report_type"]), (2, "findings-page"))
            self.assertEqual((payload["page_count"], payload["has_more"], payload["next_cursor"]), (1, False, None))
            self.assertNotIn("count", payload)
            self.assertNotIn("PRIVATE-VALUE", stdout.getvalue())
            self.assertNotIn("PRIVATE-SOURCE", stdout.getvalue())
            self.assertNotIn("policy_id", payload["findings"][0])
            self.assertEqual(payload["findings"][0]["state_reason"], "source-unavailable")
            self.assertEqual(payload["findings"][0]["first_seen"], "2026-10-25T18:00:00.000000Z")
            self.assertTrue(store.closed)
            self.assertEqual(stderr.getvalue(), "")

        clean = presentation.findings_report_to_dict("current", "general", (row,))
        text = presentation.render_findings_report(clean)
        self.assertNotIn("PRIVATE-VALUE", text)
        self.assertNotIn("PASS", text)

    def test_manage_page_cursor_is_forwarded_and_envelope_preserves_store_order(self):
        stamp = "2026-10-25T18:00:00Z"
        def finding(path, identifier):
            return {
                "id": identifier * 64,
                "source": {"kind": "filesystem", "path": path, "repository": None,
                           "commit": None, "blob_oid": None, "index_tree_oid": None},
                "part_id": "text", "start_line": 1, "end_line": 1, "rule": "fixture-rule",
                "detector_id": "builtin", "detector_severity": "review", "severity": "review",
                "classification": "credential-candidate", "state": "active",
                "first_seen": stamp, "last_seen": stamp, "last_verified": stamp,
                "resolved_at": None, "state_reason": "verified-present",
            }

        rows = (finding("z.txt", "a"), finding("a.txt", "b"))
        class FakeStore:
            closed = False
            query = None

            def query_findings_page(self, *, state, profile, limit, cursor):
                self.query = (state, profile, limit, cursor)
                return type("Page", (), {
                    "rows": rows, "has_more": True, "next_cursor": "v1.YWJj",
                })()

            def close(self):
                self.closed = True

        store = FakeStore()
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with patch("leakguard_core.manage._open_scan_store", return_value=store), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = manage.main([
                "report", "all", "--state", "history", "--format", "json",
                "--limit", "2", "--cursor", "v1.previous",
            ])
        self.assertEqual(code, 0)
        self.assertEqual(store.query, ("history", None, 2, "v1.previous"))
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["page_count"], 2)
        self.assertTrue(payload["has_more"])
        self.assertEqual(payload["next_cursor"], "v1.YWJj")
        self.assertEqual([item["source"]["path"] for item in payload["findings"]], ["z.txt", "a.txt"])
        self.assertNotIn("total", payload)
        rendered = presentation.render_findings_report(payload)
        self.assertIn("2 observations in this page", rendered)
        self.assertIn("--cursor v1.YWJj", rendered)
        self.assertTrue(store.closed)
        self.assertEqual(stderr.getvalue(), "")

    def test_findings_page_serializer_rejects_inconsistent_or_unbounded_continuation(self):
        with self.assertRaises(ValueError):
            presentation.findings_page_report_to_dict(
                "current", "all", (), has_more=True, next_cursor=None,
            )
        with self.assertRaises(ValueError):
            presentation.findings_page_report_to_dict(
                "current", "all", (), has_more=True, next_cursor="private path",
            )
        page = presentation.findings_page_report_to_dict(
            "current", "all", (), has_more=False, next_cursor=None,
        )
        self.assertEqual(page["page_count"], 0)
        self.assertFalse(page["has_more"])
        self.assertIsNone(page["next_cursor"])
        with self.assertRaises(TypeError):
            presentation.render_findings_report({
                **page, "schema_version": True,
            })

    def test_manage_explain_reads_indexed_typed_report(self):
        report = _report()

        class FakeStore:
            closed = False

            def latest_report(self, repository):
                self.repository = repository
                return report

            def close(self):
                self.closed = True

        store = FakeStore()
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with patch("leakguard_core.manage._open_scan_store", return_value=store), \
             patch("leakguard_core.manage._repository_argument", return_value="fixture-repo"):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = manage.main(["explain", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(store.repository, "fixture-repo")
        self.assertEqual(json.loads(stdout.getvalue()), report.to_dict())
        self.assertTrue(store.closed)
        self.assertEqual(stderr.getvalue(), "")

    def test_schema_one_report_file_uses_closed_decoder(self):
        report = _report()
        with tempfile.TemporaryDirectory(prefix="leakguard-test-report-") as directory:
            path = Path(directory) / "report.json"
            path.write_text(report.to_json(), encoding="utf-8")
            stdout = __import__("io").StringIO()
            stderr = __import__("io").StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = manage.main(["explain", "--report", str(path), "--format", "json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout.getvalue()), report.to_dict())
            self.assertEqual(stderr.getvalue(), "")

            payload = report.to_dict()
            payload["unexpected"] = "PRIVATE-EXTRA"
            path.write_text(json.dumps(payload), encoding="utf-8")
            stdout = __import__("io").StringIO()
            stderr = __import__("io").StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = manage.main(["explain", "--report", str(path), "--format", "json"])
            self.assertEqual(code, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("PRIVATE-EXTRA", stderr.getvalue())

    def test_schema_zero_reports_never_claim_pass_or_echo_free_labels(self):
        old = {
            "label": "PRIVATE-LABEL",
            "findings": [{
                "path": "fixture.txt", "line": 1, "rule": "fixture-rule", "severity": "review",
                "info": "PRIVATE-INFO", "field": "PRIVATE-FIELD", "material_name": "PRIVATE-MATERIAL",
            }],
            "coverage_issues": [],
        }
        rendered = presentation.render(old)
        serialized = json.dumps(presentation.sanitized_report(old), ensure_ascii=True)
        self.assertIn("INCOMPLETE (coverage unknown)", rendered)
        self.assertNotIn("PASS", rendered)
        for marker in ("PRIVATE-LABEL", "PRIVATE-INFO", "PRIVATE-FIELD", "PRIVATE-MATERIAL"):
            self.assertNotIn(marker, rendered)
            self.assertNotIn(marker, serialized)
        self.assertEqual(presentation.sanitized_report(old)["coverage"], "unknown")

    def test_explain_requires_selected_or_current_repository(self):
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with patch("leakguard_core.manage._repository_argument", return_value=None), \
             patch("leakguard_core.manage._open_scan_store") as open_store:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = manage.main(["explain"])
        self.assertEqual(code, 2)
        open_store.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("report-unavailable", stderr.getvalue())

    def test_result_invariants_prevent_bad_reuse_and_coverage_claims(self):
        report = _report()
        result = report.results[0]
        with self.assertRaises(ValueError):
            replace(
                report,
                coverage=CoverageSummary(False, False, 0),
                decision=PolicyDecision(DecisionVerdict.ALLOW, (), report.policy_id),
            )
        wrong_source = SourceRef(SourceKind.FILESYSTEM, "other.txt")
        bad_finding = replace(result.findings[0], source=wrong_source)
        with self.assertRaises(ValueError):
            ScanResult(
                source=result.source, content=result.content, identity=result.identity,
                outcome=result.outcome, coverage=result.coverage, findings=(bad_finding,),
                issues=(), observed_at=result.observed_at,
            )
        with self.assertRaises(ValueError):
            ScanResult(
                source=result.source, content=result.content, identity=result.identity,
                outcome=ScanOutcome.SCANNED, coverage=CoverageState.COMPLETE,
                findings=(), issues=(CoverageIssue(ErrorCode.DECODE_FAILED, required=True),),
                observed_at=result.observed_at,
            )
        with self.assertRaises(ValueError):
            replace(
                result,
                outcome=ScanOutcome.REUSED,
                reused_from="previous-scan",
                identity=replace(result.identity, cache_eligible=False),
            )

    def test_legacy_model_counts_are_stable_and_cli_defaults_are_bounded(self):
        parser = _parser()
        scan = parser.parse_args(["scan", "sample.txt"])
        audit = parser.parse_args(["audit", "workspace"])
        drain = parser.parse_args(["drain"])
        self.assertEqual((scan.budget_seconds, scan.max_files, scan.use_cache), (120, 1000, True))
        self.assertEqual((audit.budget_seconds, audit.max_files, audit.use_cache), (600, 3000, True))
        self.assertEqual((drain.budget_seconds, drain.max_files, drain.use_cache), (45, 150, False))

    def test_cli_json_stdout_is_one_object_and_fail_on_is_explicit(self):
        report = _report(verdict=DecisionVerdict.ALLOW, severity=FindingSeverity.BLOCK)

        class FakeScanner:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def scan_paths(self, *args, **kwargs):
                return report

        with tempfile.TemporaryDirectory(prefix="leakguard-test-public-") as directory:
            stdout = __import__("io").StringIO()
            stderr = __import__("io").StringIO()
            isolated_env = {"LEAKGUARD_CONFIG": "", "LEAKGUARD_GITLEAKS": ""}
            with patch.dict(os.environ, isolated_env), patch("leakguard_core.cli.Scanner.open", return_value=FakeScanner()):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = main(["scan", "sample.txt", "--format", "json", "--state-dir", directory])
            self.assertEqual(code, 0)
            self.assertEqual(len(stdout.getvalue().splitlines()), 1)
            self.assertEqual(json.loads(stdout.getvalue())["run_id"], "run-1")
            self.assertEqual(stderr.getvalue(), "")

            with patch.dict(os.environ, isolated_env), patch("leakguard_core.cli.Scanner.open", return_value=FakeScanner()):
                with contextlib.redirect_stdout(__import__("io").StringIO()), contextlib.redirect_stderr(__import__("io").StringIO()):
                    code = main(["scan", "sample.txt", "--fail-on", "block", "--state-dir", directory])
            self.assertEqual(code, 1)

    def test_cli_passes_validated_config_limits_to_shared_service(self):
        report = _report()

        class FakeScanner:
            limits = None

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def scan_paths(self, paths, *, policy, limits, use_cache, cancel=None):
                self.limits = limits
                return report

        with tempfile.TemporaryDirectory(prefix="leakguard-test-cli-config-") as directory:
            root = Path(directory)
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps({"max_file_bytes": 1234, "scan_timeout_seconds": 7}),
                encoding="utf-8",
            )
            state = root / "state"
            scanner = FakeScanner()
            stdout = __import__("io").StringIO()
            stderr = __import__("io").StringIO()
            with patch.dict(os.environ, {"LEAKGUARD_CONFIG": "", "LEAKGUARD_GITLEAKS": ""}), \
                 patch("leakguard_core.cli.Scanner.open", return_value=scanner), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(["scan", "sample.txt", "--config", str(config_path), "--format", "json", "--state-dir", str(state)])
            self.assertEqual(code, 0)
            self.assertEqual(scanner.limits.max_file_bytes, 1234)
            self.assertEqual(scanner.limits.detector_timeout_seconds, 7)
            self.assertEqual(stdout.getvalue().count("\n"), 1)
            self.assertEqual(stderr.getvalue(), "")

    def test_python_scanner_uses_caller_supplied_limits(self):
        report = _report()

        class FakeService:
            received = None

            def scan(self, inputs, *, policy, limits, use_cache, cancel):
                self.received = (tuple(inputs), policy, limits, use_cache, cancel)
                return report

            def close(self):
                pass

        service = FakeService()
        scanner = Scanner(service)
        input_value = FileInput(Path("synthetic.txt"))
        policy = ScanPolicy.inventory()
        limits = ScanLimits(30, 10, max_file_bytes=4567, detector_timeout_seconds=9)
        result = scanner.scan([input_value], policy=policy, limits=limits, use_cache=False)
        self.assertIs(result, report)
        self.assertEqual(service.received, ((input_value,), policy, limits, False, None))

    def test_cli_malformed_or_missing_config_fails_closed_to_stderr(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-cli-config-") as directory:
            root = Path(directory)
            malformed = root / "malformed.json"
            malformed.write_text('{"max_file_bytes":', encoding="utf-8")
            missing = root / "missing.json"
            for config_path in (malformed, missing):
                stdout = __import__("io").StringIO()
                stderr = __import__("io").StringIO()
                with patch.dict(os.environ, {"LEAKGUARD_CONFIG": "", "LEAKGUARD_GITLEAKS": ""}), \
                     contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = main(["scan", "sample.txt", "--format", "json", "--config", str(config_path)])
                self.assertEqual(code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn("LeakGuard: configuration-invalid", stderr.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
