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

from leakguard_core.api import ConfigurationError, ScanConfig
from leakguard_core.cli import _parser, main
from leakguard_core.models import (
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
    PolicyDecision,
    RuntimeIdentity,
    ScanOutcome,
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

    def test_config_file_rejects_duplicate_keys_without_echoing_values(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-public-") as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"plugins":[],"plugins":[{"marker":"PRIVATE-MARKER"}]}', encoding="utf-8")
            with self.assertRaises(ConfigurationError) as error:
                ScanConfig.from_file(path)
            self.assertEqual(error.exception.code, "configuration-invalid")
            self.assertNotIn("PRIVATE-MARKER", str(error.exception))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
