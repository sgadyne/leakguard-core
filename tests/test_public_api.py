"""Public API contract, import, serialization and CLI adapter checks."""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import json
import os
from types import SimpleNamespace
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
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
    MAX_PROVENANCE_STRING_LENGTH,
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


def _run_explicit_report(path, cwd, *, timeout=30):
    environment = dict(os.environ)
    source = str(Path(__file__).resolve().parents[1] / "src")
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = source if not existing else source + os.pathsep + existing
    environment["LEAKGUARD_CONFIG"] = ""
    environment["LEAKGUARD_STATE_DIR"] = str(Path(cwd) / "unused-state")
    return subprocess.run(
        [sys.executable, "-m", "leakguard_core.manage", "explain", "--report", str(path), "--format", "json"],
        cwd=cwd, env=environment, capture_output=True, text=True, timeout=timeout, check=False,
    )


def _finding_cursor(state, profile, position):
    filtered_profile = None if profile == "all" else profile
    filter_hash = hashlib.sha256(
        json.dumps([state, filtered_profile], separators=(",", ":")).encode()
    ).hexdigest()
    payload = [1, filter_hash, position]
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    return "lg1." + encoded


class PublicApiTests(unittest.TestCase):
    def test_a04_marker_redaction_across_api_cli_reports_and_sqlite(self):
        """A positive synthetic value never enters public output or durable state."""
        import sqlite3
        from leakguard_core import engine
        from leakguard_core.scan_store import SQLiteScanStore

        marker = "A04-Synthetic-" + uuid.uuid4().hex
        marker_bytes = marker.encode("ascii")
        source_text = f'client_secret = "{marker}"\n'

        def absent(label, value):
            if isinstance(value, str):
                leaked = marker in value
            else:
                leaked = marker_bytes in value
            self.assertFalse(leaked, f"synthetic marker leaked through {label}")

        with tempfile.TemporaryDirectory(prefix="leakguard-a04-redaction-") as directory:
            root = Path(directory)
            source_root = root / "source"
            source_root.mkdir()
            source = source_root / "fixture.txt"
            source.write_text(source_text, encoding="utf-8")
            reference = root / "private-reference.json"
            reference.write_text(json.dumps({"secret": marker}), encoding="utf-8")
            executable = Path(os.environ.get("LEAKGUARD_GITLEAKS", str(engine.EXE))).resolve()
            config = ScanConfig.from_mapping({"gitleaks_executable": str(executable)})
            limits = ScanLimits(45, 10)
            policy = ScanPolicy.inventory()

            # API scan persists a cold result and a cache replay to a private SQLite
            # store. A registered value adds a keyed material observation, not bytes.
            state_dir = root / "api-state"
            store = SQLiteScanStore(state_dir, config=config.to_mapping())
            scanner = None
            try:
                scanner = Scanner.open(config=config, state_dir=state_dir, store=store)
                first = scanner.scan([FileInput(source)], policy=policy, limits=limits)
                second = scanner.scan([FileInput(source)], policy=policy, limits=limits)
                self.assertIn("literal-client-secret", {item.rule for item in first.results[0].findings})
                self.assertEqual(second.results[0].outcome.value, "reused")
                absent("cold API JSON", first.to_json())
                absent("warm API JSON", second.to_json())
                absent("API text renderer", presentation.render(first))

                with store.conn:
                    store.conn.execute(
                        "INSERT INTO material_sources VALUES(?,?,?,?,?)",
                        ("a04-fixture", str(reference), "json", "secret", "credential"),
                    )
                material_report = scanner.scan([FileInput(source)], policy=policy, limits=limits)
                self.assertIn(
                    "known-material-credential",
                    {item.rule for item in material_report.results[0].findings},
                )
                absent("material-observation API JSON", material_report.to_json())
                absent("material-observation text", presentation.render(material_report))

                current_page = store.query_findings_page(state="current", limit=100)
                history_page = store.query_findings_page(state="history", limit=100)
                current = presentation.findings_page_report_to_dict(
                    "current", "all", current_page.rows,
                    has_more=current_page.has_more, next_cursor=current_page.next_cursor,
                )
                history = presentation.findings_page_report_to_dict(
                    "history", "all", history_page.rows,
                    has_more=history_page.has_more, next_cursor=history_page.next_cursor,
                )
                absent("current findings view", json.dumps(current, ensure_ascii=True))
                absent("history findings view", json.dumps(history, ensure_ascii=True))
                absent("current findings renderer", presentation.render_findings_report(current))
                absent("history findings renderer", presentation.render_findings_report(history))

                logical_dump = "\n".join(store.conn.iterdump())
                absent("SQLite logical dump", logical_dump)
                live_artifacts = {
                    path.name: path.read_bytes()
                    for path in state_dir.glob("state.sqlite3*") if path.is_file()
                }
                self.assertIn("state.sqlite3", live_artifacts)
                for name, raw in live_artifacts.items():
                    absent(f"live SQLite artifact {name}", raw)
                self.assertTrue(store.conn.execute("SELECT COUNT(*) FROM scan_cache").fetchone()[0])
                self.assertTrue(store.conn.execute("SELECT COUNT(*) FROM material_locations").fetchone()[0])
                self.assertTrue(store.conn.execute("SELECT COUNT(*) FROM finding_history").fetchone()[0])
            finally:
                if scanner is not None:
                    scanner.close()
                store.close()
            closed_artifacts = b"".join(
                path.read_bytes() for path in state_dir.glob("state.sqlite3*") if path.is_file()
            )
            absent("closed SQLite database/WAL/SHM", closed_artifacts)

            # The command-line scan and every management rendering consume the
            # same typed store/report schema; capture streams without echoing them.
            cli_state = root / "cli-state"
            cli_config = root / "cli-config.json"
            cli_config.write_text(json.dumps(config.to_mapping()), encoding="utf-8")
            environment = dict(os.environ)
            source_package = str(Path(__file__).resolve().parents[1] / "src")
            environment["PYTHONPATH"] = source_package
            environment["LEAKGUARD_CONFIG"] = str(cli_config)
            environment["LEAKGUARD_STATE_DIR"] = str(cli_state)
            environment["LEAKGUARD_GITLEAKS"] = str(executable)

            def run_cli(*arguments):
                return subprocess.run(
                    [sys.executable, *arguments], cwd=root, env=environment,
                    capture_output=True, text=True, timeout=60, check=False,
                )

            cold = run_cli(
                "-m", "leakguard_core.cli", "scan", "--state-dir", str(cli_state),
                "--format", "json", str(source),
            )
            self.assertEqual(cold.returncode, 0, "cold CLI scan should complete under inventory policy")
            cold_report = json.loads(cold.stdout)
            self.assertIn("literal-client-secret", {
                item["rule"] for result in cold_report["results"] for item in result["findings"]
            })
            absent("JSON CLI stdout/stderr", cold.stdout + cold.stderr)

            warm = run_cli(
                "-m", "leakguard_core.cli", "scan", "--state-dir", str(cli_state),
                "--format", "text", str(source),
            )
            self.assertEqual(warm.returncode, 0, "warm CLI scan should complete under inventory policy")
            self.assertIn("literal-client-secret", warm.stdout)
            absent("text CLI stdout/stderr", warm.stdout + warm.stderr)

            report_path = root / "typed-report.json"
            report_path.write_text(cold.stdout, encoding="utf-8")
            for format_name in ("json", "text"):
                explained = run_cli(
                    "-m", "leakguard_core.manage", "explain", "--report", str(report_path),
                    "--format", format_name,
                )
                self.assertEqual(explained.returncode, 0, "typed report explanation should succeed")
                if format_name == "json":
                    explained_data = json.loads(explained.stdout)
                    self.assertIn("literal-client-secret", {
                        item["rule"] for result in explained_data["results"] for item in result["findings"]
                    })
                else:
                    self.assertIn("literal-client-secret", explained.stdout)
                absent(f"manage explain {format_name} stdout/stderr", explained.stdout + explained.stderr)
            for state, format_name in (("current", "json"), ("history", "text")):
                viewed = run_cli(
                    "-m", "leakguard_core.manage", "report", "all", "--state", state,
                    "--format", format_name,
                )
                self.assertEqual(viewed.returncode, 0, "typed current/history report should succeed")
                if format_name == "json":
                    viewed_data = json.loads(viewed.stdout)
                    self.assertIn("literal-client-secret", {
                        item["rule"] for item in viewed_data["findings"]
                    })
                else:
                    self.assertIn("literal-client-secret", viewed.stdout)
                absent(f"manage report {state} {format_name} stdout/stderr", viewed.stdout + viewed.stderr)

            # A plugin exception and a malformed extra-field result both carry
            # this same marker through worker memory/protocol input. The public
            # report and process output retain only fixed error codes.
            plugin_root = root / "plugins"
            plugin_root.mkdir()
            plugin_root.joinpath("a04_exception.py").write_text(
                "from leakguard_core.plugins import OptionSchema, OptionSpec, PluginManifest, RuleSpec\n"
                "API_VERSION=2\n"
                "MANIFEST=PluginManifest(id='a04-exception',implementation_version='1',kind='detector',"
                "rules=(RuleSpec('a04-exception-rule'),),formats=('text',),part_kinds=('text',),"
                "options_schema=OptionSchema((OptionSpec('message','string',required=True),)))\n"
                "class Detector:\n"
                " def __init__(self,message): self.message=message\n"
                " def detect(self,text,context): raise RuntimeError(self.message)\n"
                "def create_plugin(options): return Detector(options['message'])\n",
                encoding="utf-8",
            )
            plugin_root.joinpath("a04_extra.py").write_text(
                "from leakguard_core.plugins import OptionSchema, OptionSpec, PluginManifest, RuleSpec\n"
                "API_VERSION=2\n"
                "MANIFEST=PluginManifest(id='a04-extra',implementation_version='1',kind='detector',"
                "rules=(RuleSpec('a04-extra-rule'),),formats=('text',),part_kinds=('text',),"
                "options_schema=OptionSchema((OptionSpec('value','string',required=True),)))\n"
                "class Detector:\n"
                " def __init__(self,value): self.value=value\n"
                " def detect(self,text,context): return [{'rule':'a04-extra-rule','line':1,'severity':'review','value':self.value}]\n"
                "def create_plugin(options): return Detector(options['value'])\n",
                encoding="utf-8",
            )
            plugin_mapping = config.to_mapping()
            plugin_mapping["plugins"] = [
                {"module": "a04_exception", "options": {"message": marker}},
                {"module": "a04_extra", "options": {"value": marker}},
            ]
            plugin_config = ScanConfig.from_mapping(plugin_mapping)
            plugin_environment = dict(environment)
            plugin_environment["PYTHONPATH"] = os.pathsep.join((source_package, str(plugin_root)))
            plugin_state = root / "plugin-state"
            plugin_environment["LEAKGUARD_STATE_DIR"] = str(plugin_state)
            plugin_environment["LEAKGUARD_CONFIG"] = str(root / "plugin-config.json")
            Path(plugin_environment["LEAKGUARD_CONFIG"]).write_text(
                json.dumps(plugin_config.to_mapping()), encoding="utf-8",
            )

            prior_path = list(sys.path)
            sys.path.insert(0, str(plugin_root))
            plugin_scanner = None
            try:
                plugin_scanner = Scanner.open(config=plugin_config, state_dir=plugin_state)
                plugin_report = plugin_scanner.scan([FileInput(source)], policy=policy, limits=limits)
            finally:
                if plugin_scanner is not None:
                    plugin_scanner.close()
                sys.path[:] = prior_path
            error_codes = {issue.code.value for result in plugin_report.results for issue in result.issues}
            self.assertIn("plugin-invalid", error_codes)
            self.assertIn("detector-output-invalid", error_codes)
            absent("plugin exception/extra-field API JSON", plugin_report.to_json())
            absent("plugin exception/extra-field text", presentation.render(plugin_report))

            plugin_cli = subprocess.run(
                [sys.executable, "-m", "leakguard_core.cli", "scan", "--state-dir", str(plugin_state),
                 "--format", "json", "--no-cache", str(source)],
                cwd=root, env=plugin_environment, capture_output=True, text=True, timeout=60, check=False,
            )
            self.assertEqual(plugin_cli.returncode, 2, "plugin failures must make CLI coverage incomplete")
            plugin_cli_report = json.loads(plugin_cli.stdout)
            plugin_cli_codes = {
                issue["code"] for result in plugin_cli_report["results"] for issue in result["issues"]
            }
            self.assertIn("plugin-invalid", plugin_cli_codes)
            self.assertIn("detector-output-invalid", plugin_cli_codes)
            absent("plugin exception/extra-field CLI stdout/stderr", plugin_cli.stdout + plugin_cli.stderr)
            plugin_db = sqlite3.connect(plugin_state / "state.sqlite3")
            try:
                plugin_dump = "\n".join(plugin_db.iterdump())
            finally:
                plugin_db.close()
            absent("plugin exception/extra-field SQLite logical dump", plugin_dump)
            checked = [
                "positive built-in detection through Scanner API",
                "cold and reused API reports",
                "API text rendering",
                "current/history finding serialization and rendering",
                "SQLite logical dump with cache and material observation",
                "live and closed SQLite database/WAL/SHM raw bytes",
                "JSON and text CLI output",
                "typed explain JSON/text and current/history report rendering",
                "configured plugin exception and extra-field rejection through API/CLI",
                "plugin-state SQLite logical and raw dumps",
            ]
            receipt_path = os.environ.get("LEAKGUARD_A04_RECEIPT")
            if receipt_path:
                Path(receipt_path).write_text(json.dumps({
                    "schema_version": 1,
                    "marker_sha256": hashlib.sha256(marker_bytes).hexdigest(),
                    "checks": checked,
                    "api_live_sqlite_artifacts": sorted(live_artifacts),
                    "api_cache_replay": second.results[0].outcome.value,
                    "api_material_observations": store.conn.execute(
                        "SELECT COUNT(*) FROM material_locations"
                    ).fetchone()[0],
                    "plugin_issue_codes": sorted(error_codes),
                    "source_and_transient_plugin_input_are_synthetic_exceptions": True,
                }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            for label, state in (("API", state_dir), ("CLI", cli_state), ("plugin", plugin_state)):
                raw = b"".join(
                    path.read_bytes() for path in state.glob("state.sqlite3*") if path.is_file()
                )
                absent(f"{label} SQLite raw DB/WAL/SHM", raw)

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

    def test_provenance_strings_are_bounded_before_engine_execution(self):
        calls = []

        class FakeService:
            def scan(self, *args, **kwargs):
                calls.append("scan")
                return None

        scanner = Scanner(FakeService())
        marker = "PRIVATE-OVERLONG-PATH"
        with self.assertRaises(ValueError) as error:
            scanner.scan(
                [BytesInput(b"small", marker + "x" * MAX_PROVENANCE_STRING_LENGTH)],
                policy=ScanPolicy.inventory(), limits=ScanLimits(10, 1),
            )
        self.assertNotIn(marker, str(error.exception))
        self.assertEqual(calls, [])
        with self.assertRaises(ValueError):
            BytesInput(b"small", "bad\x00path")
        with self.assertRaises(ValueError):
            SourceRef(SourceKind.FILESYSTEM, "x" * (MAX_PROVENANCE_STRING_LENGTH + 1))
        with self.assertRaises(ValueError):
            SourceRef(
                SourceKind.FILESYSTEM, "ok.txt",
                repository="r" * (MAX_PROVENANCE_STRING_LENGTH + 1),
            )
        with self.assertRaises(ValueError):
            SourceRef(SourceKind.FILESYSTEM, "ok.txt", repository="bad\x00repo")

        escaped = "bad-" + bytes([0xff]).decode("utf-8", "surrogateescape") + ".txt"
        self.assertEqual(BytesInput(b"small", escaped).logical_path, escaped)
        self.assertEqual(SourceRef(SourceKind.FILESYSTEM, escaped).path, escaped)

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

    def test_report_omission_count_matches_typed_omissions_and_decoder(self):
        from leakguard_core import scan_store

        report = _report()
        base_result = report.results[0]
        omission = CoverageIssue(
            ErrorCode.POLICY_OMISSION, source=base_result.source, part_id="text",
            required=False, omission_id="operator-exclusion-1",
        )
        omitted_result = replace(
            base_result, coverage=CoverageState.OMITTED, findings=(), issues=(omission,),
        )
        valid = replace(
            report,
            results=(omitted_result,),
            coverage=CoverageSummary(True, True, 1),
            decision=PolicyDecision(DecisionVerdict.ALLOW_WITH_OMISSIONS, (), report.policy_id),
        )
        self.assertEqual(valid.coverage.omission_count, 1)
        self.assertEqual(scan_store._report_from(valid.to_dict()), valid)

        for bad_count in (0, 2):
            with self.subTest(bad_count=bad_count):
                with self.assertRaises(ValueError):
                    replace(valid, coverage=CoverageSummary(True, True, bad_count))
                payload = valid.to_dict()
                payload["coverage"]["omission_count"] = bad_count
                with self.assertRaises(ValueError):
                    scan_store._report_from(payload)

        overcount = report.to_dict()
        overcount["coverage"]["omission_count"] = 1
        with self.assertRaises(ValueError):
            scan_store._report_from(overcount)

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
        next_cursor = _finding_cursor("history", "all", 7)
        class FakeStore:
            closed = False
            query = None

            def query_findings_page(self, *, state, profile, limit, cursor):
                self.query = (state, profile, limit, cursor)
                return type("Page", (), {
                    "rows": rows, "has_more": True, "next_cursor": next_cursor,
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
                "--limit", "2", "--cursor", _finding_cursor("history", "all", 5),
            ])
        self.assertEqual(code, 0)
        self.assertEqual(store.query, ("history", None, 2, _finding_cursor("history", "all", 5)))
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["page_count"], 2)
        self.assertTrue(payload["has_more"])
        self.assertEqual(payload["next_cursor"], next_cursor)
        self.assertEqual([item["source"]["path"] for item in payload["findings"]], ["z.txt", "a.txt"])
        self.assertNotIn("total", payload)
        rendered = presentation.render_findings_report(payload)
        self.assertIn("2 observations in this page", rendered)
        self.assertIn("--cursor " + next_cursor, rendered)
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
        with self.assertRaises(ValueError):
            presentation.findings_page_report_to_dict(
                "current", "all", (), has_more=True, next_cursor="PRIVATE-MATERIAL",
            )
        valid_cursor = _finding_cursor("current", "all", ["a" * 64, "b" * 64])
        cursor_page = presentation.findings_page_report_to_dict(
            "current", "all", (), has_more=True, next_cursor=valid_cursor,
        )
        self.assertEqual(cursor_page["next_cursor"], valid_cursor)
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
        with self.assertRaises(TypeError):
            presentation.render_findings_report({
                **page, "schema_version": 2, "report_type": "findings",
            })

    def test_public_finding_serialization_rejects_malformed_git_identity(self):
        row = {
            "id": "a" * 64,
            "source": {"kind": "git-commit", "path": "fixture.txt", "repository": "/fixture",
                       "commit": "PRIVATE-SOURCE-BYTES", "blob_oid": "b" * 40,
                       "index_tree_oid": None},
            "part_id": "text", "start_line": 1, "end_line": 1, "rule": "fixture-rule",
            "detector_id": "builtin", "detector_severity": "review", "severity": "review",
            "classification": "credential-candidate", "state": "active",
            "first_seen": "2026-10-25T18:00:00Z", "last_seen": "2026-10-25T18:00:00Z",
            "last_verified": "2026-10-25T18:00:00Z", "resolved_at": None,
            "state_reason": "verified-present",
        }
        with self.assertRaises(ValueError):
            presentation.findings_page_report_to_dict(
                "current", "all", (row,), has_more=False, next_cursor=None,
            )

    def test_manage_pages_sqlite_current_history_cursor_and_empty(self):
        from leakguard_core.scan_store import SQLiteScanStore

        with tempfile.TemporaryDirectory(prefix="leakguard-test-manage-pages-") as directory:
            root = Path(directory)
            state_dir = root / "state"
            store = SQLiteScanStore(state_dir, config={})
            try:
                for number in range(5):
                    result = _report().results[0]
                    source = replace(result.source, path=str(root / f"candidate-{number}.txt"))
                    finding = replace(
                        result.findings[0], source=source,
                        id=format(number + 1, "064x"),
                    )
                    result = replace(result, source=source, findings=(finding,))
                    store.record_result(result, generation=store.reserve(source))
            finally:
                store.close()

            environment = {"LEAKGUARD_CONFIG": "", "LEAKGUARD_STATE_DIR": str(state_dir)}
            stdout = __import__("io").StringIO()
            stderr = __import__("io").StringIO()
            with patch.dict(os.environ, environment), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = manage.main(["report", "general", "--limit", "2", "--format", "json"])
            self.assertEqual(code, 0)
            filtered = json.loads(stdout.getvalue())
            self.assertEqual(filtered["page_count"], 0)
            self.assertTrue(filtered["has_more"])
            self.assertIsInstance(filtered["next_cursor"], str)
            self.assertEqual(filtered["findings"], [])
            self.assertEqual(stderr.getvalue(), "")

            for state in ("current", "history"):
                cursor = None
                observed = []
                page_counts = []
                while True:
                    stdout = __import__("io").StringIO()
                    stderr = __import__("io").StringIO()
                    arguments = ["report", "all", "--state", state, "--limit", "2", "--format", "json"]
                    if cursor is not None:
                        arguments.extend(["--cursor", cursor])
                    with patch.dict(os.environ, environment), \
                         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        code = manage.main(arguments)
                    self.assertEqual(code, 0)
                    self.assertEqual(stderr.getvalue(), "")
                    payload = json.loads(stdout.getvalue())
                    self.assertEqual(payload["schema_version"], 2)
                    self.assertEqual(payload["state"], state)
                    self.assertLessEqual(payload["page_count"], 2)
                    self.assertNotIn("count", payload)
                    page_counts.append(payload["page_count"])
                    observed.extend(row["id"] for row in payload["findings"])
                    self.assertEqual(payload["has_more"], payload["next_cursor"] is not None)
                    if not payload["has_more"]:
                        break
                    cursor = payload["next_cursor"]
                self.assertEqual(page_counts, [2, 2, 1])
                self.assertEqual(len(observed), 5)
                self.assertEqual(len(set(observed)), 5)

            empty_state = root / "empty-state"
            stdout = __import__("io").StringIO()
            stderr = __import__("io").StringIO()
            with patch.dict(os.environ, {"LEAKGUARD_CONFIG": "", "LEAKGUARD_STATE_DIR": str(empty_state)}), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = manage.main(["report", "all", "--format", "json"])
            self.assertEqual(code, 0)
            self.assertEqual(stderr.getvalue(), "")
            empty = json.loads(stdout.getvalue())
            self.assertEqual((empty["page_count"], empty["has_more"], empty["next_cursor"]), (0, False, None))
            self.assertEqual(empty["findings"], [])

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

        with tempfile.TemporaryDirectory(prefix="leakguard-test-report-") as directory:
            path = Path(directory) / "report.json"
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

    def test_explicit_report_subprocess_rejects_unknown_schema_and_malformed_schema_one(self):
        marker = "PRIVATE-SOURCE-BYTES-MARKER"
        report = _report()
        valid = report.to_dict()
        wrong_counts = json.loads(json.dumps(valid))
        wrong_counts["counts"]["findings"] = 9182
        nested_extra = json.loads(json.dumps(valid))
        nested_extra["results"][0]["findings"][0]["source"]["private"] = marker
        cases = {
            "newer-schema.json": json.dumps({"schema_version": 2, "findings": [{"path": marker}]}),
            "boolean-schema.json": json.dumps({"schema_version": True, "findings": [{"path": marker}]}),
            "wrong-counts.json": json.dumps(wrong_counts),
            "nested-extra.json": json.dumps(nested_extra),
            "duplicate-key.json": '{"schema_version":1,"schema_version":2,"findings":["' + marker + '"]}',
        }
        with tempfile.TemporaryDirectory(prefix="leakguard-test-report-schema-") as directory:
            for name, serialized in cases.items():
                with self.subTest(name=name):
                    path = Path(directory) / name
                    path.write_text(serialized, encoding="utf-8")
                    result = _run_explicit_report(path, directory)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "LeakGuard: invalid-report\n")
                    self.assertNotIn(marker, result.stdout + result.stderr)

    def test_explicit_legacy_report_subprocess_drops_arbitrary_labels_and_source_bytes(self):
        marker = "PRIVATE-SOURCE-BYTES-MARKER"
        old = {
            "label": marker, "checked_utc": marker, "source_bytes": marker,
            "findings": [{
                "path": "fixture.txt", "line": 1, "rule": "fixture-rule", "severity": "review",
                "info": marker, "field": marker, "material_name": marker, "value": marker,
            }],
            "coverage_issues": [{"path": "fixture.txt", "status": "coverage-unknown", "material_name": marker}],
        }
        with tempfile.TemporaryDirectory(prefix="leakguard-test-report-legacy-") as directory:
            path = Path(directory) / "legacy.json"
            path.write_text(json.dumps(old), encoding="utf-8")
            result = _run_explicit_report(path, directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertNotIn(marker, result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["legacy_schema"], 0)
        self.assertEqual(payload["coverage"], "unknown")
        self.assertNotIn("source_bytes", payload)
        self.assertNotIn("material_name", payload["findings"][0])

    def test_explicit_report_subprocess_bounds_oversized_json_without_echoing_input(self):
        marker = "PRIVATE-OVERSIZED-REPORT-MARKER"
        with tempfile.TemporaryDirectory(prefix="leakguard-test-report-large-") as directory:
            path = Path(directory) / "oversized.json"
            with path.open("wb") as stream:
                stream.write(marker.encode("ascii"))
                stream.truncate(manage.MAX_EXPLICIT_REPORT_BYTES + 1)
            result = _run_explicit_report(path, directory)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "LeakGuard: invalid-report\n")
        self.assertNotIn(marker, result.stdout + result.stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO behavior is POSIX-specific")
    def test_explicit_report_subprocess_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-report-fifo-") as directory:
            path = Path(directory) / "report.fifo"
            os.mkfifo(path)
            result = _run_explicit_report(path, directory, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "LeakGuard: invalid-report\n")

    def test_manage_module_propagates_explicit_report_failure_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-manage-exit-") as directory:
            missing = Path(directory) / "missing-report.json"
            environment = dict(os.environ)
            environment["LEAKGUARD_CONFIG"] = ""
            environment["LEAKGUARD_STATE_DIR"] = str(Path(directory) / "unused-state")
            source = str(Path(__file__).resolve().parents[1] / "src")
            existing = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = source if not existing else source + os.pathsep + existing
            result = subprocess.run(
                [sys.executable, "-m", "leakguard_core.manage", "explain", "--report", str(missing)],
                cwd=directory, env=environment, capture_output=True, text=True,
                timeout=10, check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("LeakGuard: invalid-report", result.stderr)

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
        with self.assertRaises(ValueError):
            presentation.sanitized_report({"findings": [{}] * (presentation.MAX_LEGACY_REPORT_ROWS + 1)})

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

    def test_repository_argument_preserves_git_path_bytes_except_terminating_lf(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-repo-path-") as directory:
            repo = Path(directory) / "repo-é with space \n"
            repo.mkdir()
            subprocess.run(
                ["git", "init", "-q", str(repo)], capture_output=True, check=True,
            )
            previous = Path.cwd()
            try:
                os.chdir(repo)
                self.assertEqual(manage._repository_argument(None), str(repo.resolve()))
            finally:
                os.chdir(previous)

    def test_legacy_archive_uses_bounded_allowlisted_rows(self):
        marker = "PRIVATE-HISTORICAL-MARKER"
        with tempfile.TemporaryDirectory(prefix="leakguard-test-legacy-archive-") as directory:
            state = Path(directory) / "state"
            archive = state / "reports"
            archive.mkdir(parents=True)
            (archive / "old.json").write_text(json.dumps({
                "schema_version": 0,
                "label": marker,
                "repo": marker,
                "checked_utc": "2026-10-25T18:00:00Z",
                "findings": [{
                    "path": "sample.txt", "line": 4, "rule": "fixture-rule", "severity": "block",
                    "material_name": marker, "info": marker, "field": marker, "priority": marker,
                    "review": {"reason": marker}, "matched_value": marker,
                }],
            }), encoding="utf-8")
            guard = SimpleNamespace(STATE=state, CONFIG={})
            result = manage.report("all", None, guard)
            environment = dict(os.environ)
            environment["LEAKGUARD_CONFIG"] = ""
            environment["LEAKGUARD_STATE_DIR"] = str(state)
            source = str(Path(__file__).resolve().parents[1] / "src")
            prior = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = source if not prior else source + os.pathsep + prior
            process = subprocess.run(
                [sys.executable, "-m", "leakguard_core.manage", "report", "all", "--legacy-archive"],
                cwd=directory, env=environment, capture_output=True, text=True, timeout=10, check=False,
            )
        serialized = json.dumps(result, ensure_ascii=True)
        self.assertNotIn(marker, serialized)
        self.assertIn("coverage", result)
        self.assertIn("unknown", result["coverage"])
        self.assertEqual(set(result["findings"][0]), {
            "path", "line", "family", "rules", "profile", "priority", "first_reported", "last_reported",
        })
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stderr, "")
        self.assertNotIn(marker, process.stdout)
        self.assertIn('"coverage"', process.stdout)

    def test_manage_unexpected_errors_return_fixed_stderr_without_traceback(self):
        marker = "PRIVATE-MANAGE-ERROR"
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with patch("leakguard_core.manage._main", side_effect=RuntimeError(marker)):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = manage.main(["report", "all", "--legacy-archive"])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "LeakGuard: manage-failed\n")
        self.assertNotIn(marker, stderr.getvalue())

    def test_manage_subprocess_sanitizes_legacy_setup_error(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-test-manage-error-") as directory:
            bad_config = Path(directory) / "bad.json"
            bad_config.write_text("PRIVATE-CONFIG-MARKER", encoding="utf-8")
            environment = dict(os.environ)
            environment["LEAKGUARD_CONFIG"] = str(bad_config)
            environment["LEAKGUARD_STATE_DIR"] = str(Path(directory) / "state")
            source = str(Path(__file__).resolve().parents[1] / "src")
            prior = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = source if not prior else source + os.pathsep + prior
            result = subprocess.run(
                [sys.executable, "-m", "leakguard_core.manage", "report", "all", "--legacy-archive"],
                cwd=directory, env=environment, capture_output=True, text=True, timeout=10, check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "LeakGuard: manage-failed\n")
        self.assertNotIn("PRIVATE-CONFIG-MARKER", result.stdout + result.stderr)

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
        with self.assertRaises(ValueError):
            replace(report, coverage=CoverageSummary(True, True, 0, pending_files=1))
        with self.assertRaises(ValueError):
            replace(report, issues=(CoverageIssue(ErrorCode.DECODE_FAILED, required=True),))
        with self.assertRaises(ValueError):
            replace(report, results=(replace(result, coverage=CoverageState.INCOMPLETE),))
        with self.assertRaises(ValueError):
            replace(
                report,
                results=(replace(result, identity=replace(result.identity, policy_id="other-policy")),),
            )

    def test_legacy_model_counts_are_stable_and_cli_defaults_are_bounded(self):
        parser = _parser()
        scan = parser.parse_args(["scan", "sample.txt"])
        audit = parser.parse_args(["audit", "workspace"])
        drain = parser.parse_args(["drain"])
        self.assertEqual((scan.budget_seconds, scan.max_files, scan.use_cache), (120, 1000, True))
        self.assertEqual((audit.budget_seconds, audit.max_files, audit.use_cache), (600, 3000, True))
        self.assertEqual((drain.budget_seconds, drain.max_files, drain.use_cache), (45, 150, False))

    def test_scan_limits_keep_a_minimum_report_envelope_budget(self):
        self.assertEqual(ScanLimits(10, 1, max_report_bytes=2_048).max_report_bytes, 2_048)
        with self.assertRaises(ValueError):
            ScanLimits(10, 1, max_report_bytes=2_047)

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
