"""Contract checks for the public redacted result model."""
from dataclasses import fields
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
import zipfile
from contextlib import redirect_stdout
from unittest.mock import patch

from leakguard_core import models
from leakguard_core import _supervision
from leakguard_core.extraction import ExtractionLimits, extract
from leakguard_core.conformance import (
    ConformanceCode, ConformanceIssue, ConformanceKind, ConformanceReport,
    DetectorCase, ExpectedFinding, ExpectedPart, ExtractorCase, check_detector,
    check_extractor, main as conformance_main, _CliSetupError, _exit_status,
    _read_json,
)


class PublicModelConformanceTests(unittest.TestCase):
    def make_report(self):
        started = datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc)
        source = models.SourceRef(
            kind=models.SourceKind.FILESYSTEM,
            path='odd name/é\nsettings.py',
        )
        content = models.ContentIdentity('sha256', 'a' * 64, 32)
        identity = models.RuntimeIdentity(
            policy_id='policy-fixture',
            runtime_id='runtime-fixture',
            context_id='context-fixture',
            cache_eligible=True,
        )
        finding = models.FindingRecord(
            id='a' * 64,
            source=source,
            part_id='text',
            start_line=2,
            end_line=4,
            rule='literal-client-secret',
            detector_id='gitleaks',
            detector_severity=models.DetectorSeverity.REVIEW,
            severity=models.FindingSeverity.BLOCK,
            classification=models.FindingClassification.HEURISTIC,
            proof_id=None,
        )
        scanned = models.ScanResult(
            source=source,
            content=content,
            identity=identity,
            outcome=models.ScanOutcome.SCANNED,
            coverage=models.CoverageState.COMPLETE,
            findings=(finding,),
            issues=(),
            observed_at=started + timedelta(seconds=1),
            last_executed_at=started + timedelta(seconds=1),
        )
        omitted_source = models.SourceRef(
            kind=models.SourceKind.BYTES,
            path='fixture.bin',
        )
        omission = models.CoverageIssue(
            code=models.ErrorCode.POLICY_OMISSION,
            source=omitted_source,
            required=False,
            omission_id='unsupported-binary',
        )
        reused_source = models.SourceRef(kind=models.SourceKind.BYTES, path='replayed.txt')
        reused = models.ScanResult(
            source=reused_source,
            content=models.ContentIdentity('sha256', 'b' * 64, 4),
            identity=identity,
            outcome=models.ScanOutcome.REUSED,
            coverage=models.CoverageState.COMPLETE,
            findings=(),
            issues=(),
            observed_at=started + timedelta(seconds=2),
            last_executed_at=started + timedelta(seconds=1),
            last_verified_at=started + timedelta(seconds=2),
            reused_from='prior-scan-fixture',
        )
        omitted = models.ScanResult(
            source=omitted_source,
            content=None,
            identity=identity,
            outcome=models.ScanOutcome.SKIPPED,
            coverage=models.CoverageState.OMITTED,
            findings=(),
            issues=(omission,),
            observed_at=started + timedelta(seconds=2),
        )
        report = models.ScanReport(
            schema_version=1,
            run_id='run-fixture',
            started_at=started,
            finished_at=started + timedelta(seconds=3),
            policy_id='policy-fixture',
            results=(scanned, reused, omitted),
            coverage=models.CoverageSummary(
                enumeration_complete=True,
                required_complete=True,
                omission_count=1,
                pending_files=0,
                pending_directories=0,
                cycle_id='cycle-fixture',
            ),
            decision=models.PolicyDecision(
                verdict=models.DecisionVerdict.ALLOW_WITH_OMISSIONS,
                reason_codes=(models.ErrorCode.POLICY_OMISSION,),
                policy_id='policy-fixture',
            ),
        )
        return report, finding

    def test_serializer_is_fixed_redacted_and_preserves_source_identity(self):
        report, finding = self.make_report()
        payload = report.to_dict()
        serialized = report.to_json()
        decoded = json.loads(serialized)

        self.assertEqual(set(payload), {
            'schema_version', 'run_id', 'started_at', 'finished_at', 'policy_id',
            'results', 'coverage', 'decision', 'counts', 'issues',
        })
        self.assertEqual(decoded['results'][0]['source']['path'], 'odd name/é\nsettings.py')
        self.assertEqual(decoded['results'][0]['findings'][0]['start_line'], 2)
        self.assertEqual(decoded['results'][0]['findings'][0]['end_line'], 4)
        self.assertEqual(set(decoded['results'][0]['findings'][0]), {
            'id', 'source', 'part_id', 'start_line', 'end_line', 'rule',
            'detector_id', 'detector_severity', 'severity', 'classification', 'proof_id',
        })
        self.assertEqual(decoded['results'][0]['outcome'], 'scanned')
        self.assertEqual(decoded['results'][1]['outcome'], 'reused')
        self.assertEqual(decoded['results'][2]['issues'][0]['code'], 'policy-omission')
        self.assertEqual(decoded['results'][0]['findings'][0]['severity'], 'block')
        self.assertNotIn('Secret', serialized)
        self.assertNotIn('Match', serialized)
        self.assertNotIn('raw_value_fixture', serialized)
        self.assertEqual(serialized, report.to_json())

        self.assertEqual([item.name for item in fields(finding)], [
            'id', 'source', 'part_id', 'start_line', 'end_line', 'rule',
            'detector_id', 'detector_severity', 'severity', 'classification', 'proof_id',
        ])
        self.assertNotIn('value', finding.__slots__)

    def test_counts_are_derived_from_result_outcomes_and_findings(self):
        report, _ = self.make_report()
        counts = report.counts

        self.assertEqual(counts.results, 3)
        self.assertEqual((counts.scanned, counts.reused, counts.skipped), (1, 1, 1))
        self.assertEqual(counts.findings, 1)
        self.assertEqual(counts.block_findings, 1)
        self.assertEqual(counts.omitted_results, 1)
        self.assertEqual(counts.issues, 1)

    def test_result_contract_rejects_open_severity_and_invalid_ranges(self):
        _, finding = self.make_report()
        with self.assertRaises(TypeError):
            models.FindingRecord(
                id=finding.id, source=finding.source, part_id=finding.part_id,
                start_line=finding.start_line, end_line=finding.end_line, rule=finding.rule,
                detector_id=finding.detector_id, detector_severity='review',
                severity=models.FindingSeverity.BLOCK,
                classification=models.FindingClassification.HEURISTIC,
            )
        with self.assertRaises(ValueError):
            models.FindingRecord(
                id=finding.id, source=finding.source, part_id=finding.part_id,
                start_line=4, end_line=3, rule=finding.rule, detector_id=finding.detector_id,
                detector_severity=models.DetectorSeverity.REVIEW,
                severity=models.FindingSeverity.BLOCK,
                classification=models.FindingClassification.HEURISTIC,
            )
        with self.assertRaises(TypeError):
            models.FindingRecord(
                id=finding.id, source=finding.source, part_id=finding.part_id,
                start_line=1, end_line=1, rule=finding.rule, detector_id=finding.detector_id,
                detector_severity=models.DetectorSeverity.REVIEW,
                severity=models.FindingSeverity.BLOCK,
                classification=models.FindingClassification.HEURISTIC,
                raw_value_fixture='SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG',
            )


class ExtensionConformanceModelTests(unittest.TestCase):
    def run_detector_fixture(self, source, cases, *, timeout=None):
        with tempfile.TemporaryDirectory(prefix='leakguard-conformance-') as temporary:
            module_path = pathlib.Path(temporary) / 'fixture_detector.py'
            module_path.write_text(source, encoding='utf-8')
            sys.path.insert(0, temporary)
            try:
                if timeout is None:
                    return check_detector('fixture_detector', {}, cases)
                with patch('leakguard_core.conformance._CONFORMANCE_TIMEOUT_SECONDS', timeout):
                    return check_detector('fixture_detector', {}, cases)
            finally:
                sys.path.remove(temporary)

    def test_expected_extractor_part_uses_utf8_digest_and_logical_line_count(self):
        expected = ExpectedPart.from_text('office-word-1', 'one\ntwo\n')
        self.assertEqual(expected.text_sha256, hashlib.sha256('one\ntwo\n'.encode()).hexdigest())
        self.assertEqual(expected.line_count, 2)

    def test_case_ids_findings_and_issue_codes_are_closed(self):
        with self.assertRaises(ValueError):
            DetectorCase('not safe/id', 'SyntheticOnly~Content', 'sample.txt', 'text', 'text')
        with self.assertRaises(ValueError):
            ExpectedFinding('rules-from-input', True, 1, 'block')
        with self.assertRaises(ValueError):
            ExtractorCase('sample', b'fixture', 'sample.docx', 'office-word', 'extracted',
                          expected_issues=('SyntheticOnly~InputLabel',))

    def test_case_repr_hides_detector_text_and_extractor_bytes(self):
        marker = 'SyntheticOnly~repr7Q3v'
        detector = DetectorCase('private-case', marker, 'fixture.txt', 'text', 'text')
        extractor = ExtractorCase('private-case', marker.encode(), 'fixture.bin', 'fixture-format', 'unsupported')
        self.assertNotIn(marker, repr(detector))
        self.assertNotIn(marker, repr(extractor))

    def run_extractor_fixture(self, source, cases):
        with tempfile.TemporaryDirectory(prefix='leakguard-conformance-extractor-') as temporary:
            module_path = pathlib.Path(temporary) / 'fixture_extractor.py'
            module_path.write_text(source, encoding='utf-8')
            sys.path.insert(0, temporary)
            try:
                return check_extractor('fixture_extractor', {}, cases)
            finally:
                sys.path.remove(temporary)

    def test_v2_extractor_matches_core_part_id_digest_and_lines(self):
        source = '''from leakguard_core.extraction import Extraction, ExtractedPart\nfrom leakguard_core.plugins import PluginManifest\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="fixture-note", implementation_version="1", kind="extractor", formats=("fixture-format",), part_kinds=("note",))\nclass Extractor:\n def extract(self,data,context): return Extraction("extracted", (ExtractedPart("note",1,data.decode("utf-8")),))\ndef create_plugin(options): return Extractor()\n'''
        text = 'first\nsecond\n'
        case = ExtractorCase(
            'note-present', b'first\nsecond\n', 'case.note', 'fixture-format', 'extracted',
            (ExpectedPart.from_text('note-1', text),),
        )
        report = self.run_extractor_fixture(source, (case,))
        self.assertTrue(report.passed, report.to_json())
        self.assertEqual((report.passed_cases, report.failed_cases), (1, 0))

    def test_extractor_rejects_foreign_duplicate_parts_and_part_limit(self):
        fixtures = (
            ('foreign', 'Extraction("extracted", (ExtractedPart("foreign",1,"SyntheticOnly~ForeignPart"),))'),
            ('duplicate', 'Extraction("extracted", (ExtractedPart("note",1,"one"), ExtractedPart("note",1,"SyntheticOnly~DuplicatePart")))'),
            ('too-many', 'Extraction("extracted", tuple(ExtractedPart("note",i,"x") for i in range(1,1002)))'),
        )
        for case_id, expression in fixtures:
            with self.subTest(case_id=case_id):
                source = f'''from leakguard_core.extraction import Extraction, ExtractedPart\nfrom leakguard_core.plugins import PluginManifest\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="fixture-note", implementation_version="1", kind="extractor", formats=("fixture-format",), part_kinds=("note",))\nclass Extractor:\n def extract(self,data,context): return {expression}\ndef create_plugin(options): return Extractor()\n'''
                case = ExtractorCase(case_id, b'input', 'case.note', 'fixture-format', 'extracted')
                report = self.run_extractor_fixture(source, (case,))
                self.assertFalse(report.passed)
                self.assertEqual(report.failed_cases, 1)
                self.assertNotIn('SyntheticOnly~', report.to_json())

    def test_extractor_exception_and_nontext_dispositions_have_closed_results(self):
        source = '''from leakguard_core.extraction import Extraction\nfrom leakguard_core.plugins import PluginManifest\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="fixture-note", implementation_version="1", kind="extractor", formats=("fixture-format",), part_kinds=("note",))\nclass Extractor:\n def extract(self,data,context):\n  if data == b"boom": raise RuntimeError("SyntheticOnly~ExtractorFailure")\n  if data == b"encrypted": return Extraction("encrypted", ())\n  return Extraction("unsupported", ())\ndef create_plugin(options): return Extractor()\n'''
        cases = (
            ExtractorCase('unsupported', b'unknown', 'case.note', 'fixture-format', 'unsupported',
                          expected_issues=('unsupported-format',)),
            ExtractorCase('encrypted', b'encrypted', 'case.note', 'fixture-format', 'encrypted',
                          expected_issues=('encrypted',)),
            ExtractorCase('exception', b'boom', 'case.note', 'fixture-format', 'extracted'),
        )
        report = self.run_extractor_fixture(source, cases)
        self.assertEqual((report.passed_cases, report.failed_cases), (2, 1))
        self.assertEqual(report.issues[-1].code, ConformanceCode.COMPONENT_INVALID)
        self.assertNotIn('SyntheticOnly~ExtractorFailure', report.to_json())

    def test_cli_emits_one_redacted_json_and_uses_three_exit_states(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-conformance-cli-') as temporary:
            root = pathlib.Path(temporary)
            (root / 'fixture_cli.py').write_text(
                'from leakguard_core.plugins import Finding\nAPI_VERSION=1\n'
                'class Detector:\n def detect(self,text,path,part): return []\n'
                'def create_plugin(options): return Detector()\n', encoding='utf-8')
            marker = 'SyntheticOnly~CLIInput7f3A'
            cases_path = root / 'cases.json'
            cases_path.write_text(json.dumps({'cases': [{
                'case_id': 'cli-case', 'text': marker, 'logical_path': 'fixture.txt',
                'format_id': 'text', 'part_id': 'text', 'expected_findings': [],
            }]}), encoding='utf-8')
            sys.path.insert(0, temporary)
            try:
                output = io.StringIO()
                with redirect_stdout(output):
                    status = conformance_main(['--kind', 'detector', '--module', 'fixture_cli', '--cases', str(cases_path)])
                line = output.getvalue()
                self.assertEqual(status, 0)
                self.assertEqual(len(line.splitlines()), 1)
                self.assertTrue(json.loads(line)['passed'])
                self.assertNotIn(marker, line)

                mismatch = root / 'mismatch.json'
                mismatch.write_text(json.dumps({'cases': [{
                    'case_id': 'expected-match', 'text': marker, 'logical_path': 'fixture.txt',
                    'format_id': 'text', 'part_id': 'text',
                    'expected_findings': [{'rule': 'fixture-rule', 'start_line': 1, 'end_line': 1, 'severity': 'review'}],
                }]}), encoding='utf-8')
                output = io.StringIO()
                with redirect_stdout(output):
                    status = conformance_main(['--kind', 'detector', '--module', 'fixture_cli', '--cases', str(mismatch)])
                self.assertEqual(status, 1)
                self.assertEqual(len(output.getvalue().splitlines()), 1)
                self.assertFalse(json.loads(output.getvalue())['passed'])

                output = io.StringIO()
                with redirect_stdout(output):
                    status = conformance_main(['--kind', 'detector', '--module', 'fixture_cli'])
                self.assertEqual(status, 2)
                self.assertEqual(len(output.getvalue().splitlines()), 1)
                self.assertEqual(json.loads(output.getvalue())['issues'][0]['code'], 'setup-failed')
            finally:
                sys.path.remove(temporary)

    def test_cli_help_is_successful_static_output_without_a_report_object(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = conformance_main(["--help"])
        self.assertEqual(status, 0)
        self.assertIn("usage:", output.getvalue())
        self.assertNotIn('"component_id"', output.getvalue())

    def test_case_file_reader_is_stream_bounded(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-conformance-size-") as temporary:
            path = pathlib.Path(temporary) / "cases.json"
            path.write_bytes(b'{"ok":true}')
            self.assertEqual(_read_json(str(path), 11), {"ok": True})
            with patch.object(pathlib.Path, "read_bytes", side_effect=AssertionError("unbounded read")):
                with self.assertRaises(_CliSetupError):
                    _read_json(str(path), 5)

    def test_component_contract_failure_is_one_while_dependency_absence_is_two(self):
        from leakguard_core import plugins
        case = DetectorCase("component-case", "fixture", "fixture.txt", "text", "text")
        reports = (
            (plugins.PluginError("plugin-invalid"), 1, ConformanceCode.COMPONENT_INVALID),
            (plugins.PluginError("dependency-unavailable"), 2, ConformanceCode.DEPENDENCY_UNAVAILABLE),
        )
        with tempfile.TemporaryDirectory(prefix="leakguard-conformance-exit-") as temporary:
            root = pathlib.Path(temporary)
            cases = root / "cases.json"
            cases.write_text(json.dumps({"cases": [{
                "case_id": "component-case", "text": "fixture",
                "logical_path": "fixture.txt", "format_id": "text", "part_id": "text",
            }]}), encoding="utf-8")
            for error, expected_status, expected_code in reports:
                with self.subTest(code=error.code), patch.object(plugins, "load", side_effect=error):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        status = conformance_main([
                            "--kind", "detector", "--module", "fixture_plugin",
                            "--cases", str(cases),
                        ])
                    self.assertEqual(status, expected_status)
                    decoded = json.loads(output.getvalue())
                    self.assertEqual(decoded["issues"][0]["code"], expected_code.value)

        missing_api = ConformanceReport(
            "fixture-extractor", ConformanceKind.EXTRACTOR,
            total_cases=1, passed_cases=0, failed_cases=1, skipped_cases=0,
            issues=(ConformanceIssue("extractor-api", ConformanceCode.COMPONENT_INVALID),),
        )
        self.assertEqual(_exit_status(missing_api), 1)

    def test_conformance_report_serializer_is_allowlisted_and_redacted(self):
        report = ConformanceReport(
            component_id='fixture-detector', kind=ConformanceKind.DETECTOR,
            total_cases=2, passed_cases=1, failed_cases=1, skipped_cases=0,
            issues=(ConformanceIssue('case-match', ConformanceCode.CASE_MISMATCH, 'case-credential'),),
        )
        decoded = json.loads(report.to_json())
        self.assertEqual(set(decoded), {
            'component_id', 'kind', 'total_cases', 'passed_cases', 'failed_cases',
            'skipped_cases', 'passed', 'issues',
        })
        self.assertEqual(decoded['issues'], [{
            'check_id': 'case-match', 'code': 'case-mismatch', 'case_id': 'case-credential',
        }])
        self.assertFalse(decoded['passed'])
        self.assertNotIn('SyntheticOnly~', report.to_json())
        self.assertNotIn('options', report.to_json())

    def test_report_requires_consistent_counts_and_static_identifiers(self):
        with self.assertRaises(ValueError):
            ConformanceReport('fixture', ConformanceKind.EXTRACTOR, 2, 1, 0, 0)
        with self.assertRaises(ValueError):
            ConformanceIssue('invalid check', ConformanceCode.CASE_INVALID)

    def test_v1_detector_example_passes_through_supervised_adapter(self):
        source = pathlib.Path(__file__).parent / 'fixtures'
        sys.path.insert(0, str(source))
        try:
            report = check_detector('example_plugin', {}, (
                DetectorCase('marker-present', 'SYNTHETIC_REVIEW_MARKER', 'sample.txt', 'text', 'text',
                             (ExpectedFinding('example-review-marker', 1, 1, 'review'),)),
                DetectorCase('marker-absent', 'ordinary fixture', 'sample.txt', 'text', 'text'),
            ))
        finally:
            sys.path.remove(str(source))
        self.assertEqual((report.total_cases, report.passed_cases, report.failed_cases), (2, 2, 0))
        self.assertTrue(report.passed)

    def test_detector_invalid_output_and_plugin_exception_are_sanitized(self):
        invalid = '''from leakguard_core.plugins import Finding\nAPI_VERSION=1\nclass Detector:\n def detect(self,text,path,part): return [Finding("undeclared-rule",99,"review")]\ndef create_plugin(options): return Detector()\n'''
        case = DetectorCase('bad-output', 'SyntheticOnly~CaseText7x2', 'sample.txt', 'text', 'text')
        report = self.run_detector_fixture(invalid, (case,))
        self.assertEqual(report.issues[0].code, ConformanceCode.DETECTOR_OUTPUT_INVALID)
        self.assertNotIn('SyntheticOnly~CaseText7x2', report.to_json())

        crashed = '''API_VERSION=1\nclass Detector:\n def detect(self,text,path,part): raise RuntimeError("SyntheticOnly~PluginException5c8")\ndef create_plugin(options): return Detector()\n'''
        report = self.run_detector_fixture(crashed, (case,))
        self.assertEqual(report.issues[0].code, ConformanceCode.COMPONENT_INVALID)
        self.assertNotIn('SyntheticOnly~PluginException5c8', report.to_json())

    def test_detector_timeout_is_a_fixed_issue_and_worker_finishes(self):
        source = '''import time\nAPI_VERSION=1\nclass Detector:\n def detect(self,text,path,part): time.sleep(30); return []\ndef create_plugin(options): return Detector()\n'''
        case = DetectorCase('hangs', 'ordinary fixture', 'sample.txt', 'text', 'text')
        started = time.monotonic()
        report = self.run_detector_fixture(source, (case,), timeout=0.15)
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(report.issues[0].code, ConformanceCode.PLUGIN_TIMEOUT)

    def test_v2_detector_cannot_downgrade_declared_block_rule_or_add_foreign_rule(self):
        source = '''from leakguard_core.plugins import Finding, PluginManifest, RuleSpec\nAPI_VERSION=2\nMANIFEST=PluginManifest(id="fixture-v2-detector", implementation_version="1.0", kind="detector", rules=(RuleSpec("declared-block", "block"),))\nclass Detector:\n def detect(self,text,context): return [Finding("declared-block",1,"review"), Finding("foreign-rule",1,"review")]\ndef create_plugin(options): return Detector()\n'''
        case = DetectorCase('attempted-waiver', 'sample', 'sample.txt', 'text', 'text',
                            (ExpectedFinding('declared-block', 1, 1, 'block'),))
        report = self.run_detector_fixture(source, (case,))
        self.assertEqual(report.component_id, 'fixture-v2-detector')
        self.assertEqual(report.issues[0].code, ConformanceCode.DETECTOR_OUTPUT_INVALID)

class SupervisionConformanceTests(unittest.TestCase):
    def test_worker_rejects_invalid_input_with_closed_code(self):
        for argv, data, kwargs in [
            ([], b'', {'timeout': 1}),
            ([sys.executable], 'not-bytes', {'timeout': 1}),
            ([sys.executable], b'', {'timeout': 1, 'max_output_bytes': 0}),
            ([sys.executable], b'large', {'timeout': 1, 'max_input_bytes': 2}),
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(_supervision.WorkerError) as caught:
                    _supervision.run_worker(argv, data, **kwargs)
                self.assertEqual(caught.exception.code, 'worker-input-invalid')
                self.assertEqual(str(caught.exception), caught.exception.code)

    def test_worker_output_limit_does_not_expose_stderr_or_partial_output(self):
        marker = 'SyntheticOnly~WorkerStderr7z9Q'
        code = "import sys; sys.stderr.write(%r); sys.stdout.write('x' * 50000)" % marker
        with self.assertRaises(_supervision.WorkerError) as caught:
            _supervision.run_worker(
                [sys.executable, '-c', code], b'', timeout=5,
                max_output_bytes=128, memory_bytes=512 * 1024 * 1024,
            )
        self.assertEqual(caught.exception.code, 'worker-output-limit')
        self.assertNotIn(marker, str(caught.exception))

    def test_worker_timeout_is_sanitized(self):
        marker = 'SyntheticOnly~WorkerTimeout4b2K'
        code = "import sys,time; sys.stderr.write(%r); time.sleep(30)" % marker
        started = time.monotonic()
        with self.assertRaises(_supervision.WorkerError) as caught:
            _supervision.run_worker(
                [sys.executable, '-c', code], b'', timeout=0.15,
                memory_bytes=512 * 1024 * 1024,
            )
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(caught.exception.code, 'worker-timeout')
        self.assertNotIn(marker, str(caught.exception))

    @unittest.skipUnless(os.name == 'posix', 'POSIX process groups provide descendant cleanup')
    def test_worker_reaps_descendant_even_after_parent_exits_successfully(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-worker-') as temporary:
            marker = pathlib.Path(temporary) / 'child-survived'
            child = "import pathlib,time; time.sleep(0.6); pathlib.Path(%r).write_text('alive')" % str(marker)
            parent = "import subprocess,sys; subprocess.Popen([sys.executable,'-c',%r]); print('done')" % child
            result = _supervision.run_worker(
                [sys.executable, '-c', parent], b'', timeout=4,
                memory_bytes=512 * 1024 * 1024,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'done\n')
            time.sleep(0.8)
            self.assertFalse(marker.exists(), 'worker descendant outlived the completed worker')


class ExtractionConformanceTests(unittest.TestCase):
    def make_docx(self, members):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for name, value in members:
                archive.writestr(name, value)
        return buffer.getvalue()

    def test_utf16_text_and_unusual_logical_path_keep_stable_text_part(self):
        data = b'\xff\xfe' + 'first\nsecond'.encode('utf-16-le')
        result = extract(data, 'spaces/é\nodd.name')
        self.assertEqual(result.disposition, 'extracted')
        self.assertEqual(result.format_id, 'text')
        self.assertEqual([(part.part_id, part.format_id, part.text) for part in result.parts],
                         [('text', 'text', 'first\nsecond')])

    def test_office_parts_use_static_ids_independent_of_archive_names(self):
        data = self.make_docx([
            ('word/document.xml', '<document><p>body text</p></document>'),
            ('word/comments1.xml', '<comments><comment>comment text</comment></comments>'),
        ])
        result = extract(data, 'renamed-document.docx', timeout=5)
        self.assertEqual(result.disposition, 'extracted')
        self.assertEqual([part.part_id for part in result.parts], ['office-word-1', 'office-word-2'])
        self.assertEqual([part.text for part in result.parts], ['body text', 'comment text'])

    def test_malformed_docx_is_an_explicit_error(self):
        data = self.make_docx([('[Content_Types].xml', '<Types/>')])
        result = extract(data, 'incomplete.docx', timeout=5)
        self.assertEqual(result.disposition, 'error')
        self.assertEqual(result.issues, ('extract-failed',))
        self.assertEqual(result.parts, ())

    def test_unknown_binary_is_explicitly_unsupported_and_limits_are_issues(self):
        unsupported = extract(b'\x00\x01opaque', 'unlabelled.bin')
        self.assertEqual((unsupported.disposition, unsupported.issues), ('unsupported', ('unsupported-format',)))

        too_large = extract(b'abcdef', 'large.txt', limits=ExtractionLimits(max_file_bytes=4))
        self.assertEqual((too_large.disposition, too_large.issues), ('error', ('input-limit',)))

        too_much_text = extract('abcdef'.encode(), 'text.txt', limits=ExtractionLimits(max_text_bytes=4))
        self.assertEqual((too_much_text.disposition, too_much_text.issues), ('error', ('extract-output-limit',)))

    def test_duplicate_office_members_and_archive_part_limit_fail_closed(self):
        buffer = io.BytesIO()
        with self.assertWarns(UserWarning):
            with zipfile.ZipFile(buffer, 'w') as archive:
                archive.writestr('word/document.xml', '<document><p>one</p></document>')
                archive.writestr('word/document.xml', '<document><p>two</p></document>')
        duplicate = extract(buffer.getvalue(), 'dup.docx', timeout=5)
        self.assertEqual(duplicate.disposition, 'error')
        self.assertEqual(duplicate.issues, ('extract-failed',))

        multi = self.make_docx([
            ('word/document.xml', '<document><p>body</p></document>'),
            ('word/comments1.xml', '<comments><comment>comment</comment></comments>'),
        ])
        limited = extract(multi, 'many.docx', limits=ExtractionLimits(max_parts=1), timeout=5)
        self.assertEqual(limited.disposition, 'error')
        self.assertEqual(limited.issues, ('extract-part-limit',))
        self.assertEqual([part.part_id for part in limited.parts], ['office-word-1'])

    def test_all_worker_and_extractor_failure_receipts_are_closed_strings(self):
        self.assertTrue(
            {
                'extract-failed', 'extract-timeout', 'extract-crashed', 'extract-output-limit',
                'extract-part-limit', 'resource-bound-unavailable',
            } <= {item.value for item in models.ErrorCode},
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
