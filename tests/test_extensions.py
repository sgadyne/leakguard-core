"""Adversarial synthetic corpus for contextual rules, plugins and coverage."""
import json
import pathlib
import tempfile
import unittest
import os
import subprocess
import sys
from unittest.mock import patch

from leakguard_core import engine as guard, plugins, extraction, models
from test_integration import SYNTHETIC


def _darwin_test_worker_policy():
    """Select the alpha watchdog only for native Darwin worker tests."""
    return "supervised-alpha" if sys.platform == "darwin" else "strict"


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        # The deprecated engine adapter reuses its module config, so select the
        # native watchdog policy explicitly for every legacy scan in this class.
        policy_config = patch.dict(
            guard.CONFIG, {'worker_policy': _darwin_test_worker_policy()})
        policy_config.start()
        self.addCleanup(policy_config.stop)

    def test_explicit_credential_fields_across_text_formats(self):
        cases = [
            ('config.json', json.dumps({'client_secret': SYNTHETIC})),
            ('settings.py', 'client_secret = "' + SYNTHETIC + '"'),
            ('settings.cs', 'options.ClientSecret = "' + SYNTHETIC + '";'),
            ('settings.yaml', 'client_secret: "' + SYNTHETIC + '"'),
            ('settings.unknown', 'password = "' + SYNTHETIC + '"'),
            ('weak.txt', 'password = "aaaaaaaab"'),  # gitleaks:allow -- synthetic weak-password fixture
            ('prefix.txt', 'password = "example-real-pass123"'),  # gitleaks:allow -- synthetic prefix fixture
        ]
        for path, text in cases:
            with self.subTest(path=path):
                found, _ = guard.scan_blob(text.encode(), path)
                self.assertTrue(any(f['severity'] == 'block' for f in found))

    def test_display_labels_and_plain_secret_variable_do_not_trigger_custom_rule(self):
        cases = ["'xml-password': 'Literal XML configuration password'", "secret = 'NeverDisplayThisPrivateFixture'", 'password = "${PASSWORD}"', 'client_secret = "placeholder-value"']
        for text in cases:
            found, _ = guard.scan_blob(text.encode(), 'labels.py')
            self.assertFalse(any(f['rule'] in {'literal-client-secret', 'literal-password', 'xml-password'} for f in found), text)

    def test_hash_named_field_does_not_hide_credential(self):
        text = json.dumps({'sha256': SYNTHETIC, 'client_secret': SYNTHETIC}, indent=2)
        found, _ = guard.scan_blob(text.encode(), 'release.json')
        self.assertTrue(any(f['rule'] == 'literal-client-secret' for f in found))

    def test_unknown_extension_is_scanned_and_binary_is_accounted(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-test-') as folder:
            root = pathlib.Path(folder)
            (root / 'data.unusual').write_text('client_secret = "' + SYNTHETIC + '"')
            (root / 'binary.bin').write_bytes(b'\x00\xff\x01')
            state = root / 'runtime'
            with patch.object(guard, 'STATE', state):
                report = guard.scan_paths([root], 20, 20, False)
            self.assertEqual(report['file_counts'].get('scanned'), 1)
            self.assertEqual(report['file_counts'].get('skipped-binary-or-no-text'), 1)
            issue_codes = {issue['status'] for issue in report['coverage_issues']}
            self.assertTrue(any(code.endswith('unsupported-format') for code in issue_codes))
            self.assertTrue(any(code.endswith('policy-omission') for code in issue_codes))
            self.assertGreater(report['findings_count'], 0)

    def test_late_nul_is_explicit_binary_omission_and_required_mode_is_incomplete(self):
        # Place the NUL exactly after the former sniff prefix so the entire
        # admitted buffer must participate in binary classification.
        payload = b'A' * 8192 + b'\x00'
        extracted = extraction.extract(payload, 'opaque-unusual.bin')
        self.assertEqual((extracted.format_id, extracted.disposition, extracted.issues),
                         ('binary', 'unsupported', ('unsupported-format',)))

        with tempfile.TemporaryDirectory(prefix='leakguard-late-nul-') as folder:
            root = pathlib.Path(folder)
            state = root / 'state'
            source = models.BytesInput(payload, 'opaque-unusual.bin')
            service = guard.ScanService({
                'gitleaks_executable': str(guard.EXE),
                'worker_policy': _darwin_test_worker_policy(),
            }, state_dir=state)
            try:
                optional = service.scan(
                    [source], policy=models.ScanPolicy.inventory(),
                    limits=models.ScanLimits(30, 1), use_cache=False,
                )
                optional_result = optional.results[0]
                optional_codes = {issue.code.value for issue in optional_result.issues}
                self.assertEqual(optional_result.coverage, models.CoverageState.OMITTED)
                self.assertIn('unsupported-format', optional_codes)
                self.assertTrue(any(issue.omission_id == 'unsupported-binary'
                                    for issue in optional_result.issues))
                self.assertEqual(optional.decision.verdict, models.DecisionVerdict.ALLOW_WITH_OMISSIONS)

                strict = service.scan(
                    [source], policy=models.ScanPolicy.inventory(required_formats=('all',)),
                    limits=models.ScanLimits(30, 1), use_cache=False,
                )
                strict_result = strict.results[0]
                self.assertEqual(strict_result.coverage, models.CoverageState.INCOMPLETE)
                self.assertTrue(any(issue.code is models.ErrorCode.UNSUPPORTED_FORMAT and issue.required
                                    for issue in strict_result.issues))
                self.assertFalse(strict.coverage.required_complete)
                self.assertEqual(strict.decision.verdict, models.DecisionVerdict.INCOMPLETE)
            finally:
                service.close()

    def test_plugins_cannot_return_values_or_waive_findings(self):
        class Bad:
            def detect(self, text, path, part):
                yield {'rule': 'bad', 'line': 1, 'Secret': SYNTHETIC}
        with self.assertRaises(plugins.PluginError) as error:
            list(plugins.detect([Bad()], 'input', 'file', 'text'))
        self.assertNotIn(SYNTHETIC, str(error.exception))

        class Waiver:
            def detect(self, text, path, part):
                yield plugins.Finding('bad-waiver', 1, 'info')
        with self.assertRaises(plugins.PluginError):
            list(plugins.detect([Waiver()], 'input', 'file', 'text'))

    def test_plugin_exception_text_is_not_exposed(self):
        class Bad:
            def detect(self, text, path, part):
                raise ValueError(SYNTHETIC)
        with self.assertRaises(plugins.PluginError) as error:
            list(plugins.detect([Bad()], 'input', 'file', 'text'))
        self.assertNotIn(SYNTHETIC, str(error.exception))

    def test_detector_and_extractor_extensions_run_without_source_leaks(self):
        from leakguard_core import models
        with tempfile.TemporaryDirectory(prefix='leakguard-extension-fixture-') as folder:
            root = pathlib.Path(folder)
            (root / 'fixture_extractor.py').write_text('''from leakguard_core.extraction import Extraction, ExtractedPart
from leakguard_core.plugins import PluginManifest
API_VERSION=2
MANIFEST=PluginManifest(id="fixture-note-extractor",implementation_version="1",kind="extractor",formats=("fixture-note",),part_kinds=("note",))
class Extractor:
 def extract(self,data,context): return Extraction("extracted",(ExtractedPart("note",1,"SYNTHETIC_REVIEW_MARKER\\n"),))
def create_plugin(options): return Extractor()
''', encoding='utf-8')
            (root / 'fixture_detector.py').write_text('''from leakguard_core.plugins import Finding, PluginManifest, RuleSpec
API_VERSION=2
MANIFEST=PluginManifest(id="fixture-note-detector",implementation_version="1",kind="detector",rules=(RuleSpec("example-marker","review"),),formats=("fixture-note",),part_kinds=("note",))
class Detector:
 def detect(self,text,context): return [Finding("example-marker",1,"review")] if "SYNTHETIC_REVIEW_MARKER" in text else []
def create_plugin(options): return Detector()
''', encoding='utf-8')
            sys_path = str(root)
            import sys
            sys.path.insert(0, sys_path)
            service = None
            try:
                service = guard.ScanService({
                    'gitleaks_executable': str(guard.EXE), 'gitleaks_config': str(guard.RULES),
                    'worker_policy': _darwin_test_worker_policy(),
                    'plugins': [{'module': 'fixture_extractor', 'options': {}},
                                {'module': 'fixture_detector', 'options': {}}],
                    'extractor_overrides': {'.bin': 'fixture-note-extractor'},
                })
                report = service.scan(
                    [models.BytesInput(b'fixture-input', 'input.bin')],
                    policy=models.ScanPolicy.inventory(),
                    limits=models.ScanLimits(20, 4), use_cache=False,
                )
            finally:
                if service is not None:
                    service.close()
                sys.path.remove(sys_path)
        findings = [finding for result in report.results for finding in result.findings]
        self.assertEqual(report.results[0].coverage, models.CoverageState.COMPLETE)
        self.assertTrue(any(f.rule == 'example-marker' and f.part_id == 'note-1'
                            and f.severity is models.FindingSeverity.REVIEW for f in findings))
        self.assertNotIn('SYNTHETIC_REVIEW_MARKER', report.to_json())

    def test_explicit_loading_rejects_missing_or_wrong_api(self):
        with self.assertRaises(plugins.PluginError):
            plugins.load([{'module': 'missing_extension_example'}])
        fake = type('Fake', (), {'API_VERSION': 100})
        with patch('leakguard_core.plugins.importlib.import_module', return_value=fake):
            with self.assertRaises(plugins.PluginError):
                plugins.load([{'module': 'example'}])

    def test_plugin_executes_in_staged_git_guard_without_exposing_content(self):
        from leakguard_core import hooks
        from test_integration import command
        with tempfile.TemporaryDirectory(prefix='leakguard-test-') as folder:
            root = pathlib.Path(folder); repo = root / 'repo'; repo.mkdir()
            command(repo, '-c', 'init.templateDir=', 'init', '-q').check_returncode()
            command(repo, 'config', 'user.name', 'Synthetic fixture').check_returncode()
            command(repo, 'config', 'user.email', 'fixture@example.invalid').check_returncode()
            command(repo, 'config', 'commit.gpgsign', 'false').check_returncode()
            (repo / 'data.txt').write_text('SYNTHETIC_REVIEW_MARKER')
            command(repo, 'add', 'data.txt').check_returncode()
            (root / 'extension_fixture.py').write_text("from leakguard_core.plugins import Finding\nAPI_VERSION=1\nclass Detector:\n def detect(self,text,path,part):\n  if 'SYNTHETIC_REVIEW_MARKER' in text: yield Finding('fixture-marker',1,'block')\ndef create_plugin(options): return Detector()\n")
            config = root / 'config.json'; config.write_text(json.dumps({
                'worker_policy': _darwin_test_worker_policy(),
                'plugins': [{'module': 'extension_fixture'}],
            }))
            hooks.install_at(repo / '.git/hooks')
            environment = dict(os.environ, LEAKGUARD_CONFIG=str(config))
            environment['PYTHONPATH'] = str(root) + os.pathsep + environment.get('PYTHONPATH', '')
            result = subprocess.run(['git', 'commit', '-m', 'test: reject synthetic plugin marker'], cwd=repo, env=environment, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'fixture-marker', result.stderr)
            self.assertNotIn(b'SYNTHETIC_REVIEW_MARKER', result.stderr + result.stdout)

    def test_missing_engine_report_fails_closed(self):
        from leakguard_core._supervision import WorkerResult
        with tempfile.TemporaryDirectory(prefix='leakguard-test-') as folder:
            empty_report = WorkerResult(stdout=b'', returncode=0)
            with patch.object(guard, 'STATE', pathlib.Path(folder)), patch('leakguard_core.backends.run_worker', return_value=empty_report):
                with self.assertRaises(RuntimeError):
                    guard.engine(['stdin'], b'input')


if __name__ == '__main__':
    unittest.main(verbosity=2)
