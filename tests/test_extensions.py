"""Adversarial synthetic corpus for contextual rules, plugins and coverage."""
import json
import pathlib
import tempfile
import unittest
import os
import subprocess
from unittest.mock import patch

from leakguard_core import engine as guard, plugins
from test_integration import SYNTHETIC


class ExtensionTests(unittest.TestCase):
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
            self.assertEqual(len(report['coverage_issues']), 1)
            self.assertGreater(report['findings_count'], 0)

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
        class Extension:
            def extract(self, data, path):
                return [('synthetic-part', 'SYNTHETIC_REVIEW_MARKER\n')]
            def detect(self, text, path, part):
                yield plugins.Finding('example-marker', 1, 'review')
        with patch.object(guard, 'PLUGINS', [Extension()]):
            found, status = guard.scan_blob(b'\x00binary', 'input.bin')
        self.assertEqual(status, 'scanned')
        self.assertTrue(any(f['rule'] == 'example-marker' and f['part'] == 'synthetic-part' for f in found))
        self.assertNotIn('SYNTHETIC_REVIEW_MARKER', json.dumps(found))

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
            config = root / 'config.json'; config.write_text(json.dumps({'plugins': [{'module': 'extension_fixture'}]}))
            hooks.install_at(repo / '.git/hooks')
            environment = dict(os.environ, LEAKGUARD_CONFIG=str(config))
            environment['PYTHONPATH'] = str(root) + os.pathsep + environment.get('PYTHONPATH', '')
            result = subprocess.run(['git', 'commit', '-m', 'test: reject synthetic plugin marker'], cwd=repo, env=environment, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'fixture-marker', result.stderr)
            self.assertNotIn(b'SYNTHETIC_REVIEW_MARKER', result.stderr + result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
