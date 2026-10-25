"""Offline integration checks using synthetic secrets and disposable Git repos."""
import io
import os
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from leakguard_core import hooks as install_hooks
from leakguard_core import engine as guard

SYNTHETIC = 'SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG'
HEX_FIXTURE = 'fd3862a9b10ce475d8263f9a1e70bc456a21d7fb940c8e5132f6d9a0b347ce85'


def command(repo, *args, input=None):
    return subprocess.run(['git', *args], cwd=repo, input=input, capture_output=True)


def document(secret):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('word/document.xml', '<document><p><t>client_secret = &quot;' + secret + '&quot;</t></p></document>')
    return buffer.getvalue()


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='leakguard-test-', dir=pathlib.Path(tempfile.gettempdir()))
        self.repo = pathlib.Path(self.temp.name)
        self.assertTrue(self.repo.resolve().is_relative_to(pathlib.Path(tempfile.gettempdir()).resolve()))
        command(self.repo, '-c', 'init.templateDir=', 'init', '-q').check_returncode()
        command(self.repo, 'config', 'user.name', 'LeakGuard fixture').check_returncode()
        command(self.repo, 'config', 'user.email', 'scanner@localhost').check_returncode()
        command(self.repo, 'config', 'commit.gpgsign', 'false').check_returncode()
        (self.repo / 'app.py').write_text('print("initial")\n')
        command(self.repo, 'add', 'app.py').check_returncode()
        command(self.repo, 'commit', '-q', '--no-verify', '-m', 'test: seed hook fixture').check_returncode()
        self.base = command(self.repo, 'rev-parse', 'HEAD').stdout.decode().strip()
        install_hooks.install_at(self.repo / '.git' / 'hooks')

    def tearDown(self):
        self.assertTrue(self.repo.resolve().is_relative_to(pathlib.Path(tempfile.gettempdir()).resolve()))
        self.temp.cleanup()

    def test_staged_secret_is_blocked_even_when_working_tree_is_clean(self):
        (self.repo / 'app.py').write_text('client_secret = "' + SYNTHETIC + '"\n')
        command(self.repo, 'add', 'app.py').check_returncode()
        (self.repo / 'app.py').write_text('print("clean working tree content")\n')
        result = command(self.repo, 'commit', '-m', 'test: reject staged secret')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'LeakGuard blocked', result.stderr)
        self.assertNotIn(SYNTHETIC.encode(), result.stdout + result.stderr)
        self.assertEqual(command(self.repo, 'rev-parse', 'HEAD').stdout.decode().strip(), self.base)

    @unittest.skipIf(os.name == 'nt', 'POSIX hook execute bits are not represented on Windows')
    def test_installed_pre_commit_hook_has_execute_bit(self):
        hook = self.repo / '.git' / 'hooks' / 'pre-commit'
        self.assertTrue(hook.is_file())
        self.assertTrue(hook.stat().st_mode & 0o111, 'Git would ignore a non-executable installed hook')

    def test_required_no_text_docx_does_not_pass_pre_commit(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('[Content_Types].xml', '<Types/>')
        (self.repo / 'incomplete.docx').write_bytes(buffer.getvalue())
        command(self.repo, 'add', 'incomplete.docx').check_returncode()

        result = command(self.repo, 'commit', '-m', 'test: reject incomplete document scan')

        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr)
        self.assertNotIn(SYNTHETIC.encode(), result.stdout + result.stderr)

    def test_unstaged_secret_does_not_block_a_clean_index(self):
        (self.repo / 'app.py').write_text('print("clean staged change")\n')
        command(self.repo, 'add', 'app.py').check_returncode()
        (self.repo / 'app.py').write_text('client_secret = "' + SYNTHETIC + '"\n')
        result = command(self.repo, 'commit', '-m', 'test: allow clean staged change')
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_staged_office_document_is_scanned_from_index(self):
        (self.repo / 'notes.docx').write_bytes(document(SYNTHETIC))
        command(self.repo, 'add', 'notes.docx').check_returncode()
        (self.repo / 'notes.docx').write_bytes(document('placeholder'))
        result = command(self.repo, 'commit', '-m', 'test: reject staged document secret')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'literal-client-secret', result.stderr)
        self.assertNotIn(SYNTHETIC.encode(), result.stdout + result.stderr)

    def test_integrity_manifest_can_commit_but_hex_api_key_is_blocked(self):
        import secrets
        digest = __import__('hashlib').sha256((self.repo / 'app.py').read_bytes()).hexdigest()
        manifest = self.repo / 'PROPOSED-SOURCE.json'
        manifest.write_text(json.dumps({'source_fingerprints': {'app.py': digest}}, indent=2))
        command(self.repo, 'add', manifest.name).check_returncode()
        result = command(self.repo, 'commit', '-m', 'test: allow integrity digest')
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        manifest.write_text(json.dumps({'api_key': digest}, indent=2))
        command(self.repo, 'add', manifest.name).check_returncode()
        result = command(self.repo, 'commit', '-m', 'test: reject hex credential')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'LeakGuard blocked', result.stderr)

    def test_pre_push_finds_secret_in_intermediate_commit(self):
        (self.repo / 'app.py').write_text('client_secret = "' + SYNTHETIC + '"\n')
        command(self.repo, 'add', 'app.py').check_returncode()
        command(self.repo, 'commit', '-q', '--no-verify', '-m', 'test: seed historical credential').check_returncode()
        (self.repo / 'app.py').write_text('print("removed")\n')
        command(self.repo, 'add', 'app.py').check_returncode()
        command(self.repo, 'commit', '-q', '--no-verify', '-m', 'test: remove historical credential').check_returncode()
        head = command(self.repo, 'rev-parse', 'HEAD').stdout.decode().strip()
        payload = f'refs/heads/main {head} refs/heads/main {self.base}\n'.encode()
        result = subprocess.run([sys.executable, str(guard.ROOT / 'leakguard.py'), 'hook', 'pre-push', 'origin', 'local-fixture'], input=payload, cwd=self.repo, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'LeakGuard blocked', result.stderr)
        self.assertNotIn(SYNTHETIC.encode(), result.stdout + result.stderr)

    def seed_ast_manifest(self):
        import ast
        import hashlib
        folder = self.repo / 'numerical'; folder.mkdir()
        manifest = {}
        for module, symbol in [('scope.py', 'token'), ('charts.py', '_key')]:
            source = 'def ' + symbol + '(value):\n    return str(value).upper()\n'
            (folder / module).write_text(source)
            digest = hashlib.sha256(ast.dump(ast.parse(source).body[0]).encode()).hexdigest()
            manifest[module] = {'function_ast_sha256': {symbol: digest}}
        (folder / 'origins.json').write_text(json.dumps(manifest, indent=2))
        command(self.repo, 'add', 'numerical').check_returncode()
        return folder

    def test_staged_ast_metadata_uses_index_source_and_keeps_hex_keys_blocking(self):
        folder = self.seed_ast_manifest()
        (folder / 'scope.py').write_text('print("different unstaged source")\n')
        result = command(self.repo, 'commit', '-m', 'test: allow verified AST metadata')
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertIn(b'2 verified metadata', result.stderr)
        manifest = json.loads((folder / 'origins.json').read_text())
        manifest['api_key'] = HEX_FIXTURE
        (folder / 'origins.json').write_text(json.dumps(manifest, indent=2))
        command(self.repo, 'add', 'numerical/origins.json').check_returncode()
        result = command(self.repo, 'commit', '-m', 'test: reject key inside metadata file')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'api_key', result.stderr)
        self.assertIn(b'[value redacted]', result.stderr)
        self.assertNotIn(manifest['api_key'].encode(), result.stderr + result.stdout)

    def test_pre_push_verifies_metadata_against_historical_source(self):
        folder = self.seed_ast_manifest()
        command(self.repo, 'commit', '-q', '--no-verify', '-m', 'test: seed historical AST hashes').check_returncode()
        revision = command(self.repo, 'rev-parse', 'HEAD').stdout.decode().strip()
        (folder / 'scope.py').write_text('print("changed in a later commit")\n')
        command(self.repo, 'add', 'numerical/scope.py').check_returncode()
        command(self.repo, 'commit', '-q', '--no-verify', '-m', 'test: change function later').check_returncode()
        head = command(self.repo, 'rev-parse', 'HEAD').stdout.decode().strip()
        payload = f'refs/heads/main {head} refs/heads/main {self.base}\n'.encode()
        result = subprocess.run([sys.executable, str(guard.ROOT / 'leakguard.py'), 'hook', 'pre-push', 'origin', 'local-fixture'], input=payload, cwd=self.repo, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertIn(b'2 verified metadata', result.stderr)
        self.assertIn(revision[:12].encode(), result.stderr)

    def test_ast_metadata_with_wrong_hash_or_wrong_context_stays_blocked(self):
        folder = self.seed_ast_manifest()
        manifest = json.loads((folder / 'origins.json').read_text())
        manifest['scope.py']['function_ast_sha256']['token'] = HEX_FIXTURE
        (folder / 'origins.json').write_text(json.dumps(manifest, indent=2))
        command(self.repo, 'add', 'numerical/origins.json').check_returncode()
        result = command(self.repo, 'commit', '-m', 'test: reject unverified AST-shaped token')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'LeakGuard blocked', result.stderr)
        self.assertIn(b'function_ast_sha256.token', result.stderr)

    def test_plugin_mode_preserves_metadata_proof_and_real_key_blocking(self):
        module = self.repo / 'noop_fixture.py'
        module.write_text('API_VERSION=1\nclass Detector:\n def detect(self,text,path,part): return []\ndef create_plugin(options): return Detector()\n')
        config = self.repo / 'plugin-config.json'
        config.write_text(json.dumps({'plugins': [{'module': 'noop_fixture'}]}))
        paths = str(self.repo) + os.pathsep + os.environ.get('PYTHONPATH', '')
        with patch.dict(os.environ, {'LEAKGUARD_CONFIG': str(config), 'PYTHONPATH': paths}):
            self.test_staged_ast_metadata_uses_index_source_and_keeps_hex_keys_blocking()

    def test_existing_pre_push_hook_receives_original_stdin(self):
        hooks = self.repo / '.git' / 'hooks'
        (hooks / 'pre-push').write_text('#!/bin/sh\ncat > .original-hook-input\n', newline='\n')
        install_hooks.install_at(hooks)
        payload = f'refs/heads/main {self.base} refs/heads/main {self.base}\n'.encode()
        result = subprocess.run([sys.executable, str(guard.ROOT / 'leakguard.py'), 'hook', 'pre-push', 'origin', 'local-fixture'], input=payload, cwd=self.repo, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual((self.repo / '.original-hook-input').read_bytes(), payload)

    def test_pre_push_finds_secret_in_historical_office_blob(self):
        (self.repo / 'notes.docx').write_bytes(document(SYNTHETIC))
        command(self.repo, 'add', 'notes.docx').check_returncode()
        command(self.repo, 'commit', '-q', '--no-verify', '-m', 'test: seed historical document').check_returncode()
        head = command(self.repo, 'rev-parse', 'HEAD').stdout.decode().strip()
        payload = f'refs/heads/main {head} refs/heads/main {self.base}\n'.encode()
        result = subprocess.run([sys.executable, str(guard.ROOT / 'leakguard.py'), 'hook', 'pre-push', 'origin', 'local-fixture'], input=payload, cwd=self.repo, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'literal-client-secret', result.stderr)
        self.assertIn(head[:12].encode(), result.stderr)
        self.assertIn(b'word/document.xml', result.stderr)
        self.assertNotIn(SYNTHETIC.encode(), result.stdout + result.stderr)

    def test_report_does_not_contain_secret_values(self):
        connection = guard.db()
        findings, status = guard.scan_blob(('client_secret = "' + SYNTHETIC + '"').encode(), 'synthetic.py')
        report = guard.save_report('fixture-redaction', [{'status': status, 'findings': findings}], connection)
        self.assertGreater(report['findings_count'], 0)
        self.assertNotIn(SYNTHETIC, json.dumps(report))
        self.assertFalse(any(k in json.dumps(report) for k in ['"Secret"', '"Match"', '"Line"']))
        connection.close()

    def test_audit_resumes_after_file_budget(self):
        (self.repo / 'second.py').write_text('print("second")\n')
        connection = guard.db()
        scope = 'fixture-' + self.repo.name
        with patch.dict(guard.CONFIG['audit_scopes'], {scope: str(self.repo)}):
            guard.audit(scope, budget=20, max_files=1)
            guard.audit(scope, budget=20, max_files=10)
        cached = connection.execute('SELECT path FROM cache WHERE path LIKE ?', (str(self.repo) + '%',)).fetchall()
        self.assertEqual({pathlib.Path(row[0]).name for row in cached}, {'app.py', 'second.py'})
        connection.execute('DELETE FROM cycles WHERE scope=?', (scope,)); connection.commit(); connection.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
