"""Pinned Gitleaks behavior must not inherit caller suppressions or stale rules."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, scan_policy


SYNTHETIC = 'SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG'
TEXT = f'client_secret = "{SYNTHETIC}"\n'


def _minimal_environment() -> dict[str, str]:
    """Keep Gitleaks environment discovery out of these subprocess fixtures."""
    allowed = ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL')
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _raw_stdin_report(binary: Path, rules: Path, cwd: Path, text: str) -> list[dict]:
    command = [
        str(binary), 'stdin', '--config', str(rules), '--redact=100',
        '--ignore-gitleaks-allow', '--no-banner', '--no-color', '--log-level', 'fatal',
        '--report-format', 'json', '--report-path', '-', '--timeout', '30',
    ]
    result = subprocess.run(
        command, input=text.encode('utf-8'), cwd=cwd, env=_minimal_environment(),
        capture_output=True, timeout=35, check=False,
    )
    if result.returncode not in (0, 1):
        raise AssertionError(f'pinned Gitleaks fixture failed with exit {result.returncode}')
    value = json.loads(result.stdout)
    return value if type(value) is list else []


def _write_two_level_rules(root: Path, *, minimum: int = 20) -> tuple[Path, Path, bytes]:
    """Write a real two-edge relative Gitleaks extension graph under root."""
    (root / 'nested').mkdir(exist_ok=True)
    (root / 'cfg' / 'subdir').mkdir(parents=True, exist_ok=True)
    top = root / 'top.toml'
    first = root / 'cfg' / 'first.toml'
    leaf = root / 'cfg' / 'second.toml'
    top.write_text(
        'title = "synthetic root"\n[extend]\npath = "nested/../cfg/first.toml"\n',
        encoding='utf-8',
    )
    first.write_text(
        'title = "synthetic middle"\n[extend]\npath = "cfg/subdir/../second.toml"\n',
        encoding='utf-8',
    )
    leaf_bytes = (
        'title = "synthetic leaf"\n'
        '[[rules]]\n'
        'id = "synthetic-extended-credential"\n'
        'description = "Synthetic-only extension rule"\n'
        f'regex = \'\'\'client_secret\\s*=\\s*"([A-Za-z0-9~]{{{minimum},}})"\'\'\'\n'
        'secretGroup = 1\n'
        'keywords = ["client_secret"]\n'
    ).encode('utf-8')
    leaf.write_bytes(leaf_bytes)
    return top, leaf, leaf_bytes


class BackendIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get('LEAKGUARD_GITLEAKS') or str(engine.EXE)
        cls.binary = Path(selected).resolve()
        cls.rules = Path(engine.RULES).resolve()
        if not cls.binary.is_file():
            raise unittest.SkipTest('pinned Gitleaks executable is unavailable')

    def test_required_stdin_scan_cannot_be_waived_by_caller_gitleaksignore(self):
        """A real fingerprint in a disposable caller CWD must not suppress input."""
        with tempfile.TemporaryDirectory(prefix='leakguard-backend-ignore-') as temporary:
            cwd = Path(temporary)
            initialized = subprocess.run(
                ['git', 'init', '-q'], cwd=cwd, env=_minimal_environment(),
                capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(initialized.returncode, 0)

            baseline = _raw_stdin_report(self.binary, self.rules, cwd, TEXT)
            self.assertTrue(baseline, 'the pinned config must detect the synthetic credential')
            fingerprint = baseline[0].get('Fingerprint')
            self.assertIs(type(fingerprint), str)
            self.assertTrue(fingerprint)
            (cwd / '.gitleaksignore').write_text(fingerprint + '\n', encoding='utf-8')

            # backends.detect intentionally has no caller-CWD parameter. The current
            # implementation inherits the test process CWD, so run this test serially
            # with a strict try/finally restore and prove the backend ignores that file.
            original_cwd = Path.cwd()
            try:
                os.chdir(cwd)
                findings = backends.detect(TEXT, binary=self.binary, rules=self.rules)
            finally:
                os.chdir(original_cwd)

        self.assertIn(
            'literal-client-secret', {finding.rule for finding in findings},
            'caller-controlled .gitleaksignore must not waive a required scan',
        )

    def test_relative_extended_rule_change_invalidates_persistent_runtime_identity(self):
        """Hash two levels of relative rules and disable reuse for inheritance."""
        with tempfile.TemporaryDirectory(prefix='leakguard-extended-rules-') as temporary:
            cwd = Path(temporary)
            top_config, extension, first_extension = _write_two_level_rules(cwd)
            second_extension = first_extension.replace(b'{20,}', b'{99,}')
            self.assertEqual(len(first_extension), len(second_extension))

            original_cwd = Path.cwd()
            try:
                os.chdir(cwd)
                first_findings = backends.detect(TEXT, binary=self.binary, rules=top_config)
                self.assertIn('synthetic-extended-credential', {item.rule for item in first_findings})

                config = {'gitleaks_config': str(top_config)}
                before, eligible_before = scan_policy.runtime_identity(config, self.binary)
                self.assertFalse(eligible_before, 'inherited rule files conservatively disable reuse')

                previous = extension.stat()
                extension.write_bytes(second_extension)
                os.utime(extension, ns=(previous.st_atime_ns, previous.st_mtime_ns))
                changed = extension.stat()
                self.assertEqual(changed.st_size, previous.st_size)
                self.assertEqual(changed.st_mtime_ns, previous.st_mtime_ns)

                second_findings = backends.detect(TEXT, binary=self.binary, rules=top_config)
                self.assertNotIn('synthetic-extended-credential', {item.rule for item in second_findings})
                after, eligible_after = scan_policy.runtime_identity(config, self.binary)
                self.assertFalse(eligible_after, 'inherited rule files conservatively disable reuse')
            finally:
                os.chdir(original_cwd)

        self.assertNotEqual(before, after, 'runtime identity must include both inherited rule files')

    def test_relative_rule_staging_never_writes_source_and_cleans_up_after_worker_failure(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-rule-staging-') as temporary:
            cwd = Path(temporary)
            top_config, _, _ = _write_two_level_rules(cwd)
            original_cwd = Path.cwd()
            captured = {}
            try:
                os.chdir(cwd)

                def fail_worker(argv, data, **kwargs):
                    stage_cwd = Path(kwargs['cwd']).resolve()
                    scratch = next(
                        path for path in (stage_cwd, *stage_cwd.parents)
                        if path.name.startswith('leakguard-backend-')
                    )
                    files = tuple(path for path in stage_cwd.rglob('*') if path.is_file())
                    staged_bytes = tuple(path.read_bytes() for path in files)
                    self.assertEqual(data, TEXT.encode('utf-8'))
                    self.assertTrue(files, 'relative rule files must be staged for the private CWD')
                    self.assertNotIn(TEXT.encode('utf-8'), b'\n'.join(staged_bytes))
                    self.assertNotIn(SYNTHETIC.encode('utf-8'), b'\n'.join(staged_bytes))
                    captured['scratch'] = scratch
                    captured['files'] = files
                    from leakguard_core._supervision import WorkerError
                    raise WorkerError('worker-start-failed')

                with patch.object(backends, 'run_worker', side_effect=fail_worker):
                    with self.assertRaises(backends.BackendError) as error:
                        backends.detect(TEXT, binary=self.binary, rules=top_config)
                self.assertEqual(error.exception.code, 'detector-failed')
                self.assertTrue(captured['files'])
                self.assertFalse(
                    captured['scratch'].exists(),
                    'backend temporary staging must be removed before fixture cleanup',
                )
            finally:
                os.chdir(original_cwd)

    def test_missing_nonregular_and_oversized_rule_files_fail_with_fixed_error(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-invalid-rules-') as temporary:
            root = Path(temporary)
            missing = root / 'private-missing-rules.toml'
            nonregular = root / 'private-nonregular-rules.toml'
            nonregular.mkdir()
            oversized = root / 'private-oversized-rules.toml'
            oversized.write_bytes(b'# source-marker-never-echoed\n' + b'a' * 1_000_000)
            oversized_child = root / 'private-oversized-inherited-rules.toml'
            oversized_child.write_bytes(b'# source-marker-never-echoed\n' + b'b' * 1_000_000)
            inherited_top = root / 'private-inherited-top.toml'
            inherited_top.write_text(
                'title = "synthetic inherited config"\n'
                '[extend]\n'
                f'path = "{oversized_child.as_posix()}"\n',
                encoding='utf-8',
            )
            with patch.object(backends, 'run_worker') as worker:
                for label, path in (
                    ('missing', missing),
                    ('nonregular', nonregular),
                    ('oversized', oversized),
                    ('oversized-inherited', inherited_top),
                ):
                    with self.subTest(rule_path=label):
                        with self.assertRaises(backends.BackendError) as error:
                            backends.detect(TEXT, binary=self.binary, rules=path)
                        self.assertEqual(error.exception.code, 'configuration-invalid')
                        self.assertEqual(str(error.exception), 'configuration-invalid')
                        self.assertNotIn(path.name, str(error.exception))
                        self.assertNotIn('source-marker-never-echoed', str(error.exception))
            worker.assert_not_called()

    def test_remote_rule_inheritance_disables_reuse_without_fetching(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-remote-rules-') as temporary:
            top_config = Path(temporary) / 'top.toml'
            top_config.write_text(
                'title = "synthetic remote config"\n'
                '[extend]\n'
                'url = "https://rules.invalid/private.toml"\n',
                encoding='utf-8',
            )
            runtime, eligible = scan_policy.runtime_identity(
                {'gitleaks_config': str(top_config)}, self.binary,
            )

        self.assertRegex(runtime, r'^[0-9a-f]{64}$')
        self.assertFalse(eligible, 'remote/unknown inherited bytes cannot authorize persistent reuse')


if __name__ == '__main__':
    unittest.main(verbosity=2)
