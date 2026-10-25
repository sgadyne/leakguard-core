"""Pinned Gitleaks behavior must not inherit caller suppressions or stale rules."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
import io
from unittest.mock import patch

from leakguard_core import backends, engine, hooks, scan_policy


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

    @unittest.skipIf(os.name == 'nt', 'the installed POSIX hook wrapper requires executable mode bits')
    def test_installed_pre_commit_hook_blocks_ignore_fingerprint_from_stdin(self):
        """Git must execute the installed hook and block despite its CWD ignore file."""
        with tempfile.TemporaryDirectory(prefix='leakguard-hook-ignore-') as temporary:
            root = Path(temporary)
            repo = root / 'repo'
            repo.mkdir()
            home = root / 'home'
            home.mkdir()
            state = root / 'private-state'
            global_config = root / 'empty-global-gitconfig'
            source_root = Path(backends.__file__).resolve().parents[1]
            env = _minimal_environment()
            env.update({
                'HOME': str(home),
                'XDG_CONFIG_HOME': str(root / 'xdg'),
                'GIT_CONFIG_GLOBAL': str(global_config),
                'GIT_CONFIG_NOSYSTEM': '1',
                'GIT_TERMINAL_PROMPT': '0',
                'LEAKGUARD_GITLEAKS': str(self.binary),
                'LEAKGUARD_STATE_DIR': str(state),
                'PYTHONPATH': str(source_root),
            })

            def git(*args, check=False):
                return subprocess.run(
                    ['git', *args], cwd=repo, env=env,
                    capture_output=True, timeout=30, check=check,
                )

            initialized = git('-c', 'init.templateDir=', 'init', '-q')
            self.assertEqual(initialized.returncode, 0, 'disposable Git repo must initialize')
            for key, value in (
                ('user.name', 'LeakGuard synthetic fixture'),
                ('user.email', 'synthetic@example.invalid'),
                ('commit.gpgsign', 'false'),
            ):
                configured = git('config', key, value)
                self.assertEqual(configured.returncode, 0)

            baseline = _raw_stdin_report(self.binary, self.rules, repo, TEXT)
            self.assertTrue(baseline, 'the pinned config must detect the staged synthetic credential')
            fingerprint = baseline[0].get('Fingerprint')
            self.assertIs(type(fingerprint), str)
            self.assertTrue(fingerprint)
            (repo / '.gitleaksignore').write_text(fingerprint + '\n', encoding='utf-8')

            candidate = repo / 'synthetic-candidate.txt'
            candidate.write_text(TEXT, encoding='utf-8')
            staged = git('add', candidate.name)
            self.assertEqual(staged.returncode, 0)

            hooks.install_at(repo / '.git' / 'hooks')
            installed_hook = repo / '.git' / 'hooks' / 'pre-commit'
            self.assertTrue(installed_hook.is_file())
            self.assertTrue(installed_hook.stat().st_mode & 0o111)

            result = git('commit', '-m', 'test: block a staged synthetic credential')

            self.assertEqual(result.returncode, 1, result.stderr.decode('utf-8', errors='replace'))
            self.assertIn(b'literal-client-secret', result.stderr)
            self.assertNotIn(SYNTHETIC.encode('utf-8'), result.stdout + result.stderr)
            head = git('rev-parse', '--verify', 'HEAD')
            self.assertNotEqual(head.returncode, 0, 'the hook must prevent Git from creating the commit')
            self.assertTrue(state.is_dir(), 'the hook used only the explicitly private fixture state')

    @unittest.skipIf(os.name == 'nt', 'self-referential symlink creation is not portable on Windows')
    def test_top_level_and_inherited_rule_symlink_loops_are_sanitized(self):
        """Public scans return incomplete or fixed config errors without path tracebacks."""
        from leakguard_core.api import ConfigurationError, ScanConfig, Scanner
        from leakguard_core.models import (
            BytesInput, DecisionVerdict, ErrorCode, ScanLimits, ScanPolicy,
        )

        with tempfile.TemporaryDirectory(prefix='leakguard-rule-loop-marker-') as temporary:
            root = Path(temporary)
            top_loop = root / 'private-top-rule-loop.toml'
            top_loop.symlink_to(top_loop.name)
            inherited_loop = root / 'private-inherited-rule-loop.toml'
            inherited_loop.symlink_to(inherited_loop.name)
            inherited_parent = root / 'private-inherited-parent.toml'
            inherited_parent.write_text(
                '[extend]\npath = ' + json.dumps(str(inherited_loop)) + '\n',
                encoding='utf-8',
            )

            for label, selected_rules in (
                ('top-level', top_loop),
                ('inherited', inherited_parent),
            ):
                with self.subTest(config=label), patch.object(backends, 'run_worker') as worker:
                    config = ScanConfig.from_mapping({'gitleaks_config': str(selected_rules)})
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    try:
                        with redirect_stdout(stdout), redirect_stderr(stderr):
                            with Scanner.open(config=config) as scanner:
                                report = scanner.scan(
                                    [BytesInput(TEXT.encode('utf-8'), 'synthetic-input.txt')],
                                    policy=ScanPolicy.inventory(),
                                    limits=ScanLimits(deadline_seconds=10, max_files=1),
                                )
                    except Exception as error:
                        # A public boundary may reject at open time, but only as a
                        # fixed API configuration error; never let pathlib's loop
                        # diagnostic include the operator-supplied path.
                        self.assertIs(type(error), ConfigurationError)
                        self.assertEqual(getattr(error, 'code', None), 'configuration-invalid')
                        self.assertNotIn(str(root), str(error))
                        self.assertNotIn('Traceback', stdout.getvalue() + stderr.getvalue())
                        self.assertNotIn(str(root), stdout.getvalue() + stderr.getvalue())
                    else:
                        self.assertIs(report.decision.verdict, DecisionVerdict.INCOMPLETE)
                        issues = [*report.issues, *(issue for result in report.results for issue in result.issues)]
                        self.assertIn(ErrorCode.CONFIGURATION_INVALID, {issue.code for issue in issues})
                        serialized = report.to_json()
                        self.assertNotIn(str(root), serialized)
                        self.assertNotIn(SYNTHETIC, serialized)
                        self.assertNotIn('Traceback', stdout.getvalue() + stderr.getvalue())
                        self.assertNotIn(str(root), stdout.getvalue() + stderr.getvalue())
                    worker.assert_not_called()

    def test_top_level_rules_are_snapshotted_before_worker_launch(self):
        """Mutating the selected TOML after admission cannot change worker rules."""
        with tempfile.TemporaryDirectory(prefix='leakguard-rule-snapshot-race-') as temporary:
            root = Path(temporary)
            top_config, extension, extension_bytes = _write_two_level_rules(root)
            original_top = top_config.read_bytes()
            replacement = (
                'title = "synthetic no-detection replacement"\n'
                '[extend]\nuseDefault = false\n'
                '[[rules]]\n'
                'id = "synthetic-never-matches"\n'
                'description = "Synthetic nonmatching replacement rule"\n'
                'regex = "NEVER_MATCH_FOR_LEAKGUARD"\n'
                'keywords = ["NEVER_MATCH_FOR_LEAKGUARD"]\n'
            ).encode('utf-8')
            replacement_config = root / 'replacement.toml'
            replacement_config.write_bytes(replacement)
            self.assertFalse(
                _raw_stdin_report(self.binary, replacement_config, root, TEXT),
                'the replacement config must not detect the synthetic input',
            )

            original_cwd = Path.cwd()
            captured = {}
            real_run_worker = backends.run_worker
            try:
                os.chdir(root)

                def mutate_original_before_launch(argv, data, **kwargs):
                    config_argument = Path(argv[argv.index('--config') + 1]).resolve()
                    worker_cwd = Path(kwargs['cwd']).resolve()
                    stage_root = next(
                        path for path in (worker_cwd, *worker_cwd.parents)
                        if path.name.startswith('leakguard-backend-')
                    )
                    staged_files = tuple(path for path in stage_root.rglob('*') if path.is_file())
                    staged_bytes = tuple(path.read_bytes() for path in staged_files)
                    captured.update(
                        config_argument=config_argument,
                        config_bytes=config_argument.read_bytes() if config_argument.is_file() else None,
                        worker_cwd=worker_cwd,
                        stage_root=stage_root,
                        staged_files=staged_files,
                        staged_bytes=staged_bytes,
                    )
                    top_config.write_bytes(replacement)
                    return real_run_worker(argv, data, **kwargs)

                with patch.object(backends, 'run_worker', side_effect=mutate_original_before_launch):
                    findings = backends.detect(TEXT, binary=self.binary, rules=top_config)
            finally:
                os.chdir(original_cwd)

            self.assertIn(
                'synthetic-extended-credential', {item.rule for item in findings},
                'the worker must use the rule snapshot admitted before the source config changed',
            )
            self.assertNotEqual(captured['config_argument'], top_config.resolve())
            self.assertTrue(captured['config_argument'].is_relative_to(captured['stage_root']))
            self.assertFalse(captured['config_argument'].is_relative_to(captured['worker_cwd']))
            self.assertEqual(captured['config_bytes'], original_top)
            self.assertIn(original_top, captured['staged_bytes'])
            self.assertIn(extension_bytes, captured['staged_bytes'])
            self.assertNotIn(TEXT.encode('utf-8'), b'\n'.join(captured['staged_bytes']))
            self.assertNotIn(SYNTHETIC.encode('utf-8'), b'\n'.join(captured['staged_bytes']))
            self.assertFalse(captured['stage_root'].exists(), 'private top and inherited rule snapshots must be removed')
            self.assertFalse(any(path.exists() for path in captured['staged_files']))

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
