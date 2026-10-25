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
        """Hash the effective relative Gitleaks rule closure, not only the top file."""
        with tempfile.TemporaryDirectory(prefix='leakguard-extended-rules-') as temporary:
            cwd = Path(temporary)
            top_config = cwd / 'top.toml'
            extension = cwd / 'extended.toml'
            top_config.write_text(
                'title = "synthetic root"\n[extend]\npath = "extended.toml"\n',
                encoding='utf-8',
            )
            first_extension = (
                'title = "synthetic extension"\n'
                '[[rules]]\n'
                'id = "synthetic-extended-credential"\n'
                'description = "Synthetic-only extension rule"\n'
                'regex = \'\'\'client_secret\\s*=\\s*"([A-Za-z0-9~]{20,})"\'\'\'\n'
                'secretGroup = 1\n'
                'keywords = ["client_secret"]\n'
            ).encode('utf-8')
            second_extension = first_extension.replace(b'{20,}', b'{99,}')
            self.assertEqual(len(first_extension), len(second_extension))
            extension.write_bytes(first_extension)

            original_cwd = Path.cwd()
            try:
                os.chdir(cwd)
                first_findings = backends.detect(TEXT, binary=self.binary, rules=top_config)
                self.assertIn('synthetic-extended-credential', {item.rule for item in first_findings})

                config = {'gitleaks_config': str(top_config)}
                before, eligible_before = scan_policy.runtime_identity(config, self.binary)
                self.assertTrue(eligible_before, 'fixture must begin with a reusable runtime')

                previous = extension.stat()
                extension.write_bytes(second_extension)
                os.utime(extension, ns=(previous.st_atime_ns, previous.st_mtime_ns))
                changed = extension.stat()
                self.assertEqual(changed.st_size, previous.st_size)
                self.assertEqual(changed.st_mtime_ns, previous.st_mtime_ns)

                second_findings = backends.detect(TEXT, binary=self.binary, rules=top_config)
                self.assertNotIn('synthetic-extended-credential', {item.rule for item in second_findings})
                after, eligible_after = scan_policy.runtime_identity(config, self.binary)
            finally:
                os.chdir(original_cwd)

        self.assertTrue(
            before != after or not eligible_after,
            'changed relative extension bytes must change runtime identity or disable reuse',
        )


if __name__ == '__main__':
    unittest.main(verbosity=2)
