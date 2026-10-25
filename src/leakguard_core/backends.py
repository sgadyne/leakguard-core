"""Gitleaks adapter: bounded execution and narrow redacted observations only."""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import shutil
import tempfile
import time

from ._supervision import WorkerError, run_worker, worker_environment


class BackendError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class BackendFinding:
    rule: str
    start_line: int
    end_line: int
    severity: str = 'block'


def detect(text: str, *, binary=None, rules=None, timeout=45,
           max_findings=100_000, cancel=None) -> tuple[BackendFinding, ...]:
    if type(text) is not str or type(max_findings) is not int or max_findings <= 0:
        raise BackendError('detector-output-invalid')
    started = time.monotonic()
    def check_budget():
        if cancel is not None and cancel():
            raise BackendError('cancelled')
        if time.monotonic() - started >= timeout:
            raise BackendError('detector-timeout')
    selected = str(binary or os.environ.get('LEAKGUARD_GITLEAKS') or shutil.which('gitleaks') or 'gitleaks')
    executable = str(Path(shutil.which(selected) or selected).absolute())
    rule_path = str(Path(rules or Path(__file__).with_name('rules.toml')).absolute())
    command = [executable, 'stdin', '--config', rule_path, '--redact=100',
               '--ignore-gitleaks-allow', '--no-banner', '--no-color', '--log-level', 'fatal',
               '--report-format', 'json', '--report-path', '-', '--timeout', str(max(1, math.ceil(timeout)))]
    try:
        from ._rules import inspect, stage, RuleConfigError
        closure = inspect(rule_path, check=check_budget)
        with tempfile.TemporaryDirectory(prefix='leakguard-backend-') as scratch:
            # stdin still reads CWD/.gitleaksignore in the pinned backend. Keep
            # repository content out of its policy context while preserving
            # explicitly configured relative rule inheritance in private files.
            directory, staged_config = stage(closure, scratch)
            command[command.index('--config') + 1] = str(staged_config)
            check_budget()
            process = run_worker(command, text.encode('utf-8'), timeout=max(0.001, timeout - (time.monotonic() - started)),
                                 max_input_bytes=80_000_000,
                                 max_output_bytes=min(64_000_000, max(1_048_576, max_findings * 4096)),
                                 # Go reserves a large virtual arena; applying
                                 # RLIMIT_AS would prevent startup.
                                 memory_bytes=None, env=worker_environment(),
                                 cwd=directory, cancel=cancel)
    except RuleConfigError:
        raise BackendError('configuration-invalid') from None
    except WorkerError as error:
        code = {'worker-timeout': 'detector-timeout', 'worker-output-limit': 'detector-output-limit',
                'cancelled': 'cancelled'}.get(error.code, 'detector-failed')
        raise BackendError(code) from None
    if process.returncode not in (0, 1):
        raise BackendError('detector-failed')
    try:
        raw = json.loads(process.stdout)
        # Some Gitleaks versions write JSON null when there are no detections.
        if raw is None:
            raw = []
        if type(raw) is not list:
            raise ValueError
        if len(raw) > max_findings:
            raise BackendError('detector-output-limit')
        line_count = text.count('\n') + 1
        findings = []
        for item in raw:
            if type(item) is not dict:
                raise ValueError
            rule, first, last = item.get('RuleID'), item.get('StartLine'), item.get('EndLine')
            if (type(rule) is not str or not re.fullmatch('[a-z][a-z0-9-]{0,79}', rule)
                    or type(first) is not int or type(last) is not int
                    or not 1 <= first <= last <= line_count):
                raise ValueError
            findings.append(BackendFinding(rule, first, last))
        return tuple(findings)
    except BackendError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise BackendError('detector-output-invalid') from None
