"""Gitleaks adapter: bounded execution and narrow redacted observations only."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
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


@dataclass(frozen=True, repr=False)
class PreparedBackend:
    """Private immutable rule snapshot shared only within one bounded job."""
    executable: str
    directory: Path
    rules: Path


@contextmanager
def prepare(*, binary=None, rules=None, check=None):
    """Inspect and stage rules once; callers retain final runtime validation."""
    selected = str(binary or os.environ.get('LEAKGUARD_GITLEAKS') or shutil.which('gitleaks') or 'gitleaks')
    executable = str(Path(shutil.which(selected) or selected).absolute())
    rule_path = str(Path(rules or Path(__file__).with_name('rules.toml')).absolute())
    from ._rules import inspect, stage, RuleConfigError
    try:
        closure = inspect(rule_path, check=check)
        with tempfile.TemporaryDirectory(prefix='leakguard-backend-') as scratch:
            directory, staged_config = stage(closure, scratch)
            if check is not None:
                check()
            yield PreparedBackend(executable, directory, staged_config)
    except RuleConfigError:
        raise BackendError('configuration-invalid') from None


def detect(text: str, *, binary=None, rules=None, timeout=45,
           max_findings=100_000, cancel=None, prepared=None,
           worker_policy='strict') -> tuple[BackendFinding, ...]:
    if type(text) is not str or type(max_findings) is not int or max_findings <= 0:
        raise BackendError('detector-output-invalid')
    started = time.monotonic()
    def check_budget():
        if cancel is not None and cancel():
            raise BackendError('cancelled')
        if time.monotonic() - started >= timeout:
            raise BackendError('detector-timeout')
    check_budget()
    if prepared is None:
        with prepare(binary=binary, rules=rules, check=check_budget) as setup:
            return detect(text, timeout=max(0.001, timeout - (time.monotonic() - started)),
                          max_findings=max_findings, cancel=cancel, prepared=setup,
                          worker_policy=worker_policy)
    if type(prepared) is not PreparedBackend:
        raise BackendError('configuration-invalid')
    command = [prepared.executable, 'stdin', '--config', str(prepared.rules), '--redact=100',
               '--ignore-gitleaks-allow', '--no-banner', '--no-color', '--log-level', 'fatal',
               '--report-format', 'json', '--report-path', '-', '--timeout', str(max(1, math.ceil(timeout)))]
    try:
        process = run_worker(command, text.encode('utf-8'), timeout=max(0.001, timeout - (time.monotonic() - started)),
                             max_input_bytes=80_000_000,
                             max_output_bytes=min(64_000_000, max(1_048_576, max_findings * 4096)),
                             # Go reserves a large virtual arena; applying
                             # RLIMIT_AS would prevent startup.
                             memory_bytes=None, env=worker_environment(),
                             cwd=prepared.directory, cancel=cancel,
                             worker_policy=worker_policy)
    except WorkerError as error:
        code = {'worker-timeout': 'detector-timeout', 'worker-output-limit': 'detector-output-limit',
                'cancelled': 'cancelled', 'resource-bound-unavailable': 'resource-bound-unavailable'}.get(error.code, 'detector-failed')
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
