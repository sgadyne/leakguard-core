"""Gitleaks adapter: bounded execution and narrow redacted observations only."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
import json
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time

from ._supervision import WorkerError, run_worker, worker_environment
from .sources import AcquisitionError, _path_stat


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
    cache_identity: str | None = None


def _pin_executable(executable, scratch, check):
    """Hash and execute the same bounded private snapshot, never a mutable path."""
    try:
        selected = Path(executable).resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        return executable, None
    try:
        if not os.access(selected, os.X_OK):
            return executable, None
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        with os.fdopen(os.open(selected, flags), 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024 * 1024:
                return executable, None
            destination = Path(scratch) / ('backend.exe' if os.name == 'nt' else 'backend')
            digest = hashlib.sha256()
            consumed = 0
            with destination.open('xb') as output:
                while chunk := source.read(1_048_576):
                    if check is not None:
                        check()
                    consumed += len(chunk)
                    if consumed > 512 * 1024 * 1024:
                        raise BackendError('source-unavailable')
                    digest.update(chunk)
                    output.write(chunk)
            def signature(value):
                return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                        value.st_mtime_ns, value.st_ctime_ns)
            if (consumed != before.st_size or any(signature(value) != signature(before)
                    for value in (os.fstat(source.fileno()), _path_stat(selected), _path_stat(Path(executable), follow_symlinks=True)))):
                raise BackendError('source-unavailable')
        destination.chmod(0o500)
        return str(destination), digest.hexdigest()
    except (OSError, ValueError, AcquisitionError):
        # Keep normal unavailable-backend behavior; no observations may be reused.
        return executable, None


@contextmanager
def prepare(*, binary=None, rules=None, check=None, cache_native=False):
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
            # Only the native component's closed artifacts authorize this L1;
            # unknown plugin closures never authorize plugin/final result reuse.
            pinned, binary_id = (_pin_executable(executable, scratch, check)
                                 if cache_native and not closure.external else (executable, None))
            identity = (hashlib.sha256(json.dumps([binary_id, closure.identity],
                         separators=(',', ':')).encode()).hexdigest()
                        if binary_id is not None else None)
            if check is not None:
                check()
            yield PreparedBackend(pinned, directory, staged_config, identity)
    except RuleConfigError:
        raise BackendError('configuration-invalid') from None


def detect(text: str, *, binary=None, rules=None, timeout=45,
           max_findings=100_000, cancel=None, prepared=None,
           worker_policy='strict', cache_scope=None, cache_identity=None,
           cache_domain=None) -> tuple[BackendFinding, ...]:
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
        with prepare(binary=binary, rules=rules, check=check_budget,
                     cache_native=cache_scope is not None) as setup:
            return detect(text, timeout=max(0.001, timeout - (time.monotonic() - started)),
                          max_findings=max_findings, cancel=cancel, prepared=setup,
                          worker_policy=worker_policy, cache_scope=cache_scope,
                          cache_identity=cache_identity, cache_domain=cache_domain)
    if type(prepared) is not PreparedBackend:
        raise BackendError('configuration-invalid')
    payload = text.encode('utf-8')
    if len(payload) > 80_000_000:
        raise BackendError('detector-failed')
    # An unavailable/non-executable backend must never be hidden by a hit.
    eligible = (cache_scope is not None and type(cache_identity) is str
                and prepared.cache_identity is not None
                and os.path.isfile(prepared.executable) and os.access(prepared.executable, os.X_OK))
    def compute():
        check_budget()
        return _detect(text, payload, prepared, timeout=max(0.001, timeout - (time.monotonic() - started)),
                       max_findings=max_findings, cancel=cancel, worker_policy=worker_policy)
    if not eligible:
        return compute()
    from ._result_cache import OBSERVATIONS
    key = hashlib.sha256(json.dumps(['native-observations-1', cache_identity,
            prepared.cache_identity, worker_policy, max_findings, len(payload),
            hashlib.sha256(payload).hexdigest()], separators=(',', ':')).encode()).hexdigest()
    def rows():
        return tuple((item.rule, item.start_line, item.end_line, item.severity) for item in compute())
    cached = OBSERVATIONS.get_or_compute(cache_scope, key, domain=cache_domain,
                                        check=check_budget, compute=rows)
    check_budget()
    return tuple(BackendFinding(*item) for item in cached)


def _detect(text, payload, prepared, *, timeout, max_findings, cancel, worker_policy):
    command = [prepared.executable, 'stdin', '--config', str(prepared.rules), '--redact=100',
               '--ignore-gitleaks-allow', '--no-banner', '--no-color', '--log-level', 'fatal',
               '--report-format', 'json', '--report-path', '-', '--timeout', str(max(1, math.ceil(timeout)))]
    try:
        process = run_worker(command, payload, timeout=timeout,
                             max_input_bytes=80_000_000,
                             max_output_bytes=min(64_000_000, max(1_048_576, max_findings * 4096)),
                             # Go reserves a large virtual arena; applying
                             # RLIMIT_AS would prevent startup.
                             memory_bytes=None, env=worker_environment(),
                             cwd=prepared.directory, cancel=cancel,
                             worker_policy=worker_policy)
    except WorkerError as error:
        code = {'worker-timeout': 'detector-timeout', 'worker-output-limit': 'detector-output-limit',
                'cancelled': 'cancelled', 'resource-bound-unavailable': 'resource-bound-unavailable',
                'worker-memory-limit': 'worker-memory-limit'}.get(error.code, 'detector-failed')
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
