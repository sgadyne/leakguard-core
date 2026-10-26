"""Local offline secret scanning, resumable disk audits, and Git guards."""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

from .documents import DOCUMENT_SUFFIXES
from . import catalog
from . import policies
from . import finding_details
from . import presentation

ROOT = pathlib.Path(__file__).resolve().parent
from .settings import load, state_directory
from . import plugins
import shutil

_LEGACY_READY = False


def _legacy():
    # Deprecated wrappers load environment configuration only on first use. The
    # typed service always receives explicit configuration and ignores these globals.
    global _LEGACY_READY, _LEGACY_DEFAULTS, CONFIG, CONFIG_PATH, STATE, EXE, RULES, PLUGINS, SCAN_POLICY
    if _LEGACY_READY:
        return
    CONFIG, CONFIG_PATH = load()
    if CONFIG.get('extension_registry'):
        from .extensions import ExtensionRegistry
        CONFIG = ExtensionRegistry(CONFIG['extension_registry']).apply(CONFIG, CONFIG.get('detection_profile', 'credentials'))
    STATE = state_directory()
    EXE = pathlib.Path(os.environ.get('LEAKGUARD_GITLEAKS') or CONFIG.get('gitleaks_executable') or shutil.which('gitleaks') or 'gitleaks')
    RULES = pathlib.Path(CONFIG.get('gitleaks_config') or ROOT / 'rules.toml')
    from ._rules import inspect
    rule_identity = inspect(RULES).identity
    PLUGINS = plugins.load(CONFIG.get('plugins', []), worker_policy=CONFIG.get('worker_policy', 'strict'))
    SCAN_POLICY = hashlib.sha256((ROOT / 'finding_details.py').read_bytes() + json.dumps(rule_identity, separators=(',', ':')).encode() + json.dumps(CONFIG, sort_keys=True).encode()).hexdigest()
    _LEGACY_DEFAULTS = {name: globals()[name] for name in ('CONFIG', 'CONFIG_PATH', 'STATE', 'EXE', 'RULES', 'PLUGINS', 'SCAN_POLICY')}
    _LEGACY_READY = True


def __getattr__(name):
    if name in {'CONFIG', 'CONFIG_PATH', 'STATE', 'EXE', 'RULES', 'PLUGINS', 'SCAN_POLICY'}:
        _legacy()
        if name not in globals():
            globals()[name] = _LEGACY_DEFAULTS[name]
        return globals()[name]
    raise AttributeError(name)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def db():
    _legacy()
    from .scan_store import open_database, StateError
    if CONFIG.get('observation_backend') == 'encrypted':
        raise StateError()
    return open_database(STATE)


def excluded(path):
    _legacy()
    path = pathlib.Path(path)
    low = os.path.normcase(os.path.abspath(path))
    state_root = os.path.normcase(os.path.abspath(STATE))
    if low == state_root or low.startswith(state_root + os.sep):
        return True
    for root in CONFIG['exclude_roots']:
        base = os.path.normcase(os.path.abspath(root))
        if low == base or low.startswith(base + os.sep):
            return True
    return any(part.lower() in CONFIG['exclude_components'] for part in path.parts)


def candidate(path):
    # Every regular file gets a result, including unsupported/oversized content.
    return not excluded(path)


def safe_findings(raw, path_override=None, part='text', digest=''):
    _legacy()
    results = []
    for item in raw or []:
        path = policies.canonical(path_override or item.get('File', ''), CONFIG)
        rule = item.get('RuleID', 'unknown')
        line = int(item.get('StartLine', 0))
        severity = 'review' if rule in CONFIG['review_only_rules'] else 'block'
        identity = '|'.join([path, part, rule, str(line), digest, str(item.get('Commit', ''))])
        finding = {'id': hashlib.sha256(identity.encode()).hexdigest(), 'path': path, 'part': part, 'line': line, 'rule': rule, 'severity': severity}
        revision = str(item.get('Commit', ''))
        if __import__('re').fullmatch('[0-9a-f]{40,64}', revision) and set(revision) != {'0'}:
            finding['commit'] = revision
        if item.get('EndLine'):
            finding['end_line'] = int(item['EndLine'])
        results.append(finding)
    return results


def engine(command, text=None, cwd=None):
    """Deprecated narrow backend adapter; native Git orchestration was removed."""
    _legacy()
    from . import backends
    if command != ['stdin']:
        raise RuntimeError('legacy-backend-unsupported')
    try:
        decoded = text.decode('utf-8', errors='strict') if isinstance(text, bytes) else text or ''
        return [{'RuleID': item.rule, 'StartLine': item.start_line, 'EndLine': item.end_line}
                for item in backends.detect(decoded, binary=EXE, rules=RULES, timeout=CONFIG['scan_timeout_seconds'])]
    except Exception:
        raise RuntimeError('detector-failed') from None


def _legacy_config():
    _legacy()
    config = dict(CONFIG)
    config['gitleaks_executable'] = str(EXE)
    config['gitleaks_config'] = str(RULES)
    return config


def _legacy_service(conn=None):
    from .scan_store import SQLiteScanStore
    config = _legacy_config()
    store = SQLiteScanStore.from_connection(conn, state_dir=STATE, config=config) if conn is not None else None
    service = ScanService(config, store=store)
    # Preserve trusted in-memory detector fixtures in the deprecated internal
    # wrapper. Configured deployment always uses supervised module handles.
    if any(not isinstance(instance, plugins.LoadedPlugin) for instance in PLUGINS):
        # Module handles were freshly loaded by the service; only an explicit
        # trusted in-memory fixture overrides them. Keep configured scripts.
        service._plugins = [*PLUGINS, *(instance for instance in service._plugins if not isinstance(instance, plugins.LoadedPlugin))]
        service._cache_eligible = False
    return service


def _legacy_result(result, run_issues=()):
    from . import models as m
    findings = []
    for finding in result.findings:
        item = {'id': finding.id, 'path': finding.source.path, 'part': finding.part_id,
                'line': finding.start_line, 'end_line': finding.end_line, 'rule': finding.rule,
                'severity': finding.severity.value, 'detector_severity': finding.detector_severity.value,
                'classification': finding.classification.value, 'proof_id': finding.proof_id}
        if finding.source.commit:
            item['commit'] = finding.source.commit
        findings.append(finding_details.describe(item))
    all_issues = (*result.issues, *run_issues)
    required = next((issue for issue in all_issues if issue.required), None)
    if required:
        status = 'missing' if required.code is m.ErrorCode.INPUT_MISSING else 'error-' + required.code.value
    elif result.outcome is m.ScanOutcome.REUSED:
        status = 'unchanged'
    elif result.outcome is m.ScanOutcome.SCANNED:
        status = 'scanned'
    else:
        status = 'skipped-binary-or-no-text'
    return {'path': result.source.path, 'status': status, 'findings': findings,
            'coverage': 'incomplete' if required else result.coverage.value,
            'issues': [{'path': issue.source.path if issue.source else result.source.path,
                        'status': issue.code.value, 'required': issue.required,
                        'part': issue.part_id, 'omission_id': issue.omission_id} for issue in all_issues],
            'last_executed_at': result.last_executed_at.isoformat() if result.last_executed_at else None,
            'last_verified_at': result.last_verified_at.isoformat() if result.last_verified_at else None}


def scan_blob(data, path, conn=None):
    """Deprecated tuple result adapter over the shared per-part service."""
    from . import models as m
    service = _legacy_service(conn)
    try:
        report = service.scan((m.BytesInput(data, str(path)),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(120, 1, max_file_bytes=CONFIG['max_file_bytes']), use_cache=False)
        if not report.results:
            return [], 'error-state-failed'
        result = _legacy_result(report.results[0], report.issues)
        return result['findings'], result['status']
    finally:
        service.close()


def scan_file(path, conn, use_cache=True):
    """Deprecated dictionary result adapter; content/proof/runtime reuse is shared."""
    from . import models as m
    service = _legacy_service(conn)
    try:
        report = service.scan((m.FileInput(pathlib.Path(path)),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(120, 1, max_file_bytes=CONFIG['max_file_bytes']), use_cache=use_cache)
        return _legacy_result(report.results[0], report.issues) if report.results else {'path': str(path), 'status': 'error-state-failed', 'findings': []}
    finally:
        service.close()


def save_report(label, results, conn, extra=None):
    _legacy()
    counts = {}
    findings = []
    issues = []
    timestamp = now()
    for result in results:
        status = result.get('status', 'scanned')
        counts[status] = counts.get(status, 0) + 1
        for finding in result.get('findings', []):
            finding = dict(finding)
            finding['profile'] = 'git' if label.startswith('git-') else policies.profile(finding['path'], CONFIG)
            finding['detector_severity'] = finding['severity']
            if finding['profile'] == 'companion':
                finding['severity'] = 'inventory'
            finding['priority'] = 'inventory' if finding['profile'] == 'companion' else ('info' if finding['severity'] == 'info' else ('review' if finding['severity'] == 'review' or finding['rule'] == 'generic-api-key' else 'high'))
            findings.append(finding)
        if result.get('issues'):
            issues.extend(result['issues'])
        elif status.startswith(('error', 'skipped', 'changed', 'timeout', 'missing')):
            issues.append({k: v for k, v in result.items() if k not in {'findings'}})
    new_count = 0
    for finding in findings:
        exists = conn.execute('SELECT 1 FROM findings WHERE id=?', (finding['id'],)).fetchone()
        new_count += not bool(exists)
        conn.execute('INSERT INTO findings VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen', (finding['id'], finding['path'], finding['rule'], finding['line'], finding['part'], finding['severity'], timestamp, timestamp))
    conn.commit()
    report = {'checked_utc': timestamp, 'label': label, 'file_counts': counts, 'findings_count': len(findings), 'new_findings_count': new_count, 'findings': findings, 'coverage_issues': issues, **(extra or {})}
    reports = STATE / 'reports'; reports.mkdir(exist_ok=True)
    name = dt.datetime.now().strftime('%Y%m%d-%H%M%S-') + label.replace('/', '-') + '-' + uuid.uuid4().hex[:6] + '.json'
    report['report_path'] = str(reports / name)
    (reports / name).write_text(json.dumps(report, indent=2), encoding='utf-8')
    fixture = 'fixture' in label or 'leakguard-test-' in report.get('repo', '')
    if not fixture:
        (STATE / 'LATEST.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    for profile in {'general', 'companion', 'git'}:
        subset = [item for item in findings if item.get('profile') == profile]
        profile_report = {**report, 'profile': profile, 'findings': subset, 'findings_count': len(subset)}
        if not fixture and (subset or label.removeprefix('audit-') in CONFIG.get('profiles', {}).get(profile, {}).get('sources', [])):
            (STATE / ('LATEST-' + profile + '.json')).write_text(json.dumps(profile_report, indent=2), encoding='utf-8')
    if not label.startswith('git-'):
        print(json.dumps({'label': label, 'file_counts': counts, 'findings': len(findings), 'new': new_count, 'report': str(reports / name)}), flush=True)
    return report


def _legacy_report_from_typed(report, label):
    conn = db()
    try:
        results = [_legacy_result(result) for result in report.results]
        for issue in report.issues:
            results.append({'path': issue.source.path if issue.source else '', 'status': ('error-' if issue.required else 'skipped-') + issue.code.value, 'findings': [], 'required': issue.required, 'omission_id': issue.omission_id})
        return save_report(label, results, conn, {'pending_files': report.coverage.pending_files, 'pending_directories': report.coverage.pending_directories, 'complete_cycle': report.coverage.enumeration_complete and report.coverage.required_complete, 'bounded': not report.coverage.enumeration_complete, 'decision': report.decision.verdict.value})
    finally:
        conn.close()


def scan_paths(paths, budget, max_files, use_cache=True):
    from . import models as m
    service = ScanService(_legacy_config(), state_dir=STATE)
    try:
        report = service.scan_paths(paths, policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(budget, max_files, max_file_bytes=CONFIG['max_file_bytes']), use_cache=use_cache)
    finally:
        service.close()
    return _legacy_report_from_typed(report, 'manual')


def audit(scope, budget, max_files):
    from . import models as m
    service = ScanService(_legacy_config(), state_dir=STATE)
    try:
        report = service.audit(scope, limits=m.ScanLimits(budget, max_files, max_file_bytes=CONFIG['max_file_bytes']))
    finally:
        service.close()
    return _legacy_report_from_typed(report, 'audit-' + scope)


def drain():
    from . import models as m
    service = ScanService(_legacy_config(), state_dir=STATE)
    try:
        report = service.drain(limits=m.ScanLimits(45, 150, max_file_bytes=CONFIG['max_file_bytes']))
    finally:
        service.close()
    return _legacy_report_from_typed(report, 'watch')


def git(*args, cwd=None, check=True):
    return subprocess.run(['git', *args], cwd=cwd, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def git_findings(raw, repo):
    normalized = []
    for item in raw:
        item = dict(item)
        path = pathlib.Path(item.get('File', ''))
        item['File'] = str(path if path.is_absolute() else repo / path)
        normalized.append(item)
    findings = safe_findings(normalized)
    blobs = {}

    def blob(revision, relative):
        key = (revision, relative)
        if key not in blobs:
            spec = (revision or '') + ':' + relative
            size = git('cat-file', '-s', spec, cwd=repo, check=False)
            if size.returncode or int(size.stdout) > finding_details.MAX_CONTEXT_BYTES:
                blobs[key] = None
            else:
                content = git('show', spec, cwd=repo, check=False)
                blobs[key] = content.stdout if content.returncode == 0 else None
        return blobs[key]

    described = []
    for finding in findings:
        path = pathlib.Path(finding['path'])
        if path.suffix.lower() != '.json':
            described.append(finding_details.describe(finding)); continue
        try:
            relative = path.relative_to(repo).as_posix()
        except ValueError:
            described.append(finding_details.describe(finding)); continue
        revision = finding.get('commit')
        data = blob(revision, relative)
        parent = pathlib.PurePosixPath(relative).parent
        described.append(finding_details.describe(finding, data, lambda module: blob(revision, str(parent / module))))
    return described


def existing_hook(repo, kind, args, payload):
    from .git_scanning import git_output, path_output
    hooks = pathlib.Path(path_output(git_output(repo, 'rev-parse', '--path-format=absolute', '--git-path', 'hooks', maximum=1_000_000, timeout=5)[1]))
    backup = hooks / (kind + '.before-leakguard')
    if not backup.exists():
        return 0
    import shutil
    exe = pathlib.Path(shutil.which('git'))
    shell = next((p for p in [exe.parent.parent / 'bin' / 'sh.exe', exe.parent.parent / 'usr' / 'bin' / 'sh.exe'] if p.exists()), None)
    return subprocess.run([str(shell or 'sh'), str(backup), *args], cwd=repo, input=payload).returncode


def git_hook(kind, args):
    """Compatibility hook adapter; the typed service owns scan and policy."""
    _legacy()
    from . import models as m
    from .git_scanning import parse_push, repository_root
    service = None
    try:
        repo = repository_root(pathlib.Path.cwd(), deadline=time.monotonic() + 5)
        payload = sys.stdin.buffer.read(1_000_001) if kind == 'pre-push' else b''
        if kind == 'pre-commit':
            prior = existing_hook(repo, kind, args, payload)
            if prior:
                return prior
        request = m.GitRequest(m.GitRequestKind.INDEX) if kind == 'pre-commit' else parse_push(payload)
        config = dict(CONFIG)
        config['gitleaks_executable'] = str(EXE)
        config['gitleaks_config'] = str(RULES)
        service = ScanService(config, state_dir=STATE)
        report = service.scan_git(repo, request=request, limits=m.ScanLimits(120, 1000, max_file_bytes=CONFIG['max_file_bytes']))
        print(presentation.render(report), file=sys.stderr)
        if report.decision.verdict is m.DecisionVerdict.INCOMPLETE:
            print('LeakGuard could not complete this Git scan; Git operation blocked.', file=sys.stderr)
            return 2
        if report.decision.verdict is m.DecisionVerdict.BLOCK:
            print('LeakGuard blocked this Git operation; values remain redacted.', file=sys.stderr)
            return 1
    except Exception:
        print('LeakGuard could not complete the scan (scan-failed); Git operation blocked.', file=sys.stderr)
        return 2
    finally:
        if service is not None:
            service.close()
    return existing_hook(repo, kind, args, payload) if kind == 'pre-push' else 0


def _legacy_git_report(report, repo, kind):
    findings = []
    for result in report.results:
        for finding in result.findings:
            item = {'id': finding.id, 'path': str(repo / finding.source.path), 'part': finding.part_id, 'line': finding.start_line, 'end_line': finding.end_line, 'rule': finding.rule, 'severity': finding.severity.value, 'detector_severity': finding.detector_severity.value, 'classification': finding.classification.value, 'profile': 'git'}
            if finding.source.commit:
                item['commit'] = finding.source.commit
            findings.append(finding_details.describe(item))
    issues = [{'path': issue.source.path if issue.source else str(repo), 'status': issue.code.value} for result in report.results for issue in result.issues if issue.required]
    issues.extend({'path': issue.source.path if issue.source else str(repo), 'status': issue.code.value} for issue in report.issues if issue.required)
    return {'checked_utc': report.finished_at.isoformat(), 'label': 'git-' + kind, 'repo': str(repo), 'file_counts': {result.outcome.value: sum(item.outcome == result.outcome for item in report.results) for result in report.results}, 'findings': findings, 'findings_count': len(findings), 'coverage_issues': issues, 'decision': report.decision.verdict.value}


class _IssueBudget(list):
    """Bound diagnostics while reserving a fixed, source-less truncation issue."""
    def __init__(self, maximum):
        from . import models as m
        super().__init__()
        self.maximum = maximum
        self.used = 0
        self.truncated = False
        self.marker = m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, required=True)
        self.reserve = self._size(self.marker) + 1

    @staticmethod
    def _size(issue):
        from . import models as m
        return len(json.dumps(m._issue_dict(issue), ensure_ascii=True, separators=(',', ':')).encode('utf-8'))

    def append(self, issue):
        if self.truncated:
            return False
        size = self._size(issue) + 1
        if self.used + size + self.reserve > self.maximum:
            super().append(self.marker)
            self.used += self.reserve
            self.truncated = True
            return False
        super().append(issue)
        self.used += size
        return True

    def extend(self, values):
        for issue in values:
            if not self.append(issue):
                break


def _admit_result(result, available):
    """Keep a bounded positive prefix before using remaining space for issues."""
    from dataclasses import replace
    from . import models as m
    from .scan_store import _result_json
    # Never materialize the entire candidate merely to measure it. A bounded
    # base plus one record at a time has exactly the same canonical JSON cost.
    base = replace(result, findings=(), issues=())
    size = len(_result_json(base).encode('utf-8'))
    exceeded = size > available
    if not exceeded:
        for index, finding in enumerate(result.findings):
            cost = len(json.dumps(m._finding_dict(finding), ensure_ascii=True, separators=(',', ':')).encode('utf-8')) + bool(index)
            if size + cost > available:
                exceeded = True
                break
            size += cost
    if not exceeded:
        for index, issue in enumerate(result.issues):
            cost = _IssueBudget._size(issue) + bool(index)
            if size + cost > available:
                exceeded = True
                break
            size += cost
    if not exceeded:
        return result, size, False
    marker = m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, required=True)
    bounded = replace(result, outcome=m.ScanOutcome.ERROR if result.outcome is m.ScanOutcome.REUSED else result.outcome,
                      coverage=m.CoverageState.INCOMPLETE, findings=(), issues=(marker,), last_verified_at=None)
    used = len(_result_json(bounded).encode('utf-8'))
    if used > available:
        return None, 0, True
    accepted = []
    for finding in result.findings:
        cost = len(json.dumps(m._finding_dict(finding), ensure_ascii=True, separators=(',', ':')).encode('utf-8')) + bool(accepted)
        if used + cost > available:
            break
        accepted.append(finding)
        used += cost
    issues = [marker]
    for issue in result.issues:
        cost = _IssueBudget._size(issue) + 1
        if used + cost > available:
            break
        issues.append(issue)
        used += cost
    bounded = replace(bounded, findings=tuple(accepted), issues=tuple(issues))
    return bounded, len(_result_json(bounded).encode('utf-8')), True


def _cap_report(report, maximum):
    """Last-resort guard after exact canonical serialization, always fail closed."""
    from . import models as m
    if len(report.to_json().encode('utf-8')) <= maximum:
        return report
    return m.ScanReport(1, report.run_id, report.started_at, report.finished_at, report.policy_id, (),
                        m.CoverageSummary(False, False, 0),
                        m.PolicyDecision(m.DecisionVerdict.INCOMPLETE, (m.ErrorCode.DETECTOR_OUTPUT_LIMIT,), report.policy_id),
                        (m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, required=True),))


class ScanService:
    """One bounded pipeline for files, caller bytes and immutable Git snapshots."""
    def __init__(self, config, *, state_dir=None, store=None):
        from . import scan_policy
        from .scan_store import MemoryScanStore, SQLiteScanStore
        from .settings import validate
        self.config = validate(config.to_mapping() if hasattr(config, 'to_mapping') else dict(config))
        if self.config.get('extension_registry'):
            from .extensions import ExtensionRegistry
            self.config = ExtensionRegistry(self.config['extension_registry']).apply(self.config, self.config.get('detection_profile', 'credentials'))
        self.binary = self.config.get('gitleaks_executable') or shutil.which('gitleaks') or 'gitleaks'
        self.rules = self.config.get('gitleaks_config') or ROOT / 'rules.toml'
        self.state_dir = pathlib.Path(state_dir) if state_dir is not None else None
        from .storage import open_scan_store
        self.store = store if store is not None else open_scan_store(self.state_dir, config=self.config)
        self._owns_store = store is None
        self._closed = False
        try:
            self._plugins = plugins.load(self.config.get('plugins', []), worker_policy=self.config.get('worker_policy', 'strict'))
            if self.config.get('script_checks'):
                self._plugins.extend(plugins.load_scripts(self.config['script_checks']))
            self._runtime, self._cache_eligible = scan_policy.runtime_identity(self.config, self.binary, self.config.get('plugins', ()), plugin_manifests=tuple(getattr(instance, 'manifest', None) for instance in self._plugins))
            # Until a verifiable plugin dependency closure is available, execution is
            # supported and persistent semantic reuse is deliberately disabled.
            self._cache_eligible = self._cache_eligible and not self._plugins
        except Exception:
            if self._owns_store:
                self.store.close()
            raise

    def close(self):
        if not self._closed:
            self._closed = True
            if self._owns_store:
                self.store.close()

    def _material_snapshot(self, limits):
        try:
            return self.store.material_snapshot(max_bytes=min(limits.max_file_bytes, 1_000_000), max_sources=100)
        except Exception:
            return catalog.MaterialSnapshot((), 'unavailable', ('source-unavailable',))

    def _work_context(self, *, policy, limits):
        """Capture one transient material capability for identity and execution.

        Only the bounded keyed snapshot identity enters the continuation digest.
        This reads registered references, never the separate credential vault.
        """
        from . import models as m, scan_policy
        from .execution import work_identity
        from .sources import AcquisitionError
        materials = None
        if scan_policy.effective_policy(policy, self.config).mode is m.ScanMode.INVENTORY:
            materials = self._material_snapshot(limits)
            if materials.issues:
                raise AcquisitionError(materials.issues[0])
            try:
                valid = materials.valid()
            except Exception:
                valid = False
            if not valid:
                raise AcquisitionError('source-unavailable')
        identity = work_identity(config=self.config, runtime=self._runtime, policy=policy, limits=limits,
                                 material_identity=materials.identity if materials is not None else None)
        return identity, materials

    def work_identity(self, *, policy, limits):
        from .scan_store import StateError
        if self._closed:
            raise StateError('state-closed')
        return self._work_context(policy=policy, limits=limits)[0]

    def scan(self, inputs, *, policy, limits, use_cache=True, cancel=None):
        return self._run(inputs, policy=policy, limits=limits, use_cache=use_cache, cancel=cancel)

    def scan_paths(self, paths, *, policy, limits, use_cache=True, cancel=None):
        from .execution import Cancellation
        if not isinstance(cancel, Cancellation):
            cancel = Cancellation(cancel)
        from itertools import islice
        from . import models as m
        from .sources import (directory_signature, AcquisitionError, FilesystemBoundary,
                              ScopedFileInput, scoped_scandir)
        state = {'complete': True, 'issues': _IssueBudget(min(32768, limits.max_report_bytes // 16)), 'pending_files': None, 'pending_directories': 0}
        deadline = time.monotonic() + limits.deadline_seconds
        pending = [pathlib.Path(path) for path in islice(iter(paths), limits.max_directory_entries + 1)]
        if len(pending) > limits.max_directory_entries:
            pending.pop()
            state['complete'] = False
            state['issues'].append(m.CoverageIssue(m.ErrorCode.BUDGET_EXHAUSTED, required=True))
        signatures = {}
        retry = set()
        admitted = 0
        boundaries = []
        invalid_roots = set()
        for path in pending:
            if path.is_dir() and not path.is_symlink():
                try:
                    boundaries.append(FilesystemBoundary(path))
                except (OSError, AcquisitionError):
                    invalid_roots.add(path)
                    state['complete'] = False
                    state['issues'].append(m.CoverageIssue(m.ErrorCode.SOURCE_UNAVAILABLE, m.SourceRef(m.SourceKind.FILESYSTEM, str(path.absolute())), required=True))

        def boundary_for(path):
            absolute = pathlib.Path(os.path.abspath(path))
            choices = [item for item in boundaries if absolute.is_relative_to(item.root)]
            return max(choices, key=lambda item: len(item.root.parts)) if choices else None

        def changed(path, code=m.ErrorCode.INPUT_CHANGED):
            state['complete'] = False
            retry.add(path)
            state['issues'].append(m.CoverageIssue(code, m.SourceRef(m.SourceKind.FILESYSTEM, str(path.absolute())), required=True))

        def walk():
            nonlocal admitted
            while pending:
                if time.monotonic() >= deadline or (cancel and cancel()):
                    state['complete'] = False
                    break
                path = pending.pop()
                if path in invalid_roots:
                    continue
                boundary = boundary_for(path)
                if self._excluded(path):
                    state['issues'].append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, m.SourceRef(m.SourceKind.FILESYSTEM, str(path.absolute())), omission_id='operator-exclusion'))
                    continue
                if path.is_dir() and not path.is_symlink():
                    finished = False
                    try:
                        before = directory_signature(path, boundary)
                        signatures[path] = before
                        with scoped_scandir(path, boundary) as entries:
                            for entry in entries:
                                if time.monotonic() >= deadline or admitted >= limits.max_directory_entries or (cancel and cancel()):
                                    state['complete'] = False
                                    return
                                admitted += 1
                                child = path / entry.name
                                if self._excluded(child):
                                    state['issues'].append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, m.SourceRef(m.SourceKind.FILESYSTEM, str(child.absolute())), omission_id='operator-exclusion'))
                                    continue
                                if entry.is_dir(follow_symlinks=False):
                                    pending.append(child)
                                else:
                                    yield ScopedFileInput(child, boundary) if boundary is not None else m.FileInput(child)
                        finished = True
                        if directory_signature(path, boundary) != before:
                            changed(path)
                    except (OSError, AcquisitionError):
                        changed(path, m.ErrorCode.ENUMERATION_FAILED)
                    finally:
                        if not finished:
                            state['complete'] = False
                            retry.add(path)
                else:
                    yield ScopedFileInput(path, boundary) if boundary is not None else m.FileInput(path)

        def enumeration():
            # Recheck even directories whose iterator closed before a later
            # detector ran. These are sequential observations, not a tree lock.
            checked = set()
            for path, expected in signatures.items():
                boundary = boundary_for(path)
                if time.monotonic() >= deadline or (cancel and cancel()):
                    state['complete'] = False
                    state['issues'].append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                    break
                try:
                    if directory_signature(path, boundary) != expected:
                        changed(path)
                except AcquisitionError:
                    changed(path, m.ErrorCode.SOURCE_UNAVAILABLE)
                checked.add(path)
            state['pending_directories'] = len(set(pending) | retry | (set(signatures) - checked))
            return {**state, 'complete': state['complete'] and not state['issues'].truncated}
        return self._run(walk(), policy=policy, limits=limits, use_cache=use_cache, cancel=cancel, enumeration=enumeration, _deadline=deadline, _clear_deadline=True)

    def _excluded(self, path):
        path = pathlib.Path(path).absolute()
        if self.state_dir is not None and (path == self.state_dir.absolute() or self.state_dir.absolute() in path.parents):
            return True
        for root in self.config.get('exclude_roots', []):
            base = pathlib.Path(root).absolute()
            if path == base or base in path.parents:
                return True
        return any(part.lower() in self.config.get('exclude_components', ('.git',)) for part in path.parts)

    def scan_git(self, repo, *, request, limits, cancel=None):
        from . import git_scanning, models as m
        session = git_scanning.GitInputs(pathlib.Path(repo), request, limits=limits, cancel=cancel)
        return self._run(session, policy=m.ScanPolicy.git(), limits=limits, use_cache=False, cancel=cancel, enumeration=session.status, final_check=session.valid, repository=str(session.repo), _deadline=session.deadline, _clear_deadline=True)

    def confirm_absent(self, path, *, root, limits):
        """Internal explicit absence check, separate from failed scans/events."""
        from . import models as m
        from .sources import confirm_absence
        if self._closed or type(limits) is not m.ScanLimits:
            return False
        deadline = time.monotonic() + limits.deadline_seconds
        if '..' in pathlib.Path(path).parts or '..' in pathlib.Path(root).parts:
            return False
        source = m.SourceRef(m.SourceKind.FILESYSTEM, os.path.abspath(path))
        if not hasattr(self.store, 'source_anchor') or not hasattr(self.store, 'confirm_absent'):
            return False
        try:
            if hasattr(self.store, 'set_deadline'):
                self.store.set_deadline(deadline)
            generation = self.store.reserve(source)
            anchor = self.store.source_anchor(source)
            proof = confirm_absence(path, root, anchor)
            if time.monotonic() >= deadline:
                return False
            return self.store.confirm_absent(proof, generation=generation)
        except Exception:
            try:
                self.store.invalidate_scope(source.path)
            except Exception:
                pass
            return False
        finally:
            if hasattr(self.store, 'set_deadline'):
                try:
                    self.store.set_deadline(None)
                except Exception:
                    pass

    def audit(self, scope, *, limits, use_cache=True, cancel=None):
        from .settings import ConfigurationError
        if scope not in self.config.get('audit_scopes', {}):
            raise ConfigurationError('audit_scopes')
        root = pathlib.Path(self.config['audit_scopes'][scope]).absolute()
        return self._work_batch('audit:' + scope, root, limits=limits, use_cache=use_cache, cancel=cancel)

    def drain(self, *, limits, use_cache=False, cancel=None):
        return self._work_batch('watch', None, limits=limits, use_cache=use_cache, cancel=cancel, ingest=True)

    def _work_batch(self, scope, root, *, limits, use_cache, cancel, ingest=False):
        from .execution import Cancellation
        if not isinstance(cancel, Cancellation):
            cancel = Cancellation(cancel)
        from . import models as m
        from .scan_store import StateError, DirectoryProgress
        from .sources import (directory_signature, AcquisitionError, FilesystemBoundary,
                              ScopedFileInput, scoped_scandir)
        issues = _IssueBudget(min(32768, limits.max_report_bytes // 16))
        lease = None
        claims = {}
        deadline = time.monotonic() + limits.deadline_seconds
        enumerated = 0
        replayed = 0
        progress_supported = all(hasattr(self.store, name) for name in (
            'get_directory_progress', 'set_directory_progress'))
        completed = False
        def failure(code, source=None):
            try:
                return self._run((), policy=m.ScanPolicy.inventory(), limits=limits, use_cache=False, cancel=cancel, enumeration=lambda: {'complete': False, 'issues': (m.CoverageIssue(code, source, required=True),)}, _deadline=deadline)
            finally:
                if hasattr(self.store, 'set_deadline'):
                    try:
                        self.store.set_deadline(None)
                    except Exception:
                        pass
        required_methods = ('acquire_cycle', 'claim_work', 'enqueue_work', 'finish_directory', 'directory_page', 'record_directory_checks', 'cycle_status', 'lease_valid', 'release_cycle', 'invalidate_scope', 'record_event')
        if root is not None:
            required_methods += ('reconcile_cycle',)
        if any(not hasattr(self.store, name) for name in required_methods):
            return failure(m.ErrorCode.STATE_FAILED)
        if hasattr(self.store, 'set_deadline'):
            try:
                self.store.set_deadline(deadline)
            except Exception:
                return self._state_failure_report(m.ScanPolicy.inventory(), limits)
        if root is not None and any(not hasattr(self.store, name) for name in ('bind_cycle_identity', 'cycle_decision_evidence')):
            return failure(m.ErrorCode.WORK_IDENTITY_UNAVAILABLE)
        if root is not None and not root.is_dir():
            try:
                self.store.invalidate_scope(root)
            except Exception:
                pass
            return failure(m.ErrorCode.SOURCE_UNAVAILABLE, m.SourceRef(m.SourceKind.FILESYSTEM, str(root)))
        try:
            boundary = FilesystemBoundary(root) if root is not None else None
        except (OSError, AcquisitionError):
            return failure(m.ErrorCode.SOURCE_UNAVAILABLE)
        try:
            lease = self.store.acquire_cycle(scope, root, lease_seconds=limits.deadline_seconds + 30)
        except Exception:
            lease = None
        if lease is None:
            return failure(m.ErrorCode.STATE_FAILED)
        try:
            materials = None
            if root is not None:
                try:
                    identity, materials = self._work_context(policy=m.ScanPolicy.inventory(), limits=limits)
                except AcquisitionError as error:
                    return failure(self._error_code(error.code, 'source-unavailable'))
                digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                self.store.bind_cycle_identity(lease, digest, root=root)
            if ingest:
                issues.extend(self._ingest_queue(lease))
            elif root is not None:
                preferred = self.config.get('priority_paths', {}).get(scope.removeprefix('audit:'), ())
                self.store.enqueue_work(lease, ((str(pathlib.Path(path).absolute()), 'directory', 0) for path in preferred[:1000]))

            def work_inputs():
                nonlocal enumerated, replayed
                while time.monotonic() < deadline and not (cancel and cancel()):
                    claim = self.store.claim_work(lease)
                    if claim is None:
                        return
                    path = pathlib.Path(claim.path)
                    if self._excluded(path):
                        issues.append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), omission_id='operator-exclusion'))
                        self.store.finish_directory(claim, success=True, omitted=True)
                        continue
                    if claim.kind == 'file':
                        claims[str(path.absolute())] = claim
                        yield ScopedFileInput(path, boundary) if boundary is not None else m.FileInput(path)
                        continue
                    if enumerated >= limits.max_directory_entries:
                        issues.append(m.CoverageIssue(m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                        return
                    entries_batch = []
                    exhausted = True
                    position = 0
                    prefix = hashlib.sha256()
                    def changed_cursor():
                        if progress_supported:
                            self.store.set_directory_progress(claim, None)
                        self.store.finish_directory(claim, success=None)
                        self.store.invalidate_scope(path)
                        issues.append(m.CoverageIssue(m.ErrorCode.INPUT_CHANGED, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), required=True))
                    try:
                        before = directory_signature(path, boundary)
                        progress = self.store.get_directory_progress(claim) if progress_supported else None
                        if progress is not None and progress.signature != before:
                            self.store.set_directory_progress(claim, None)
                            self.store.invalidate_scope(path)
                            issues.append(m.CoverageIssue(m.ErrorCode.INPUT_CHANGED, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), required=True))
                            progress = None
                        resume = progress.entries if progress is not None else 0
                        with scoped_scandir(path, boundary) as entries:
                            for entry in entries:
                                if time.monotonic() >= deadline or (cancel and cancel()):
                                    exhausted = False
                                    break
                                if position < resume:
                                    if replayed >= 100_000:
                                        self.store.finish_directory(claim, success=False)
                                        issues.append(m.CoverageIssue(m.ErrorCode.INPUT_LIMIT, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), required=True))
                                        return
                                    kind = 'directory' if entry.is_dir(follow_symlinks=False) else 'file'
                                    prefix.update(json.dumps([entry.name, kind], ensure_ascii=True, separators=(',', ':')).encode() + b'\n')
                                    position += 1
                                    replayed += 1
                                    if position == resume and prefix.hexdigest() != progress.prefix_sha256:
                                        changed_cursor()
                                        return
                                    continue
                                if position >= 100_000:
                                    self.store.finish_directory(claim, success=False)
                                    issues.append(m.CoverageIssue(m.ErrorCode.INPUT_LIMIT, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), required=True))
                                    return
                                if enumerated >= limits.max_directory_entries:
                                    exhausted = False
                                    break
                                enumerated += 1
                                position += 1
                                child = path / entry.name
                                kind = 'directory' if entry.is_dir(follow_symlinks=False) else 'file'
                                prefix.update(json.dumps([entry.name, kind], ensure_ascii=True, separators=(',', ':')).encode() + b'\n')
                                if self._excluded(child):
                                    # A synthetic directory row records an
                                    # exclusion durably, including excluded
                                    # files. Its claim is finished as omitted
                                    # above, without acquiring or enumerating it.
                                    entries_batch.append((str(child.absolute()), 'directory', 101))
                                else:
                                    entries_batch.append((str(child.absolute()), kind, 100 if kind == 'file' else 101))
                                if len(entries_batch) >= 256:
                                    self.store.enqueue_work(lease, tuple(entry for entry in entries_batch if entry[1] == 'directory'))
                                    self.store.enqueue_work(lease, tuple(entry for entry in entries_batch if entry[1] == 'file'), refresh=True)
                                    entries_batch.clear()
                        if entries_batch:
                            self.store.enqueue_work(lease, tuple(entry for entry in entries_batch if entry[1] == 'directory'))
                            self.store.enqueue_work(lease, tuple(entry for entry in entries_batch if entry[1] == 'file'), refresh=True)
                        stable = directory_signature(path, boundary) == before
                        if not stable or position < resume and exhausted:
                            changed_cursor()
                            return
                        if position < resume:
                            # Budget/cancellation during prefix verification does
                            # not invalidate the previously durable cursor.
                            self.store.finish_directory(claim, success=None)
                            issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                            return
                        if progress_supported and not exhausted:
                            self.store.set_directory_progress(claim, DirectoryProgress(before, position, prefix.hexdigest()))
                        self.store.finish_directory(claim, success=True if exhausted else None if progress_supported else False, signature=before if exhausted else None)
                        if not exhausted:
                            code = m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED if progress_supported else m.ErrorCode.INPUT_LIMIT
                            issues.append(m.CoverageIssue(code, required=True))
                            if cancel and cancel():
                                return
                            # Drain the newly queued files before this partial
                            # directory is eligible for a retry on the next slice.
                            continue
                    except (OSError, AcquisitionError):
                        self.store.finish_directory(claim, success=False)
                        self.store.invalidate_scope(path)
                        issues.append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), required=True))
                issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, required=True))

            def status():
                metadata = self.store.cycle_status(lease)
                checked = 0
                while not metadata.get('pending_files') and checked < limits.max_directory_entries:
                    if time.monotonic() >= deadline or cancel is not None and cancel():
                        issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                        break
                    page = self.store.directory_page(lease, limit=min(256, limits.max_directory_entries - checked))
                    if not page:
                        break
                    checks = []
                    invalid = False
                    for snapshot in page:
                        if time.monotonic() >= deadline or cancel is not None and cancel():
                            issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                            break
                        code = m.ErrorCode.INPUT_CHANGED
                        try:
                            valid = snapshot.signature is not None and directory_signature(snapshot.path, boundary) == snapshot.signature
                        except AcquisitionError:
                            valid = False
                            code = m.ErrorCode.SOURCE_UNAVAILABLE
                        checks.append((snapshot.path, snapshot.signature, valid))
                        checked += 1
                        if not valid:
                            invalid = True
                            self.store.invalidate_scope(snapshot.path)
                            issues.append(m.CoverageIssue(code, m.SourceRef(m.SourceKind.FILESYSTEM, snapshot.path), required=True))
                    if checks:
                        self.store.record_directory_checks(lease, checks)
                    if invalid or len(checks) < len(page):
                        break
                if time.monotonic() < deadline:
                    metadata = self.store.cycle_status(lease)
                else:
                    metadata = {**metadata, 'complete': False}
                if metadata.get('failed'):
                    issues.append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, required=True))
                complete = metadata['complete'] and not any(issue.required for issue in issues)
                evidence = None
                if root is not None and complete:
                    evidence = self.store.cycle_decision_evidence(lease)
                    if (type(evidence) is not dict or set(evidence) != {'severities', 'has_omissions', 'files'}
                            or type(evidence['severities']) is not tuple
                            or any(value not in {'block', 'review', 'info'} for value in evidence['severities'])
                            or type(evidence['has_omissions']) is not bool
                            or type(evidence['files']) is not int or evidence['files'] < 0):
                        raise StateError()
                return {**metadata, 'complete': complete, 'issues': tuple(issues), 'cycle_evidence': evidence}
            report = self._run(work_inputs(), policy=m.ScanPolicy.inventory(), limits=limits, use_cache=use_cache, cancel=cancel, enumeration=status, final_check=lambda: self.store.lease_valid(lease), work_claims=claims, _deadline=deadline, _materials=materials)
            if report.coverage.enumeration_complete and report.coverage.required_complete:
                try:
                    if time.monotonic() >= deadline or cancel is not None and cancel():
                        raise StateError()
                    if root is not None:
                        self.store.reconcile_cycle(lease, root)
                    self.store.release_cycle(lease, allow_complete=True)
                    completed = True
                except Exception:
                    from dataclasses import replace
                    from . import scan_policy
                    failure_issues = report.issues + (m.CoverageIssue(m.ErrorCode.STATE_FAILED, required=True),)
                    coverage, decision = scan_policy.evaluate(report.results, policy=m.ScanPolicy.inventory(), policy_id=report.policy_id, enumeration_complete=False, issues=failure_issues, pending_files=report.coverage.pending_files, pending_directories=report.coverage.pending_directories, cycle_id=report.coverage.cycle_id)
                    report = _cap_report(replace(report, coverage=coverage, decision=decision, issues=failure_issues), limits.max_report_bytes)
                    try:
                        self.store.record_report(report)
                    except Exception:
                        pass
            return report
        except Exception:
            return failure(m.ErrorCode.STATE_FAILED)
        finally:
            try:
                self.store.release_cycle(lease, allow_complete=completed)
            except Exception:
                pass
            if hasattr(self.store, 'set_deadline'):
                try:
                    self.store.set_deadline(None)
                except Exception:
                    pass

    def _ingest_queue(self, lease):
        from . import models as m
        from .scan_store import SQLiteScanStore
        from .sources import _bounded_file, AcquisitionError
        issues = []
        # This is a bounded import of the legacy notification spool into the
        # default store. Injected stores receive work through their own queue API.
        if not self._owns_store or not isinstance(self.store, SQLiteScanStore) or self.state_dir is None:
            return issues
        queue = self.state_dir / 'queue'
        if not queue.is_dir():
            return issues
        imported = 0
        try:
            with os.scandir(queue) as entries:
                for entry in entries:
                    if imported >= 20:
                        issues.append(m.CoverageIssue(m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                        break
                    if not entry.name.endswith('.json') or entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        continue
                    imported += 1
                    try:
                        batch = json.loads(_bounded_file(pathlib.Path(entry.path), 1_000_000).decode('utf-8-sig'))
                        values = batch if type(batch) is list else [batch]
                        if len(values) > 10_000:
                            raise ValueError()
                        events = []
                        for value in values:
                            if type(value) is str:
                                value = {'path': value, 'kind': 'changed'}
                            if (type(value) is not dict or not {'path'} <= set(value) <= {'path', 'kind', 'old_path', 'observed'}
                                    or type(value['path']) is not str or not 0 < len(value['path']) <= 4096
                                    or value.get('kind', 'changed') not in {'created', 'changed', 'renamed', 'deleted'}
                                    or value.get('old_path') is not None and (type(value['old_path']) is not str or len(value['old_path']) > 4096)):
                                raise ValueError()
                            events.append(value)
                        pending = []
                        for event in events:
                            path = str(pathlib.Path(event['path']).absolute())
                            if self._excluded(path):
                                continue
                            kind = event.get('kind', 'changed')
                            self.store.record_event(path, kind, old_path=event.get('old_path'))
                            if kind != 'deleted':
                                try:
                                    target = pathlib.Path(path)
                                    if target.is_file() and not target.is_symlink() and hasattr(self.store, 'record_metadata'):
                                        self.store.record_metadata(path, target.stat().st_size)
                                except OSError:
                                    pass
                                pending.append((path, 'file', 0))
                        for offset in range(0, len(pending), 1000):
                            self.store.enqueue_work(lease, pending[offset:offset + 1000], refresh=True)
                        pathlib.Path(entry.path).unlink()
                    except (ValueError, UnicodeError, OSError, AcquisitionError):
                        issues.append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, required=True))
        except OSError:
            issues.append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, required=True))
        return issues

    def _state_failure_report(self, policy, limits):
        # Failed budget setup authorizes no further calls into that store. This
        # local result has no fallback archive or implicit durable mirror.
        from . import models as m, scan_policy
        policy = scan_policy.effective_policy(policy, self.config)
        policy_id = scan_policy.policy_identity(config=self.config, policy=policy, limits=limits)
        issues = (m.CoverageIssue(m.ErrorCode.STATE_FAILED, required=True),)
        if getattr(self.store, '_leakguard_ephemeral_observations', False):
            issues += (m.CoverageIssue(m.ErrorCode.OBSERVATIONS_EPHEMERAL),)
        if self.config.get('worker_policy') == 'supervised-alpha':
            issues += (m.CoverageIssue(m.ErrorCode.SUPERVISED_ALPHA_POLICY),)
        coverage, decision = scan_policy.evaluate((), policy=policy, policy_id=policy_id, enumeration_complete=False, issues=issues)
        now = dt.datetime.now(dt.timezone.utc)
        return _cap_report(m.ScanReport(1, uuid.uuid4().hex, now, now, policy_id, (), coverage, decision, issues), limits.max_report_bytes)

    def _run(self, inputs, *, policy, limits, use_cache, cancel, enumeration=None, final_check=None, work_claims=None, _deadline=None, repository=None, _clear_deadline=False, _materials=None):
        from .scan_store import StateError
        if self._closed:
            raise StateError('state-closed')
        if limits.max_report_bytes < 2048:
            raise ValueError('max_report_bytes')
        from .execution import Cancellation
        if not isinstance(cancel, Cancellation):
            cancel = Cancellation(cancel)
        deadline = _deadline if _deadline is not None else time.monotonic() + limits.deadline_seconds
        if hasattr(self.store, 'set_deadline'):
            try:
                self.store.set_deadline(deadline)
            except Exception:
                return self._state_failure_report(policy, limits)
        try:
            return self._run_inner(inputs, policy=policy, limits=limits, use_cache=use_cache, cancel=cancel, enumeration=enumeration, final_check=final_check, work_claims=work_claims, _deadline=deadline, repository=repository, _materials=_materials)
        finally:
            if (_deadline is None or _clear_deadline) and hasattr(self.store, 'set_deadline'):
                try:
                    self.store.set_deadline(None)
                except Exception:
                    pass

    def _run_inner(self, inputs, *, policy, limits, use_cache, cancel, enumeration=None, final_check=None, work_claims=None, _deadline=None, repository=None, _materials=None):
        from dataclasses import replace
        from . import models as m, scan_policy
        from .sources import SnapshotInput, acquire_file, acquire_bytes, AcquisitionError
        from .scan_store import StateError, _result_json
        if self._closed:
            raise StateError('state-closed')
        policy = scan_policy.effective_policy(policy, self.config)
        policy_id = scan_policy.policy_identity(config=self.config, policy=policy, limits=limits)
        started = dt.datetime.now(dt.timezone.utc)
        deadline = _deadline
        results = []
        reservations = []
        material_results = []
        snapshots = []
        anchors = []
        run_issues = _IssueBudget(min(32768, limits.max_report_bytes // 16))
        if getattr(self.store, '_leakguard_ephemeral_observations', False):
            run_issues.append(m.CoverageIssue(m.ErrorCode.OBSERVATIONS_EPHEMERAL))
        if self.config.get('worker_policy') == 'supervised-alpha':
            run_issues.append(m.CoverageIssue(m.ErrorCode.SUPERVISED_ALPHA_POLICY))
        enumeration_complete = True
        finding_count = 0
        report_bytes = 0
        envelope_bytes = 1024 + min(1024, limits.max_report_bytes // 16)
        identity_failure = None
        try:
            runtime, eligible = scan_policy.runtime_identity(self.config, self.binary, self.config.get('plugins', ()), plugin_manifests=tuple(getattr(instance, 'manifest', None) for instance in self._plugins), deadline=deadline, cancel=cancel)
            runtime_valid = runtime == self._runtime
            if not runtime_valid:
                identity_failure = m.ErrorCode.SOURCE_UNAVAILABLE
        except scan_policy.RuntimeIdentityError as error:
            runtime_valid = False
            identity_failure = self._error_code(error.code, 'source-unavailable')
        if identity_failure is not None:
            run_issues.append(m.CoverageIssue(identity_failure, required=True))
            enumeration_complete = False
        materials = _materials
        if runtime_valid and policy.mode is m.ScanMode.INVENTORY:
            if materials is None:
                materials = self._material_snapshot(limits)
            if materials.issues:
                enumeration_complete = False
                run_issues.extend(m.CoverageIssue(self._error_code(code), required=True) for code in materials.issues)
        iterator = self._iter_scanned(inputs, policy=policy, policy_id=policy_id, limits=limits,
                                      deadline=deadline, use_cache=use_cache, cancel=cancel, materials=materials)
        while runtime_valid:
            if time.monotonic() >= deadline or (cancel and cancel()):
                code = m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED
                run_issues.append(m.CoverageIssue(code, required=True))
                enumeration_complete = False
                break
            try:
                source, generation, snapshot, result, cache_key, material_observations = next(iterator)
            except StopIteration:
                break
            except Exception as error:
                code = getattr(error, 'code', 'enumeration-failed')
                source = getattr(error, 'source', None)
                run_issues.append(m.CoverageIssue(self._error_code(code, 'enumeration-failed'), source, required=True))
                enumeration_complete = False
                break
            if finding_count + len(result.findings) > limits.max_findings:
                remaining = max(0, limits.max_findings - finding_count)
                result = replace(result, outcome=m.ScanOutcome.ERROR if result.outcome is m.ScanOutcome.REUSED else result.outcome, findings=result.findings[:remaining], coverage=m.CoverageState.INCOMPLETE, issues=result.issues + (m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, result.source, required=True),), last_verified_at=None)
                cache_key = None
            result, size, truncated = _admit_result(result, limits.max_report_bytes - envelope_bytes - run_issues.maximum - report_bytes - 768)
            if truncated:
                cache_key = None
                enumeration_complete = False
                run_issues.append(m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, required=True))
            if result is None:
                if source.kind is m.SourceKind.FILESYSTEM and hasattr(self.store, 'invalidate_scope'):
                    try:
                        self.store.invalidate_scope(source.path, reason='incomplete-scan')
                    except Exception:
                        pass
                snapshot = None
                break
            # Reserve final source/runtime/material validation issues for every
            # accepted result; later failures cannot evict accepted positives.
            report_bytes += size + 1 + 768
            finding_count += len(result.findings)
            results.append(result)
            reservations.append((generation, cache_key))
            material_results.append(material_observations)
            snapshots.append(snapshot.detach_validator() if snapshot is not None else None)
            anchors.append(snapshot.anchor if snapshot is not None else None)
            snapshot = None
            if not enumeration_complete:
                break
        if hasattr(iterator, 'close'):
            try:
                iterator.close()
            except Exception:
                enumeration_complete = False
                run_issues.append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, required=True))
        try:
            final_valid = final_check is None or final_check()
        except Exception:
            final_valid = False
        if not final_valid:
            enumeration_complete = False
            run_issues.append(m.CoverageIssue(m.ErrorCode.INPUT_CHANGED, required=True))
            results = [replace(r, outcome=m.ScanOutcome.ERROR if r.outcome is m.ScanOutcome.REUSED else r.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=r.issues + (m.CoverageIssue(m.ErrorCode.INPUT_CHANGED, required=True),)) for r in results]
        if identity_failure is None:
            try:
                current_runtime, _ = scan_policy.runtime_identity(self.config, self.binary, self.config.get('plugins', ()), plugin_manifests=tuple(getattr(instance, 'manifest', None) for instance in self._plugins), deadline=deadline, cancel=cancel)
                if current_runtime != self._runtime:
                    identity_failure = m.ErrorCode.SOURCE_UNAVAILABLE
            except scan_policy.RuntimeIdentityError as error:
                identity_failure = self._error_code(error.code, 'source-unavailable')
        if identity_failure is not None:
            enumeration_complete = False
            if not any(issue.code is identity_failure for issue in run_issues):
                run_issues.append(m.CoverageIssue(identity_failure, required=True))
            results = [replace(r, outcome=m.ScanOutcome.ERROR if r.outcome is m.ScanOutcome.REUSED else r.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=r.issues + (m.CoverageIssue(identity_failure, required=True),)) for r in results]
        try:
            materials_valid = materials is None or materials.valid()
        except Exception:
            materials_valid = False
        if not materials_valid:
            enumeration_complete = False
            run_issues.append(m.CoverageIssue(m.ErrorCode.SOURCE_UNAVAILABLE, required=True))
            results = [replace(r, outcome=m.ScanOutcome.ERROR if r.outcome is m.ScanOutcome.REUSED else r.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=r.issues + (m.CoverageIssue(m.ErrorCode.SOURCE_UNAVAILABLE, required=True),)) for r in results]
        for index, validate_snapshot in enumerate(snapshots):
            if validate_snapshot is not None and (time.monotonic() >= deadline or not validate_snapshot()):
                result = results[index]
                code = m.ErrorCode.BUDGET_EXHAUSTED if time.monotonic() >= deadline else m.ErrorCode.INPUT_CHANGED
                anchors[index] = None
                results[index] = replace(result, outcome=m.ScanOutcome.ERROR if result.outcome is m.ScanOutcome.REUSED else result.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=result.issues + (m.CoverageIssue(code, required=True),))
        # Publication is after validation; no slow detector runs under a write lock.
        for result, (generation, cache_key), observations, anchor in zip(results, reservations, material_results, anchors):
            try:
                kwargs = {'work': work_claims.get(result.source.path)} if work_claims is not None else {}
                if anchor is not None and hasattr(self.store, 'source_anchor') and hasattr(self.store, 'confirm_absent'):
                    kwargs['anchor'] = anchor
                if materials is not None and (materials.references or materials.issues):
                    kwargs.update(material_observations=observations, materials_checked=True, materials_complete=result.coverage is m.CoverageState.COMPLETE)
                self.store.record_result(result, generation=generation, cache_key=cache_key if result.coverage is m.CoverageState.COMPLETE else None, **kwargs)
            except Exception:
                run_issues.append(m.CoverageIssue(m.ErrorCode.STATE_FAILED, result.source, required=True))
                enumeration_complete = False
        try:
            metadata = enumeration() if enumeration else {}
        except Exception:
            metadata = {'complete': False, 'issues': (m.CoverageIssue(m.ErrorCode.STATE_FAILED, required=True),)}
        enumeration_complete = enumeration_complete and metadata.get('complete', True)
        run_issues.extend(metadata.get('issues', ()))
        # Enumeration and store publication can outlast file work, including a
        # final slice with no files. Never complete under a changed reference
        # capability merely because the per-file validation loop was empty.
        try:
            materials_valid = materials is None or materials.valid()
        except Exception:
            materials_valid = False
        if not materials_valid:
            enumeration_complete = False
            if not any(issue.code is m.ErrorCode.SOURCE_UNAVAILABLE and issue.required for issue in run_issues):
                run_issues.append(m.CoverageIssue(m.ErrorCode.SOURCE_UNAVAILABLE, required=True))
        cycle_evidence = metadata.get('cycle_evidence')
        if cycle_evidence is not None and (cycle_evidence['files'] > len({result.source.path for result in results})
                                           or cycle_evidence['has_omissions']):
            run_issues.append(m.CoverageIssue(m.ErrorCode.AUDIT_CYCLE_EVIDENCE))
        enumeration_complete = enumeration_complete and not run_issues.truncated
        coverage, decision = scan_policy.evaluate(tuple(results), policy=policy, policy_id=policy_id, enumeration_complete=enumeration_complete, issues=tuple(run_issues), pending_files=metadata.get('pending_files'), pending_directories=metadata.get('pending_directories'), cycle_id=metadata.get('cycle_id'))
        if coverage.required_complete and cycle_evidence is not None:
            # Coverage/decision span the completed audit cycle; immutable results,
            # counts and typed omission_count remain scoped to this report slice.
            blocking = {severity.value for severity in policy.block_severities}
            verdict = (m.DecisionVerdict.BLOCK if blocking.intersection(cycle_evidence['severities'])
                       else m.DecisionVerdict.ALLOW_WITH_OMISSIONS if cycle_evidence['has_omissions'] or decision.verdict is m.DecisionVerdict.ALLOW_WITH_OMISSIONS
                       else m.DecisionVerdict.ALLOW)
            decision = m.PolicyDecision(verdict, (), policy_id)
        report = m.ScanReport(1, uuid.uuid4().hex, started, dt.datetime.now(dt.timezone.utc), policy_id, tuple(results), coverage, decision, tuple(run_issues))
        report = _cap_report(report, limits.max_report_bytes)
        try:
            if repository is None:
                self.store.record_report(report)
            else:
                self.store.record_report(report, repository=repository)
        except Exception:
            issue = m.CoverageIssue(m.ErrorCode.STATE_FAILED, required=True)
            coverage, decision = scan_policy.evaluate(report.results, policy=policy, policy_id=policy_id, enumeration_complete=False, issues=report.issues + (issue,), pending_files=coverage.pending_files, pending_directories=coverage.pending_directories, cycle_id=coverage.cycle_id)
            report = replace(report, coverage=coverage, decision=decision, issues=report.issues + (issue,))
        return _cap_report(report, limits.max_report_bytes)

    @staticmethod
    def _error_code(value, fallback='detector-failed'):
        from .models import ErrorCode
        try:
            return ErrorCode(value)
        except ValueError:
            return ErrorCode(fallback)

    def _iter_scanned(self, inputs, *, policy, policy_id, limits, deadline, use_cache, cancel, materials):
        from . import models as m, backends
        from .execution import Cancellation, InputFailure, ordered_work
        from .sources import SnapshotInput, acquire_file, acquire_bytes
        stopped = Cancellation(cancel)

        def check():
            if stopped():
                raise InputFailure('cancelled')
            if time.monotonic() >= deadline:
                raise InputFailure('budget-exhausted')

        def prepare(item):
            check()
            try:
                source = item.source if isinstance(item, SnapshotInput) else m.SourceRef(m.SourceKind.FILESYSTEM, str(item.path.absolute())) if isinstance(item, m.FileInput) else m.SourceRef(m.SourceKind.BYTES, item.logical_path) if isinstance(item, m.BytesInput) else None
            except (TypeError, ValueError, OSError):
                raise InputFailure('input-limit') from None
            if source is None:
                raise InputFailure('configuration-invalid')
            try:
                generation = self.store.reserve(source)
            except Exception:
                raise InputFailure('state-failed', source) from None
            snapshot = None
            cached = None
            error = None
            try:
                if isinstance(item, SnapshotInput):
                    snapshot = item
                elif isinstance(item, m.FileInput):
                    snapshot = acquire_file(item.path, max_bytes=limits.max_file_bytes, boundary=getattr(item, 'boundary', None))
                else:
                    snapshot = acquire_bytes(item.data, item.logical_path, max_bytes=limits.max_file_bytes)
                identity, cache_key = self._snapshot_identity(snapshot, policy_id, materials)
                if use_cache and identity.cache_eligible:
                    cached = self.store.get_cached(cache_key)
            except Exception as failure:
                error = failure
            return source, generation, snapshot, cached, error

        def execute(work):
            source, generation, snapshot, cached, error = work
            cache_key = None
            observations = ()
            try:
                if error is not None:
                    raise error
                result, cache_key, observations = self._scan_snapshot(snapshot, policy, policy_id, limits, deadline, use_cache, stopped, materials, cached=cached, prepared=backend)
            except Exception as failure:
                code = self._error_code(getattr(failure, 'code', 'input-unreadable'), 'input-unreadable')
                when = dt.datetime.now(dt.timezone.utc)
                result = m.ScanResult(source, snapshot.content if snapshot else None, m.RuntimeIdentity(policy_id, self._runtime, snapshot.context.identity if snapshot else 'unavailable', False), m.ScanOutcome.ERROR, m.CoverageState.INCOMPLETE, (), (m.CoverageIssue(code, source, required=True),), when)
            return source, generation, snapshot, result, cache_key, observations

        # At most two input byte buffers and proof contexts are admitted. Store
        # reservations, cache reads and publication all stay on this thread.
        workers = min(self.config.get('scan_workers', 2), limits.max_files)
        with backends.prepare(binary=self.binary, rules=self.rules, check=check) as backend:
            yield from ordered_work(inputs, prepare=prepare, execute=execute, workers=workers,
                                    max_items=limits.max_files, stop=stopped.stop)

    def _snapshot_identity(self, snapshot, policy_id, materials=None):
        from . import models as m
        source = snapshot.source
        material_enabled = materials is not None and bool(materials.references or materials.issues)
        runtime_id = hashlib.sha256((self._runtime + '|' + materials.identity).encode()).hexdigest() if material_enabled else self._runtime
        identity = m.RuntimeIdentity(policy_id, runtime_id, snapshot.context.identity, self._cache_eligible and not snapshot.context.truncated and not material_enabled)
        key_data = [snapshot.content.digest, snapshot.content.size_bytes, identity.runtime_id, policy_id, source.kind.value, source.path, source.repository, source.commit, source.index_tree_oid, identity.context_id]
        return identity, hashlib.sha256(json.dumps(key_data, separators=(',', ':')).encode()).hexdigest()

    def _scan_snapshot(self, snapshot, policy, policy_id, limits, deadline, use_cache, cancel, materials=None, *, cached=None, prepared=None):
        from dataclasses import replace
        from . import models as m, extraction, backends
        source = snapshot.source
        identity, cache_key = self._snapshot_identity(snapshot, policy_id, materials)
        if use_cache and identity.cache_eligible:
            if cached is not None and cached.coverage is m.CoverageState.COMPLETE and cached.identity == identity and cached.content == snapshot.content and snapshot.valid():
                when = dt.datetime.now(dt.timezone.utc)
                return replace(cached, source=source, outcome=m.ScanOutcome.REUSED, observed_at=when, last_verified_at=when, reused_from=cached.reused_from or hashlib.sha256(_legacy_origin(cached).encode()).hexdigest()), cache_key, ()
        when = dt.datetime.now(dt.timezone.utc)
        remaining = max(0.001, deadline - time.monotonic())
        extracted = extraction.extract(snapshot.data, source.path, limits=limits, timeout=min(limits.extract_timeout_seconds, remaining), plugins=self._plugins, cancel=cancel, extractor_overrides=self.config.get('extractor_overrides'), worker_policy=self.config.get('worker_policy', 'strict'))
        issues = _IssueBudget(min(32768, limits.max_report_bytes // 16))
        if materials is not None:
            issues.extend(m.CoverageIssue(self._error_code(code), source, required=True) for code in materials.issues)
        findings = []
        observations = []
        omitted = self._omission(policy, source.path, extracted.format_id)
        unknown_binary = extracted.format_id in {'binary', 'unknown', 'unsupported-binary'} or (extracted.disposition == 'unsupported' and not pathlib.Path(source.path).suffix.lower() in DOCUMENT_SUFFIXES)
        required = not omitted and (not unknown_binary or any(value in policy.required_formats for value in ('all', 'binary', extracted.format_id)))
        for code in extracted.issues:
            issues.append(m.CoverageIssue(self._error_code(code, 'extract-failed'), source, required=required, omission_id=omitted or ('unsupported-binary' if unknown_binary and not required else None)))
        if extracted.disposition != 'extracted' and not extracted.issues:
            code = {'unsupported': m.ErrorCode.UNSUPPORTED_FORMAT, 'no-text': m.ErrorCode.NO_TEXT, 'encrypted': m.ErrorCode.ENCRYPTED}.get(extracted.disposition, m.ErrorCode.EXTRACT_FAILED)
            issues.append(m.CoverageIssue(code, source, required=required, omission_id=omitted or ('unsupported-binary' if unknown_binary and not required else None)))
        document_omissions = extraction.DOCUMENT_OMISSIONS.get(extracted.format_id, ())
        if isinstance(document_omissions, str):
            document_omissions = (document_omissions,)
        for omission in document_omissions:
            issues.append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, source, omission_id=omission))
        if omitted and not any(issue.omission_id == omitted for issue in issues):
            issues.append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, source, omission_id=omitted))
        finding_admission_stopped = False
        def admit_finding(part):
            nonlocal finding_admission_stopped
            stopped = cancel is not None and cancel()
            code = m.ErrorCode.CANCELLED if stopped else m.ErrorCode.BUDGET_EXHAUSTED if time.monotonic() >= deadline else m.ErrorCode.DETECTOR_OUTPUT_LIMIT if len(findings) >= limits.max_findings else None
            if code is not None:
                issues.append(m.CoverageIssue(code, source, part.part_id, True))
                finding_admission_stopped = True
                return False
            return True

        for part in extracted.parts:
            stopped = cancel is not None and cancel()
            if time.monotonic() >= deadline or stopped:
                issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if stopped else m.ErrorCode.BUDGET_EXHAUSTED, source, part.part_id, True))
                break
            if materials is not None:
                for observation in catalog.material_observations(materials, part.part_id, part.text):
                    if not admit_finding(part):
                        break
                    observations.append(observation)
                    findings.append(self._finding(snapshot, part, 'known-material-' + observation.kind, observation.line, observation.end_line, 'review' if observation.kind == 'license' else 'block', 'known-material', mode=policy.mode))
            if finding_admission_stopped:
                break
            if time.monotonic() >= deadline or (cancel and cancel()):
                issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, source, part.part_id, True))
                break
            try:
                detected = backends.detect(part.text, binary=self.binary, rules=self.rules, timeout=min(limits.detector_timeout_seconds, max(0.001, deadline - time.monotonic())), max_findings=limits.max_findings, cancel=cancel, prepared=prepared, worker_policy=self.config.get('worker_policy', 'strict'))
                for item in detected:
                    if not admit_finding(part):
                        break
                    findings.append(self._finding(snapshot, part, item.rule, item.start_line, item.end_line, item.severity, 'gitleaks', mode=policy.mode))
            except Exception as error:
                issues.append(m.CoverageIssue(self._error_code(getattr(error, 'code', 'detector-failed')), source, part.part_id, True))
            if finding_admission_stopped:
                break
            for instance in self._plugins:
                stopped = cancel is not None and cancel()
                if time.monotonic() >= deadline or stopped:
                    issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if stopped else m.ErrorCode.BUDGET_EXHAUSTED, source, part.part_id, True))
                    break
                try:
                    for item in plugins.detect([instance], part.text, source.path, part.part_id, format_id=part.format_id, timeout=min(limits.detector_timeout_seconds, max(0.001, deadline - time.monotonic())), limits=limits, cancel=cancel, worker_policy=self.config.get('worker_policy', 'strict')):
                        if not admit_finding(part):
                            break
                        findings.append(self._finding(snapshot, part, item.rule, item.line, item.line, item.severity, plugins.detector_id(instance), mode=policy.mode))
                except Exception as error:
                    issues.append(m.CoverageIssue(self._error_code(getattr(error, 'code', 'detector-failed')), source, part.part_id, True))
                if finding_admission_stopped:
                    break
            if finding_admission_stopped:
                break
        rank = {'block': 3, 'review': 2, 'info': 1}
        merged = {}
        for finding in findings:
            key = (finding.part_id, finding.start_line, finding.end_line, finding.rule)
            if key not in merged or rank[finding.severity.value] > rank[merged[key].severity.value]:
                merged[key] = finding
        if not snapshot.valid():
            issues.append(m.CoverageIssue(m.ErrorCode.INPUT_CHANGED, source, required=True))
        coverage = m.CoverageState.INCOMPLETE if any(issue.required for issue in issues) else m.CoverageState.OMITTED if issues else m.CoverageState.COMPLETE
        outcome = m.ScanOutcome.SCANNED if extracted.parts else m.ScanOutcome.SKIPPED
        # A document's declared nontext omissions are not eligible negatives.
        finished = dt.datetime.now(dt.timezone.utc)
        result = m.ScanResult(source, snapshot.content, identity, outcome, coverage, tuple(merged.values()), tuple(issues), finished, when if extracted.parts else None, finished if coverage is m.CoverageState.COMPLETE else None)
        return result, cache_key, tuple(observations)

    def _omission(self, policy, path, format_id):
        import fnmatch
        for omission in policy.omissions:
            if omission.selector.kind.value == 'format' and omission.selector.value == format_id or omission.selector.kind.value == 'path' and fnmatch.fnmatchcase(path, omission.selector.value):
                return omission.id
        return None

    def _finding(self, snapshot, part, rule, first, last, severity, detector_id, *, mode=None):
        from . import models as m
        if isinstance(first, bool) or isinstance(last, bool) or not 1 <= first <= last <= part.text.count('\n') + 1:
            raise ValueError('detector-output-invalid')
        detector_severity = severity
        inventory_review = mode is m.ScanMode.INVENTORY and detector_id == 'gitleaks' and rule in self.config.get('review_only_rules', ())
        effective_severity = 'review' if inventory_review else severity
        informational = ((detector_id == 'plugin-sensitive-basics' and rule.startswith('pii-'))
                         or (detector_id == 'plugin-firm-example' and rule.startswith('firm-')))
        classification = 'heuristic' if rule == 'generic-api-key' or informational else 'credential-candidate'
        final_severity = effective_severity
        proof_id = None
        if detector_id == 'gitleaks':
            try:
                described = finding_details.describe({'path': snapshot.source.path, 'part': part.part_id, 'rule': rule, 'line': first, 'end_line': last, 'severity': effective_severity}, snapshot.data if part.part_id == 'text' else None, snapshot.context.read)
                final_severity = described['severity']
                classification = described.get('classification', classification)
                m.FindingSeverity(final_severity)
                m.FindingClassification(classification)
                if final_severity == 'info':
                    proof_id = snapshot.context.identity
            except Exception:
                # Failure to establish an exemption cannot discard the detector's
                # original candidate or reduce its configured severity.
                final_severity = effective_severity
                classification = 'heuristic' if rule == 'generic-api-key' else 'credential-candidate'
                proof_id = None
        identity = [snapshot.source.kind.value, snapshot.source.path, snapshot.source.repository, snapshot.source.commit, snapshot.source.index_tree_oid, snapshot.content.digest, part.part_id, first, last, rule, detector_id]
        finding_id = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
        return m.FindingRecord(finding_id, snapshot.source, part.part_id, first, last, rule, detector_id, m.DetectorSeverity(detector_severity), m.FindingSeverity(final_severity), m.FindingClassification(classification), proof_id)


def _legacy_origin(result):
    return '|'.join([result.source.path, result.content.digest if result.content else '', result.identity.policy_id, result.identity.runtime_id, result.observed_at.isoformat()])

def main():
    _legacy()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('scan'); scan.add_argument('paths', nargs='+'); scan.add_argument('--budget-seconds', type=int, default=120); scan.add_argument('--max-files', type=int, default=1000); scan.add_argument('--no-cache', action='store_true')
    job = commands.add_parser('audit'); job.add_argument('scope', choices=CONFIG['audit_scopes']); job.add_argument('--budget-seconds', type=int, default=600); job.add_argument('--max-files', type=int, default=3000)
    commands.add_parser('drain')
    hook = commands.add_parser('hook'); hook.add_argument('kind', choices=['pre-commit', 'pre-push']); hook.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command == 'scan':
        scan_paths(args.paths, args.budget_seconds, args.max_files, not args.no_cache)
    elif args.command == 'audit':
        audit(args.scope, args.budget_seconds, args.max_files)
    elif args.command == 'drain':
        drain()
    else:
        return git_hook(args.kind, args.args)
    return 0


def run():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='backslashreplace')
    try:
        return main()
    except Exception:
        print('LeakGuard could not complete the operation (operation-failed).', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(run())
