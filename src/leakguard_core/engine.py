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
    STATE = state_directory()
    EXE = pathlib.Path(os.environ.get('LEAKGUARD_GITLEAKS') or CONFIG.get('gitleaks_executable') or shutil.which('gitleaks') or 'gitleaks')
    RULES = pathlib.Path(CONFIG.get('gitleaks_config') or ROOT / 'rules.toml')
    PLUGINS = plugins.load(CONFIG.get('plugins', []))
    SCAN_POLICY = hashlib.sha256((ROOT / 'finding_details.py').read_bytes() + RULES.read_bytes() + json.dumps(CONFIG, sort_keys=True).encode()).hexdigest()
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
    from .scan_store import open_database
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
    hooks = pathlib.Path(git('rev-parse', '--path-format=absolute', '--git-path', 'hooks', cwd=repo).stdout.decode().strip())
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
    from .git_scanning import parse_push
    repo = pathlib.Path(git('rev-parse', '--show-toplevel').stdout.decode('utf-8', errors='surrogateescape').strip())
    payload = sys.stdin.buffer.read(1_000_001) if kind == 'pre-push' else b''
    if kind == 'pre-commit':
        prior = existing_hook(repo, kind, args, payload)
        if prior:
            return prior
    service = None
    try:
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


class ScanService:
    """One bounded pipeline for files, caller bytes and immutable Git snapshots."""
    def __init__(self, config, *, state_dir=None, store=None):
        from . import scan_policy
        from .scan_store import MemoryScanStore, SQLiteScanStore
        from .settings import validate
        self.config = validate(config.to_mapping() if hasattr(config, 'to_mapping') else dict(config))
        self.binary = self.config.get('gitleaks_executable') or shutil.which('gitleaks') or 'gitleaks'
        self.rules = self.config.get('gitleaks_config') or ROOT / 'rules.toml'
        self.state_dir = pathlib.Path(state_dir) if state_dir is not None else None
        self.store = store if store is not None else (SQLiteScanStore(self.state_dir, config=self.config) if self.state_dir is not None else MemoryScanStore(config=self.config))
        self._owns_store = store is None
        self._closed = False
        try:
            self._plugins = plugins.load(self.config.get('plugins', []))
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

    def scan(self, inputs, *, policy, limits, use_cache=True, cancel=None):
        return self._run(inputs, policy=policy, limits=limits, use_cache=use_cache, cancel=cancel)

    def scan_paths(self, paths, *, policy, limits, use_cache=True, cancel=None):
        from . import models as m
        state = {'complete': True, 'issues': [], 'pending_files': None, 'pending_directories': 0}
        deadline = time.monotonic() + limits.deadline_seconds
        pending = [pathlib.Path(path) for path in paths]
        admitted = 0

        def walk():
            nonlocal admitted
            while pending:
                if time.monotonic() >= deadline or (cancel and cancel()):
                    state['complete'] = False
                    break
                path = pending.pop()
                if self._excluded(path):
                    state['issues'].append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, m.SourceRef(m.SourceKind.FILESYSTEM, str(path.absolute())), omission_id='operator-exclusion'))
                    continue
                if path.is_dir() and not path.is_symlink():
                    try:
                        with os.scandir(path) as entries:
                            for entry in entries:
                                if time.monotonic() >= deadline or admitted >= limits.max_directory_entries or (cancel and cancel()):
                                    pending.append(path)
                                    state['complete'] = False
                                    return
                                admitted += 1
                                child = pathlib.Path(entry.path)
                                if self._excluded(child):
                                    state['issues'].append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, m.SourceRef(m.SourceKind.FILESYSTEM, str(child.absolute())), omission_id='operator-exclusion'))
                                    continue
                                if entry.is_dir(follow_symlinks=False):
                                    pending.append(child)
                                else:
                                    yield m.FileInput(child)
                    except OSError:
                        state['complete'] = False
                        state['issues'].append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, m.SourceRef(m.SourceKind.FILESYSTEM, str(path.absolute())), required=True))
                else:
                    yield m.FileInput(path)
            state['pending_directories'] = len(pending)

        def enumeration():
            state['pending_directories'] = len(pending)
            return state
        return self._run(walk(), policy=policy, limits=limits, use_cache=use_cache, cancel=cancel, enumeration=enumeration)

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
        return self._run(session, policy=m.ScanPolicy.git(), limits=limits, use_cache=False, cancel=cancel, enumeration=session.status, final_check=session.valid, repository=str(session.repo))

    def confirm_absent(self, path, *, root, limits):
        """Internal explicit absence check, separate from failed scans/events."""
        from . import models as m
        from .sources import confirm_absence
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
        from . import models as m
        from .scan_store import StateError
        issues = []
        lease = None
        claims = {}
        deadline = time.monotonic() + limits.deadline_seconds
        enumerated = 0
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
        required_methods = ('acquire_cycle', 'claim_work', 'enqueue_work', 'finish_directory', 'cycle_status', 'lease_valid', 'release_cycle', 'invalidate_scope', 'record_event')
        if any(not hasattr(self.store, name) for name in required_methods):
            return failure(m.ErrorCode.STATE_FAILED)
        if hasattr(self.store, 'set_deadline'):
            try:
                self.store.set_deadline(deadline)
            except Exception:
                pass
        if root is not None and not root.is_dir():
            try:
                self.store.invalidate_scope(root)
            except Exception:
                pass
            return failure(m.ErrorCode.SOURCE_UNAVAILABLE, m.SourceRef(m.SourceKind.FILESYSTEM, str(root)))
        try:
            lease = self.store.acquire_cycle(scope, root, lease_seconds=limits.deadline_seconds + 30)
        except Exception:
            lease = None
        if lease is None:
            return failure(m.ErrorCode.STATE_FAILED)
        try:
            if ingest:
                issues.extend(self._ingest_queue(lease))
            elif root is not None:
                preferred = self.config.get('priority_paths', {}).get(scope.removeprefix('audit:'), ())
                self.store.enqueue_work(lease, ((str(pathlib.Path(path).absolute()), 'directory', 0) for path in preferred[:1000]))

            def work_inputs():
                nonlocal enumerated
                while time.monotonic() < deadline and not (cancel and cancel()):
                    claim = self.store.claim_work(lease)
                    if claim is None:
                        return
                    path = pathlib.Path(claim.path)
                    if self._excluded(path):
                        issues.append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), omission_id='operator-exclusion'))
                        self.store.finish_directory(claim, success=True)
                        continue
                    if claim.kind == 'file':
                        claims[str(path.absolute())] = claim
                        yield m.FileInput(path)
                        continue
                    entries_batch = []
                    exhausted = True
                    try:
                        with os.scandir(path) as entries:
                            for entry in entries:
                                if time.monotonic() >= deadline or enumerated >= limits.max_directory_entries or (cancel and cancel()):
                                    exhausted = False
                                    break
                                enumerated += 1
                                child = pathlib.Path(entry.path)
                                if self._excluded(child):
                                    issues.append(m.CoverageIssue(m.ErrorCode.POLICY_OMISSION, m.SourceRef(m.SourceKind.FILESYSTEM, str(child)), omission_id='operator-exclusion'))
                                    continue
                                kind = 'directory' if entry.is_dir(follow_symlinks=False) else 'file'
                                entries_batch.append((str(child.absolute()), kind, 100 if kind == 'file' else 101))
                                if len(entries_batch) >= 256:
                                    self.store.enqueue_work(lease, entries_batch)
                                    entries_batch.clear()
                        if entries_batch:
                            self.store.enqueue_work(lease, entries_batch)
                        self.store.finish_directory(claim, success=True if exhausted else None)
                        if not exhausted:
                            issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                            return
                    except OSError:
                        self.store.finish_directory(claim, success=False)
                        self.store.invalidate_scope(path)
                        issues.append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, m.SourceRef(m.SourceKind.FILESYSTEM, str(path)), required=True))
                issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, required=True))

            def status():
                metadata = self.store.cycle_status(lease)
                if metadata.get('failed'):
                    issues.append(m.CoverageIssue(m.ErrorCode.ENUMERATION_FAILED, required=True))
                return {**metadata, 'complete': metadata['complete'] and not any(issue.required for issue in issues), 'issues': tuple(issues)}
            report = self._run(work_inputs(), policy=m.ScanPolicy.inventory(), limits=limits, use_cache=use_cache, cancel=cancel, enumeration=status, final_check=lambda: self.store.lease_valid(lease), work_claims=claims, _deadline=deadline)
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
                    report = replace(report, coverage=coverage, decision=decision, issues=failure_issues)
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

    def _run(self, inputs, *, policy, limits, use_cache, cancel, enumeration=None, final_check=None, work_claims=None, _deadline=None, repository=None):
        from .scan_store import StateError
        if self._closed:
            raise StateError('state-closed')
        deadline = _deadline if _deadline is not None else time.monotonic() + limits.deadline_seconds
        if hasattr(self.store, 'set_deadline'):
            try:
                self.store.set_deadline(deadline)
            except Exception:
                pass  # The bounded run will publish a sanitized state issue.
        try:
            return self._run_inner(inputs, policy=policy, limits=limits, use_cache=use_cache, cancel=cancel, enumeration=enumeration, final_check=final_check, work_claims=work_claims, _deadline=deadline, repository=repository)
        finally:
            if _deadline is None and hasattr(self.store, 'set_deadline'):
                try:
                    self.store.set_deadline(None)
                except Exception:
                    pass

    def _run_inner(self, inputs, *, policy, limits, use_cache, cancel, enumeration=None, final_check=None, work_claims=None, _deadline=None, repository=None):
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
        run_issues = []
        enumeration_complete = True
        finding_count = 0
        report_bytes = 0
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
        materials = None
        if runtime_valid and policy.mode is m.ScanMode.INVENTORY:
            try:
                materials = self.store.material_snapshot(max_bytes=min(limits.max_file_bytes, 1_000_000), max_sources=100)
            except Exception:
                materials = catalog.MaterialSnapshot((), 'unavailable', ('source-unavailable',))
        iterator = iter(inputs)
        while runtime_valid:
            if time.monotonic() >= deadline or (cancel and cancel()):
                code = m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED
                run_issues.append(m.CoverageIssue(code, required=True))
                enumeration_complete = False
                break
            try:
                item = next(iterator)
            except StopIteration:
                break
            except Exception as error:
                code = getattr(error, 'code', 'enumeration-failed')
                run_issues.append(m.CoverageIssue(self._error_code(code, 'enumeration-failed'), required=True))
                enumeration_complete = False
                break
            if len(results) >= limits.max_files:
                run_issues.append(m.CoverageIssue(m.ErrorCode.BUDGET_EXHAUSTED, required=True))
                enumeration_complete = False
                break
            source = item.source if isinstance(item, SnapshotInput) else m.SourceRef(m.SourceKind.FILESYSTEM, str(item.path.absolute())) if isinstance(item, m.FileInput) else m.SourceRef(m.SourceKind.BYTES, item.logical_path) if isinstance(item, m.BytesInput) else None
            if source is None:
                run_issues.append(m.CoverageIssue(m.ErrorCode.CONFIGURATION_INVALID, required=True))
                enumeration_complete = False
                break
            try:
                generation = self.store.reserve(source)
            except Exception:
                run_issues.append(m.CoverageIssue(m.ErrorCode.STATE_FAILED, source, required=True))
                enumeration_complete = False
                break
            snapshot = None
            cache_key = None
            material_observations = ()
            try:
                if not runtime_valid:
                    raise AcquisitionError('source-unavailable')
                if isinstance(item, SnapshotInput):
                    snapshot = item
                elif isinstance(item, m.FileInput):
                    snapshot = acquire_file(item.path, max_bytes=limits.max_file_bytes)
                else:
                    snapshot = acquire_bytes(item.data, item.logical_path, max_bytes=limits.max_file_bytes)
                result, cache_key, material_observations = self._scan_snapshot(snapshot, policy, policy_id, limits, deadline, use_cache, cancel, materials)
            except Exception as error:
                code = self._error_code(getattr(error, 'code', 'input-unreadable'), 'input-unreadable')
                when = dt.datetime.now(dt.timezone.utc)
                result = m.ScanResult(source, snapshot.content if snapshot else None, m.RuntimeIdentity(policy_id, self._runtime, snapshot.context.identity if snapshot else 'unavailable', False), m.ScanOutcome.ERROR, m.CoverageState.INCOMPLETE, (), (m.CoverageIssue(code, source, required=True),), when)
            if finding_count + len(result.findings) > limits.max_findings:
                remaining = max(0, limits.max_findings - finding_count)
                result = replace(result, outcome=m.ScanOutcome.ERROR if result.outcome is m.ScanOutcome.REUSED else result.outcome, findings=result.findings[:remaining], coverage=m.CoverageState.INCOMPLETE, issues=result.issues + (m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, result.source, required=True),), last_verified_at=None)
                cache_key = None
            size = len(_result_json(result).encode('utf-8'))
            if report_bytes + size > limits.max_report_bytes:
                result = replace(result, outcome=m.ScanOutcome.ERROR if result.outcome is m.ScanOutcome.REUSED else result.outcome, findings=(), coverage=m.CoverageState.INCOMPLETE, issues=result.issues + (m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, result.source, required=True),), last_verified_at=None)
                cache_key = None
                enumeration_complete = False
            report_bytes += len(_result_json(result).encode('utf-8'))
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
            results = [replace(r, outcome=m.ScanOutcome.ERROR if r.outcome is m.ScanOutcome.REUSED else r.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=r.issues + (m.CoverageIssue(m.ErrorCode.INPUT_CHANGED, r.source, required=True),)) for r in results]
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
            results = [replace(r, outcome=m.ScanOutcome.ERROR if r.outcome is m.ScanOutcome.REUSED else r.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=r.issues + (m.CoverageIssue(identity_failure, r.source, required=True),)) for r in results]
        try:
            materials_valid = materials is None or materials.valid()
        except Exception:
            materials_valid = False
        if not materials_valid:
            results = [replace(r, outcome=m.ScanOutcome.ERROR if r.outcome is m.ScanOutcome.REUSED else r.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=r.issues + (m.CoverageIssue(m.ErrorCode.SOURCE_UNAVAILABLE, r.source, required=True),)) for r in results]
        for index, validate_snapshot in enumerate(snapshots):
            if validate_snapshot is not None and (time.monotonic() >= deadline or not validate_snapshot()):
                result = results[index]
                code = m.ErrorCode.BUDGET_EXHAUSTED if time.monotonic() >= deadline else m.ErrorCode.INPUT_CHANGED
                anchors[index] = None
                results[index] = replace(result, outcome=m.ScanOutcome.ERROR if result.outcome is m.ScanOutcome.REUSED else result.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=result.issues + (m.CoverageIssue(code, result.source, required=True),))
        # Publication is after validation; no slow detector runs under a write lock.
        for result, (generation, cache_key), observations, anchor in zip(results, reservations, material_results, anchors):
            try:
                kwargs = {'work': work_claims.get(result.source.path)} if work_claims is not None else {}
                if anchor is not None:
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
        coverage, decision = scan_policy.evaluate(tuple(results), policy=policy, policy_id=policy_id, enumeration_complete=enumeration_complete, issues=tuple(run_issues), pending_files=metadata.get('pending_files'), pending_directories=metadata.get('pending_directories'), cycle_id=metadata.get('cycle_id'))
        report = m.ScanReport(1, uuid.uuid4().hex, started, dt.datetime.now(dt.timezone.utc), policy_id, tuple(results), coverage, decision, tuple(run_issues))
        try:
            if repository is None:
                self.store.record_report(report)
            else:
                self.store.record_report(report, repository=repository)
        except Exception:
            issue = m.CoverageIssue(m.ErrorCode.STATE_FAILED, required=True)
            coverage, decision = scan_policy.evaluate(report.results, policy=policy, policy_id=policy_id, enumeration_complete=False, issues=report.issues + (issue,), pending_files=coverage.pending_files, pending_directories=coverage.pending_directories, cycle_id=coverage.cycle_id)
            report = replace(report, coverage=coverage, decision=decision, issues=report.issues + (issue,))
        return report

    @staticmethod
    def _error_code(value, fallback='detector-failed'):
        from .models import ErrorCode
        try:
            return ErrorCode(value)
        except ValueError:
            return ErrorCode(fallback)

    def _scan_snapshot(self, snapshot, policy, policy_id, limits, deadline, use_cache, cancel, materials=None):
        from dataclasses import replace
        from . import models as m, extraction, backends
        source = snapshot.source
        material_enabled = materials is not None and bool(materials.references or materials.issues)
        runtime_id = hashlib.sha256((self._runtime + '|' + materials.identity).encode()).hexdigest() if material_enabled else self._runtime
        identity = m.RuntimeIdentity(policy_id, runtime_id, snapshot.context.identity, self._cache_eligible and not snapshot.context.truncated and not material_enabled)
        key_data = [snapshot.content.digest, snapshot.content.size_bytes, identity.runtime_id, policy_id, source.kind.value, source.path, source.repository, source.commit, source.index_tree_oid, identity.context_id]
        cache_key = hashlib.sha256(json.dumps(key_data, separators=(',', ':')).encode()).hexdigest()
        if use_cache and identity.cache_eligible:
            cached = self.store.get_cached(cache_key)
            if cached is not None and cached.coverage is m.CoverageState.COMPLETE and cached.identity == identity and cached.content == snapshot.content and snapshot.valid():
                when = dt.datetime.now(dt.timezone.utc)
                return replace(cached, source=source, outcome=m.ScanOutcome.REUSED, observed_at=when, last_verified_at=when, reused_from=cached.reused_from or hashlib.sha256(_legacy_origin(cached).encode()).hexdigest()), cache_key, ()
        when = dt.datetime.now(dt.timezone.utc)
        remaining = max(0.001, deadline - time.monotonic())
        extracted = extraction.extract(snapshot.data, source.path, limits=limits, timeout=min(limits.extract_timeout_seconds, remaining), plugins=self._plugins, cancel=cancel, extractor_overrides=self.config.get('extractor_overrides'))
        issues = [m.CoverageIssue(self._error_code(code), source, required=True) for code in materials.issues] if materials is not None else []
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
        for part in extracted.parts:
            stopped = cancel is not None and cancel()
            if time.monotonic() >= deadline or stopped:
                issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if stopped else m.ErrorCode.BUDGET_EXHAUSTED, source, part.part_id, True))
                break
            if materials is not None:
                for observation in catalog.material_observations(materials, part.part_id, part.text):
                    observations.append(observation)
                    findings.append(self._finding(snapshot, part, 'known-material-' + observation.kind, observation.line, observation.end_line, 'review' if observation.kind == 'license' else 'block', 'known-material'))
            if time.monotonic() >= deadline or (cancel and cancel()):
                issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if cancel and cancel() else m.ErrorCode.BUDGET_EXHAUSTED, source, part.part_id, True))
                break
            try:
                detected = backends.detect(part.text, binary=self.binary, rules=self.rules, timeout=min(limits.detector_timeout_seconds, max(0.001, deadline - time.monotonic())), max_findings=limits.max_findings, cancel=cancel)
                for item in detected:
                    findings.append(self._finding(snapshot, part, item.rule, item.start_line, item.end_line, item.severity, 'gitleaks'))
            except Exception as error:
                issues.append(m.CoverageIssue(self._error_code(getattr(error, 'code', 'detector-failed')), source, part.part_id, True))
            for instance in self._plugins:
                stopped = cancel is not None and cancel()
                if time.monotonic() >= deadline or stopped:
                    issues.append(m.CoverageIssue(m.ErrorCode.CANCELLED if stopped else m.ErrorCode.BUDGET_EXHAUSTED, source, part.part_id, True))
                    break
                try:
                    for item in plugins.detect([instance], part.text, source.path, part.part_id, format_id=part.format_id, timeout=min(limits.detector_timeout_seconds, max(0.001, deadline - time.monotonic())), limits=limits, cancel=cancel):
                        findings.append(self._finding(snapshot, part, item.rule, item.line, item.line, item.severity, plugins.detector_id(instance)))
                except Exception as error:
                    issues.append(m.CoverageIssue(self._error_code(getattr(error, 'code', 'detector-failed')), source, part.part_id, True))
            if len(findings) > limits.max_findings:
                findings = findings[:limits.max_findings]
                issues.append(m.CoverageIssue(m.ErrorCode.DETECTOR_OUTPUT_LIMIT, source, part.part_id, True))
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

    def _finding(self, snapshot, part, rule, first, last, severity, detector_id):
        from . import models as m
        if isinstance(first, bool) or isinstance(last, bool) or not 1 <= first <= last <= part.text.count('\n') + 1:
            raise ValueError('detector-output-invalid')
        detector_severity = 'review' if rule in self.config.get('review_only_rules', ()) else severity
        classification = 'heuristic' if rule == 'generic-api-key' else 'credential-candidate'
        final_severity = detector_severity
        proof_id = None
        if detector_id == 'gitleaks':
            described = finding_details.describe({'path': snapshot.source.path, 'part': part.part_id, 'rule': rule, 'line': first, 'end_line': last, 'severity': detector_severity}, snapshot.data if part.part_id == 'text' else None, snapshot.context.read)
            final_severity = described['severity']
            classification = described.get('classification', classification)
            if final_severity == 'info':
                proof_id = snapshot.context.identity
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
