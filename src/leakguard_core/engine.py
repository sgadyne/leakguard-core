"""Local offline secret scanning, resumable disk audits, and Git guards."""
import argparse
import bisect
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

from .documents import DOCUMENT_SUFFIXES, extract
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
    _legacy()
    # --redact runs before sanitization. Raw report files never leave the private state directory.
    with tempfile.TemporaryDirectory(prefix='scan-', dir=STATE) as temp:
        assert pathlib.Path(temp).resolve().is_relative_to(STATE.resolve())
        report = pathlib.Path(temp) / 'redacted.json'
        args = [str(EXE), *command, '--config', str(RULES), '--redact=100', '--no-banner', '--no-color', '--log-level', 'fatal', '--report-format', 'json', '--report-path', str(report), '--timeout', str(CONFIG['scan_timeout_seconds'])]
        process = subprocess.run(args, input=text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, timeout=CONFIG['scan_timeout_seconds'] + 10)
        if process.returncode not in (0, 1):
            raise RuntimeError(f'Gitleaks failed with exit code {process.returncode}')
        if not report.is_file():
            raise RuntimeError('Detection engine did not produce a report')
        return json.loads(report.read_text(encoding='utf-8'))


def scan_blob(data, path, conn=None):
    _legacy()
    digest = hashlib.sha256(data).hexdigest()
    found = []
    extracted = False
    provided = plugins.extract(PLUGINS, data, path)
    if provided is not None:
        parts = provided
    elif pathlib.Path(path).suffix.lower() in DOCUMENT_SUFFIXES:
        worker = subprocess.run([sys.executable, '-X', 'utf8', '-m', 'leakguard_core.extract_worker', pathlib.Path(path).suffix.lower()], input=data, capture_output=True, timeout=25)
        if worker.returncode:
            raise ValueError('Document extraction failed or reached a configured limit')
        parts = json.loads(worker.stdout)
    else:
        parts = list(extract(data, path))
    if conn is not None:
        rendered = '\n'.join(text for _, text in parts)
        for material in catalog.match_materials(conn, policies.canonical(path, CONFIG), rendered, STATE):
            extra = safe_findings([{'RuleID': 'known-material-' + material['kind'], 'StartLine': material['line']}], str(path), digest=digest)[0]
            extra['material_name'] = material['name']
            if material['kind'] == 'license':
                extra['severity'] = 'review'
            found.append(extra)
    # One scanner invocation per bounded document batch; preserve source part/line mapping.
    batch = []; starts = []; offset = 1; size = 0

    def flush():
        if not batch:
            return
        raw = engine(['stdin'], '\n'.join(text for _, text in batch).encode('utf-8'))
        for finding in raw:
            index = max(0, bisect.bisect_right(starts, finding.get('StartLine', 1)) - 1)
            finding['StartLine'] = finding.get('StartLine', 1) - starts[index] + 1
            found.extend(safe_findings([finding], str(path), batch[index][0], digest))

    for part, text in parts:
        extracted = True
        if text:
            for item in plugins.detect(PLUGINS, text, str(path), part):
                extra = safe_findings([{'RuleID': item.rule, 'StartLine': item.line}], str(path), part, digest)[0]
                extra['severity'] = item.severity
                found.append(extra)
            if batch and size + len(text) > 2_000_000:
                flush(); batch = []; starts = []; offset = 1; size = 0
            starts.append(offset); batch.append((part, text)); offset += text.count('\n') + 1; size += len(text)
    flush()
    return found, 'scanned' if extracted else 'skipped-binary-or-no-text'


def scan_file(path, conn, use_cache=True):
    path = pathlib.Path(path)
    result = {'path': str(path), 'findings': []}
    try:
        stat = path.stat()
        if not path.is_file() or path.is_symlink():
            result['status'] = 'skipped-nonregular'
            return result
        if stat.st_size > CONFIG['max_file_bytes']:
            catalog.metadata_only(conn, str(path), stat.st_size, CONFIG)
            result['status'] = 'skipped-size'
            return result
        # Stat metadata is admission information, never content identity.
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        old = conn.execute('SELECT digest,status,policy,payload,executed_at FROM cache WHERE path=?', (str(path),)).fetchone()
        # Until the service has a full dependency closure, contextual/plugin/material
        # scans deliberately run again. Their unchanged primary bytes prove too little.
        eligible = path.suffix.lower() != '.json' and not PLUGINS and not conn.execute('SELECT 1 FROM material_sources LIMIT 1').fetchone()
        if use_cache and eligible and old and old[:3] == (digest, 'scanned', SCAN_POLICY) and old[3]:
            after = path.stat()
            if (after.st_size, after.st_mtime_ns) == (stat.st_size, stat.st_mtime_ns):
                result.update(status='unchanged', findings=json.loads(old[3]), last_executed_at=old[4], last_verified_at=now())
                catalog.observe(conn, str(path), data, CONFIG)
                return result
        digest = catalog.observe(conn, str(path), data, CONFIG)
        result['findings'], result['status'] = scan_blob(data, str(path), conn)
        def sibling(module):
            sibling_path = path.parent / module
            if sibling_path.is_symlink() or not sibling_path.resolve().is_relative_to(path.parent.resolve()):
                return None
            if sibling_path.stat().st_size > finding_details.MAX_CONTEXT_BYTES:
                return None
            return sibling_path.read_bytes()
        result['findings'] = [finding_details.describe(f, data, sibling) for f in result['findings']]
        after = path.stat()
        if (after.st_size, after.st_mtime_ns) != (stat.st_size, stat.st_mtime_ns):
            result['status'] = 'changed-during-scan'
        result['last_executed_at'] = now()
        result['last_verified_at'] = result['last_executed_at'] if result['status'] == 'scanned' else None
        conn.execute('INSERT OR REPLACE INTO cache(path,size,mtime,status,policy,digest,payload,executed_at) VALUES(?,?,?,?,?,?,?,?)', (str(path), stat.st_size, stat.st_mtime_ns, result['status'], SCAN_POLICY, digest, json.dumps(result['findings']), result['last_executed_at']))
        conn.commit()  # Release SQLite's writer lock before the next potentially slow document.
    except Exception as error:
        result['status'] = 'error'
        result['error_type'] = type(error).__name__
        if isinstance(error, FileNotFoundError):
            catalog.event(conn, str(path), 'deleted', CONFIG)
            result['status'] = 'missing'
        if isinstance(error, subprocess.TimeoutExpired):
            result['status'] = 'timeout'
    return result


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
        if status.startswith(('error', 'skipped', 'changed', 'timeout')):
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


def scan_paths(paths, budget, max_files, use_cache=True):
    conn = db(); results = []; start = time.monotonic()
    pending = list(paths)
    while pending and len(results) < max_files and time.monotonic() - start < budget:
        path = pathlib.Path(pending.pop())
        if excluded(path):
            continue
        if path.is_dir() and not path.is_symlink():
            try:
                pending.extend(str(p) for p in path.iterdir() if not excluded(p))
            except OSError as error:
                results.append({'path': str(path), 'status': 'error-directory', 'error_type': type(error).__name__})
        elif candidate(path):
            results.append(scan_file(path, conn, use_cache))
    report = save_report('manual', results, conn, {'pending_paths': len(pending), 'bounded': bool(pending)})
    conn.close()
    return report


def audit(scope, budget, max_files):
    conn = db(); root = CONFIG['audit_scopes'][scope]
    results = []; started = time.monotonic(); dirs = 0
    if not pathlib.Path(root).is_dir():
        save_report('audit-' + scope, [], conn, {'root': root, 'offline': True})
        return
    cycle = conn.execute('SELECT completed FROM cycles WHERE scope=?', (scope,)).fetchone()
    if not cycle or cycle[0]:
        conn.execute('INSERT OR REPLACE INTO cycles VALUES(?,?,NULL)', (scope, now()))
        conn.execute('INSERT OR IGNORE INTO directories(scope,path,priority) VALUES(?,?,?)', (scope, root, 10))
    cycle_id = conn.execute('SELECT started FROM cycles WHERE scope=?', (scope,)).fetchone()[0]
    for preferred in CONFIG.get('priority_paths', {}).get(scope, []):
        inserted = conn.execute('INSERT OR IGNORE INTO priority_seeds VALUES(?,?,?)', (scope, preferred, cycle_id)).rowcount
        if inserted:
            conn.execute('INSERT OR IGNORE INTO directories(scope,path,priority) VALUES(?,?,0)', (scope, preferred))
    conn.commit()
    while len(results) < max_files and time.monotonic() - started < budget:
        file_row = conn.execute('SELECT path,priority FROM files WHERE scope=? ORDER BY priority,rowid LIMIT 1', (scope,)).fetchone()
        row = conn.execute('SELECT path,priority FROM directories WHERE scope=? ORDER BY priority,rowid LIMIT 1', (scope,)).fetchone()
        if file_row and (not row or file_row[1] <= row[1]):
            path = file_row[0]
            results.append(scan_file(path, conn))
            conn.execute('DELETE FROM files WHERE scope=? AND path=?', (scope, path)); conn.commit()
            continue
        if not row:
            conn.execute('UPDATE cycles SET completed=? WHERE scope=?', (now(), scope)); conn.commit(); break
        folder, priority = row
        try:
            with os.scandir(folder) as entries:
                for entry_index, entry in enumerate(entries, 1):
                    if excluded(entry.path) or entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        conn.execute('INSERT OR IGNORE INTO directories(scope,path,priority) VALUES(?,?,?)', (scope, entry.path, priority + 1))
                    elif entry.is_file(follow_symlinks=False) and candidate(entry.path):
                        conn.execute('INSERT OR IGNORE INTO files(scope,path,priority) VALUES(?,?,?)', (scope, entry.path, priority))
                    if entry_index % 1000 == 0:
                        conn.commit()
            dirs += 1
        except OSError as error:
            results.append({'path': folder, 'status': 'error-directory', 'error_type': type(error).__name__})
        # The directory is removed only after enumeration, so an interrupted job can resume safely.
        conn.execute('DELETE FROM directories WHERE scope=? AND path=?', (scope, folder)); conn.commit()
    pending_files = conn.execute('SELECT count(*) FROM files WHERE scope=?', (scope,)).fetchone()[0]
    pending_dirs = conn.execute('SELECT count(*) FROM directories WHERE scope=?', (scope,)).fetchone()[0]
    save_report('audit-' + scope, results, conn, {'root': root, 'directories_enumerated': dirs, 'pending_files': pending_files, 'pending_directories': pending_dirs, 'complete_cycle': not (pending_files or pending_dirs)})
    conn.close()


def drain():
    queue = STATE / 'queue'; queue.mkdir(exist_ok=True)
    paths = set(); consumed = []; events = []
    for item in list(queue.glob('*.json'))[:20]:
        try:
            batch = json.loads(item.read_text(encoding='utf-8-sig'))
            for value in batch if isinstance(batch, list) else [batch]:
                if isinstance(value, dict):
                    events.append(value)
                    if value.get('kind') != 'deleted':
                        paths.add(value['path'])
                else:
                    paths.add(value)
            consumed.append(item)
        except (OSError, ValueError):
            continue
    conn = db(); results = []; started = time.monotonic(); remaining = []
    for value in events:
        if not excluded(value['path']):
            catalog.event(conn, value['path'], value.get('kind', 'changed'), CONFIG, old_path=value.get('old_path'), when=value.get('observed'))
            # Fast local location inventory must not wait behind deep content scans.
            if value.get('kind') != 'deleted' and policies.profile(value['path'], CONFIG) == 'companion':
                try:
                    event_path = pathlib.Path(value['path'])
                    if event_path.is_file() and not event_path.is_symlink():
                        catalog.metadata_only(conn, str(event_path), event_path.stat().st_size, CONFIG)
                except OSError:
                    pass
    fresh = {item['path'] for item in events}
    ordered = sorted(paths, key=lambda path: (policies.profile(path, CONFIG) != 'general', policies.classify(path) == 'history-or-log', path not in fresh, path))
    spent = {'general': 0.0, 'companion': 0.0}
    for index, path in enumerate(ordered):
        if len(results) >= 150 or time.monotonic() - started >= 45:
            remaining.extend(ordered[index:])
            break
        kind = policies.profile(path, CONFIG)
        if spent[kind] >= (25 if kind == 'general' else 15):
            remaining.append(path)
            continue
        if candidate(path) and pathlib.Path(path).is_file():
            file_started = time.monotonic()
            results.append(scan_file(path, conn, use_cache=False))
            spent[kind] += time.monotonic() - file_started
    if paths:
        save_report('watch', results, conn, {'queued_paths': len(paths), 'remaining_paths': len(remaining)})
    if remaining:
        (queue / (uuid.uuid4().hex + '.json')).write_text(json.dumps(remaining), encoding='utf-8')
    for item in consumed:
        item.unlink(missing_ok=True)
    conn.close()


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
        legacy = _legacy_git_report(report, repo, kind)
        print(presentation.render(legacy), file=sys.stderr)
        if report.decision.verdict is m.DecisionVerdict.INCOMPLETE:
            return 2
        if report.decision.verdict is m.DecisionVerdict.BLOCK:
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
            self._runtime, self._cache_eligible = scan_policy.runtime_identity(self.config, self.binary, self.config.get('plugins', ()))
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
        return self._run(session, policy=m.ScanPolicy.git(), limits=limits, use_cache=False, cancel=cancel, enumeration=session.status, final_check=session.valid)

    def _run(self, inputs, *, policy, limits, use_cache, cancel, enumeration=None, final_check=None):
        from dataclasses import replace
        from . import models as m, scan_policy
        from .sources import SnapshotInput, acquire_file, acquire_bytes, AcquisitionError
        from .scan_store import StateError, _result_json
        if self._closed:
            raise StateError('state-closed')
        policy = scan_policy.effective_policy(policy, self.config)
        policy_id = scan_policy.policy_identity(config=self.config, policy=policy, limits=limits)
        started = dt.datetime.now(dt.timezone.utc)
        deadline = time.monotonic() + limits.deadline_seconds
        results = []
        reservations = []
        snapshots = []
        run_issues = []
        enumeration_complete = True
        finding_count = 0
        report_bytes = 0
        runtime, eligible = scan_policy.runtime_identity(self.config, self.binary, self.config.get('plugins', ()))
        runtime_valid = runtime == self._runtime
        iterator = iter(inputs)
        while True:
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
            try:
                if not runtime_valid:
                    raise AcquisitionError('source-unavailable')
                if isinstance(item, SnapshotInput):
                    snapshot = item
                elif isinstance(item, m.FileInput):
                    snapshot = acquire_file(item.path, max_bytes=limits.max_file_bytes)
                else:
                    snapshot = acquire_bytes(item.data, item.logical_path, max_bytes=limits.max_file_bytes)
                result, cache_key = self._scan_snapshot(snapshot, policy, policy_id, limits, deadline, use_cache, cancel)
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
            snapshots.append(snapshot)
            if not enumeration_complete:
                break
        if hasattr(iterator, 'close'):
            iterator.close()
        metadata = enumeration() if enumeration else {}
        enumeration_complete = enumeration_complete and metadata.get('complete', True)
        run_issues.extend(metadata.get('issues', ()))
        if final_check is not None and not final_check():
            enumeration_complete = False
            run_issues.append(m.CoverageIssue(m.ErrorCode.INPUT_CHANGED, required=True))
        current_runtime, _ = scan_policy.runtime_identity(self.config, self.binary, self.config.get('plugins', ()))
        if current_runtime != self._runtime:
            enumeration_complete = False
            run_issues.append(m.CoverageIssue(m.ErrorCode.SOURCE_UNAVAILABLE, required=True))
            results = [replace(r, outcome=m.ScanOutcome.ERROR if r.outcome is m.ScanOutcome.REUSED else r.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=r.issues + (m.CoverageIssue(m.ErrorCode.SOURCE_UNAVAILABLE, r.source, required=True),)) for r in results]
        for index, snapshot in enumerate(snapshots):
            if snapshot is not None and (time.monotonic() >= deadline or not snapshot.valid()):
                result = results[index]
                code = m.ErrorCode.BUDGET_EXHAUSTED if time.monotonic() >= deadline else m.ErrorCode.INPUT_CHANGED
                results[index] = replace(result, outcome=m.ScanOutcome.ERROR if result.outcome is m.ScanOutcome.REUSED else result.outcome, coverage=m.CoverageState.INCOMPLETE, last_verified_at=None, issues=result.issues + (m.CoverageIssue(code, result.source, required=True),))
        # Publication is after validation; no slow detector runs under a write lock.
        for result, (generation, cache_key) in zip(results, reservations):
            try:
                self.store.record_result(result, generation=generation, cache_key=cache_key if result.coverage is m.CoverageState.COMPLETE else None)
            except Exception:
                run_issues.append(m.CoverageIssue(m.ErrorCode.STATE_FAILED, result.source, required=True))
                enumeration_complete = False
        coverage, decision = scan_policy.evaluate(tuple(results), policy=policy, policy_id=policy_id, enumeration_complete=enumeration_complete, issues=tuple(run_issues), pending_files=metadata.get('pending_files'), pending_directories=metadata.get('pending_directories'), cycle_id=metadata.get('cycle_id'))
        report = m.ScanReport(1, uuid.uuid4().hex, started, dt.datetime.now(dt.timezone.utc), policy_id, tuple(results), coverage, decision, tuple(run_issues))
        try:
            self.store.record_report(report)
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

    def _scan_snapshot(self, snapshot, policy, policy_id, limits, deadline, use_cache, cancel):
        from dataclasses import replace
        from . import models as m, extraction, backends
        source = snapshot.source
        identity = m.RuntimeIdentity(policy_id, self._runtime, snapshot.context.identity, self._cache_eligible)
        key_data = [snapshot.content.digest, snapshot.content.size_bytes, identity.runtime_id, policy_id, source.kind.value, source.path, source.repository, source.commit, source.index_tree_oid, identity.context_id]
        cache_key = hashlib.sha256(json.dumps(key_data, separators=(',', ':')).encode()).hexdigest()
        if use_cache and identity.cache_eligible:
            cached = self.store.get_cached(cache_key)
            if cached is not None and cached.coverage is m.CoverageState.COMPLETE and cached.identity == identity and cached.content == snapshot.content and snapshot.valid():
                when = dt.datetime.now(dt.timezone.utc)
                return replace(cached, source=source, outcome=m.ScanOutcome.REUSED, observed_at=when, last_verified_at=when, reused_from=cached.reused_from or hashlib.sha256(_legacy_origin(cached).encode()).hexdigest()), cache_key
        when = dt.datetime.now(dt.timezone.utc)
        remaining = max(0.001, deadline - time.monotonic())
        extracted = extraction.extract(snapshot.data, source.path, limits=limits, timeout=min(limits.extract_timeout_seconds, remaining), plugins=self._plugins, cancel=cancel, extractor_overrides=self.config.get('extractor_overrides'))
        issues = []
        findings = []
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
        return result, cache_key

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
