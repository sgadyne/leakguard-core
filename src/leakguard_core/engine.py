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

CONFIG, CONFIG_PATH = load()
STATE = state_directory()
EXE = pathlib.Path(os.environ.get('LEAKGUARD_GITLEAKS') or CONFIG.get('gitleaks_executable') or shutil.which('gitleaks') or 'gitleaks')
RULES = pathlib.Path(CONFIG.get('gitleaks_config') or ROOT / 'rules.toml')
PLUGINS = plugins.load(CONFIG.get('plugins', []))
TEXT_SUFFIXES = {'.py', '.js', '.jsx', '.ts', '.tsx', '.cs', '.java', '.go', '.rb', '.sh', '.ps1', '.bat', '.cmd', '.sql', '.json', '.jsonl', '.ipynb', '.xml', '.config', '.ini', '.cfg', '.properties', '.yaml', '.yml', '.toml', '.env', '.txt', '.md', '.rst', '.html', '.htm', '.csv', '.tsv', '.log', '.eml', '.rdp', '.tf', '.tfvars', '.pem', '.key', '.linq'}
SCAN_POLICY = hashlib.sha256((ROOT / 'finding_details.py').read_bytes() + RULES.read_bytes() + json.dumps(CONFIG, sort_keys=True).encode()).hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def db():
    from .scan_store import open_database
    return open_database(STATE)


def excluded(path):
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
    repo = pathlib.Path(git('rev-parse', '--show-toplevel').stdout.decode().strip())
    payload = sys.stdin.buffer.read() if kind == 'pre-push' else b''
    if kind == 'pre-commit':
        prior = existing_hook(repo, kind, args, payload)
        if prior:
            return prior
    conn = db(); findings = []; issues = []
    try:
        if kind == 'pre-commit':
            findings.extend(git_findings(engine(['git', '--pre-commit', '--staged', str(repo)], cwd=repo), repo))
            paths = git('diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z', cwd=repo).stdout.split(b'\x00')
            for raw in paths:
                if not raw:
                    continue
                path = raw.decode('utf-8', errors='surrogateescape')
                if pathlib.Path(path).suffix.lower() not in DOCUMENT_SUFFIXES and not PLUGINS:
                    continue
                size = int(git('cat-file', '-s', ':' + path, cwd=repo).stdout)
                if size > CONFIG['max_file_bytes']:
                    issues.append({'path': path, 'status': 'skipped-size'}); continue
                blob = git('show', ':' + path, cwd=repo).stdout
                extra, status = scan_blob(blob, str(repo / path))
                if status != 'scanned':
                    issues.append({'path': path, 'status': status})
                for item in extra:
                    if pathlib.Path(path).suffix.lower() == '.json' and item['rule'] == 'generic-api-key':
                        findings.extend(git_findings([{'File': str(repo / path), 'RuleID': item['rule'], 'StartLine': item['line']}], repo))
                    else:
                        findings.append(finding_details.describe(item))
        else:
            document_blobs = set()
            for line in payload.decode('utf-8', errors='replace').splitlines():
                fields = line.split()
                if len(fields) != 4:
                    continue
                _, local, _, remote = fields
                if set(local) == {'0'}:
                    continue
                import re
                if not re.fullmatch('[0-9a-f]{40,64}', local) or not re.fullmatch('[0-9a-f]{40,64}', remote):
                    raise ValueError('Unexpected push object ID')
                available = set(remote) != {'0'} and git('cat-file', '-e', remote, cwd=repo, check=False).returncode == 0
                log_opts = remote + '..' + local if available else local + ' --not --remotes'
                findings.extend(git_findings(engine(['git', str(repo), '--log-opts', log_opts], cwd=repo), repo))
                revisions = git('rev-list', *log_opts.split(), cwd=repo).stdout.decode().splitlines()
                if len(revisions) > 1000:
                    raise RuntimeError('Push exceeds the bounded historical document scan')
                for revision in revisions:
                    changed = git('diff-tree', '--root', '--no-commit-id', '--name-only', '-r', '-z', revision, cwd=repo).stdout.split(b'\x00')
                    for raw in changed:
                        if not raw:
                            continue
                        path = raw.decode('utf-8', errors='surrogateescape')
                        if pathlib.Path(path).suffix.lower() not in DOCUMENT_SUFFIXES and not PLUGINS:
                            continue
                        entry = git('rev-parse', revision + ':' + path, cwd=repo, check=False)
                        if entry.returncode:
                            continue  # Deleted file: its earlier added blob is scanned separately.
                        oid = entry.stdout.decode().strip()
                        if oid in document_blobs:
                            continue
                        document_blobs.add(oid)
                        if len(document_blobs) > 100:
                            raise RuntimeError('Push exceeds the bounded historical document scan')
                        size = int(git('cat-file', '-s', oid, cwd=repo).stdout)
                        if size > CONFIG['max_file_bytes']:
                            issues.append({'path': path, 'status': 'skipped-size'}); continue
                        extra, status = scan_blob(git('cat-file', 'blob', oid, cwd=repo).stdout, str(repo / path))
                        if status != 'scanned':
                            issues.append({'path': path, 'status': status})
                        for item in extra:
                            item['commit'] = revision
                            item['id'] = hashlib.sha256((item['id'] + '|' + revision).encode()).hexdigest()
                            if pathlib.Path(path).suffix.lower() == '.json' and item['rule'] == 'generic-api-key':
                                findings.extend(git_findings([{'File': str(repo / path), 'RuleID': item['rule'], 'StartLine': item['line'], 'Commit': revision}], repo))
                            else:
                                findings.append(finding_details.describe(item))
        unique = {}
        rank = {'block': 3, 'review': 2, 'info': 1}
        for item in findings:
            key = (item['path'], item['part'], item['line'], item['rule'], item.get('commit'))
            previous = unique.get(key)
            if previous is None or rank.get(item['severity'], 3) > rank.get(previous['severity'], 3):
                unique[key] = item
        report = save_report('git-' + kind, [{'status': 'scanned', 'findings': list(unique.values())}, *issues], conn, {'repo': str(repo)})
        blocked = [f for f in report['findings'] if f['severity'] == 'block']
        print(presentation.render(report, report['report_path']), file=sys.stderr)
        if issues:
            return 2
        if blocked:
            return 1
    except Exception as error:
        print(f'LeakGuard could not complete the scan ({type(error).__name__}); Git operation blocked.', file=sys.stderr)
        return 2
    finally:
        conn.close()
    return existing_hook(repo, kind, args, payload) if kind == 'pre-push' else 0


def main():
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
    return main()


if __name__ == '__main__':
    sys.exit(run())
