"""JSON CLI for shared-drive reports and the companion location catalog.

All commands emit metadata only. No command moves/removes files or prints secrets.
"""
import argparse
import collections
import fnmatch
import json
import os
import pathlib
import sqlite3
import stat
import subprocess
import sys

from . import catalog
from . import policies
from . import presentation

MAX_EXPLICIT_REPORT_BYTES = 64_000_000
MAX_LEGACY_ARCHIVE_ENTRIES = 1_000
MAX_LEGACY_ARCHIVE_TOTAL_BYTES = 64_000_000
MAX_LEGACY_ARCHIVE_FILE_BYTES = 4_000_000
MAX_LEGACY_ARCHIVE_FINDINGS = 10_000


def rows(conn, sql, args=()):
    cursor = conn.execute(sql, args)
    names = [item[0] for item in cursor.description]
    return [dict(zip(names, row)) for row in cursor]


def report(profile, conn, guard):
    """Return a bounded schema-0 view using only the safe legacy allowlist."""
    cases = {}
    report_dir = guard.STATE / 'reports'
    total_bytes = 0
    entries_seen = 0
    findings_seen = 0
    if report_dir.exists():
        with os.scandir(report_dir) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > MAX_LEGACY_ARCHIVE_ENTRIES:
                    raise ValueError('legacy archive entry bound exceeded')
                if not entry.name.endswith('.json'):
                    continue
                remaining = MAX_LEGACY_ARCHIVE_TOTAL_BYTES - total_bytes
                if remaining <= 0:
                    raise ValueError('legacy archive byte bound exceeded')
                raw = _read_explicit_report_bytes(
                    pathlib.Path(entry.path),
                    max_bytes=min(MAX_LEGACY_ARCHIVE_FILE_BYTES, remaining),
                )
                total_bytes += len(raw)
                try:
                    data = _decode_report(raw)
                except (ValueError, UnicodeError):
                    continue
                version = data.get('schema_version', 0) if type(data) is dict else None
                if type(version) is not int or version != 0:
                    continue
                safe = presentation.sanitized_report(data)
                checked = safe.get('checked_utc')
                for finding in safe['findings']:
                    findings_seen += 1
                    if findings_seen > MAX_LEGACY_ARCHIVE_FINDINGS:
                        raise ValueError('legacy archive finding bound exceeded')
                    if finding['severity'] == 'info':
                        continue
                    name = policies.canonical(finding['path'], guard.CONFIG)
                    case_profile = policies.profile(name, guard.CONFIG)
                    if profile != 'all' and case_profile != profile:
                        continue
                    rule = finding['rule']
                    family = (
                        'application-credential'
                        if rule in {'azure-ad-client-secret', 'literal-client-secret', 'known-material-credential'}
                        else rule
                    )
                    key = (name, finding['line'], family)
                    priority = (
                        'inventory' if case_profile == 'companion'
                        else ('review' if finding['severity'] == 'review' or rule == 'generic-api-key' else 'high')
                    )
                    case = cases.setdefault(key, {
                        'path': name, 'line': finding['line'], 'family': family,
                        'rules': [], 'profile': case_profile, 'priority': priority,
                        'first_reported': checked, 'last_reported': checked,
                    })
                    if checked is not None:
                        if case['first_reported'] is None or checked < case['first_reported']:
                            case['first_reported'] = checked
                        if case['last_reported'] is None or checked > case['last_reported']:
                            case['last_reported'] = checked
                    if rule not in case['rules']:
                        case['rules'].append(rule)
    for case in cases.values():
        case['rules'].sort()
    active = [case for case in cases.values() if case['profile'] == 'general']
    return {
        'legacy_schema': 0,
        'profile': profile,
        'cases': len(cases),
        'needs_review': len(active),
        'priority_counts': dict(collections.Counter(case['priority'] for case in active)),
        'coverage': 'unknown (legacy historical observations; current presence and archive completeness are unverified)',
        'findings': sorted(cases.values(), key=lambda case: (case['priority'] != 'high', case['path'], case['line'])),
    }


def main(argv=None):
    try:
        return _main(argv)
    except Exception:
        print('LeakGuard: manage-failed', file=sys.stderr)
        return 2


def _main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('status')
    explain = commands.add_parser('explain', help='Concise redacted report for the current repository')
    explain.add_argument('--report'); explain.add_argument('--repo'); explain.add_argument('--format', choices=['text', 'json'], default='text')
    find = commands.add_parser('locate'); find.add_argument('pattern'); find.add_argument('--profile', choices=['general', 'companion', 'all'], default='companion'); find.add_argument('--limit', type=int, default=50)
    history = commands.add_parser('history'); history.add_argument('path'); history.add_argument('--limit', type=int, default=50)
    copies = commands.add_parser('copies'); copies.add_argument('path')
    where = commands.add_parser('where'); where.add_argument('name')
    plan = commands.add_parser('plan-location'); plan.add_argument('path')
    summary = commands.add_parser('report'); summary.add_argument('profile', choices=['general', 'companion', 'all'])
    summary.add_argument('--state', choices=['current', 'history'], default='current')
    summary.add_argument('--format', choices=['text', 'json'], default='text')
    summary.add_argument('--legacy-archive', action='store_true', help='Read the pre-0.2 report archive')
    summary.add_argument('--limit', type=_page_limit,
                         help='Maximum indexed findings to return (1..10000; default: 1000)')
    summary.add_argument('--cursor', help='Opaque continuation token from a previous findings page')
    register = commands.add_parser('register-material'); register.add_argument('name'); register.add_argument('--source', required=True); register.add_argument('--field', required=True); register.add_argument('--format', choices=['json', 'python-assignment'], default='json'); register.add_argument('--kind', choices=['credential', 'license'], default='credential')
    share = commands.add_parser('add-share'); share.add_argument('name'); share.add_argument('root'); share.add_argument('--alias', action='append', default=[])
    companion = commands.add_parser('add-companion'); companion.add_argument('name'); companion.add_argument('root')
    review = commands.add_parser('review'); review.add_argument('path'); review.add_argument('--line', type=int, required=True); review.add_argument('--family', required=True); review.add_argument('--status', choices=['false-positive', 'accepted-location', 'needs-owner'], required=True); review.add_argument('--reason', required=True)
    args = parser.parse_args(argv)
    if args.command == 'explain' and not args.report:
        return _typed_explain(args)
    if args.command == 'explain':
        try:
            path = pathlib.Path(args.report)
            data = _read_explicit_report(path)
            if type(data) is not dict:
                raise ValueError('report must be an object')
            version = data.get('schema_version')
            if 'schema_version' in data and (type(version) is not int or version not in {0, 1}):
                raise ValueError('unsupported report schema')
            if version == 1:
                from .scan_store import _report_from
                typed = _report_from(data)
                canonical = json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
                if canonical != typed.to_json():
                    raise ValueError('invalid schema-1 report')
                if args.format == 'json':
                    print(typed.to_json())
                else:
                    print(presentation.render(typed, path))
            else:
                sanitized = presentation.sanitized_report(data)
                if args.format == 'json':
                    print(json.dumps(sanitized, ensure_ascii=True, sort_keys=True, indent=2))
                else:
                    print(presentation.render(data, path))
            return 0
        except Exception:
            print('LeakGuard: invalid-report', file=sys.stderr)
            return 2
    if args.command == 'report' and not args.legacy_archive:
        return _typed_findings_report(args)
    if args.command == 'report' and args.legacy_archive and (args.cursor is not None or args.limit is not None):
        print('LeakGuard: pagination-unavailable-for-legacy-archive', file=sys.stderr)
        return 2
    from . import engine as guard

    conn = guard.db()
    conn.execute('CREATE TABLE IF NOT EXISTS finding_reviews(path TEXT,line INTEGER,family TEXT,status TEXT,reason TEXT,updated TEXT,PRIMARY KEY(path,line,family))')
    if args.command == 'status':
        result = {'host': catalog.HOST, 'sources': guard.CONFIG['audit_scopes'], 'profiles': guard.CONFIG.get('profiles'), 'catalog_counts': rows(conn, 'SELECT profile,category,count(*) AS files FROM locations WHERE path NOT LIKE ? GROUP BY profile,category', ('%leakguard-test-%',)), 'pending_files': rows(conn, 'SELECT scope,count(*) AS queued FROM files WHERE scope NOT LIKE ? GROUP BY scope', ('fixture-%',)), 'pending_directories': rows(conn, 'SELECT scope,count(*) AS queued FROM directories WHERE scope NOT LIKE ? GROUP BY scope', ('fixture-%',)), 'cycles': rows(conn, 'SELECT * FROM cycles WHERE scope NOT LIKE ?', ('fixture-%',))}
        status = guard.STATE / 'watch-status.json'
        result['watcher'] = json.loads(status.read_text(encoding='utf-8-sig')) if status.exists() else None
    elif args.command == 'register-material':
        source = pathlib.Path(args.source).resolve()
        if not source.is_file():
            raise ValueError('Reference file must exist')
        conn.execute('INSERT OR REPLACE INTO material_sources VALUES(?,?,?,?,?)', (args.name, str(source), args.format, args.field, args.kind)); conn.commit()
        if not any(name == args.name for name, _, _ in catalog.known_values(conn)):
            conn.execute('DELETE FROM material_sources WHERE name=?', (args.name,)); conn.commit()
            raise ValueError('The reference must identify a string of at least eight characters')
        result = {'registered': args.name, 'source': str(source), 'value_stored_or_printed': False}
    elif args.command in {'add-share', 'add-companion'}:
        path = pathlib.Path(args.root)
        if not path.is_absolute() or args.name in guard.CONFIG['audit_scopes']:
            raise ValueError('Use an absolute approved share path and a distinct source name')
        if guard.CONFIG_PATH is None:
            raise ValueError('Set LEAKGUARD_CONFIG to an external writable configuration first')
        config = dict(guard.CONFIG)
        config['audit_scopes'][args.name] = str(path)
        config.setdefault('scope_aliases', {})[args.name] = getattr(args, 'alias', [])
        kind = 'general' if args.command == 'add-share' else 'companion'
        config.setdefault('profiles', {}).setdefault(kind, {}).setdefault('sources', []).append(args.name)
        config.setdefault('watch_scopes', {})[args.name] = str(path)
        guard.CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding='utf-8')
        result = {'registered_read_only_source': args.name, 'profile': kind, 'root': str(path), 'next_step': 'Restart Local-LeakGuard-Watch to load the new source; scheduled audits read config at each run.', 'network_hosts_discovered_automatically': False}
    elif args.command == 'report':
        result = report(args.profile, conn, guard)
        (guard.STATE / ('SUMMARY-' + args.profile + '.json')).write_text(json.dumps(result, indent=2), encoding='utf-8')
    elif args.command == 'review':
        path = policies.canonical(args.path, guard.CONFIG)
        conn.execute('INSERT OR REPLACE INTO finding_reviews VALUES(?,?,?,?,?,?)', (path, args.line, args.family, args.status, args.reason, guard.now())); conn.commit()
        result = {'path': path, 'review_status': args.status, 'file_modified': False, 'git_detection_suppressed': False}
    elif args.command == 'locate':
        records = rows(conn, 'SELECT host,path,category,size,first_seen,last_seen,present FROM locations WHERE (?=? OR profile=?) ORDER BY last_seen DESC', (args.profile, 'all', args.profile))
        selected = [r for r in records if fnmatch.fnmatch(r['path'].lower(), args.pattern.lower()) or fnmatch.fnmatch(pathlib.Path(r['path']).name.lower(), args.pattern.lower())]
        result = {'matches': selected[:args.limit], 'truncated': len(selected) > args.limit, 'no_file_contents_read': True}
    elif args.command == 'where':
        result = {'name': args.name, 'reference': rows(conn, 'SELECT source,kind FROM material_sources WHERE name=?', (args.name,)), 'locations': rows(conn, 'SELECT host,name,path,first_seen,last_seen,present FROM material_locations WHERE name=? ORDER BY last_seen DESC', (args.name,)), 'values_withheld': True}
    else:
        path = policies.canonical(args.path, guard.CONFIG)
        if args.command == 'history':
            result = {'path': path, 'events': rows(conn, 'SELECT host,path,old_path,kind,profile,observed FROM location_events WHERE path=? OR old_path=? ORDER BY observed DESC LIMIT ?', (path, path, args.limit))}
        elif args.command == 'copies':
            found = conn.execute('SELECT digest FROM locations WHERE path=? AND digest IS NOT NULL ORDER BY last_seen DESC LIMIT 1', (path,)).fetchone()
            result = {'path': path, 'copies': rows(conn, 'SELECT host,path,profile,first_seen,last_seen,present FROM locations WHERE digest=?', (found[0],)) if found else [], 'matching': 'exact small-file content checksum; names alone do not establish a copy'}
        else:
            category = policies.classify(path)
            materials = rows(conn, 'SELECT name FROM material_locations WHERE path=? AND present=1', (path,))
            target = guard.CONFIG.get('credential_store') if category == 'credential-material' or materials else None
            conventions = {'source-code': 'Keep code in its owning checkout under the owning project directory.', 'document': 'Keep project documents with their project; personal reference documents under Documents/<project>.', 'configuration': 'Keep application settings with the owning project; machine settings under a user-managed service configuration directory; sensitive values in pwds.', 'history-or-log': 'Keep application-managed logs/history in the application location; change its configuration before relocating.'}
            result = {'path': path, 'category': category, 'known_material_names': materials, 'suggested_store': target, 'location_convention': conventions.get(category, 'Review owner, consumers and retention before choosing a location.'), 'plan': 'Extract sensitive values into the private store and reference them; do not relocate application source or logs wholesale.' if materials and category != 'credential-material' else 'Review service/project ownership before choosing a destination.', 'actions_performed': [], 'automatic_moves_enabled': False}
    print(json.dumps(result, indent=2)); conn.close()
    return 0


def _open_scan_store():
    """Open the durable store explicitly without importing detector setup."""
    from . import settings
    from .scan_store import SQLiteScanStore

    config, _ = settings.load()
    return SQLiteScanStore(settings.state_directory(), config=config)


def _typed_findings_report(args):
    store = None
    try:
        store = _open_scan_store()
        profile = None if args.profile == 'all' else args.profile
        page = store.query_findings_page(
            state=args.state, profile=profile, limit=args.limit or 1000, cursor=args.cursor,
        )
        result = presentation.findings_page_report_to_dict(
            args.state, args.profile, page.rows,
            has_more=page.has_more, next_cursor=page.next_cursor,
        )
        if args.format == 'json':
            print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
        else:
            print(presentation.render_findings_report(result))
        return 0
    except Exception as error:
        _report_state_error(error)
        return 2
    finally:
        if store is not None:
            try:
                store.close()
            except Exception:
                pass


def _typed_explain(args):
    store = None
    try:
        repository = _repository_argument(args.repo)
        if repository is None:
            print('LeakGuard: report-unavailable', file=sys.stderr)
            return 2
        store = _open_scan_store()
        report = store.latest_report(repository)
        if report is None:
            print('LeakGuard: report-unavailable', file=sys.stderr)
            return 2
        if args.format == 'json':
            print(report.to_json())
        else:
            print(presentation.render(report))
        return 0
    except Exception as error:
        _report_state_error(error)
        return 2
    finally:
        if store is not None:
            try:
                store.close()
            except Exception:
                pass


def _repository_argument(value):
    if value:
        return str(pathlib.Path(value).expanduser().resolve())
    try:
        process = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'], capture_output=True,
            timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if process.returncode:
        return None
    return os.fsdecode(process.stdout.removesuffix(b'\n'))


def _read_explicit_report(path):
    return _decode_report(_read_explicit_report_bytes(path))


def _read_explicit_report_bytes(path, *, max_bytes=MAX_EXPLICIT_REPORT_BYTES):
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ValueError('report is not a bounded regular file')
        chunks = []
        size = 0
        while size <= max_bytes:
            chunk = os.read(descriptor, min(1_048_576, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > max_bytes:
            raise ValueError('report exceeds the configured read bound')
        return b''.join(chunks)
    finally:
        os.close(descriptor)


def _decode_report(raw):
    return json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_unique_json_object)


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate report field')
        result[key] = value
    return result


def _report_state_error(error):
    code = getattr(error, 'code', None)
    field = getattr(error, 'field', None)
    if code == 'configuration-invalid':
        suffix = f' ({field})' if field in {'configuration', 'plugins', 'audit_scopes', 'profiles'} else ''
        print(f'LeakGuard: configuration-invalid{suffix}', file=sys.stderr)
    else:
        print('LeakGuard: state-failed', file=sys.stderr)


def _page_limit(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError('limit must be an integer from 1 to 10000') from None
    if parsed < 1 or parsed > 10000:
        raise argparse.ArgumentTypeError('limit must be an integer from 1 to 10000')
    return parsed


if __name__ == '__main__':
    raise SystemExit(main())
