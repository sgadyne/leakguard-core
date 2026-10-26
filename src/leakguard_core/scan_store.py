"""Injectable redacted scan state; credential storage is a separate capability.

An injected store is the sole durable sink. The memory implementation is useful for
an ephemeral scanner and as a reference for application-owned encrypted stores.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
from typing import Protocol, runtime_checkable
import uuid
import threading
from functools import wraps


def _synchronized(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._lock:
            import time
            deadline = getattr(self, '_deadlines', {}).get(threading.get_ident())
            if method.__name__ not in {'set_deadline', 'close'} and deadline is not None and time.monotonic() >= deadline:
                raise StateError()
            return method(self, *args, **kwargs)
    return locked


def _bounded_sql(method):
    @wraps(method)
    def bounded(self, *args, **kwargs):
        import sqlite3
        try:
            self._apply_budget()
            return method(self, *args, **kwargs)
        except sqlite3.Error:
            try:
                self.conn.rollback()
            except sqlite3.Error:
                pass
            raise StateError() from None
    return bounded

from . import models as m


class StateError(RuntimeError):
    """A stable state failure, without database paths or exception text."""
    def __init__(self, code='state-failed'):
        self.code = code
        super().__init__(code)


def source_key(source: m.SourceRef, scope: str = '') -> str:
    # Git observations are historical, but their complete immutable version remains
    # part of the key so unrelated snapshots cannot share current state.
    value = [scope, source.kind.value, source.repository, source.path,
             source.commit, source.index_tree_oid]
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True)
class WorkLease:
    scope: str
    generation: int
    owner: str


@dataclass(frozen=True)
class WorkClaim:
    lease: WorkLease
    path: str
    kind: str


@dataclass(frozen=True)
class DirectorySnapshot:
    path: str
    signature: tuple[int, int, int, int, int] | None


@dataclass(frozen=True)
class DirectoryProgress:
    signature: tuple[int, int, int, int, int]
    entries: int
    prefix_sha256: str

    def __post_init__(self):
        if (_directory_signature(self.signature) is None or type(self.entries) is not int
                or not 0 <= self.entries <= 100_000 or type(self.prefix_sha256) is not str
                or not __import__('re').fullmatch('[0-9a-f]{64}', self.prefix_sha256)):
            raise StateError()


def _directory_signature(value):
    if value is None:
        return None
    if type(value) is not tuple or len(value) != 5 or any(type(item) is not int for item in value):
        raise StateError()
    return value


@dataclass(frozen=True)
class FindingPage:
    rows: tuple[dict, ...]
    next_cursor: str | None

    @property
    def page_count(self):
        return len(self.rows)

    @property
    def has_more(self):
        return self.next_cursor is not None


def _query_position(state, profile, limit, cursor):
    import base64
    if state not in {'current', 'history'} or type(limit) is not int or not 1 <= limit <= 10_000 or profile is not None and (type(profile) is not str or not 1 <= len(profile) <= 80):
        raise StateError('state-query-invalid')
    fingerprint = hashlib.sha256(json.dumps([state, profile], separators=(',', ':')).encode()).hexdigest()
    position = ['', ''] if state == 'current' else 0
    if cursor is not None:
        try:
            if type(cursor) is not str or not cursor.startswith('lg1.') or len(cursor) > 1024:
                raise ValueError()
            encoded = cursor[4:]
            payload = json.loads(base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True))
            import re
            if not re.fullmatch('[A-Za-z0-9_-]+', encoded):
                raise ValueError()
            if type(payload) is not list or len(payload) != 3 or type(payload[0]) is not int or payload[0] != 1 or payload[1] != fingerprint:
                raise ValueError()
            position = payload[2]
            if state == 'current':
                if type(position) is not list or len(position) != 2 or any(type(x) is not str or not 0 < len(x) <= 256 for x in position):
                    raise ValueError()
            elif type(position) is not int or position < 0:
                raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            raise StateError('state-query-invalid') from None
    return fingerprint, position


def _query_cursor(fingerprint, position):
    import base64
    return 'lg1.' + base64.urlsafe_b64encode(json.dumps([1, fingerprint, position], separators=(',', ':')).encode()).decode().rstrip('=')


def _filter_page(rows, profile, config):
    if profile is None:
        return tuple(rows)
    from .policies import profile as select_profile
    return tuple(row for row in rows if ('git' if row['source']['kind'] in {'git-index', 'git-commit'} else select_profile(row['source']['path'], config)) == profile)


@runtime_checkable
class ScanStore(Protocol):
    def set_deadline(self, deadline: float | None) -> None: ...
    def reserve(self, source: m.SourceRef, *, scope: str = '') -> int: ...
    def get_cached(self, cache_key: str) -> m.ScanResult | None: ...
    def record_result(self, result: m.ScanResult, *, generation: int,
                      cache_key: str | None = None, scope: str = '', work: WorkClaim | None = None,
                      material_observations: tuple = (), materials_checked: bool = False,
                      materials_complete: bool = False, anchor=None) -> str: ...
    def record_report(self, report: m.ScanReport, *, repository: str | None = None) -> None: ...
    def latest_report(self, repository: str | None = None) -> m.ScanReport | None: ...
    def query_findings_page(self, *, state: str = 'current', profile: str | None = None, limit: int = 1000, cursor: str | None = None) -> FindingPage: ...
    def query_findings(self, *, state: str = 'current', profile: str | None = None) -> tuple[dict, ...]: ...
    def source_anchor(self, source: m.SourceRef): ...
    def confirm_absent(self, proof, *, generation: int) -> bool: ...
    def material_snapshot(self, *, max_bytes: int = 1_000_000, max_sources: int = 100): ...
    def acquire_cycle(self, scope: str, root, *, lease_seconds: float) -> WorkLease | None: ...
    def lease_valid(self, lease: WorkLease) -> bool: ...
    def enqueue_work(self, lease: WorkLease, entries, *, refresh: bool = False) -> None: ...
    def claim_work(self, lease: WorkLease) -> WorkClaim | None: ...
    def finish_directory(self, claim: WorkClaim, *, success: bool | None, signature=None, omitted=False) -> None: ...
    def directory_page(self, lease: WorkLease, *, limit: int = 256) -> tuple[DirectorySnapshot, ...]: ...
    def record_directory_checks(self, lease: WorkLease, checks: tuple) -> None: ...
    def cycle_status(self, lease: WorkLease) -> dict: ...
    def release_cycle(self, lease: WorkLease, *, allow_complete: bool = True) -> None: ...
    def reconcile_cycle(self, lease: WorkLease, root) -> None: ...
    def invalidate_scope(self, root, *, reason: str = 'source-unavailable') -> None: ...
    def record_event(self, path: str, kind: str, *, old_path=None, when=None) -> None: ...
    def record_metadata(self, path: str, size: int) -> None: ...
    def close(self) -> None: ...


class MemoryScanStore:
    """No filesystem writes, JSON archive, SQLite connection or implicit mirror."""
    def __init__(self, *, config=None):
        self._lock = threading.RLock()
        self._deadlines = {}
        self.config = config or {}
        self.generations = {}
        self.reservation_times = {}
        self.results = {}
        self.cache = {}
        self.reports = []
        self.report_context = {}
        self.states = {}
        self._current_order = []
        self._history = []
        self.current = {}
        self.cycles = {}
        self.work = {}
        self.locations = {}
        self.anchors = {}
        self.material_sources = []
        self.material_locations = {}
        self._material_key = __import__('secrets').token_bytes(32)

    @_synchronized
    def set_deadline(self, deadline):
        if deadline is None:
            self._deadlines.pop(threading.get_ident(), None)
        else:
            self._deadlines[threading.get_ident()] = deadline

    @_synchronized
    def reserve(self, source, *, scope=''):
        key = source_key(source, scope)
        generation = self.generations.get(key, 0) + 1
        self.generations[key] = generation
        self.reservation_times[key] = datetime.now(timezone.utc).isoformat()
        return generation

    @_synchronized
    def get_cached(self, cache_key):
        entry = self.cache.get(cache_key)
        return replace(self.results[entry], reused_from=self.results[entry].reused_from or entry) if entry else None

    @_synchronized
    def record_result(self, result, *, generation, cache_key=None, scope='', work=None, material_observations=(), materials_checked=False, materials_complete=False, anchor=None):
        if type(result) is not m.ScanResult:
            raise StateError()
        scan_id = uuid.uuid4().hex
        self.results[scan_id] = result
        self._history.extend(_query_row(finding, result) for finding in result.findings)
        key = source_key(result.source, scope)
        if self.generations.get(key) != generation or work is not None and not self.lease_valid(work.lease):
            return scan_id
        if result.coverage is m.CoverageState.COMPLETE and result.identity.cache_eligible and cache_key:
            self.cache[cache_key] = scan_id
        if result.source.kind is m.SourceKind.FILESYSTEM:
            prior = self.current.get(key)
            comparable = prior is not None and prior.identity.policy_id == result.identity.policy_id and prior.identity.runtime_id == result.identity.runtime_id
            _transition(self.states, key, result, comparable)
            import bisect
            for state_key, row in self.states.items():
                if state_key[0] != key:
                    continue
                position = bisect.bisect_left(self._current_order, state_key)
                present = position < len(self._current_order) and self._current_order[position] == state_key
                if row['state'] in {'active', 'unknown'} and not present:
                    self._current_order.insert(position, state_key)
                elif row['state'] == 'resolved' and present:
                    self._current_order.pop(position)
            self.current[key] = result
            if result.content:
                self.locations[result.source.path] = {'size': result.content.size_bytes, 'digest': result.content.digest, 'present': True}
        if anchor is not None and result.source.kind is m.SourceKind.FILESYSTEM:
            self.anchors[key] = anchor
        if materials_checked and result.source.kind is m.SourceKind.FILESYSTEM:
            self._record_materials(result, material_observations, complete=materials_complete)
        self._finish_work(work, result, scan_id=scan_id)
        return scan_id

    @_synchronized
    def record_report(self, report, *, repository=None):
        if type(report) is not m.ScanReport:
            raise StateError()
        self.reports.append(report)
        repositories = {result.source.repository for result in report.results if result.source.repository}
        self.report_context[report.run_id] = repository if repository is not None else next(iter(repositories)) if len(repositories) == 1 else None

    @_synchronized
    def latest_report(self, repository=None):
        return next((report for report in reversed(self.reports)
                     if repository is None or self.report_context.get(report.run_id) == repository), None)

    @_synchronized
    def query_findings_page(self, *, state='current', profile=None, limit=1000, cursor=None):
        import bisect
        import copy
        fingerprint, position = _query_position(state, profile, limit, cursor)
        if state == 'current':
            offset = bisect.bisect_right(self._current_order, tuple(position))
            keys = self._current_order[offset:offset + limit + 1]
            rows = [copy.deepcopy(self.states[key]) for key in keys[:limit]]
            next_cursor = _query_cursor(fingerprint, list(keys[limit - 1])) if len(keys) > limit else None
        else:
            rows = [copy.deepcopy(row) for row in self._history[position:position + limit]]
            next_cursor = _query_cursor(fingerprint, position + limit) if position + limit < len(self._history) else None
        return FindingPage(_filter_page(rows, profile, self.config), next_cursor)

    @_synchronized
    def query_findings(self, *, state='current', profile=None):
        """Compatibility wrapper returning the first bounded page only."""
        return self.query_findings_page(state=state, profile=profile).rows

    @_synchronized
    def close(self):
        pass

    @_synchronized
    def acquire_cycle(self, scope, root, *, lease_seconds):
        import time
        now = time.time()
        current = self.cycles.get(scope)
        if current and current['owner'] and current['lease_until'] > now:
            return None
        fresh = current is None or current['completed'] is not None
        generation = (current['generation'] + 1) if current and fresh else current['generation'] if current else 1
        owner = uuid.uuid4().hex
        cycle = {'generation': generation, 'owner': owner, 'lease_until': now + lease_seconds, 'completed': None, 'started': datetime.now(timezone.utc).isoformat() if fresh else current['started'], 'has_checked': bool(current and not fresh and current.get('has_checked')), 'work_identity': current.get('work_identity') if current else None}
        self.cycles[scope] = cycle
        lease = WorkLease(scope, generation, owner)
        for key, work in self.work.items():
            if key[:2] == (scope, generation):
                work['claimed'] = None
        if fresh and root is not None:
            self.enqueue_work(lease, ((str(root), 'directory', 10),))
        return lease

    @_synchronized
    def bind_cycle_identity(self, lease, identity, *, root):
        if (not self.lease_valid(lease) or type(identity) is not str
                or not __import__('re').fullmatch('[0-9a-f]{64}', identity)):
            raise StateError()
        cycle = self.cycles[lease.scope]
        if cycle.get('work_identity') == identity:
            return False
        self.invalidate_scope(root)
        for key in tuple(self.work):
            if key[:2] == (lease.scope, lease.generation):
                del self.work[key]
        cycle.update(work_identity=identity, started=datetime.now(timezone.utc).isoformat(), has_checked=False)
        self.enqueue_work(lease, ((str(__import__('pathlib').Path(root).absolute()), 'directory', 10),))
        return True

    @_synchronized
    def lease_valid(self, lease):
        import time
        cycle = self.cycles.get(lease.scope)
        return bool(cycle and cycle['generation'] == lease.generation and cycle['owner'] == lease.owner and cycle['lease_until'] > time.time())

    @_synchronized
    def enqueue_work(self, lease, entries, *, refresh=False):
        if not self.lease_valid(lease):
            raise StateError()
        changed = False
        for path, kind, priority in entries:
            key = (lease.scope, lease.generation, path, kind)
            if refresh or key not in self.work:
                self.work[key] = {'priority': priority, 'attempts': 0, 'failed': False, 'done': False, 'claimed': None, 'verified': False, 'directory_signature': None, 'directory_checked': False, 'directory_progress': None, 'result_scan_id': None}
                changed = True
        if changed:
            self._reset_directory_checks(lease)

    @_synchronized
    def claim_work(self, lease):
        if not self.lease_valid(lease):
            raise StateError()
        pending = [(key, row) for key, row in self.work.items() if key[:2] == (lease.scope, lease.generation) and not row['done'] and not row['failed'] and row['claimed'] is None]
        if not pending:
            return None
        key, row = min(pending, key=lambda item: (item[0][3] != 'file', item[1]['priority'], item[0][2]))
        row['claimed'] = lease.owner
        return WorkClaim(lease, key[2], key[3])

    @_synchronized
    def get_directory_progress(self, claim):
        row = self.work.get((claim.lease.scope, claim.lease.generation, claim.path, claim.kind))
        if (claim.kind != 'directory' or not self.lease_valid(claim.lease)
                or row is None or row['claimed'] != claim.lease.owner):
            raise StateError()
        return row.get('directory_progress')

    @_synchronized
    def set_directory_progress(self, claim, progress):
        if progress is not None and type(progress) is not DirectoryProgress:
            raise StateError()
        self.get_directory_progress(claim)
        self.work[(claim.lease.scope, claim.lease.generation, claim.path, claim.kind)]['directory_progress'] = progress

    def _reset_directory_checks(self, lease):
        cycle = self.cycles[lease.scope]
        if not cycle.get('has_checked'):
            return
        for key, row in self.work.items():
            if key[:2] == (lease.scope, lease.generation) and key[3] == 'directory' and row.get('directory_signature') != 'omitted':
                row['directory_checked'] = False
        cycle['has_checked'] = False

    @_synchronized
    def finish_directory(self, claim, *, success, signature=None, omitted=False):
        if not self.lease_valid(claim.lease):
            raise StateError()
        signature = _directory_signature(signature)
        row = self.work[(claim.lease.scope, claim.lease.generation, claim.path, claim.kind)]
        self._reset_directory_checks(claim.lease)
        row['done'] = success is True
        row['directory_signature'] = 'omitted' if omitted else signature
        row['directory_checked'] = bool(omitted)
        if success is not None:
            row['directory_progress'] = None
        if success is False:
            row['attempts'] += 1
            row['failed'] = row['attempts'] >= 3

    @_synchronized
    def directory_page(self, lease, *, limit=256):
        import heapq
        import time
        if not self.lease_valid(lease) or type(limit) is not int or not 1 <= limit <= 1000:
            raise StateError()
        deadline = self._deadlines.get(threading.get_ident())
        def pending():
            for key, row in self.work.items():
                if deadline is not None and time.monotonic() >= deadline:
                    raise StateError()
                if key[:2] == (lease.scope, lease.generation) and key[3] == 'directory' and row['done'] and not row.get('directory_checked') and row.get('directory_signature') != 'omitted':
                    yield key[2], row.get('directory_signature')
        return tuple(DirectorySnapshot(path, signature) for path, signature in heapq.nsmallest(limit, pending(), key=lambda row: row[0]))

    @_synchronized
    def record_directory_checks(self, lease, checks):
        from itertools import islice
        checks = tuple(islice(iter(checks), 1001))
        if not self.lease_valid(lease) or len(checks) > 1000:
            raise StateError()
        if any(not valid for _, _, valid in checks):
            self._reset_directory_checks(lease)
        for path, expected, valid in checks:
            expected = _directory_signature(expected)
            row = self.work.get((lease.scope, lease.generation, path, 'directory'))
            if row is None or row.get('directory_signature') != expected or not row['done']:
                raise StateError()
            if valid and expected is not None:
                row['directory_checked'] = True
                self.cycles[lease.scope]['has_checked'] = True
            else:
                row.update(done=False, claimed=None, failed=False, attempts=0, directory_signature=None, directory_checked=False, directory_progress=None)

    @_synchronized
    def cycle_decision_evidence(self, lease):
        """Summarize accepted results and exclusion markers in this exact cycle."""
        if not self.lease_valid(lease) or not self.cycle_status(lease)['complete']:
            raise StateError()
        severities = set()
        omissions = False
        files = 0
        for key, row in self.work.items():
            if key[:2] != (lease.scope, lease.generation):
                continue
            if key[3] == 'directory':
                omissions |= row['done'] and row.get('directory_signature') == 'omitted'
                continue
            if key[3] != 'file':
                continue
            result = self.results.get(row.get('result_scan_id'))
            if (not row['done'] or result is None or result.source.path != key[2]
                    or result.coverage is m.CoverageState.INCOMPLETE):
                raise StateError()
            files += 1
            omissions |= result.coverage is m.CoverageState.OMITTED or any(
                not issue.required and issue.omission_id is not None for issue in result.issues)
            input_key = source_key(result.source)
            for finding in result.findings:
                state = self.states.get((input_key, finding.id))
                if state is None or state['state'] != 'resolved':
                    severities.add(finding.severity.value)
        return {'severities': tuple(sorted(severities)), 'has_omissions': omissions, 'files': files}

    @_synchronized
    def _finish_work(self, work, result, *, scan_id):
        if work is None:
            return
        row = self.work.get((work.lease.scope, work.lease.generation, work.path, work.kind))
        if row is None or row['claimed'] != work.lease.owner:
            return
        self._reset_directory_checks(work.lease)
        row['result_scan_id'] = scan_id
        row['done'] = result.coverage is not m.CoverageState.INCOMPLETE
        row['verified'] = result.coverage is m.CoverageState.COMPLETE
        if not row['done']:
            row['attempts'] += 1
            row['failed'] = row['attempts'] >= 3

    @_synchronized
    def cycle_status(self, lease):
        pending = [(key, row) for key, row in self.work.items() if key[:2] == (lease.scope, lease.generation) and (not row['done'] or key[3] == 'directory' and not row.get('directory_checked'))]
        return {'complete': not pending, 'pending_files': sum(key[3] == 'file' for key, _ in pending), 'pending_directories': sum(key[3] == 'directory' for key, _ in pending), 'failed': sum(row['failed'] for _, row in pending), 'cycle_id': str(lease.generation)}

    @_synchronized
    def release_cycle(self, lease, *, allow_complete=True):
        if not self.lease_valid(lease):
            return
        status = self.cycle_status(lease)
        cycle = self.cycles[lease.scope]
        cycle['owner'] = None
        cycle['lease_until'] = 0
        if status['complete'] and allow_complete:
            cycle['completed'] = datetime.now(timezone.utc).isoformat()
        for key, row in self.work.items():
            if key[:2] == (lease.scope, lease.generation):
                row['claimed'] = None

    @_synchronized
    def reset_cycle(self, scope):
        """Abandon inactive enumeration only; retain all exposure evidence."""
        import time
        if type(scope) is not str or not scope:
            raise StateError()
        cycle = self.cycles.get(scope)
        if cycle and cycle.get('owner') and cycle.get('lease_until', 0) > time.time():
            raise StateError('state-cycle-busy')
        self.cycles.pop(scope, None)
        self.work = {key: value for key, value in self.work.items() if key[0] != scope}

    @_synchronized
    def reconcile_cycle(self, lease, root):
        from pathlib import Path
        if not self.lease_valid(lease):
            raise StateError()
        root = Path(root).absolute()
        observed = {key[2] for key, row in self.work.items() if key[:2] == (lease.scope, lease.generation) and row.get('verified')}
        started = self.cycles[lease.scope]['started']
        changed = set()
        for (key, _), row in self.states.items():
            path = Path(row['source']['path']).absolute()
            if row['state'] in {'active', 'unknown'} and (path == root or root in path.parents) and row['source']['path'] not in observed and row['last_seen'] <= started and self.reservation_times.get(key, '') <= started:
                row.update(state='unknown', resolved_at=None, state_reason='source-unavailable')
                changed.add(key)
        for key in changed:
            self.generations[key] = self.generations.get(key, 0) + 1

    @_synchronized
    def invalidate_scope(self, root, *, reason='source-unavailable'):
        if reason not in {'source-unavailable', 'source-event', 'incomplete-scan'}:
            raise StateError()
        from pathlib import Path
        root = Path(root).absolute()
        for row in self.states.values():
            path = Path(row['source']['path']).absolute()
            if row['state'] in {'active', 'unknown'} and (root == path or root in path.parents):
                row.update(state='unknown', resolved_at=None, state_reason=reason)

    @_synchronized
    def source_anchor(self, source):
        return self.anchors.get(source_key(source))

    @_synchronized
    def confirm_absent(self, proof, *, generation):
        from .sources import AbsenceProof
        if type(proof) is not AbsenceProof or not proof.valid():
            raise StateError()
        source = m.SourceRef(m.SourceKind.FILESYSTEM, proof.anchor.source_path)
        key = source_key(source)
        if self.generations.get(key) != generation or self.anchors.get(key) != proof.anchor:
            return False
        when = proof.observed_at.isoformat()
        for state_key, row in self.states.items():
            if state_key[0] == key and row['state'] in {'active', 'unknown'}:
                row.update(state='resolved', state_reason='source-absent', resolved_at=when, last_verified=when)
                if state_key in self._current_order:
                    self._current_order.remove(state_key)
        if source.path in self.locations:
            self.locations[source.path]['present'] = False
        for (_, path), row in self.material_locations.items():
            if path == source.path:
                row['present'] = False
        return True

    @_synchronized
    def material_snapshot(self, *, max_bytes=1_000_000, max_sources=100):
        from .catalog import snapshot_materials
        from itertools import islice
        rows = tuple(islice(iter(self.material_sources), max_sources + 1))
        snapshot = snapshot_materials(rows, self._material_key, max_bytes=max_bytes, max_sources=max_sources)
        def valid():
            with self._lock:
                current = tuple(islice(iter(self.material_sources), max_sources + 1))
            return current == rows and snapshot.valid()
        return replace(snapshot, validate=valid)

    @_synchronized
    def _record_materials(self, result, observations, *, complete):
        names = {item.name for item in observations}
        for (name, path), row in self.material_locations.items():
            if path == result.source.path and name not in names:
                row['present'] = False if complete else None
        for item in observations:
            self.material_locations[(item.name, result.source.path)] = {'fingerprint': item.fingerprint, 'present': True, 'last_seen': result.observed_at.isoformat()}

    @_synchronized
    def record_metadata(self, path, size):
        if type(size) is not int or size < 0:
            raise StateError()
        self.locations[path] = {'size': size, 'digest': None, 'present': True}

    @_synchronized
    def record_event(self, path, kind, *, old_path=None, when=None):
        if kind not in {'changed', 'created', 'deleted', 'renamed'}:
            raise StateError()
        paths = {path, old_path}
        for row in self.states.values():
            if row['state'] in {'active', 'unknown'} and row['source']['path'] in paths:
                row.update(state='unknown', resolved_at=None, state_reason='source-event')
        for candidate in paths:
            if candidate in self.locations:
                self.locations[candidate]['present'] = None
        for (_, candidate), row in self.material_locations.items():
            if candidate in paths:
                row['present'] = None

def _source_data(source):
    return {'kind': source.kind.value, 'path': source.path, 'repository': source.repository,
            'commit': source.commit, 'blob_oid': source.blob_oid, 'index_tree_oid': source.index_tree_oid}


def _finding_data(finding):
    return {'id': finding.id, 'source': _source_data(finding.source), 'part_id': finding.part_id,
            'start_line': finding.start_line, 'end_line': finding.end_line, 'rule': finding.rule,
            'detector_id': finding.detector_id, 'detector_severity': finding.detector_severity.value,
            'severity': finding.severity.value, 'classification': finding.classification.value,
            'proof_id': finding.proof_id}


def _query_row(finding, result):
    when = result.observed_at.isoformat()
    return {**_finding_data(finding), 'state': 'unknown', 'first_seen': when, 'last_seen': when,
            'last_verified': result.last_verified_at.isoformat() if result.last_verified_at else None,
            'resolved_at': None, 'state_reason': 'historical-observation',
            'policy_id': result.identity.policy_id, 'runtime_id': result.identity.runtime_id}


def _transition(states, key, result, comparable):
    complete = result.coverage is m.CoverageState.COMPLETE
    found = {item.id for item in result.findings}
    when = result.observed_at.isoformat()
    for (input_key, evidence), row in list(states.items()):
        if input_key != key or evidence in found or row['state'] == 'resolved':
            continue
        row_comparable = row['policy_id'] == result.identity.policy_id and row['runtime_id'] == result.identity.runtime_id
        if complete and comparable and row_comparable:
            row.update(state='resolved', resolved_at=when, state_reason='complete-content-scan')
        else:
            row.update(state='unknown', resolved_at=None, state_reason='incomplete-scan' if not complete else 'policy-obsolete')
    for finding in result.findings:
        previous = states.get((key, finding.id))
        row = _query_row(finding, result)
        row.update(state='active' if complete else 'unknown', state_reason='verified-present' if complete else 'partial-observation')
        if previous:
            row['first_seen'] = previous['first_seen']
        states[(key, finding.id)] = row


# Persisted payloads use this closed decoder; arbitrary plugin dictionaries never
# enter either this schema or the public report serializer.
def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields.split()):
        raise StateError()
    return value


def _source_from(value):
    v = _exact(value, 'kind path repository commit blob_oid index_tree_oid')
    return m.SourceRef(m.SourceKind(v['kind']), v['path'], v['repository'], v['commit'], v['blob_oid'], v['index_tree_oid'])


def _time(value):
    return datetime.fromisoformat(value) if value is not None else None


def _finding_from(value):
    v = _exact(value, 'id source part_id start_line end_line rule detector_id detector_severity severity classification proof_id')
    return m.FindingRecord(v['id'], _source_from(v['source']), v['part_id'], v['start_line'], v['end_line'], v['rule'], v['detector_id'], m.DetectorSeverity(v['detector_severity']), m.FindingSeverity(v['severity']), m.FindingClassification(v['classification']), v['proof_id'])


def _issue_from(value):
    v = _exact(value, 'code source part_id required omission_id')
    return m.CoverageIssue(m.ErrorCode(v['code']), _source_from(v['source']) if v['source'] is not None else None, v['part_id'], v['required'], v['omission_id'])


def _array(value):
    if type(value) is not list:
        raise StateError()
    return value


def _result_from(value):
    v = _exact(value, 'source content identity outcome coverage findings issues observed_at last_executed_at last_verified_at reused_from')
    c = _exact(v['content'], 'algorithm digest size_bytes') if v['content'] is not None else None
    i = _exact(v['identity'], 'policy_id runtime_id context_id cache_eligible')
    return m.ScanResult(_source_from(v['source']), m.ContentIdentity(**c) if c is not None else None, m.RuntimeIdentity(**i), m.ScanOutcome(v['outcome']), m.CoverageState(v['coverage']), tuple(_finding_from(f) for f in _array(v['findings'])), tuple(_issue_from(x) for x in _array(v['issues'])), _time(v['observed_at']), _time(v['last_executed_at']), _time(v['last_verified_at']), v['reused_from'])


def _report_from(value):
    v = _exact(value, 'schema_version run_id started_at finished_at policy_id results coverage decision counts issues')
    c = _exact(v['coverage'], 'enumeration_complete required_complete omission_count pending_files pending_directories cycle_id')
    d = _exact(v['decision'], 'verdict reason_codes policy_id')
    report = m.ScanReport(v['schema_version'], v['run_id'], _time(v['started_at']), _time(v['finished_at']), v['policy_id'], tuple(_result_from(r) for r in _array(v['results'])), m.CoverageSummary(**c), m.PolicyDecision(m.DecisionVerdict(d['verdict']), tuple(m.ErrorCode(x) for x in _array(d['reason_codes'])), d['policy_id']), tuple(_issue_from(x) for x in _array(v['issues'])))
    expected = report.to_dict()['counts']
    counts = _exact(v['counts'], ' '.join(expected))
    if any(type(value) is not int or value < 0 for value in counts.values()) or counts != expected:
        raise StateError()
    return report


def _result_json(result):
    # Reuse the single public allowlist, including nested source/identity fields.
    policy_id = result.identity.policy_id
    omissions = sum(not issue.required and issue.omission_id is not None for issue in result.issues) + int(result.coverage is m.CoverageState.OMITTED and not result.issues)
    report = m.ScanReport(1, 'store-result', result.observed_at, result.observed_at, policy_id, (result,), m.CoverageSummary(True, result.coverage is not m.CoverageState.INCOMPLETE, omissions), m.PolicyDecision(m.DecisionVerdict.INCOMPLETE if result.coverage is m.CoverageState.INCOMPLETE else m.DecisionVerdict.ALLOW, (), policy_id))
    return json.dumps(report.to_dict()['results'][0], separators=(',', ':'), ensure_ascii=True)


def _anchor_data(anchor):
    return json.dumps({'source_path': anchor.source_path, 'directories': [[item.path, item.device, item.inode, item.mode] for item in anchor.directories]}, ensure_ascii=True, separators=(',', ':'))


def _anchor_from(payload):
    from .sources import FilesystemAnchor, DirectoryIdentity
    value = _exact(json.loads(payload), 'source_path directories')
    if type(value['source_path']) is not str or type(value['directories']) is not list or not 1 <= len(value['directories']) <= 128:
        raise StateError()
    directories = []
    for item in value['directories']:
        if type(item) is not list or len(item) != 4 or type(item[0]) is not str or len(item[0]) > 4096 or any(type(x) is not int or x < 0 for x in item[1:]):
            raise StateError()
        directories.append(DirectoryIdentity(*item))
    return FilesystemAnchor(value['source_path'], tuple(directories))


_SCHEMA = '''
CREATE TABLE IF NOT EXISTS cache(path TEXT PRIMARY KEY,size INTEGER,mtime INTEGER,status TEXT,policy TEXT,digest TEXT,payload TEXT,executed_at TEXT);
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,path TEXT,rule TEXT,line INTEGER,part TEXT,severity TEXT,first_seen TEXT,last_seen TEXT);
CREATE TABLE IF NOT EXISTS directories(scope TEXT,path TEXT,priority INTEGER NOT NULL DEFAULT 100,PRIMARY KEY(scope,path));
CREATE TABLE IF NOT EXISTS files(scope TEXT,path TEXT,priority INTEGER NOT NULL DEFAULT 100,PRIMARY KEY(scope,path));
CREATE TABLE IF NOT EXISTS cycles(scope TEXT PRIMARY KEY,started TEXT,completed TEXT);
CREATE TABLE IF NOT EXISTS priority_seeds(scope TEXT,path TEXT,cycle TEXT,PRIMARY KEY(scope,path,cycle));
CREATE TABLE IF NOT EXISTS locations(host TEXT,path TEXT,profile TEXT,category TEXT,size INTEGER,digest TEXT,first_seen TEXT,last_seen TEXT,present INTEGER,PRIMARY KEY(host,path));
CREATE TABLE IF NOT EXISTS location_events(id TEXT PRIMARY KEY,host TEXT,path TEXT,old_path TEXT,kind TEXT,profile TEXT,digest TEXT,observed TEXT);
CREATE TABLE IF NOT EXISTS material_sources(name TEXT PRIMARY KEY,source TEXT,format TEXT,field TEXT,kind TEXT);
CREATE TABLE IF NOT EXISTS material_locations(host TEXT,name TEXT,path TEXT,fingerprint TEXT,first_seen TEXT,last_seen TEXT,present INTEGER,PRIMARY KEY(host,name,path));
CREATE TABLE IF NOT EXISTS scan_runs(run_id TEXT PRIMARY KEY,repository TEXT,finished_at TEXT,policy_id TEXT,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS input_scans(scan_id TEXT PRIMARY KEY,input_key TEXT,source_kind TEXT,path TEXT,generation INTEGER,policy_id TEXT,runtime_id TEXT,context_id TEXT,coverage TEXT,observed_at TEXT,payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS input_scans_path ON input_scans(path,observed_at);
CREATE TABLE IF NOT EXISTS scan_findings(scan_id TEXT,finding_id TEXT,payload TEXT NOT NULL,PRIMARY KEY(scan_id,finding_id));
CREATE TABLE IF NOT EXISTS finding_current(input_key TEXT,finding_id TEXT,payload TEXT NOT NULL,PRIMARY KEY(input_key,finding_id));
CREATE TABLE IF NOT EXISTS finding_history(id INTEGER PRIMARY KEY AUTOINCREMENT,scan_id TEXT,finding_id TEXT,payload TEXT NOT NULL,UNIQUE(scan_id,finding_id));
CREATE TABLE IF NOT EXISTS current_inputs(input_key TEXT PRIMARY KEY,generation INTEGER NOT NULL DEFAULT 0,last_complete_scan_id TEXT,latest_attempt_id TEXT,current_state TEXT,state_reason TEXT,policy_id TEXT,runtime_id TEXT,reserved_at TEXT);
CREATE TABLE IF NOT EXISTS finding_state(input_key TEXT,finding_id TEXT,state TEXT,rule TEXT,path TEXT,payload TEXT NOT NULL,PRIMARY KEY(input_key,finding_id));
CREATE INDEX IF NOT EXISTS finding_state_query ON finding_state(state,path,rule);
CREATE INDEX IF NOT EXISTS finding_state_input_state ON finding_state(input_key,state,finding_id);
CREATE INDEX IF NOT EXISTS scan_runs_repository ON scan_runs(repository,finished_at DESC);
CREATE INDEX IF NOT EXISTS scan_runs_finished ON scan_runs(finished_at DESC);
CREATE TABLE IF NOT EXISTS source_anchors(input_key TEXT PRIMARY KEY,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_cache(cache_key TEXT PRIMARY KEY,scan_id TEXT NOT NULL REFERENCES input_scans(scan_id));
CREATE TABLE IF NOT EXISTS audit_cycles(scope TEXT PRIMARY KEY,generation INTEGER,started TEXT,completed TEXT,failed INTEGER NOT NULL DEFAULT 0,owner TEXT,lease_until REAL,work_identity TEXT);
CREATE TABLE IF NOT EXISTS audit_work(scope TEXT,generation INTEGER,path TEXT,kind TEXT,priority INTEGER,attempts INTEGER NOT NULL DEFAULT 0,failed INTEGER NOT NULL DEFAULT 0,done INTEGER NOT NULL DEFAULT 0,claimed TEXT,verified INTEGER NOT NULL DEFAULT 0,directory_signature TEXT,directory_checked INTEGER NOT NULL DEFAULT 0,directory_progress TEXT,result_scan_id TEXT,PRIMARY KEY(scope,generation,path,kind));
'''


def open_database(state_dir):
    """Open the default store with an atomic v0->v2 migration and private backup."""
    import os
    from pathlib import Path
    import sqlite3
    root = Path(state_dir)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = root / 'state.sqlite3'
    existed = path.exists() and path.stat().st_size > 0
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    conn = sqlite3.connect(path, timeout=30)
    try:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version > 2:
            raise StateError('state-schema-newer')
        if existed and version < 2:
            backup = root / ('state.sqlite3.pre-v2-' + uuid.uuid4().hex + '.bak')
            descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            destination = sqlite3.connect(backup)
            try:
                conn.backup(destination)
            finally:
                destination.close()
        conn.execute('BEGIN IMMEDIATE')
        new_views = not conn.execute("SELECT 1 FROM sqlite_master WHERE name='finding_history'").fetchone()
        # Recheck after obtaining the writer lock: concurrent openers can observe
        # only an old schema or a fully committed new schema.
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version > 2:
            raise StateError('state-schema-newer')
        for statement in _SCHEMA.split(';'):
            if statement.strip():
                conn.execute(statement)
        added_result_link = False
        for table, additions in {
            'cache': [('policy', 'TEXT'), ('digest', 'TEXT'), ('payload', 'TEXT'), ('executed_at', 'TEXT')],
            'directories': [('priority', 'INTEGER NOT NULL DEFAULT 100')],
            'files': [('priority', 'INTEGER NOT NULL DEFAULT 100')],
            'audit_work': [('done', 'INTEGER NOT NULL DEFAULT 0'), ('claimed', 'TEXT'), ('verified', 'INTEGER NOT NULL DEFAULT 0'), ('directory_signature', 'TEXT'), ('directory_checked', 'INTEGER NOT NULL DEFAULT 0'), ('directory_progress', 'TEXT'), ('result_scan_id', 'TEXT')],
            'current_inputs': [('reserved_at', 'TEXT')],
            'audit_cycles': [('work_identity', 'TEXT')],
        }.items():
            present = {row[1] for row in conn.execute('PRAGMA table_info(' + table + ')')}
            for column, declaration in additions:
                if column not in present:
                    conn.execute('ALTER TABLE ' + table + ' ADD COLUMN ' + column + ' ' + declaration)
                    if table == 'audit_work' and column == 'result_scan_id':
                        added_result_link = True
        # A pre-link checkpoint cannot prove which results completed its files.
        # Preserve evidence, but force the next semantic bind to replay that root.
        if added_result_link:
            conn.execute("UPDATE audit_cycles SET work_identity=NULL WHERE completed IS NULL AND EXISTS(SELECT 1 FROM audit_work w WHERE w.scope=audit_cycles.scope AND w.generation=audit_cycles.generation AND w.kind='file' AND w.done=1 AND w.result_scan_id IS NULL)")
        conn.execute('CREATE INDEX IF NOT EXISTS audit_directory_checks ON audit_work(scope,generation,kind,directory_checked,done,path)')
        if version < 2:
            _import_legacy_findings(conn)
            conn.execute('DELETE FROM cache')
        if new_views:
            conn.execute("INSERT OR IGNORE INTO finding_current SELECT input_key,finding_id,payload FROM finding_state WHERE state IN ('active','unknown')")
            conn.execute("INSERT OR IGNORE INTO finding_history(scan_id,finding_id,payload) SELECT 'legacy',finding_id,payload FROM finding_state WHERE json_extract(payload,'$.state_reason')='legacy-unverified'")
            conn.execute("INSERT OR IGNORE INTO finding_history(scan_id,finding_id,payload) SELECT f.scan_id,f.finding_id,json_patch(f.payload,json_object('state','unknown','first_seen',i.observed_at,'last_seen',i.observed_at,'last_verified',CASE i.coverage WHEN 'complete' THEN i.observed_at ELSE NULL END,'resolved_at',NULL,'state_reason','historical-observation','policy_id',i.policy_id,'runtime_id',i.runtime_id)) FROM scan_findings f JOIN input_scans i ON i.scan_id=f.scan_id")
        conn.execute('PRAGMA user_version=2')
        conn.commit()
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA busy_timeout=30000')
        return conn
    except Exception as error:
        conn.rollback()
        conn.close()
        if isinstance(error, StateError):
            raise
        raise StateError() from None


def _import_legacy_findings(conn):
    import re
    for identity, path, rule, line, part, severity, first, last in conn.execute('SELECT id,path,rule,line,part,severity,first_seen,last_seen FROM findings'):
        if not isinstance(path, str) or not path or not isinstance(rule, str) or not re.fullmatch('[a-z][a-z0-9-]{0,79}', rule):
            continue
        source = m.SourceRef(m.SourceKind.FILESYSTEM, path)
        key = source_key(source)
        row = {'id': str(identity), 'source': _source_data(source), 'part_id': 'text',
               'start_line': max(1, int(line or 1)), 'end_line': max(1, int(line or 1)),
               'rule': rule, 'detector_id': 'legacy', 'detector_severity': 'review' if severity == 'review' else 'block',
               'severity': 'review' if severity == 'review' else 'block', 'classification': 'credential-candidate',
               'proof_id': None, 'state': 'unknown', 'first_seen': first, 'last_seen': last,
               'last_verified': None, 'resolved_at': None, 'state_reason': 'legacy-unverified',
               'policy_id': 'legacy', 'runtime_id': 'legacy'}
        conn.execute('INSERT OR IGNORE INTO finding_state VALUES(?,?,?,?,?,?)', (key, str(identity), 'unknown', rule, path, json.dumps(row, separators=(',', ':'))))
        conn.execute('INSERT OR IGNORE INTO current_inputs(input_key,generation,current_state,state_reason,policy_id,runtime_id) VALUES(?,0,?,?,?,?)', (key, 'unknown', 'legacy-unverified', 'legacy', 'legacy'))


class SQLiteScanStore:
    def __init__(self, state_dir, *, config=None):
        self.config = config or {}
        self.conn = open_database(state_dir)
        self.state_dir = __import__('pathlib').Path(state_dir)
        self._deadline = None

    @classmethod
    def from_memory(cls, serialized=None, *, config=None, max_bytes=64 * 1024 * 1024,
                    material_key=None):
        """Application-owned SQLite state with no filesystem database or key.

        The caller serializes access and encrypts ``serialize()`` before writing.
        Material identity keys must be supplied again when reopening a checkpoint.
        """
        import sqlite3
        import secrets
        if type(max_bytes) is not int or not 1024 * 1024 <= max_bytes <= 64 * 1024 * 1024:
            raise StateError('state-capacity-invalid')
        if serialized is not None and (type(serialized) is not bytes or len(serialized) > max_bytes):
            raise StateError('state-capacity-limit')
        if material_key is not None and (type(material_key) is not bytes or len(material_key) != 32):
            raise StateError()
        conn = sqlite3.connect(':memory:', check_same_thread=False)
        try:
            if not hasattr(conn, 'serialize') or not hasattr(conn, 'deserialize'):
                raise StateError('state-serialization-unavailable')
            options = {row[0] for row in conn.execute('PRAGMA compile_options')}
            if 'TEMP_STORE=0' in options:
                # This build forces transient tables/indices onto disk even
                # when temp_store=MEMORY is requested. Reject, never downgrade.
                raise StateError('state-memory-storage-unavailable')
            if serialized is not None:
                conn.deserialize(serialized)
                if conn.execute('PRAGMA user_version').fetchone()[0] != 2:
                    raise StateError('state-schema-unsupported')
            conn.execute('PRAGMA temp_store=MEMORY')
            conn.execute('PRAGMA journal_mode=MEMORY')
            conn.execute('PRAGMA trusted_schema=OFF')
            if conn.execute('PRAGMA temp_store').fetchone()[0] != 2 or conn.execute('PRAGMA journal_mode').fetchone()[0] != 'memory':
                raise StateError('state-memory-storage-unavailable')
            page_size = conn.execute('PRAGMA page_size').fetchone()[0]
            conn.execute('PRAGMA max_page_count=' + str(max_bytes // page_size))
            conn.executescript(_SCHEMA)
            work_columns = {row[1] for row in conn.execute('PRAGMA table_info(audit_work)')}
            if 'directory_progress' not in work_columns:
                conn.execute('ALTER TABLE audit_work ADD COLUMN directory_progress TEXT')
            cycle_columns = {row[1] for row in conn.execute('PRAGMA table_info(audit_cycles)')}
            if 'work_identity' not in cycle_columns:
                conn.execute('ALTER TABLE audit_cycles ADD COLUMN work_identity TEXT')
            if 'result_scan_id' not in work_columns:
                conn.execute('ALTER TABLE audit_work ADD COLUMN result_scan_id TEXT')
                # Older completed claims lack exact accepted-result linkage.
                # Replay unfinished cycles through the identity fence rather
                # than treating their partial evidence as a complete verdict.
                conn.execute("UPDATE audit_cycles SET work_identity=NULL WHERE completed IS NULL AND EXISTS(SELECT 1 FROM audit_work w WHERE w.scope=audit_cycles.scope AND w.generation=audit_cycles.generation AND w.kind='file' AND w.done=1 AND w.result_scan_id IS NULL)")
            conn.execute('CREATE INDEX IF NOT EXISTS audit_directory_checks ON audit_work(scope,generation,kind,directory_checked,done,path)')
            conn.execute('PRAGMA user_version=2')
            conn.commit()
            instance = object.__new__(cls)
            instance.conn = conn
            instance.config = config or {}
            instance.state_dir = None
            instance._deadline = None
            instance._memory_material_key = material_key or secrets.token_bytes(32)
            return instance
        except Exception as error:
            conn.close()
            if isinstance(error, StateError):
                raise
            raise StateError() from None

    def serialize(self, *, max_bytes=64 * 1024 * 1024):
        """Return a committed in-memory checkpoint; never write an implicit mirror."""
        if self.state_dir is not None:
            raise StateError('state-not-memory')
        try:
            size = self.conn.execute('PRAGMA page_count').fetchone()[0] * self.conn.execute('PRAGMA page_size').fetchone()[0]
            if size > max_bytes:
                raise StateError('state-capacity-limit')
            self.conn.commit()
            value = self.conn.serialize()
            if len(value) > max_bytes:
                raise StateError('state-capacity-limit')
            return value
        except Exception as error:
            if isinstance(error, StateError):
                raise
            raise StateError() from None

    @classmethod
    def from_connection(cls, conn, *, state_dir, config=None):
        """Deprecated wrapper adapter; caller retains connection ownership."""
        instance = object.__new__(cls)
        instance.conn = conn
        instance.state_dir = __import__('pathlib').Path(state_dir)
        instance.config = config or {}
        instance._deadline = None
        return instance

    def set_deadline(self, deadline):
        self._deadline = deadline
        self.conn.set_progress_handler(None, 0)
        if deadline is None:
            self.conn.execute('PRAGMA busy_timeout=30000')
        else:
            self._apply_budget()

    def _apply_budget(self):
        import time
        if self._deadline is None:
            return
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise StateError()
        self.conn.set_progress_handler(None, 0)
        self.conn.execute('PRAGMA busy_timeout=' + str(max(1, min(30_000, int(remaining * 1000)))))
        self.conn.set_progress_handler(lambda: int(time.monotonic() >= self._deadline), 1000)

    @_bounded_sql
    def reserve(self, source, *, scope=''):
        key = source_key(source, scope)
        with self.conn:
            self.conn.execute('INSERT INTO current_inputs(input_key,generation,reserved_at) VALUES(?,1,?) ON CONFLICT(input_key) DO UPDATE SET generation=generation+1,reserved_at=excluded.reserved_at', (key, datetime.now(timezone.utc).isoformat()))
            return self.conn.execute('SELECT generation FROM current_inputs WHERE input_key=?', (key,)).fetchone()[0]

    @_bounded_sql
    def get_cached(self, cache_key):
        row = self.conn.execute('SELECT i.scan_id,i.payload FROM scan_cache c JOIN input_scans i ON i.scan_id=c.scan_id WHERE cache_key=?', (cache_key,)).fetchone()
        if row:
            try:
                result = _result_from(json.loads(row[1]))
                return replace(result, reused_from=result.reused_from or row[0])
            except Exception:
                raise StateError() from None
        return None

    @_bounded_sql
    def record_result(self, result, *, generation, cache_key=None, scope='', work=None, material_observations=(), materials_checked=False, materials_complete=False, anchor=None):
        if type(result) is not m.ScanResult:
            raise StateError()
        key = source_key(result.source, scope)
        scan_id = uuid.uuid4().hex
        complete = result.coverage is m.CoverageState.COMPLETE
        try:
            with self.conn:
                self.conn.execute('INSERT INTO input_scans VALUES(?,?,?,?,?,?,?,?,?,?,?)', (scan_id, key, result.source.kind.value, result.source.path, generation, result.identity.policy_id, result.identity.runtime_id, result.identity.context_id, result.coverage.value, result.observed_at.isoformat(), _result_json(result)))
                for finding in result.findings:
                    self.conn.execute('INSERT INTO scan_findings VALUES(?,?,?)', (scan_id, finding.id, json.dumps(_finding_data(finding), separators=(',', ':'))))
                    self.conn.execute('INSERT INTO finding_history(scan_id,finding_id,payload) VALUES(?,?,?)', (scan_id, finding.id, json.dumps(_query_row(finding, result), separators=(',', ':'))))
                previous = self.conn.execute('SELECT generation,policy_id,runtime_id FROM current_inputs WHERE input_key=?', (key,)).fetchone()
                if not previous or previous[0] != generation or work is not None and not self._lease_valid(work.lease):
                    return scan_id
                if complete and result.identity.cache_eligible and cache_key:
                    self.conn.execute('INSERT OR REPLACE INTO scan_cache VALUES(?,?)', (cache_key, scan_id))
                if result.source.kind is m.SourceKind.FILESYSTEM:
                    comparable = previous[1:] == (result.identity.policy_id, result.identity.runtime_id)
                    self._transition_sql(key, result, complete=complete, comparable=comparable)
                    self._record_location(result)
                if anchor is not None and result.source.kind is m.SourceKind.FILESYSTEM:
                    self.conn.execute('INSERT OR REPLACE INTO source_anchors VALUES(?,?)', (key, _anchor_data(anchor)))
                if materials_checked and result.source.kind is m.SourceKind.FILESYSTEM:
                    self._record_materials(result, material_observations, complete=materials_complete)
                self._finish_work(work, result, scan_id=scan_id)
                self.conn.execute('UPDATE current_inputs SET latest_attempt_id=?,last_complete_scan_id=CASE WHEN ? THEN ? ELSE last_complete_scan_id END,current_state=?,state_reason=?,policy_id=?,runtime_id=? WHERE input_key=? AND generation=?', (scan_id, complete, scan_id, 'verified' if complete else 'unknown', 'complete-content-scan' if complete else 'incomplete-scan', result.identity.policy_id, result.identity.runtime_id, key, generation))
            return scan_id
        except Exception as error:
            if isinstance(error, StateError):
                raise
            raise StateError() from None

    def _transition_sql(self, key, result, *, complete, comparable):
        """Update active evidence in SQL; never load resolved history into Python."""
        self.conn.execute('CREATE TEMP TABLE IF NOT EXISTS new_evidence(id TEXT PRIMARY KEY)')
        self.conn.execute('DELETE FROM new_evidence')
        self.conn.executemany('INSERT OR IGNORE INTO new_evidence VALUES(?)', ((finding.id,) for finding in result.findings))
        condition = "? AND json_extract(payload,'$.policy_id')=? AND json_extract(payload,'$.runtime_id')=?"
        args = (bool(complete and comparable), result.identity.policy_id, result.identity.runtime_id)
        state = "CASE WHEN " + condition + " THEN 'resolved' ELSE 'unknown' END"
        reason = "CASE WHEN " + condition + " THEN 'complete-content-scan' ELSE ? END"
        statement = "UPDATE finding_state SET state=" + state + ",payload=json_set(payload,'$.state'," + state + ",'$.resolved_at',CASE WHEN " + condition + " THEN ? ELSE NULL END,'$.state_reason'," + reason + ") WHERE input_key=? AND state IN ('active','unknown') AND NOT EXISTS(SELECT 1 FROM new_evidence WHERE id=finding_state.finding_id)"
        self.conn.execute(statement, (*args, *args, *args, result.observed_at.isoformat(), *args, 'policy-obsolete' if complete else 'incomplete-scan', key))
        self.conn.execute("DELETE FROM finding_current WHERE input_key=? AND NOT EXISTS(SELECT 1 FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id AND s.state IN ('active','unknown'))", (key,))
        self.conn.execute('UPDATE finding_current SET payload=(SELECT s.payload FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id) WHERE input_key=?', (key,))
        for finding in result.findings:
            row = _query_row(finding, result)
            row.update(state='active' if complete else 'unknown', state_reason='verified-present' if complete else 'partial-observation')
            previous = self.conn.execute("SELECT json_extract(payload,'$.first_seen') FROM finding_state WHERE input_key=? AND finding_id=?", (key, finding.id)).fetchone()
            if previous:
                row['first_seen'] = previous[0]
            payload = json.dumps(row, separators=(',', ':'))
            self.conn.execute('INSERT INTO finding_state VALUES(?,?,?,?,?,?) ON CONFLICT(input_key,finding_id) DO UPDATE SET state=excluded.state,rule=excluded.rule,path=excluded.path,payload=excluded.payload', (key, finding.id, row['state'], finding.rule, result.source.path, payload))
            self.conn.execute('INSERT INTO finding_current VALUES(?,?,?) ON CONFLICT(input_key,finding_id) DO UPDATE SET payload=excluded.payload', (key, finding.id, payload))

    def _record_location(self, result):
        from . import policies, catalog
        source = result.source
        when = result.observed_at.isoformat()
        path = policies.canonical(source.path, self.config)
        if result.content:
            self.conn.execute('INSERT INTO locations VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(host,path) DO UPDATE SET profile=excluded.profile,category=excluded.category,size=excluded.size,digest=excluded.digest,last_seen=excluded.last_seen,present=1', (catalog.HOST, path, policies.profile(path, self.config), policies.classify(path), result.content.size_bytes, result.content.digest, when, when))
        # A failed/missing acquisition does not prove remediation or erase a
        # previous location. Absence confirmation is an explicit separate action.

    @_bounded_sql
    def record_report(self, report, *, repository=None):
        repositories = {r.source.repository for r in report.results if r.source.repository}
        repository = repository if repository is not None else next(iter(repositories)) if len(repositories) == 1 else None
        try:
            with self.conn:
                self.conn.execute('INSERT OR REPLACE INTO scan_runs VALUES(?,?,?,?,?)', (report.run_id, repository, report.finished_at.isoformat(), report.policy_id, report.to_json()))
        except Exception:
            raise StateError() from None

    @_bounded_sql
    def latest_report(self, repository=None):
        row = self.conn.execute('SELECT payload FROM scan_runs ' + ('WHERE repository=? ' if repository else '') + 'ORDER BY finished_at DESC,rowid DESC LIMIT 1', (repository,) if repository else ()).fetchone()
        try:
            return _report_from(json.loads(row[0])) if row else None
        except Exception:
            raise StateError() from None

    @_bounded_sql
    def query_findings_page(self, *, state='current', profile=None, limit=1000, cursor=None):
        fingerprint, position = _query_position(state, profile, limit, cursor)
        if state == 'current':
            selected = self.conn.execute('SELECT input_key,finding_id,payload FROM finding_current WHERE (input_key,finding_id)>(?,?) ORDER BY input_key,finding_id LIMIT ?', (position[0], position[1], limit + 1)).fetchall()
            rows = [json.loads(row[2]) for row in selected[:limit]]
            next_cursor = _query_cursor(fingerprint, list(selected[limit - 1][:2])) if len(selected) > limit else None
        else:
            selected = self.conn.execute('SELECT id,payload FROM finding_history WHERE id>? ORDER BY id LIMIT ?', (position, limit + 1)).fetchall()
            rows = [json.loads(row[1]) for row in selected[:limit]]
            next_cursor = _query_cursor(fingerprint, selected[limit - 1][0]) if len(selected) > limit else None
        return FindingPage(_filter_page(rows, profile, self.config), next_cursor)

    @_bounded_sql
    def query_findings(self, *, state='current', profile=None):
        """Compatibility wrapper returning the first bounded page only."""
        return self.query_findings_page(state=state, profile=profile).rows

    def close(self):
        self.conn.close()

    @_bounded_sql
    def reset_cycle(self, scope):
        """Retry failed work with a fresh cycle, without deleting any evidence."""
        import time
        if type(scope) is not str or not scope:
            raise StateError()
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            row = self.conn.execute('SELECT owner,lease_until FROM audit_cycles WHERE scope=?', (scope,)).fetchone()
            if row and row[0] and row[1] > time.time():
                raise StateError('state-cycle-busy')
            self.conn.execute('DELETE FROM audit_work WHERE scope=?', (scope,))
            self.conn.execute('DELETE FROM audit_cycles WHERE scope=?', (scope,))
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def _lease_valid(self, lease):
        import time
        row = self.conn.execute('SELECT generation,owner,lease_until FROM audit_cycles WHERE scope=?', (lease.scope,)).fetchone()
        return bool(row and row[0] == lease.generation and row[1] == lease.owner and row[2] > time.time())

    @_bounded_sql
    def lease_valid(self, lease):
        return self._lease_valid(lease)

    @_bounded_sql
    def bind_cycle_identity(self, lease, identity, *, root):
        if type(identity) is not str or not __import__('re').fullmatch('[0-9a-f]{64}', identity):
            raise StateError()
        from pathlib import Path
        root = str(Path(root).absolute())
        prefix = root.rstrip('/\\') + __import__('os').sep
        with self.conn:
            if not self._lease_valid(lease):
                raise StateError()
            row = self.conn.execute('SELECT work_identity FROM audit_cycles WHERE scope=? AND generation=? AND owner=?',
                                    (lease.scope, lease.generation, lease.owner)).fetchone()
            if row is None:
                raise StateError()
            if row[0] == identity:
                return False
            self.conn.execute("UPDATE finding_state SET state='unknown',payload=json_set(payload,'$.state','unknown','$.state_reason','source-unavailable','$.resolved_at',NULL) WHERE state IN ('active','unknown') AND (path=? OR substr(path,1,?)=?)", (root, len(prefix), prefix))
            self.conn.execute("UPDATE finding_current SET payload=(SELECT s.payload FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id) WHERE EXISTS(SELECT 1 FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id AND s.state IN ('active','unknown') AND (s.path=? OR substr(s.path,1,?)=?))", (root, len(prefix), prefix))
            self.conn.execute('DELETE FROM audit_work WHERE scope=? AND generation=?', (lease.scope, lease.generation))
            self.conn.execute('INSERT INTO audit_work(scope,generation,path,kind,priority) VALUES(?,?,?,?,10)',
                              (lease.scope, lease.generation, root, 'directory'))
            self.conn.execute('UPDATE audit_cycles SET work_identity=?,started=?,failed=0 WHERE scope=? AND generation=? AND owner=?',
                              (identity, datetime.now(timezone.utc).isoformat(), lease.scope, lease.generation, lease.owner))
        return True

    @_bounded_sql
    def acquire_cycle(self, scope, root, *, lease_seconds):
        import time
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            now = time.time()
            row = self.conn.execute('SELECT generation,completed,owner,lease_until FROM audit_cycles WHERE scope=?', (scope,)).fetchone()
            if row and row[2] and row[3] > now:
                self.conn.rollback()
                return None
            fresh = not row or row[1] is not None
            generation = row[0] + 1 if row and fresh else row[0] if row else 1
            owner = uuid.uuid4().hex
            self.conn.execute('INSERT INTO audit_cycles(scope,generation,started,completed,failed,owner,lease_until) VALUES(?,?,?,NULL,0,?,?) ON CONFLICT(scope) DO UPDATE SET generation=excluded.generation,started=CASE WHEN ? THEN excluded.started ELSE started END,completed=NULL,owner=excluded.owner,lease_until=excluded.lease_until', (scope, generation, datetime.now(timezone.utc).isoformat(), owner, now + lease_seconds, fresh))
            self.conn.execute('UPDATE audit_work SET claimed=NULL WHERE scope=? AND generation=?', (scope, generation))
            if fresh and root is not None:
                self.conn.execute('INSERT OR IGNORE INTO audit_work(scope,generation,path,kind,priority) VALUES(?,?,?,?,10)', (scope, generation, str(root), 'directory'))
            self.conn.commit()
            return WorkLease(scope, generation, owner)
        except Exception:
            self.conn.rollback()
            raise StateError() from None

    @_bounded_sql
    def enqueue_work(self, lease, entries, *, refresh=False):
        entries = tuple(entries)
        if len(entries) > 1000:
            raise StateError()
        with self.conn:
            if not self._lease_valid(lease):
                raise StateError()
            before = self.conn.total_changes
            if refresh:
                self.conn.executemany('INSERT INTO audit_work(scope,generation,path,kind,priority) VALUES(?,?,?,?,?) ON CONFLICT(scope,generation,path,kind) DO UPDATE SET done=0,attempts=0,failed=0,claimed=NULL,directory_signature=NULL,directory_checked=0,directory_progress=NULL,result_scan_id=NULL', ((lease.scope, lease.generation, path, kind, priority) for path, kind, priority in entries))
            else:
                self.conn.executemany('INSERT OR IGNORE INTO audit_work(scope,generation,path,kind,priority) VALUES(?,?,?,?,?)', ((lease.scope, lease.generation, path, kind, priority) for path, kind, priority in entries))
            if self.conn.total_changes != before:
                self._reset_directory_checks(lease)

    @_bounded_sql
    def claim_work(self, lease):
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            if not self._lease_valid(lease):
                raise StateError()
            row = self.conn.execute("SELECT path,kind FROM audit_work WHERE scope=? AND generation=? AND done=0 AND failed=0 AND claimed IS NULL ORDER BY CASE kind WHEN 'file' THEN 0 ELSE 1 END,priority,path LIMIT 1", (lease.scope, lease.generation)).fetchone()
            if row:
                self.conn.execute('UPDATE audit_work SET claimed=? WHERE scope=? AND generation=? AND path=? AND kind=?', (lease.owner, lease.scope, lease.generation, row[0], row[1]))
            self.conn.commit()
            return WorkClaim(lease, row[0], row[1]) if row else None
        except Exception:
            self.conn.rollback()
            raise StateError() from None

    @_bounded_sql
    def get_directory_progress(self, claim):
        if claim.kind != 'directory' or not self._lease_valid(claim.lease):
            raise StateError()
        row = self.conn.execute('SELECT directory_progress FROM audit_work WHERE scope=? AND generation=? AND path=? AND kind=? AND claimed=?',
                                (claim.lease.scope, claim.lease.generation, claim.path, claim.kind, claim.lease.owner)).fetchone()
        if row is None:
            raise StateError()
        if row[0] is None:
            return None
        try:
            value = json.loads(row[0])
            if type(value) is not dict or set(value) != {'signature', 'entries', 'prefix_sha256'}:
                raise StateError()
            return DirectoryProgress(tuple(value['signature']), value['entries'], value['prefix_sha256'])
        except Exception:
            raise StateError() from None

    @_bounded_sql
    def set_directory_progress(self, claim, progress):
        if progress is not None and type(progress) is not DirectoryProgress:
            raise StateError()
        with self.conn:
            self.get_directory_progress(claim)
            value = json.dumps({'signature': progress.signature, 'entries': progress.entries,
                                'prefix_sha256': progress.prefix_sha256}) if progress is not None else None
            self.conn.execute('UPDATE audit_work SET directory_progress=? WHERE scope=? AND generation=? AND path=? AND kind=? AND claimed=?',
                              (value, claim.lease.scope, claim.lease.generation, claim.path, claim.kind, claim.lease.owner))

    def _reset_directory_checks(self, lease):
        self.conn.execute("UPDATE audit_work SET directory_checked=0 WHERE scope=? AND generation=? AND kind='directory' AND directory_checked=1 AND (directory_signature IS NULL OR directory_signature<>'omitted')", (lease.scope, lease.generation))

    @_bounded_sql
    def finish_directory(self, claim, *, success, signature=None, omitted=False):
        signature = _directory_signature(signature)
        with self.conn:
            if not self._lease_valid(claim.lease):
                raise StateError()
            self._reset_directory_checks(claim.lease)
            self.conn.execute('UPDATE audit_work SET done=?,directory_signature=?,directory_checked=?,directory_progress=CASE WHEN ? THEN directory_progress ELSE NULL END,attempts=attempts+?,failed=CASE WHEN attempts+? >= 3 THEN 1 ELSE failed END WHERE scope=? AND generation=? AND path=? AND kind=? AND claimed=?', (success is True, 'omitted' if omitted else json.dumps(signature) if signature else None, bool(omitted), success is None, success is False, success is False, claim.lease.scope, claim.lease.generation, claim.path, claim.kind, claim.lease.owner))

    @_bounded_sql
    def directory_page(self, lease, *, limit=256):
        if not self._lease_valid(lease) or type(limit) is not int or not 1 <= limit <= 1000:
            raise StateError()
        rows = self.conn.execute("SELECT path,directory_signature FROM audit_work WHERE scope=? AND generation=? AND kind='directory' AND done=1 AND directory_checked=0 AND (directory_signature IS NULL OR directory_signature<>'omitted') ORDER BY path LIMIT ?", (lease.scope, lease.generation, limit)).fetchall()
        return tuple(DirectorySnapshot(path, _directory_signature(tuple(json.loads(signature))) if signature else None) for path, signature in rows)

    @_bounded_sql
    def record_directory_checks(self, lease, checks):
        from itertools import islice
        checks = tuple(islice(iter(checks), 1001))
        if len(checks) > 1000:
            raise StateError()
        with self.conn:
            if not self._lease_valid(lease):
                raise StateError()
            if any(not valid for _, _, valid in checks):
                self._reset_directory_checks(lease)
            for path, expected, valid in checks:
                expected = _directory_signature(expected)
                row = self.conn.execute("SELECT directory_signature,done FROM audit_work WHERE scope=? AND generation=? AND path=? AND kind='directory'", (lease.scope, lease.generation, path)).fetchone()
                actual = tuple(json.loads(row[0])) if row and row[0] and row[0] != 'omitted' else None
                if not row or not row[1] or actual != expected:
                    raise StateError()
                if valid and expected is not None:
                    self.conn.execute("UPDATE audit_work SET directory_checked=1 WHERE scope=? AND generation=? AND path=? AND kind='directory'", (lease.scope, lease.generation, path))
                else:
                    self.conn.execute("UPDATE audit_work SET done=0,claimed=NULL,failed=0,attempts=0,directory_signature=NULL,directory_checked=0,directory_progress=NULL WHERE scope=? AND generation=? AND path=? AND kind='directory'", (lease.scope, lease.generation, path))

    @_bounded_sql
    def cycle_decision_evidence(self, lease):
        """Aggregate exact results/exclusion markers; stale policy rows do not vote."""
        if not self._lease_valid(lease) or not self.cycle_status(lease)['complete']:
            raise StateError()
        parameters = (lease.scope, lease.generation)
        invalid = self.conn.execute("SELECT 1 FROM audit_work w LEFT JOIN input_scans s ON s.scan_id=w.result_scan_id WHERE w.scope=? AND w.generation=? AND w.kind='file' AND (w.done=0 OR s.scan_id IS NULL OR s.path<>w.path OR s.coverage='incomplete') LIMIT 1", parameters).fetchone()
        if invalid:
            raise StateError()
        files = self.conn.execute("SELECT count(*) FROM audit_work WHERE scope=? AND generation=? AND kind='file'", parameters).fetchone()[0]
        rows = self.conn.execute("SELECT DISTINCT json_extract(f.payload,'$.severity') FROM audit_work w JOIN input_scans s ON s.scan_id=w.result_scan_id JOIN scan_findings f ON f.scan_id=s.scan_id LEFT JOIN finding_state e ON e.input_key=s.input_key AND e.finding_id=f.finding_id WHERE w.scope=? AND w.generation=? AND w.kind='file' AND (e.state IS NULL OR e.state<>'resolved')", parameters).fetchall()
        severities = tuple(sorted(row[0] for row in rows))
        if any(value not in {'block', 'review', 'info'} for value in severities):
            raise StateError()
        omissions = self.conn.execute("SELECT 1 FROM audit_work w LEFT JOIN input_scans s ON s.scan_id=w.result_scan_id WHERE w.scope=? AND w.generation=? AND ((w.kind='directory' AND w.done=1 AND w.directory_signature='omitted') OR (w.kind='file' AND (s.coverage='omitted' OR EXISTS(SELECT 1 FROM json_each(s.payload,'$.issues') i WHERE json_extract(i.value,'$.required')=0 AND json_extract(i.value,'$.omission_id') IS NOT NULL)))) LIMIT 1", parameters).fetchone() is not None
        return {'severities': severities, 'has_omissions': omissions, 'files': files}

    def _finish_work(self, work, result, *, scan_id):
        if work is None:
            return
        complete = result.coverage is not m.CoverageState.INCOMPLETE
        self._reset_directory_checks(work.lease)
        self.conn.execute('UPDATE audit_work SET done=?,verified=?,result_scan_id=?,attempts=attempts+?,failed=CASE WHEN attempts+? >= 3 THEN 1 ELSE failed END WHERE scope=? AND generation=? AND path=? AND kind=? AND claimed=?', (complete, result.coverage is m.CoverageState.COMPLETE, scan_id, not complete, not complete, work.lease.scope, work.lease.generation, work.path, work.kind, work.lease.owner))

    @_bounded_sql
    def cycle_status(self, lease):
        rows = self.conn.execute("SELECT kind,count(*),sum(failed) FROM audit_work WHERE scope=? AND generation=? AND (done=0 OR (kind='directory' AND directory_checked=0)) GROUP BY kind", (lease.scope, lease.generation)).fetchall()
        counts = {kind: count for kind, count, _ in rows}
        return {'complete': not rows, 'pending_files': counts.get('file', 0), 'pending_directories': counts.get('directory', 0), 'failed': sum(failed for _, _, failed in rows), 'cycle_id': str(lease.generation)}

    @_bounded_sql
    def release_cycle(self, lease, *, allow_complete=True):
        with self.conn:
            if not self._lease_valid(lease):
                return
            status = self.cycle_status(lease)
            self.conn.execute('UPDATE audit_cycles SET completed=?,failed=?,owner=NULL,lease_until=0 WHERE scope=? AND generation=? AND owner=?', (datetime.now(timezone.utc).isoformat() if status['complete'] and allow_complete else None, status['failed'] > 0, lease.scope, lease.generation, lease.owner))
            self.conn.execute('UPDATE audit_work SET claimed=NULL WHERE scope=? AND generation=?', (lease.scope, lease.generation))

    @_bounded_sql
    def reconcile_cycle(self, lease, root):
        from pathlib import Path
        root = str(Path(root).absolute())
        prefix = root.rstrip('/\\') + __import__('os').sep
        with self.conn:
            if not self._lease_valid(lease):
                raise StateError()
            started = self.conn.execute('SELECT started FROM audit_cycles WHERE scope=? AND generation=?', (lease.scope, lease.generation)).fetchone()[0]
            self.conn.execute('CREATE TEMP TABLE IF NOT EXISTS reconcile_inputs(input_key TEXT PRIMARY KEY)')
            self.conn.execute('DELETE FROM reconcile_inputs')
            self.conn.execute("INSERT OR IGNORE INTO reconcile_inputs SELECT s.input_key FROM finding_state s JOIN current_inputs i ON i.input_key=s.input_key WHERE s.state IN ('active','unknown') AND (s.path=? OR substr(s.path,1,?)=?) AND json_extract(s.payload,'$.last_seen')<=? AND coalesce(i.reserved_at,'')<=? AND NOT EXISTS(SELECT 1 FROM audit_work w WHERE w.scope=? AND w.generation=? AND w.path=s.path AND w.verified=1)", (root, len(prefix), prefix, started, started, lease.scope, lease.generation))
            self.conn.execute("UPDATE finding_state SET state='unknown',payload=json_set(payload,'$.state','unknown','$.state_reason','source-unavailable','$.resolved_at',NULL) WHERE state IN ('active','unknown') AND input_key IN (SELECT input_key FROM reconcile_inputs)")
            self.conn.execute("UPDATE finding_current SET payload=(SELECT s.payload FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id) WHERE input_key IN (SELECT input_key FROM reconcile_inputs)")
            self.conn.execute("UPDATE current_inputs SET generation=generation+1,current_state='unknown',state_reason='source-unavailable' WHERE input_key IN (SELECT input_key FROM reconcile_inputs)")

    @_bounded_sql
    def invalidate_scope(self, root, *, reason='source-unavailable'):
        if reason not in {'source-unavailable', 'source-event', 'incomplete-scan'}:
            raise StateError()
        from pathlib import Path
        root = str(Path(root).absolute())
        prefix = root.rstrip('/\\') + __import__('os').sep
        with self.conn:
            self.conn.execute("UPDATE finding_state SET state='unknown',payload=json_set(payload,'$.state','unknown','$.state_reason',?,'$.resolved_at',NULL) WHERE state IN ('active','unknown') AND (path=? OR substr(path,1,?)=?)", (reason, root, len(prefix), prefix))
            self.conn.execute("UPDATE finding_current SET payload=(SELECT s.payload FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id) WHERE EXISTS(SELECT 1 FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id AND s.state IN ('active','unknown') AND (s.path=? OR substr(s.path,1,?)=?))", (root, len(prefix), prefix))

    @_bounded_sql
    def source_anchor(self, source):
        row = self.conn.execute('SELECT payload FROM source_anchors WHERE input_key=?', (source_key(source),)).fetchone()
        return _anchor_from(row[0]) if row else None

    @_bounded_sql
    def confirm_absent(self, proof, *, generation):
        from .sources import AbsenceProof
        from . import catalog, policies
        if type(proof) is not AbsenceProof or not proof.valid():
            raise StateError()
        source = m.SourceRef(m.SourceKind.FILESYSTEM, proof.anchor.source_path)
        key = source_key(source)
        when = proof.observed_at.isoformat()
        self._apply_budget()
        with self.conn:
            row = self.conn.execute('SELECT generation FROM current_inputs WHERE input_key=?', (key,)).fetchone()
            recorded = self.conn.execute('SELECT payload FROM source_anchors WHERE input_key=?', (key,)).fetchone()
            if not row or row[0] != generation or not recorded or _anchor_from(recorded[0]) != proof.anchor:
                return False
            self.conn.execute("UPDATE finding_state SET state='resolved',payload=json_set(payload,'$.state','resolved','$.state_reason','source-absent','$.resolved_at',?,'$.last_verified',?) WHERE input_key=? AND state IN ('active','unknown')", (when, when, key))
            self.conn.execute('DELETE FROM finding_current WHERE input_key=?', (key,))
            self.conn.execute("UPDATE current_inputs SET current_state='absent',state_reason='source-absent' WHERE input_key=? AND generation=?", (key, generation))
            path = policies.canonical(source.path, self.config)
            self.conn.execute('UPDATE locations SET present=0,last_seen=? WHERE host=? AND path=?', (when, catalog.HOST, path))
            self.conn.execute('UPDATE material_locations SET present=0,last_seen=? WHERE host=? AND path=?', (when, catalog.HOST, path))
        return True

    @_bounded_sql
    def material_snapshot(self, *, max_bytes=1_000_000, max_sources=100):
        from .catalog import snapshot_materials, MaterialSnapshot
        import os
        rows = self.conn.execute('SELECT name,source,format,field,kind FROM material_sources ORDER BY name LIMIT ?', (max_sources + 1,)).fetchall()
        if not rows:
            return MaterialSnapshot((), 'no-materials', validate=lambda: self.conn.execute('SELECT 1 FROM material_sources LIMIT 1').fetchone() is None)
        if self.state_dir is None:
            key = self._memory_material_key
        else:
            key_path = self.state_dir / 'material-key.bin'
            try:
                descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(__import__('secrets').token_bytes(32))
            from .sources import _bounded_file
            key = _bounded_file(key_path, 32)
        if len(key) != 32:
            raise StateError()
        snapshot = snapshot_materials(rows, key, max_bytes=max_bytes, max_sources=max_sources)
        def valid():
            current = self.conn.execute('SELECT name,source,format,field,kind FROM material_sources ORDER BY name LIMIT ?', (max_sources + 1,)).fetchall()
            return current == rows and snapshot.valid()
        return replace(snapshot, validate=valid)

    def _record_materials(self, result, observations, *, complete):
        from . import catalog, policies
        path = policies.canonical(result.source.path, self.config)
        names = {item.name for item in observations}
        when = result.observed_at.isoformat()
        placeholders = ','.join('?' for _ in names)
        self.conn.execute('UPDATE material_locations SET present=?,last_seen=? WHERE host=? AND path=?' + (' AND name NOT IN (' + placeholders + ')' if names else ''), (0 if complete else None, when, catalog.HOST, path, *sorted(names)))
        for item in observations:
            self.conn.execute('INSERT INTO material_locations VALUES(?,?,?,?,?,?,1) ON CONFLICT(host,name,path) DO UPDATE SET fingerprint=excluded.fingerprint,last_seen=excluded.last_seen,present=1', (catalog.HOST, item.name, path, item.fingerprint, when, when))

    @_bounded_sql
    def record_metadata(self, path, size):
        if type(size) is not int or size < 0:
            raise StateError()
        from . import catalog
        catalog.metadata_only(self.conn, path, size, self.config)

    @_bounded_sql
    def record_event(self, path, kind, *, old_path=None, when=None):
        if kind not in {'changed', 'created', 'deleted', 'renamed'}:
            raise StateError()
        from . import catalog
        catalog.event(self.conn, path, kind, self.config, old_path=old_path, when=when)
        with self.conn:
            self.conn.execute("UPDATE finding_state SET state='unknown',payload=json_set(payload,'$.state','unknown','$.state_reason','source-event','$.resolved_at',NULL) WHERE (path=? OR path=?) AND state IN ('active','unknown')", (path, old_path))
            self.conn.execute("UPDATE finding_current SET payload=(SELECT s.payload FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id) WHERE EXISTS(SELECT 1 FROM finding_state s WHERE s.input_key=finding_current.input_key AND s.finding_id=finding_current.finding_id AND s.state IN ('active','unknown') AND (s.path=? OR s.path=?))", (path, old_path))
