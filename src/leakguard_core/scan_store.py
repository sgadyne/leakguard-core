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
            return method(self, *args, **kwargs)
    return locked

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


@runtime_checkable
class ScanStore(Protocol):
    def reserve(self, source: m.SourceRef, *, scope: str = '') -> int: ...
    def get_cached(self, cache_key: str) -> m.ScanResult | None: ...
    def record_result(self, result: m.ScanResult, *, generation: int,
                      cache_key: str | None = None, scope: str = '', work: WorkClaim | None = None,
                      material_observations: tuple = (), materials_checked: bool = False,
                      materials_complete: bool = False) -> str: ...
    def record_report(self, report: m.ScanReport) -> None: ...
    def latest_report(self, repository: str | None = None) -> m.ScanReport | None: ...
    def query_findings(self, *, state: str = 'current', profile: str | None = None) -> tuple[dict, ...]: ...
    def material_snapshot(self, *, max_bytes: int = 1_000_000, max_sources: int = 100): ...
    def acquire_cycle(self, scope: str, root, *, lease_seconds: float) -> WorkLease | None: ...
    def lease_valid(self, lease: WorkLease) -> bool: ...
    def enqueue_work(self, lease: WorkLease, entries, *, refresh: bool = False) -> None: ...
    def claim_work(self, lease: WorkLease) -> WorkClaim | None: ...
    def finish_directory(self, claim: WorkClaim, *, success: bool | None) -> None: ...
    def cycle_status(self, lease: WorkLease) -> dict: ...
    def release_cycle(self, lease: WorkLease) -> None: ...
    def invalidate_scope(self, root, *, reason: str = 'source-unavailable') -> None: ...
    def record_event(self, path: str, kind: str, *, old_path=None, when=None) -> None: ...
    def record_metadata(self, path: str, size: int) -> None: ...
    def close(self) -> None: ...


class MemoryScanStore:
    """No filesystem writes, JSON archive, SQLite connection or implicit mirror."""
    def __init__(self, *, config=None):
        self._lock = threading.RLock()
        self.config = config or {}
        self.generations = {}
        self.results = {}
        self.cache = {}
        self.reports = []
        self.states = {}
        self.current = {}
        self.cycles = {}
        self.work = {}
        self.locations = {}
        self.material_sources = []
        self.material_locations = {}
        self._material_key = __import__('secrets').token_bytes(32)

    @_synchronized
    def reserve(self, source, *, scope=''):
        key = source_key(source, scope)
        generation = self.generations.get(key, 0) + 1
        self.generations[key] = generation
        return generation

    @_synchronized
    def get_cached(self, cache_key):
        entry = self.cache.get(cache_key)
        return replace(self.results[entry], reused_from=self.results[entry].reused_from or entry) if entry else None

    @_synchronized
    def record_result(self, result, *, generation, cache_key=None, scope='', work=None, material_observations=(), materials_checked=False, materials_complete=False):
        if type(result) is not m.ScanResult:
            raise StateError()
        scan_id = uuid.uuid4().hex
        self.results[scan_id] = result
        key = source_key(result.source, scope)
        if self.generations.get(key) != generation or work is not None and not self.lease_valid(work.lease):
            return scan_id
        if result.coverage is m.CoverageState.COMPLETE and result.identity.cache_eligible and cache_key:
            self.cache[cache_key] = scan_id
        if result.source.kind is m.SourceKind.FILESYSTEM:
            prior = self.current.get(key)
            comparable = prior is not None and prior.identity.policy_id == result.identity.policy_id and prior.identity.runtime_id == result.identity.runtime_id
            _transition(self.states, key, result, comparable)
            self.current[key] = result
            if result.content:
                self.locations[result.source.path] = {'size': result.content.size_bytes, 'digest': result.content.digest, 'present': True}
        if materials_checked and result.source.kind is m.SourceKind.FILESYSTEM:
            self._record_materials(result, material_observations, complete=materials_complete)
        self._finish_work(work, result)
        return scan_id

    @_synchronized
    def record_report(self, report):
        if type(report) is not m.ScanReport:
            raise StateError()
        self.reports.append(report)

    @_synchronized
    def latest_report(self, repository=None):
        return next((report for report in reversed(self.reports)
                     if repository is None or any(result.source.repository == repository for result in report.results)), None)

    @_synchronized
    def query_findings(self, *, state='current', profile=None):
        if state not in {'current', 'history'}:
            raise ValueError('invalid state')
        if state == 'history':
            rows = [_query_row(f, result) for result in self.results.values() for f in result.findings]
        else:
            rows = [dict(row) for row in self.states.values() if row['state'] in {'active', 'unknown'}]
        if profile:
            from .policies import profile as select_profile
            rows = [row for row in rows if select_profile(row['source']['path'], self.config) == profile]
        return tuple(rows)

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
        cycle = {'generation': generation, 'owner': owner, 'lease_until': now + lease_seconds, 'completed': None}
        self.cycles[scope] = cycle
        lease = WorkLease(scope, generation, owner)
        for key, work in self.work.items():
            if key[:2] == (scope, generation):
                work['claimed'] = None
        if fresh and root is not None:
            self.enqueue_work(lease, ((str(root), 'directory', 10),))
        return lease

    @_synchronized
    def lease_valid(self, lease):
        import time
        cycle = self.cycles.get(lease.scope)
        return bool(cycle and cycle['generation'] == lease.generation and cycle['owner'] == lease.owner and cycle['lease_until'] > time.time())

    @_synchronized
    def enqueue_work(self, lease, entries, *, refresh=False):
        if not self.lease_valid(lease):
            raise StateError()
        for path, kind, priority in entries:
            key = (lease.scope, lease.generation, path, kind)
            if refresh or key not in self.work:
                self.work[key] = {'priority': priority, 'attempts': 0, 'failed': False, 'done': False, 'claimed': None}

    @_synchronized
    def claim_work(self, lease):
        if not self.lease_valid(lease):
            raise StateError()
        pending = [(key, row) for key, row in self.work.items() if key[:2] == (lease.scope, lease.generation) and not row['done'] and not row['failed'] and row['claimed'] is None]
        if not pending:
            return None
        key, row = min(pending, key=lambda item: (item[1]['priority'], item[0][3] != 'file', item[0][2]))
        row['claimed'] = lease.owner
        return WorkClaim(lease, key[2], key[3])

    @_synchronized
    def finish_directory(self, claim, *, success):
        if not self.lease_valid(claim.lease):
            raise StateError()
        row = self.work[(claim.lease.scope, claim.lease.generation, claim.path, claim.kind)]
        row['done'] = success is True
        if success is False:
            row['attempts'] += 1
            row['failed'] = row['attempts'] >= 3

    @_synchronized
    def _finish_work(self, work, result):
        if work is None:
            return
        row = self.work[(work.lease.scope, work.lease.generation, work.path, work.kind)]
        row['done'] = result.coverage is not m.CoverageState.INCOMPLETE
        if not row['done']:
            row['attempts'] += 1
            row['failed'] = row['attempts'] >= 3

    @_synchronized
    def cycle_status(self, lease):
        pending = [(key, row) for key, row in self.work.items() if key[:2] == (lease.scope, lease.generation) and not row['done']]
        return {'complete': not pending, 'pending_files': sum(key[3] == 'file' for key, _ in pending), 'pending_directories': sum(key[3] == 'directory' for key, _ in pending), 'failed': sum(row['failed'] for _, row in pending), 'cycle_id': str(lease.generation)}

    @_synchronized
    def release_cycle(self, lease):
        if not self.lease_valid(lease):
            return
        status = self.cycle_status(lease)
        cycle = self.cycles[lease.scope]
        cycle['owner'] = None
        cycle['lease_until'] = 0
        if status['complete']:
            cycle['completed'] = datetime.now(timezone.utc).isoformat()
        for key, row in self.work.items():
            if key[:2] == (lease.scope, lease.generation):
                row['claimed'] = None

    @_synchronized
    def invalidate_scope(self, root, *, reason='source-unavailable'):
        from pathlib import Path
        root = Path(root).absolute()
        for row in self.states.values():
            path = Path(row['source']['path']).absolute()
            if root == path or root in path.parents:
                row.update(state='unknown', resolved_at=None, state_reason=reason)

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
        self.locations[path] = {'size': size, 'digest': None, 'present': True}

    @_synchronized
    def record_event(self, path, kind, *, old_path=None, when=None):
        if kind not in {'changed', 'created', 'deleted', 'renamed'}:
            raise StateError()
        for row in self.states.values():
            if row['source']['path'] in {path, old_path}:
                row.update(state='unknown', resolved_at=None, state_reason='source-event')

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
        if input_key != key or evidence in found:
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
    return m.CoverageIssue(m.ErrorCode(v['code']), _source_from(v['source']) if v['source'] else None, v['part_id'], v['required'], v['omission_id'])


def _result_from(value):
    v = _exact(value, 'source content identity outcome coverage findings issues observed_at last_executed_at last_verified_at reused_from')
    c = _exact(v['content'], 'algorithm digest size_bytes') if v['content'] else None
    i = _exact(v['identity'], 'policy_id runtime_id context_id cache_eligible')
    return m.ScanResult(_source_from(v['source']), m.ContentIdentity(**c) if c else None, m.RuntimeIdentity(**i), m.ScanOutcome(v['outcome']), m.CoverageState(v['coverage']), tuple(_finding_from(f) for f in v['findings']), tuple(_issue_from(x) for x in v['issues']), _time(v['observed_at']), _time(v['last_executed_at']), _time(v['last_verified_at']), v['reused_from'])


def _report_from(value):
    v = _exact(value, 'schema_version run_id started_at finished_at policy_id results coverage decision counts issues')
    c = _exact(v['coverage'], 'enumeration_complete required_complete omission_count pending_files pending_directories cycle_id')
    d = _exact(v['decision'], 'verdict reason_codes policy_id')
    return m.ScanReport(v['schema_version'], v['run_id'], _time(v['started_at']), _time(v['finished_at']), v['policy_id'], tuple(_result_from(r) for r in v['results']), m.CoverageSummary(**c), m.PolicyDecision(m.DecisionVerdict(d['verdict']), tuple(m.ErrorCode(x) for x in d['reason_codes']), d['policy_id']), tuple(_issue_from(x) for x in v['issues']))


def _result_json(result):
    # Reuse the single public allowlist, including nested source/identity fields.
    policy_id = result.identity.policy_id
    report = m.ScanReport(1, 'store-result', result.observed_at, result.observed_at, policy_id, (result,), m.CoverageSummary(True, result.coverage is not m.CoverageState.INCOMPLETE, 0), m.PolicyDecision(m.DecisionVerdict.INCOMPLETE if result.coverage is m.CoverageState.INCOMPLETE else m.DecisionVerdict.ALLOW, (), policy_id))
    return json.dumps(report.to_dict()['results'][0], separators=(',', ':'), ensure_ascii=True)


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
CREATE TABLE IF NOT EXISTS current_inputs(input_key TEXT PRIMARY KEY,generation INTEGER NOT NULL DEFAULT 0,last_complete_scan_id TEXT,latest_attempt_id TEXT,current_state TEXT,state_reason TEXT,policy_id TEXT,runtime_id TEXT);
CREATE TABLE IF NOT EXISTS finding_state(input_key TEXT,finding_id TEXT,state TEXT,rule TEXT,path TEXT,payload TEXT NOT NULL,PRIMARY KEY(input_key,finding_id));
CREATE INDEX IF NOT EXISTS finding_state_query ON finding_state(state,path,rule);
CREATE TABLE IF NOT EXISTS scan_cache(cache_key TEXT PRIMARY KEY,scan_id TEXT NOT NULL REFERENCES input_scans(scan_id));
CREATE TABLE IF NOT EXISTS audit_cycles(scope TEXT PRIMARY KEY,generation INTEGER,started TEXT,completed TEXT,failed INTEGER NOT NULL DEFAULT 0,owner TEXT,lease_until REAL);
CREATE TABLE IF NOT EXISTS audit_work(scope TEXT,generation INTEGER,path TEXT,kind TEXT,priority INTEGER,attempts INTEGER NOT NULL DEFAULT 0,failed INTEGER NOT NULL DEFAULT 0,done INTEGER NOT NULL DEFAULT 0,claimed TEXT,PRIMARY KEY(scope,generation,path,kind));
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
        # Recheck after obtaining the writer lock: concurrent openers can observe
        # only an old schema or a fully committed new schema.
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version > 2:
            raise StateError('state-schema-newer')
        for statement in _SCHEMA.split(';'):
            if statement.strip():
                conn.execute(statement)
        for table, additions in {
            'cache': [('policy', 'TEXT'), ('digest', 'TEXT'), ('payload', 'TEXT'), ('executed_at', 'TEXT')],
            'directories': [('priority', 'INTEGER NOT NULL DEFAULT 100')],
            'files': [('priority', 'INTEGER NOT NULL DEFAULT 100')],
            'audit_work': [('done', 'INTEGER NOT NULL DEFAULT 0'), ('claimed', 'TEXT')],
        }.items():
            present = {row[1] for row in conn.execute('PRAGMA table_info(' + table + ')')}
            for column, declaration in additions:
                if column not in present:
                    conn.execute('ALTER TABLE ' + table + ' ADD COLUMN ' + column + ' ' + declaration)
        if version < 2:
            _import_legacy_findings(conn)
            conn.execute('DELETE FROM cache')
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

    @classmethod
    def from_connection(cls, conn, *, state_dir, config=None):
        """Deprecated wrapper adapter; caller retains connection ownership."""
        instance = object.__new__(cls)
        instance.conn = conn
        instance.state_dir = __import__('pathlib').Path(state_dir)
        instance.config = config or {}
        return instance

    def reserve(self, source, *, scope=''):
        key = source_key(source, scope)
        with self.conn:
            self.conn.execute('INSERT INTO current_inputs(input_key,generation) VALUES(?,1) ON CONFLICT(input_key) DO UPDATE SET generation=generation+1', (key,))
            return self.conn.execute('SELECT generation FROM current_inputs WHERE input_key=?', (key,)).fetchone()[0]

    def get_cached(self, cache_key):
        row = self.conn.execute('SELECT i.scan_id,i.payload FROM scan_cache c JOIN input_scans i ON i.scan_id=c.scan_id WHERE cache_key=?', (cache_key,)).fetchone()
        if row:
            try:
                result = _result_from(json.loads(row[1]))
                return replace(result, reused_from=result.reused_from or row[0])
            except Exception:
                raise StateError() from None
        return None

    def record_result(self, result, *, generation, cache_key=None, scope='', work=None, material_observations=(), materials_checked=False, materials_complete=False):
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
                previous = self.conn.execute('SELECT generation,policy_id,runtime_id FROM current_inputs WHERE input_key=?', (key,)).fetchone()
                if not previous or previous[0] != generation or work is not None and not self._lease_valid(work.lease):
                    return scan_id
                if complete and result.identity.cache_eligible and cache_key:
                    self.conn.execute('INSERT OR REPLACE INTO scan_cache VALUES(?,?)', (cache_key, scan_id))
                if result.source.kind is m.SourceKind.FILESYSTEM:
                    states = {(key, row[0]): json.loads(row[1]) for row in self.conn.execute('SELECT finding_id,payload FROM finding_state WHERE input_key=?', (key,))}
                    comparable = previous[1:] == (result.identity.policy_id, result.identity.runtime_id)
                    _transition(states, key, result, comparable)
                    for (_, finding_id), row in states.items():
                        self.conn.execute('INSERT OR REPLACE INTO finding_state VALUES(?,?,?,?,?,?)', (key, finding_id, row['state'], row['rule'], result.source.path, json.dumps(row, separators=(',', ':'))))
                    self._record_location(result)
                if materials_checked and result.source.kind is m.SourceKind.FILESYSTEM:
                    self._record_materials(result, material_observations, complete=materials_complete)
                self._finish_work(work, result)
                self.conn.execute('UPDATE current_inputs SET latest_attempt_id=?,last_complete_scan_id=CASE WHEN ? THEN ? ELSE last_complete_scan_id END,current_state=?,state_reason=?,policy_id=?,runtime_id=? WHERE input_key=? AND generation=?', (scan_id, complete, scan_id, 'verified' if complete else 'unknown', 'complete-content-scan' if complete else 'incomplete-scan', result.identity.policy_id, result.identity.runtime_id, key, generation))
            return scan_id
        except Exception as error:
            if isinstance(error, StateError):
                raise
            raise StateError() from None

    def _record_location(self, result):
        from . import policies, catalog
        source = result.source
        when = result.observed_at.isoformat()
        path = policies.canonical(source.path, self.config)
        if result.content:
            self.conn.execute('INSERT INTO locations VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(host,path) DO UPDATE SET profile=excluded.profile,category=excluded.category,size=excluded.size,digest=excluded.digest,last_seen=excluded.last_seen,present=1', (catalog.HOST, path, policies.profile(path, self.config), policies.classify(path), result.content.size_bytes, result.content.digest, when, when))
        # A failed/missing acquisition does not prove remediation or erase a
        # previous location. Absence confirmation is an explicit separate action.

    def record_report(self, report):
        repositories = {r.source.repository for r in report.results if r.source.repository}
        repository = next(iter(repositories)) if len(repositories) == 1 else None
        try:
            with self.conn:
                self.conn.execute('INSERT OR REPLACE INTO scan_runs VALUES(?,?,?,?,?)', (report.run_id, repository, report.finished_at.isoformat(), report.policy_id, report.to_json()))
        except Exception:
            raise StateError() from None

    def latest_report(self, repository=None):
        row = self.conn.execute('SELECT payload FROM scan_runs ' + ('WHERE repository=? ' if repository else '') + 'ORDER BY finished_at DESC,rowid DESC LIMIT 1', (repository,) if repository else ()).fetchone()
        try:
            return _report_from(json.loads(row[0])) if row else None
        except Exception:
            raise StateError() from None

    def query_findings(self, *, state='current', profile=None):
        if state == 'current':
            rows = [json.loads(row[0]) for row in self.conn.execute("SELECT payload FROM finding_state WHERE state IN ('active','unknown') ORDER BY path,rule,finding_id")]
        elif state == 'history':
            rows = [_query_row(f, r) for (payload,) in self.conn.execute('SELECT payload FROM input_scans ORDER BY observed_at') for r in [_result_from(json.loads(payload))] for f in r.findings]
            rows.extend(json.loads(row[0]) for row in self.conn.execute("SELECT payload FROM finding_state WHERE json_extract(payload,'$.state_reason')='legacy-unverified'"))
        else:
            raise ValueError('invalid state')
        if profile:
            from .policies import profile as select_profile
            rows = [row for row in rows if select_profile(row['source']['path'], self.config) == profile]
        return tuple(rows)

    def close(self):
        self.conn.close()

    def _lease_valid(self, lease):
        import time
        row = self.conn.execute('SELECT generation,owner,lease_until FROM audit_cycles WHERE scope=?', (lease.scope,)).fetchone()
        return bool(row and row[0] == lease.generation and row[1] == lease.owner and row[2] > time.time())

    def lease_valid(self, lease):
        return self._lease_valid(lease)

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

    def enqueue_work(self, lease, entries, *, refresh=False):
        entries = tuple(entries)
        if len(entries) > 1000:
            raise StateError()
        with self.conn:
            if not self._lease_valid(lease):
                raise StateError()
            self.conn.executemany('INSERT INTO audit_work(scope,generation,path,kind,priority) VALUES(?,?,?,?,?) ON CONFLICT(scope,generation,path,kind) DO UPDATE SET done=CASE WHEN ? THEN 0 ELSE done END,attempts=CASE WHEN ? THEN 0 ELSE attempts END,failed=CASE WHEN ? THEN 0 ELSE failed END,claimed=CASE WHEN ? THEN NULL ELSE claimed END', ((lease.scope, lease.generation, path, kind, priority, refresh, refresh, refresh, refresh) for path, kind, priority in entries))

    def claim_work(self, lease):
        try:
            self.conn.execute('BEGIN IMMEDIATE')
            if not self._lease_valid(lease):
                raise StateError()
            row = self.conn.execute("SELECT path,kind FROM audit_work WHERE scope=? AND generation=? AND done=0 AND failed=0 AND claimed IS NULL ORDER BY priority,CASE kind WHEN 'file' THEN 0 ELSE 1 END,path LIMIT 1", (lease.scope, lease.generation)).fetchone()
            if row:
                self.conn.execute('UPDATE audit_work SET claimed=? WHERE scope=? AND generation=? AND path=? AND kind=?', (lease.owner, lease.scope, lease.generation, row[0], row[1]))
            self.conn.commit()
            return WorkClaim(lease, row[0], row[1]) if row else None
        except Exception:
            self.conn.rollback()
            raise StateError() from None

    def finish_directory(self, claim, *, success):
        with self.conn:
            if not self._lease_valid(claim.lease):
                raise StateError()
            self.conn.execute('UPDATE audit_work SET done=?,attempts=attempts+?,failed=CASE WHEN attempts+? >= 3 THEN 1 ELSE failed END WHERE scope=? AND generation=? AND path=? AND kind=? AND claimed=?', (success is True, success is False, success is False, claim.lease.scope, claim.lease.generation, claim.path, claim.kind, claim.lease.owner))

    def _finish_work(self, work, result):
        if work is None:
            return
        complete = result.coverage is not m.CoverageState.INCOMPLETE
        self.conn.execute('UPDATE audit_work SET done=?,attempts=attempts+?,failed=CASE WHEN attempts+? >= 3 THEN 1 ELSE failed END WHERE scope=? AND generation=? AND path=? AND kind=? AND claimed=?', (complete, not complete, not complete, work.lease.scope, work.lease.generation, work.path, work.kind, work.lease.owner))

    def cycle_status(self, lease):
        rows = self.conn.execute('SELECT kind,count(*),sum(failed) FROM audit_work WHERE scope=? AND generation=? AND done=0 GROUP BY kind', (lease.scope, lease.generation)).fetchall()
        counts = {kind: count for kind, count, _ in rows}
        return {'complete': not rows, 'pending_files': counts.get('file', 0), 'pending_directories': counts.get('directory', 0), 'failed': sum(failed for _, _, failed in rows), 'cycle_id': str(lease.generation)}

    def release_cycle(self, lease):
        with self.conn:
            if not self._lease_valid(lease):
                return
            status = self.cycle_status(lease)
            self.conn.execute('UPDATE audit_cycles SET completed=?,failed=?,owner=NULL,lease_until=0 WHERE scope=? AND generation=? AND owner=?', (datetime.now(timezone.utc).isoformat() if status['complete'] else None, status['failed'] > 0, lease.scope, lease.generation, lease.owner))
            self.conn.execute('UPDATE audit_work SET claimed=NULL WHERE scope=? AND generation=?', (lease.scope, lease.generation))

    def invalidate_scope(self, root, *, reason='source-unavailable'):
        from pathlib import Path
        root = Path(root).absolute()
        with self.conn:
            for key, identity, payload in self.conn.execute("SELECT input_key,finding_id,payload FROM finding_state WHERE state IN ('active','unknown')").fetchall():
                row = json.loads(payload)
                path = Path(row['source']['path']).absolute()
                if path == root or root in path.parents:
                    row.update(state='unknown', resolved_at=None, state_reason=reason)
                    self.conn.execute('UPDATE finding_state SET state=?,payload=? WHERE input_key=? AND finding_id=?', ('unknown', json.dumps(row, separators=(',', ':')), key, identity))

    def material_snapshot(self, *, max_bytes=1_000_000, max_sources=100):
        from .catalog import snapshot_materials, MaterialSnapshot
        import os
        rows = self.conn.execute('SELECT name,source,format,field,kind FROM material_sources ORDER BY name LIMIT ?', (max_sources + 1,)).fetchall()
        if not rows:
            return MaterialSnapshot((), 'no-materials', validate=lambda: self.conn.execute('SELECT 1 FROM material_sources LIMIT 1').fetchone() is None)
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
        for (name,) in self.conn.execute('SELECT name FROM material_locations WHERE host=? AND path=?', (catalog.HOST, path)).fetchall():
            if name not in names:
                self.conn.execute('UPDATE material_locations SET present=?,last_seen=? WHERE host=? AND path=? AND name=?', (0 if complete else None, when, catalog.HOST, path, name))
        for item in observations:
            self.conn.execute('INSERT INTO material_locations VALUES(?,?,?,?,?,?,1) ON CONFLICT(host,name,path) DO UPDATE SET fingerprint=excluded.fingerprint,last_seen=excluded.last_seen,present=1', (catalog.HOST, item.name, path, item.fingerprint, when, when))

    def record_metadata(self, path, size):
        from . import catalog
        catalog.metadata_only(self.conn, path, size, self.config)

    def record_event(self, path, kind, *, old_path=None, when=None):
        if kind not in {'changed', 'created', 'deleted', 'renamed'}:
            raise StateError()
        from . import catalog
        catalog.event(self.conn, path, kind, self.config, old_path=old_path, when=when)
        with self.conn:
            for key, identity, payload in self.conn.execute('SELECT input_key,finding_id,payload FROM finding_state WHERE path=? OR path=?', (path, old_path)).fetchall():
                row = json.loads(payload)
                row.update(state='unknown', resolved_at=None, state_reason='source-event')
                self.conn.execute('UPDATE finding_state SET state=?,payload=? WHERE input_key=? AND finding_id=?', ('unknown', json.dumps(row, separators=(',', ':')), key, identity))
