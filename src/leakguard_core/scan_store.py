"""Injectable redacted scan state; credential storage is a separate capability.

An injected store is the sole durable sink. The memory implementation is useful for
an ephemeral scanner and as a reference for application-owned encrypted stores.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from typing import Protocol, runtime_checkable
import uuid

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


@runtime_checkable
class ScanStore(Protocol):
    def reserve(self, source: m.SourceRef, *, scope: str = '') -> int: ...
    def get_cached(self, cache_key: str) -> m.ScanResult | None: ...
    def record_result(self, result: m.ScanResult, *, generation: int,
                      cache_key: str | None = None, scope: str = '') -> str: ...
    def record_report(self, report: m.ScanReport) -> None: ...
    def latest_report(self, repository: str | None = None) -> m.ScanReport | None: ...
    def query_findings(self, *, state: str = 'current', profile: str | None = None) -> tuple[dict, ...]: ...
    def close(self) -> None: ...


class MemoryScanStore:
    """No filesystem writes, JSON archive, SQLite connection or implicit mirror."""
    def __init__(self, *, config=None):
        self.config = config or {}
        self.generations = {}
        self.results = {}
        self.cache = {}
        self.reports = []
        self.states = {}
        self.current = {}

    def reserve(self, source, *, scope=''):
        key = source_key(source, scope)
        generation = self.generations.get(key, 0) + 1
        self.generations[key] = generation
        return generation

    def get_cached(self, cache_key):
        entry = self.cache.get(cache_key)
        return replace(self.results[entry], reused_from=self.results[entry].reused_from or entry) if entry else None

    def record_result(self, result, *, generation, cache_key=None, scope=''):
        if type(result) is not m.ScanResult:
            raise StateError()
        scan_id = uuid.uuid4().hex
        self.results[scan_id] = result
        key = source_key(result.source, scope)
        if self.generations.get(key) != generation:
            return scan_id
        if result.coverage is m.CoverageState.COMPLETE and result.identity.cache_eligible and cache_key:
            self.cache[cache_key] = scan_id
        if result.source.kind is m.SourceKind.FILESYSTEM:
            prior = self.current.get(key)
            comparable = prior is not None and prior.identity.policy_id == result.identity.policy_id and prior.identity.runtime_id == result.identity.runtime_id
            _transition(self.states, key, result, comparable)
            self.current[key] = result
        return scan_id

    def record_report(self, report):
        if type(report) is not m.ScanReport:
            raise StateError()
        self.reports.append(report)

    def latest_report(self, repository=None):
        return next((report for report in reversed(self.reports)
                     if repository is None or any(result.source.repository == repository for result in report.results)), None)

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

    def close(self):
        pass


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
    report = m.ScanReport(1, 'store-result', result.observed_at, result.observed_at, policy_id, (result,), m.CoverageSummary(True, result.coverage is not m.CoverageState.INCOMPLETE, 0), m.PolicyDecision(m.DecisionVerdict.ALLOW, (), policy_id))
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
CREATE TABLE IF NOT EXISTS audit_work(scope TEXT,generation INTEGER,path TEXT,kind TEXT,priority INTEGER,attempts INTEGER NOT NULL DEFAULT 0,failed INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(scope,generation,path,kind));
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

    def record_result(self, result, *, generation, cache_key=None, scope=''):
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
                if not previous or previous[0] != generation:
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
