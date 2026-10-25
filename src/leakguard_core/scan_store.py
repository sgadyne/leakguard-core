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
        return self.results.get(entry) if entry else None

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
