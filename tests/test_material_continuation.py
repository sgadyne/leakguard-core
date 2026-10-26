"""Registered reference snapshots participate in resumable audit semantics."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import api, backends, engine, models as m
from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
from leakguard_core.sources import AcquisitionError


class MaterialContinuationTests(unittest.TestCase):
    def setUp(self):
        runtime = patch('leakguard_core.scan_policy.runtime_identity', return_value=('runtime', True))
        runtime.start(); self.addCleanup(runtime.stop)
        backend = patch.object(backends, 'detect', return_value=())
        backend.start(); self.addCleanup(backend.stop)

    def make(self, base, kind, *, empty=False):
        root = base / 'source'; root.mkdir()
        if not empty:
            (root / 'a.txt').write_text('SyntheticNewReference42')
            (root / 'b.txt').write_text('clean fixture')
        reference = base / 'reference.json'
        reference.write_text(json.dumps({'value': 'SyntheticOldReference42'}))
        store = MemoryScanStore() if kind == 'memory' else SQLiteScanStore(base / 'state')
        row = ('private-registration', str(reference), 'json', 'value', 'credential')
        if kind == 'memory':
            store.material_sources.append(row)
        else:
            with store.conn:
                store.conn.execute('INSERT INTO material_sources VALUES(?,?,?,?,?)', row)
        service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=store)
        return root, reference, store, service

    def test_changed_reference_restarts_prior_clean_files_after_reopen(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-material-cycle-') as folder:
                base = Path(folder)
                root, reference, store, service = self.make(base, kind)
                limits = m.ScanLimits(5, 1)
                scanner = api.Scanner(service)
                identity = scanner.work_identity(policy=m.ScanPolicy.inventory(), limits=limits)
                self.assertEqual(set(identity), {'policy_id', 'runtime_id'})
                self.assertEqual(identity['runtime_id'], 'runtime')
                self.assertEqual(identity, scanner.work_identity(policy=m.ScanPolicy.inventory(), limits=replace(limits, max_files=2, deadline_seconds=10)))
                bind = store.bind_cycle_identity
                with patch.object(store, 'bind_cycle_identity', wraps=bind) as binder, patch.object(store, 'material_snapshot', wraps=store.material_snapshot) as snapshots:
                    first = service.audit('synthetic', limits=limits)
                digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
                self.assertEqual(binder.call_args.args[1], digest)
                self.assertEqual(snapshots.call_count, 1, 'identity and execution must share a captured capability')
                self.assertEqual(first.counts.findings, 0)
                self.assertEqual(first.results[0].source.path, str(root / 'a.txt'))
                service.close()
                reference.write_text(json.dumps({'value': 'SyntheticNewReference42'}))
                if kind == 'sqlite':
                    store.close(); store = SQLiteScanStore(base / 'state')
                service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=store)
                changed = api.Scanner(service).work_identity(policy=m.ScanPolicy.inventory(), limits=limits)
                self.assertNotEqual(identity['policy_id'], changed['policy_id'])
                self.assertEqual(identity['runtime_id'], changed['runtime_id'])
                seen = []
                for _ in range(5):
                    report = service.audit('synthetic', limits=limits)
                    seen.extend(result.source.path for result in report.results)
                    if report.coverage.required_complete:
                        break
                self.assertEqual(set(seen), {str(root / 'a.txt'), str(root / 'b.txt')})
                self.assertTrue(report.coverage.required_complete)
                self.assertEqual(report.decision.verdict, m.DecisionVerdict.BLOCK)
                self.assertTrue(any(row['rule'] == 'known-material-credential' for row in store.query_findings()))
                self.assertNotIn('SyntheticNewReference42', report.to_json())
                self.assertNotIn('private-registration', report.to_json())
                service.close(); store.close()

    def test_unreadable_reference_fails_empty_scan_and_identity_closed(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-material-cycle-') as folder:
            root, reference, store, service = self.make(Path(folder), 'memory', empty=True)
            reference.unlink()
            with self.assertRaises(AcquisitionError):
                api.Scanner(service).work_identity(policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 1))
            for report in (service.audit('synthetic', limits=m.ScanLimits(5, 1)),
                           service.scan((), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 1))):
                self.assertFalse(report.coverage.required_complete)
                self.assertEqual(report.results, ())
                self.assertTrue(any(issue.code is m.ErrorCode.SOURCE_UNAVAILABLE and issue.required for issue in report.issues))
            service.close(); store.close()

    def test_reference_change_during_slice_and_empty_final_enumeration_never_completes(self):
        for empty in (False, True):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory(prefix='leakguard-material-cycle-') as folder:
                root, reference, store, service = self.make(Path(folder), 'memory', empty=empty)
                published = []
                record = store.record_report
                def publish(report, **kwargs):
                    published.append(report)
                    return record(report, **kwargs)
                def mutate(*args, **kwargs):
                    reference.write_text(json.dumps({'value': 'SyntheticNewReference42'}))
                    return ()
                evidence = store.cycle_decision_evidence
                def mutate_after_enumeration(lease):
                    result = evidence(lease)
                    mutate()
                    return result
                with patch.object(store, 'record_report', side_effect=publish):
                    if empty:
                        with patch.object(store, 'cycle_decision_evidence', side_effect=mutate_after_enumeration):
                            report = service.audit('synthetic', limits=m.ScanLimits(5, 10))
                    else:
                        with patch.object(backends, 'detect', side_effect=mutate):
                            report = service.audit('synthetic', limits=m.ScanLimits(5, 10))
                self.assertFalse(report.coverage.required_complete)
                self.assertTrue(published)
                self.assertTrue(all(not item.coverage.required_complete for item in published))
                self.assertTrue(any(issue.code is m.ErrorCode.SOURCE_UNAVAILABLE and issue.required for issue in report.issues))
                if not empty:
                    self.assertTrue(all(result.coverage is m.CoverageState.INCOMPLETE for result in report.results))
                service.close(); store.close()
