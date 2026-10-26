"""Audit continuation never mixes earlier work with a changed scan contract."""
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, models as m
from leakguard_core.execution import work_identity
from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore


class AuditIdentityTests(unittest.TestCase):
    def test_slice_budgets_change_without_restarting_reopened_sqlite_work(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-work-id-') as folder:
            root = Path(folder) / 'source'; root.mkdir()
            for number in range(6):
                (root / f'{number}.txt').write_text('synthetic')
            state = Path(folder) / 'state'
            config = {'audit_scopes': {'synthetic': str(root)}}
            seen = []
            with patch('leakguard_core.scan_policy.runtime_identity', return_value=('runtime', True)), patch.object(backends, 'detect', return_value=()) as detector:
                for index in range(8):
                    store = SQLiteScanStore(state)
                    service = engine.ScanService({**config, 'scan_workers': 1 if index == 0 else 2}, store=store)
                    limits = m.ScanLimits(5 if index == 0 else 10, 1 if index == 0 else 2,
                                          max_directory_entries=2 if index == 0 else 3,
                                          max_report_bytes=1_000_000 if index == 0 else 2_000_000,
                                          max_findings=20 if index == 0 else 40)
                    report = service.audit('synthetic', limits=limits)
                    seen.extend(result.source.path for result in report.results)
                    service.close(); store.close()
                    if report.coverage.required_complete:
                        break
                self.assertTrue(report.coverage.required_complete)
                self.assertEqual(len(seen), 6)
                self.assertEqual(len(set(seen)), 6)
                self.assertEqual(detector.call_count, 6)

    def test_changed_rule_bytes_restart_and_keep_earlier_positives_unknown(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-work-id-') as folder:
                base = Path(folder); root = base / 'source'; root.mkdir()
                for number in range(4):
                    (root / f'{number}.txt').write_text('synthetic')
                rules = base / 'rules.toml'; rules.write_text('title="old policy"\n')
                config = {'audit_scopes': {'synthetic': str(root)}, 'gitleaks_config': str(rules)}
                store = MemoryScanStore() if kind == 'memory' else SQLiteScanStore(base / 'state')
                runtime = lambda *args, **kwargs: (hashlib.sha256(rules.read_bytes()).hexdigest(), True)
                with patch('leakguard_core.scan_policy.runtime_identity', side_effect=runtime):
                    service = engine.ScanService(config, store=store)
                    with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                        first = service.audit('synthetic', limits=m.ScanLimits(5, 1, max_directory_entries=2))
                    old_id = first.results[0].findings[0].id
                    service.close()
                    rules.write_text('title="changed policy"\n')
                    seen = []
                    for _ in range(8):
                        service = engine.ScanService(config, store=store)
                        with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-client-secret', 1, 1),)):
                            report = service.audit('synthetic', limits=m.ScanLimits(5, 1, max_directory_entries=2))
                        seen.extend(result.source.path for result in report.results)
                        service.close()
                        if report.coverage.required_complete:
                            break
                    self.assertTrue(report.coverage.required_complete)
                    self.assertEqual(set(seen), {str(file) for file in root.iterdir()})
                    old = next(row for row in store.query_findings() if row['id'] == old_id)
                    self.assertEqual(old['state'], 'unknown')
                    self.assertIsNone(old['resolved_at'])
                store.close()

    def test_extraction_and_profile_changes_affect_continuation_identity(self):
        from leakguard_core.settings import validate
        config = validate({})
        limits = m.ScanLimits(5, 10)
        baseline = work_identity(config=config, runtime='runtime', policy=m.ScanPolicy.inventory(), limits=limits)
        for altered in (replace(limits, max_file_bytes=1024), replace(limits, max_parts=2),
                        replace(limits, worker_memory_bytes=128 * 1024 * 1024)):
            self.assertNotEqual(baseline, work_identity(config=config, runtime='runtime', policy=m.ScanPolicy.inventory(), limits=altered))
        self.assertNotEqual(baseline, work_identity(config={**config, 'detection_profile': 'firm'}, runtime='runtime', policy=m.ScanPolicy.inventory(), limits=limits))

    def test_custom_store_without_identity_fence_reports_required_limitation(self):
        class LegacyStore:
            def __init__(self):
                self.store = MemoryScanStore()
            def __getattr__(self, name):
                if name == 'bind_cycle_identity':
                    raise AttributeError(name)
                return getattr(self.store, name)
        with tempfile.TemporaryDirectory(prefix='leakguard-work-id-') as folder, patch('leakguard_core.scan_policy.runtime_identity', return_value=('runtime', True)):
            root = Path(folder)
            service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=LegacyStore())
            report = service.audit('synthetic', limits=m.ScanLimits(5, 10))
            service.close()
            self.assertFalse(report.coverage.required_complete)
            self.assertEqual(report.results, ())
            self.assertTrue(any(issue.required and issue.code is m.ErrorCode.WORK_IDENTITY_UNAVAILABLE for issue in report.issues))
