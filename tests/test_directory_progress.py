"""Partial directory enumeration makes durable bounded progress without skips."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, models as m, sources
from leakguard_core.scan_store import DirectoryProgress, MemoryScanStore, SQLiteScanStore, StateError


class DirectoryProgressTests(unittest.TestCase):
    def setUp(self):
        identity = patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', True))
        identity.start(); self.addCleanup(identity.stop)
        detector = patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),))
        detector.start(); self.addCleanup(detector.stop)

    def test_six_files_advance_beyond_first_three_with_reopened_sqlite(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-progress-') as folder:
                root = Path(folder) / 'source'; root.mkdir()
                for number in range(6):
                    (root / f'{number}.txt').write_text('synthetic')
                config = {'audit_scopes': {'synthetic': str(root)}}
                store = MemoryScanStore() if kind == 'memory' else SQLiteScanStore(Path(folder) / 'state')
                seen = set(); reports = []
                for _ in range(8):
                    service = engine.ScanService(config, store=store)
                    report = service.audit('synthetic', limits=m.ScanLimits(5, 2, max_directory_entries=3))
                    reports.append(report)
                    seen.update(result.source.path for result in report.results)
                    service.close()
                    if report.coverage.required_complete:
                        break
                    if kind == 'sqlite':
                        store.close(); store = SQLiteScanStore(Path(folder) / 'state')
                self.assertTrue(reports[-1].coverage.required_complete)
                self.assertEqual(seen, {str(file) for file in root.iterdir()})
                self.assertTrue(reports[0].results)
                store.close()

    def test_changed_directory_restarts_cursor_and_finds_late_entry(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-progress-') as folder:
            root = Path(folder)
            for number in range(6):
                (root / f'{number}.txt').write_text('synthetic')
            store = MemoryScanStore()
            service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=store)
            limits = m.ScanLimits(5, 1, max_directory_entries=2)
            first = service.audit('synthetic', limits=limits)
            (root / 'late.txt').write_text('synthetic')
            seen = {r.source.path for r in first.results}; changed = False
            for _ in range(20):
                report = service.audit('synthetic', limits=limits)
                seen.update(r.source.path for r in report.results)
                changed |= any(i.code is m.ErrorCode.INPUT_CHANGED for i in report.issues)
                if report.coverage.required_complete:
                    break
            service.close()
            self.assertTrue(changed)
            self.assertTrue(report.coverage.required_complete)
            self.assertIn(str(root / 'late.txt'), seen)

    def test_order_mismatch_never_resumes_unverified_offset(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-progress-') as folder:
            root = Path(folder)
            for number in range(5):
                (root / f'{number}.txt').write_text('synthetic')
            store = MemoryScanStore()
            service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=store)
            original = sources.scoped_scandir
            reverse = False
            @contextmanager
            def reordered(path, boundary=None):
                with original(path, boundary) as entries:
                    yield iter(sorted(entries, key=lambda entry: entry.name, reverse=reverse))
            limits = m.ScanLimits(5, 10, max_directory_entries=2)
            with patch.object(sources, 'scoped_scandir', reordered):
                service.audit('synthetic', limits=limits)
                reverse = True
                mismatch = service.audit('synthetic', limits=limits)
                self.assertFalse(mismatch.coverage.required_complete)
                self.assertTrue(any(i.code is m.ErrorCode.INPUT_CHANGED for i in mismatch.issues))
                for _ in range(5):
                    report = service.audit('synthetic', limits=limits)
                    if report.coverage.required_complete:
                        break
            self.assertTrue(report.coverage.required_complete)
            service.close()

    def test_store_without_progress_extension_fails_explicitly_and_drains_files(self):
        class LegacyStore:
            def __init__(self):
                self.store = MemoryScanStore()
            def __getattr__(self, name):
                if name in {'get_directory_progress', 'set_directory_progress'}:
                    raise AttributeError(name)
                return getattr(self.store, name)
        with tempfile.TemporaryDirectory(prefix='leakguard-progress-') as folder:
            root = Path(folder)
            for number in range(4):
                (root / f'{number}.txt').write_text('synthetic')
            service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=LegacyStore())
            report = service.audit('synthetic', limits=m.ScanLimits(5, 10, max_directory_entries=2))
            self.assertEqual(len(report.results), 2)
            self.assertFalse(report.coverage.required_complete)
            self.assertTrue(any(i.required and i.code is m.ErrorCode.INPUT_LIMIT for i in report.issues))
            service.close()

    def test_progress_methods_reject_expired_or_unowned_claims(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-progress-') as folder:
                root = Path(folder)
                store = MemoryScanStore() if kind == 'memory' else SQLiteScanStore(root / 'state')
                lease = store.acquire_cycle('synthetic', root, lease_seconds=10)
                claim = store.claim_work(lease)
                progress = DirectoryProgress(sources.directory_signature(root), 1, '0' * 64)
                store.set_directory_progress(claim, progress)
                self.assertEqual(store.get_directory_progress(claim), progress)
                store.release_cycle(lease, allow_complete=False)
                with self.assertRaises(StateError):
                    store.set_directory_progress(claim, None)
                store.close()
