"""Synthetic regressions for identity, replay and durable scan state."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import engine, hooks


class ReplayTests(unittest.TestCase):
    def test_positive_replay_and_same_stat_content_change(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-state-') as folder:
            root = Path(folder)
            state = root / 'state'
            source = root / 'candidate.txt'
            source.write_bytes(b'first content')
            calls = []

            def scan(data, path, conn=None):
                calls.append(data)
                return engine.safe_findings([{'RuleID': 'literal-password', 'StartLine': 1}], path), 'scanned'

            with patch.object(engine, 'STATE', state), patch.object(engine, 'scan_blob', side_effect=scan):
                conn = engine.db()
                try:
                    first = engine.scan_file(source, conn)
                    warm = engine.scan_file(source, conn)
                    self.assertEqual(first['findings'], warm['findings'])
                    self.assertEqual(warm['status'], 'unchanged')
                    self.assertEqual(len(calls), 1)
                    before = source.stat()
                    source.write_bytes(b'other content')
                    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
                    changed = engine.scan_file(source, conn)
                    self.assertEqual(changed['status'], 'scanned')
                    self.assertEqual(len(calls), 2)
                finally:
                    conn.close()

    @unittest.skipIf(os.name == 'nt', 'POSIX mode bits')
    def test_install_and_upgrade_add_execute_bits_preserving_permissions(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-hooks-') as folder:
            root = Path(folder)
            hooks.install_at(root)
            for kind in ('pre-commit', 'pre-push'):
                target = root / kind
                self.assertTrue(target.stat().st_mode & 0o111)
                target.chmod(0o640)
            hooks.install_at(root)
            self.assertEqual((root / 'pre-commit').stat().st_mode & 0o777, 0o751)


if __name__ == '__main__':
    unittest.main()


class StoreLifecycleTests(unittest.TestCase):
    def make_result(self, *, findings=True, complete=True, policy='policy', runtime='runtime'):
        from datetime import datetime, timezone
        from leakguard_core import models as m
        source = m.SourceRef(m.SourceKind.FILESYSTEM, '/synthetic/candidate.txt')
        when = datetime.now(timezone.utc)
        finding = m.FindingRecord('1' * 64, source, 'text', 1, 1, 'literal-password', 'gitleaks', m.DetectorSeverity.BLOCK, m.FindingSeverity.BLOCK, m.FindingClassification.CREDENTIAL_CANDIDATE)
        return m.ScanResult(source, m.ContentIdentity('sha256', '0' * 64, 1), m.RuntimeIdentity(policy, runtime, 'context', True), m.ScanOutcome.SCANNED, m.CoverageState.COMPLETE if complete else m.CoverageState.INCOMPLETE, (finding,) if findings else (), (), when, when, when if complete else None)

    def test_store_lifecycle_fencing_replay_and_no_mirror(self):
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-store-') as folder:
                root = Path(folder)
                store = store_type(root) if store_type is SQLiteScanStore else store_type()
                try:
                    positive = self.make_result()
                    store.record_result(positive, generation=store.reserve(positive.source), cache_key='positive')
                    self.assertEqual(store.get_cached('positive').findings, positive.findings)
                    failed = self.make_result(findings=False, complete=False)
                    store.record_result(failed, generation=store.reserve(failed.source))
                    self.assertEqual(store.query_findings()[0]['state'], 'unknown')
                    # A late worker cannot erase a newer positive observation.
                    old_generation = store.reserve(positive.source)
                    new_generation = store.reserve(positive.source)
                    store.record_result(positive, generation=new_generation)
                    store.record_result(self.make_result(findings=False), generation=old_generation)
                    self.assertEqual(store.query_findings()[0]['state'], 'active')
                    changed_policy = self.make_result(findings=False, policy='new-policy')
                    store.record_result(changed_policy, generation=store.reserve(positive.source))
                    self.assertEqual(store.query_findings()[0]['state'], 'unknown')
                    store.record_result(positive, generation=store.reserve(positive.source))
                    clean = self.make_result(findings=False)
                    store.record_result(clean, generation=store.reserve(positive.source))
                    self.assertEqual(store.query_findings(), ())
                    if store_type is MemoryScanStore:
                        self.assertEqual(list(root.iterdir()), [])
                finally:
                    store.close()

    def test_legacy_migration_is_transactional_and_unknown(self):
        import sqlite3
        from unittest.mock import patch
        from leakguard_core.scan_store import SQLiteScanStore, StateError
        from leakguard_core import scan_store
        with tempfile.TemporaryDirectory(prefix='leakguard-migrate-') as folder:
            path = Path(folder) / 'state.sqlite3'
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE findings(id TEXT PRIMARY KEY,path TEXT,rule TEXT,line INTEGER,part TEXT,severity TEXT,first_seen TEXT,last_seen TEXT)')
            conn.execute("INSERT INTO findings VALUES('old','/synthetic/old.txt','literal-password',1,'text','block','then','then')")
            conn.execute('CREATE TABLE cache(path TEXT PRIMARY KEY,size INTEGER,mtime INTEGER,status TEXT)')
            conn.execute("INSERT INTO cache VALUES('/synthetic/old.txt',1,1,'scanned')")
            conn.commit(); conn.close()
            with patch.object(scan_store, '_import_legacy_findings', side_effect=RuntimeError('synthetic failure')):
                with self.assertRaises(StateError):
                    SQLiteScanStore(folder)
            conn = sqlite3.connect(path)
            self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0], 0)
            self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='input_scans'").fetchone())
            conn.close()
            store = SQLiteScanStore(folder)
            self.assertEqual(store.conn.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertEqual(store.query_findings()[0]['state_reason'], 'legacy-unverified')
            self.assertEqual(store.conn.execute('SELECT count(*) FROM cache').fetchone()[0], 0)
            store.close()
            self.assertTrue(list(Path(folder).glob('*.bak')))

    def test_newer_schema_rejected_without_modification(self):
        import hashlib
        import sqlite3
        from leakguard_core.scan_store import SQLiteScanStore, StateError
        with tempfile.TemporaryDirectory(prefix='leakguard-newer-') as folder:
            path = Path(folder) / 'state.sqlite3'
            conn = sqlite3.connect(path)
            conn.execute('PRAGMA user_version=99'); conn.close()
            original = hashlib.sha256(path.read_bytes()).digest()
            with self.assertRaises(StateError):
                SQLiteScanStore(folder)
            self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), original)
            self.assertFalse(list(Path(folder).glob('*.bak')))


class ServiceTests(unittest.TestCase):
    def config(self):
        return {'gitleaks_executable': str(engine.EXE)}

    def test_injected_store_receives_all_observations_without_plaintext_mirror(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore
        with tempfile.TemporaryDirectory(prefix='leakguard-service-') as folder:
            root = Path(folder)
            source = root / 'candidate.txt'
            source.write_text('synthetic only\n')
            store = MemoryScanStore()
            service = engine.ScanService(self.config(), state_dir=root / 'no-mirror', store=store)
            try:
                with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                    cold = service.scan([m.FileInput(source)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                    warm = service.scan([m.FileInput(source)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                    fresh = service.scan([m.FileInput(source)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10), use_cache=False)
                self.assertEqual(cold.results[0].findings, warm.results[0].findings)
                self.assertEqual(cold.results[0].findings, fresh.results[0].findings)
                self.assertEqual(warm.results[0].outcome, m.ScanOutcome.REUSED)
                self.assertEqual(warm.results[0].last_executed_at, cold.results[0].last_executed_at)
                self.assertGreaterEqual(warm.results[0].last_verified_at, cold.results[0].last_verified_at)
                self.assertEqual(len(store.results), 3)
                self.assertEqual(len(store.reports), 3)
                self.assertFalse((root / 'no-mirror').exists())
                self.assertEqual([path.name for path in root.iterdir()], ['candidate.txt'])
            finally:
                service.close()

    def test_dependency_change_invalidates_verified_metadata_cache(self):
        import hashlib
        import json
        from leakguard_core import models as m, backends
        with tempfile.TemporaryDirectory(prefix='leakguard-context-') as folder:
            root = Path(folder)
            dependency = root / 'module.py'
            dependency.write_bytes(b'print(1)\n')
            manifest = root / 'metadata.json'
            manifest.write_text(json.dumps({'source_fingerprints': {'module.py': hashlib.sha256(dependency.read_bytes()).hexdigest()}}, indent=2))
            service = engine.ScanService(self.config())
            calls = []
            def detect(*args, **kwargs):
                calls.append(1)
                return (backends.BackendFinding('generic-api-key', 3, 3),)
            try:
                with patch.object(backends, 'detect', side_effect=detect):
                    first = service.scan([m.FileInput(manifest)], policy=m.ScanPolicy.git(), limits=m.ScanLimits(30, 10))
                    dependency.write_bytes(b'print(2)\n')
                    second = service.scan([m.FileInput(manifest)], policy=m.ScanPolicy.git(), limits=m.ScanLimits(30, 10))
                self.assertEqual(first.results[0].findings[0].severity, m.FindingSeverity.INFO)
                self.assertEqual(second.results[0].findings[0].severity, m.FindingSeverity.BLOCK)
                self.assertEqual(second.results[0].outcome, m.ScanOutcome.SCANNED)
                self.assertEqual(len(calls), 2)
            finally:
                service.close()

    def test_source_changes_during_detection_retains_positive_with_incomplete_coverage(self):
        from leakguard_core import models as m, backends
        with tempfile.TemporaryDirectory(prefix='leakguard-change-') as folder:
            source = Path(folder) / 'candidate.txt'
            source.write_bytes(b'first')
            service = engine.ScanService(self.config())
            def detect(*args, **kwargs):
                source.write_bytes(b'other')
                return (backends.BackendFinding('literal-password', 1, 1),)
            try:
                with patch.object(backends, 'detect', side_effect=detect):
                    report = service.scan([m.FileInput(source)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                self.assertEqual(report.counts.findings, 1)
                self.assertEqual(service.store.query_findings()[0]['state'], 'unknown')
            finally:
                service.close()
