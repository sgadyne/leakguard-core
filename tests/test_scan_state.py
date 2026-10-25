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

            from leakguard_core import backends
            def scan(text, **kwargs):
                calls.append(text)
                return (backends.BackendFinding('literal-password', 1, 1),)

            with patch.object(engine, 'STATE', state), patch.object(backends, 'detect', side_effect=scan), patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic-runtime', True)):
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
    def setUp(self):
        # These tests isolate orchestration; the live pinned-backend probe covers
        # eligibility of a concrete installed runtime closure separately.
        self.runtime = patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic-runtime', True))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)

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


class ProofBudgetTests(unittest.TestCase):
    def test_truncated_dependency_closure_cannot_authorize_proof(self):
        from leakguard_core.sources import ProofContext
        context = ProofContext(lambda name: b'synthetic')
        context.max_dependencies = 1
        self.assertEqual(context.read('one.py'), b'synthetic')
        self.assertIsNone(context.read('two.py'))
        self.assertTrue(context.truncated)
        self.assertIsNone(context.read('one.py'))

    def test_detached_validator_keeps_digests_without_raw_dependency_data(self):
        from leakguard_core.sources import ProofContext
        data = {'module.py': b'original synthetic bytes'}
        context = ProofContext(data.get, validator=data.get)
        context.read('module.py')
        validate = context.detach_validator()
        context.dependencies.clear()
        self.assertTrue(validate())
        data['module.py'] = b'changed synthetic bytes'
        self.assertFalse(validate())


class QueueTests(unittest.TestCase):
    make_result = StoreLifecycleTests.make_result
    def test_expired_cycle_cannot_complete_work_or_resolve_newer_observation(self):
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-lease-') as folder:
                store = store_type(folder) if store_type is SQLiteScanStore else store_type()
                positive = self.make_result()
                try:
                    old = store.acquire_cycle('synthetic', None, lease_seconds=60)
                    store.enqueue_work(old, ((positive.source.path, 'file', 0),))
                    old_claim = store.claim_work(old)
                    old_generation = store.reserve(positive.source)
                    self.assertIsNone(store.acquire_cycle('synthetic', None, lease_seconds=60))
                    if store_type is MemoryScanStore:
                        store.cycles['synthetic']['lease_until'] = 0
                    else:
                        store.conn.execute('UPDATE audit_cycles SET lease_until=0'); store.conn.commit()
                    new = store.acquire_cycle('synthetic', None, lease_seconds=60)
                    new_claim = store.claim_work(new)
                    store.record_result(positive, generation=store.reserve(positive.source), work=new_claim)
                    store.record_result(self.make_result(findings=False), generation=old_generation, work=old_claim)
                    self.assertEqual(store.query_findings()[0]['state'], 'active')
                    self.assertTrue(store.cycle_status(new)['complete'])
                    store.release_cycle(old)
                    self.assertTrue(store.lease_valid(new))
                    store.release_cycle(new)
                finally:
                    store.close()

    def test_typed_audit_resumes_file_and_directory_budgets_without_mirror(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-audit-') as folder:
                root = Path(folder)
                corpus = root / 'corpus'; corpus.mkdir()
                (corpus / 'one.txt').write_text('one')
                (corpus / 'two.txt').write_text('two')
                config = {'audit_scopes': {'synthetic': str(corpus)}, 'gitleaks_executable': str(engine.EXE)}
                store = store_type(root / 'store', config=config) if store_type is SQLiteScanStore else store_type(config=config)
                service = engine.ScanService(config, state_dir=root / 'forbidden-mirror', store=store)
                try:
                    with patch.object(backends, 'detect', return_value=()):
                        partial_dir = service.audit('synthetic', limits=m.ScanLimits(30, 10, max_directory_entries=1))
                        self.assertEqual(partial_dir.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                        self.assertGreater(partial_dir.coverage.pending_directories, 0)
                        partial_files = service.audit('synthetic', limits=m.ScanLimits(30, 1))
                        self.assertEqual(partial_files.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                        final = service.audit('synthetic', limits=m.ScanLimits(30, 10))
                    self.assertTrue(final.coverage.enumeration_complete)
                    self.assertEqual(final.coverage.pending_files, 0)
                    self.assertEqual(final.coverage.pending_directories, 0)
                    self.assertEqual(final.decision.verdict, m.DecisionVerdict.ALLOW)
                    self.assertFalse((root / 'forbidden-mirror').exists())
                finally:
                    service.close(); store.close()

    def test_failed_directory_stays_pending_and_never_completes_cycle(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore
        with tempfile.TemporaryDirectory(prefix='leakguard-enumerate-') as folder:
            root = Path(folder)
            store = MemoryScanStore()
            service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}, 'gitleaks_executable': str(engine.EXE)}, store=store)
            try:
                for _ in range(3):
                    with patch('os.scandir', side_effect=PermissionError()), patch.object(backends, 'detect', return_value=()):
                        report = service.audit('synthetic', limits=m.ScanLimits(30, 10))
                    self.assertFalse(report.coverage.enumeration_complete)
                    self.assertEqual(report.coverage.pending_directories, 1)
                    self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                self.assertTrue(next(iter(store.work.values()))['failed'])
            finally:
                service.close()


class MaterialServiceTests(unittest.TestCase):
    def test_reference_changes_and_failures_do_not_manufacture_resolution_or_leak_values(self):
        import json
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        marker = 'SyntheticOnly~MaterialReferenceForOfflineTests42'
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-material-') as folder:
                root = Path(folder)
                reference = root / 'reference.json'; reference.write_text(json.dumps({'value': marker}))
                candidate = root / 'candidate.txt'; candidate.write_text('header\n' + marker)
                rows = [('private-registration', str(reference), 'json', 'value', 'credential')]
                store = store_type(root / 'store') if store_type is SQLiteScanStore else store_type()
                if store_type is MemoryScanStore:
                    store.material_sources = rows
                else:
                    store.conn.executemany('INSERT INTO material_sources VALUES(?,?,?,?,?)', rows); store.conn.commit()
                service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=store)
                try:
                    with patch.object(backends, 'detect', return_value=()):
                        first = service.scan([m.FileInput(candidate)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                        self.assertEqual(first.counts.findings, 1)
                        finding = first.results[0].findings[0]
                        self.assertEqual(finding.rule, 'known-material-credential')
                        self.assertEqual((finding.part_id, finding.start_line), ('text', 2))
                        self.assertNotIn(marker, first.to_json())
                        self.assertNotIn('private-registration', first.to_json())
                        reference.unlink()
                        failed = service.scan([m.FileInput(candidate)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                        self.assertEqual(failed.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                        self.assertEqual(store.query_findings()[0]['state'], 'unknown')
                        reference.write_text(json.dumps({'value': marker}))
                        restored = service.scan([m.FileInput(candidate)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                        self.assertEqual(restored.counts.findings, 1)
                        candidate.write_text('removed')
                        clean = service.scan([m.FileInput(candidate)], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                        self.assertEqual(clean.counts.findings, 0)
                        self.assertEqual(store.query_findings(), ())
                    if store_type is SQLiteScanStore:
                        self.assertNotIn(marker, '\n'.join(store.conn.iterdump()))
                        self.assertEqual(store.conn.execute('SELECT present FROM material_locations').fetchone()[0], 0)
                    else:
                        self.assertFalse(next(iter(store.material_locations.values()))['present'])
                finally:
                    service.close(); store.close()

    def test_duplicate_reference_keys_produce_explicit_failure(self):
        from leakguard_core.catalog import snapshot_materials
        with tempfile.TemporaryDirectory(prefix='leakguard-material-') as folder:
            reference = Path(folder) / 'reference.json'
            reference.write_text('{"value":"synthetic-one","value":"synthetic-two"}')
            snapshot = snapshot_materials((('private', str(reference), 'json', 'value', 'credential'),), b'k' * 32)
            self.assertEqual(snapshot.references, ())
            self.assertIn('detector-failed', snapshot.issues)


class MemoryConcurrencyTests(unittest.TestCase):
    def test_concurrent_publish_keeps_the_newest_reserved_generation(self):
        from concurrent.futures import ThreadPoolExecutor
        from dataclasses import replace
        import threading
        from leakguard_core.scan_store import MemoryScanStore
        for _ in range(25):
            store = MemoryScanStore()
            base = StoreLifecycleTests.make_result(self)
            gate = threading.Barrier(2)
            def publish(number):
                finding = replace(base.findings[0], id=str(number) * 64)
                result = replace(base, findings=(finding,))
                generation = store.reserve(result.source)
                gate.wait(timeout=5)
                store.record_result(result, generation=generation)
                return generation, finding.id
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(publish, number) for number in (1, 2)]
                expected = max(future.result(timeout=5) for future in futures)[1]
            rows = store.query_findings()
            self.assertEqual([row['id'] for row in rows], [expected])
            self.assertEqual(rows[0]['state'], 'active')


class MaterialRegistrationTests(unittest.TestCase):
    def test_registration_changes_invalidate_snapshot_and_assignment_format_is_supported(self):
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        with tempfile.TemporaryDirectory(prefix='leakguard-registration-') as folder:
            root = Path(folder)
            source = root / 'reference.py'; source.write_text('TOKEN = "synthetic-reference-value"\n')
            row = ('private', str(source), 'python-assignment', 'TOKEN', 'credential')
            for store in (MemoryScanStore(), SQLiteScanStore(root / 'store')):
                try:
                    empty = store.material_snapshot()
                    if isinstance(store, MemoryScanStore):
                        store.material_sources.append(row)
                    else:
                        store.conn.execute('INSERT INTO material_sources VALUES(?,?,?,?,?)', row); store.conn.commit()
                    self.assertFalse(empty.valid())
                    registered = store.material_snapshot()
                    self.assertEqual(registered.issues, ())
                    self.assertEqual(len(registered.references), 1)
                    self.assertTrue(registered.valid())
                    if isinstance(store, MemoryScanStore):
                        store.material_sources.clear()
                    else:
                        store.conn.execute('DELETE FROM material_sources'); store.conn.commit()
                    self.assertFalse(registered.valid())
                finally:
                    store.close()


class LegacyAdapterTests(unittest.TestCase):
    def test_run_state_failure_cannot_be_adapted_to_success(self):
        from datetime import datetime, timezone
        from leakguard_core import models as m
        from leakguard_core.scan_store import MemoryScanStore, StateError
        class BrokenReportStore(MemoryScanStore):
            def record_report(self, report):
                raise StateError()
        result = StoreLifecycleTests.make_result(self)
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=BrokenReportStore())
        from leakguard_core import backends
        try:
            with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                report = service.scan((m.BytesInput(b'synthetic', 'candidate.txt'),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1))
            legacy = engine._legacy_result(report.results[0], report.issues)
            self.assertTrue(legacy['status'].startswith('error-'))
            self.assertEqual(legacy['coverage'], 'incomplete')
            self.assertEqual(len(legacy['findings']), 1)
        finally:
            service.close()

    def test_multiline_known_material_has_inclusive_part_range(self):
        from leakguard_core.catalog import MaterialReference, MaterialSnapshot, material_observations
        snapshot = MaterialSnapshot((MaterialReference('private', 'credential', 'first\nsecond\n', 'opaque'),), 'opaque')
        observed = material_observations(snapshot, 'text', 'header\nfirst\nsecond\nfooter')
        self.assertEqual((observed[0].line, observed[0].end_line), (2, 3))
