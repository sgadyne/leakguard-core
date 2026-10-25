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
                    with patch('os.scandir', side_effect=PermissionError()), patch.object(backends, 'detect', return_value=()), patch('leakguard_core.scan_policy.runtime_identity', return_value=(service._runtime, True)):
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


class FindingPageTests(unittest.TestCase):
    def test_current_and_history_pages_are_bounded_and_filter_bound(self):
        from dataclasses import replace
        from leakguard_core import models as m
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore, StateError
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-page-') as folder:
                store = store_type(folder) if store_type is SQLiteScanStore else store_type()
                try:
                    expected = set()
                    for number in range(5):
                        result = StoreLifecycleTests.make_result(self)
                        source = replace(result.source, path='/synthetic/candidate-' + str(number) + '.txt')
                        finding = replace(result.findings[0], source=source, id=format(number + 1, '064x'))
                        result = replace(result, source=source, findings=(finding,))
                        store.record_result(result, generation=store.reserve(source))
                        expected.add(finding.id)
                    for state in ('current', 'history'):
                        cursor = None
                        observed = []
                        pages = 0
                        while True:
                            page = store.query_findings_page(state=state, limit=2, cursor=cursor)
                            self.assertLessEqual(page.page_count, 2)
                            self.assertEqual(page.has_more, page.next_cursor is not None)
                            observed.extend(row['id'] for row in page.rows)
                            pages += 1
                            if not page.has_more:
                                break
                            cursor = page.next_cursor
                            with self.assertRaises(StateError):
                                store.query_findings_page(state=state, profile='general', limit=2, cursor=cursor)
                        self.assertEqual(pages, 3)
                        self.assertEqual(set(observed), expected)
                        self.assertEqual(len(observed), len(expected))
                    for invalid in (True, 0, 10_001):
                        with self.assertRaises(StateError):
                            store.query_findings_page(limit=invalid)
                    with self.assertRaises(StateError) as error:
                        store.query_findings_page(cursor='SyntheticMarkerNotACursor')
                    self.assertNotIn('SyntheticMarkerNotACursor', str(error.exception))
                finally:
                    store.close()


class StoreBudgetTests(unittest.TestCase):
    def test_sqlite_writer_contention_obeys_short_scan_deadline(self):
        import sqlite3
        import time
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import SQLiteScanStore
        with tempfile.TemporaryDirectory(prefix='leakguard-busy-') as folder:
            root = Path(folder)
            source = root / 'candidate.txt'; source.write_text('synthetic')
            store = SQLiteScanStore(root / 'store')
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=store)
            blocker = sqlite3.connect(root / 'store' / 'state.sqlite3')
            blocker.execute('BEGIN IMMEDIATE')
            try:
                started = time.monotonic()
                with patch.object(backends, 'detect', return_value=()), patch('leakguard_core.scan_policy.runtime_identity', return_value=(service._runtime, True)):
                    report = service.scan((m.FileInput(source),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(0.15, 1))
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 1.0)
                self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                self.assertTrue(any(issue.code is m.ErrorCode.STATE_FAILED for issue in report.issues))
            finally:
                blocker.rollback(); blocker.close(); service.close(); store.close()

    def test_resolved_history_is_not_reopened_by_unreadability_or_events(self):
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with tempfile.TemporaryDirectory(prefix='leakguard-resolved-') as folder:
                store = store_type(folder) if store_type is SQLiteScanStore else store_type()
                try:
                    positive = StoreLifecycleTests.make_result(self)
                    clean = StoreLifecycleTests.make_result(self, findings=False)
                    store.record_result(positive, generation=store.reserve(positive.source))
                    store.record_result(clean, generation=store.reserve(positive.source))
                    self.assertEqual(store.query_findings(), ())
                    incomplete = StoreLifecycleTests.make_result(self, findings=False, complete=False)
                    store.record_result(incomplete, generation=store.reserve(positive.source))
                    store.record_event(positive.source.path, 'changed')
                    self.assertEqual(store.query_findings(), ())
                    store.record_result(positive, generation=store.reserve(positive.source))
                    self.assertEqual(store.query_findings()[0]['state'], 'active')
                finally:
                    store.close()


class AuditStoreBudgetTests(unittest.TestCase):
    def test_audit_lease_contention_uses_original_short_deadline_and_clears_budget(self):
        import sqlite3
        import time
        from leakguard_core import models as m
        from leakguard_core.scan_store import SQLiteScanStore
        with tempfile.TemporaryDirectory(prefix='leakguard-audit-busy-') as folder:
            root = Path(folder)
            corpus = root / 'corpus'; corpus.mkdir()
            store = SQLiteScanStore(root / 'store')
            service = engine.ScanService({'audit_scopes': {'synthetic': str(corpus)}, 'gitleaks_executable': str(engine.EXE)}, store=store)
            blocker = sqlite3.connect(root / 'store' / 'state.sqlite3')
            blocker.execute('BEGIN IMMEDIATE')
            try:
                started = time.monotonic()
                with patch('leakguard_core.scan_policy.runtime_identity', return_value=(service._runtime, True)):
                    report = service.audit('synthetic', limits=m.ScanLimits(0.15, 1))
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                self.assertIsNone(store._deadline)
            finally:
                blocker.rollback(); blocker.close(); service.close(); store.close()


class PageIsolationTests(unittest.TestCase):
    def test_page_source_mutation_does_not_corrupt_memory_store(self):
        from leakguard_core.scan_store import MemoryScanStore
        store = MemoryScanStore()
        result = StoreLifecycleTests.make_result(self)
        store.record_result(result, generation=store.reserve(result.source))
        for state in ('current', 'history'):
            row = store.query_findings_page(state=state).rows[0]
            row['source']['path'] = '/synthetic/mutated'
            self.assertEqual(store.query_findings_page(state=state).rows[0]['source']['path'], result.source.path)


class AbsenceConfirmationTests(unittest.TestCase):
    def test_delete_notification_unknown_then_explicit_confirmed_absence(self):
        import json
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-absence-') as folder:
                root = Path(folder)
                corpus = root / 'corpus'; corpus.mkdir()
                source = corpus / 'candidate.txt'; source.write_text('synthetic')
                store = store_type(root / 'store') if store_type is SQLiteScanStore else store_type()
                service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=store)
                try:
                    with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                        initial = service.scan((m.FileInput(source),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1))
                    self.assertEqual(initial.counts.findings, 1)
                    source.unlink()
                    store.record_event(str(source), 'deleted')
                    self.assertEqual(store.query_findings()[0]['state'], 'unknown')
                    self.assertTrue(service.confirm_absent(source, root=corpus, limits=m.ScanLimits(30, 1)))
                    self.assertEqual(store.query_findings(), ())
                    if store_type is MemoryScanStore:
                        row = next(iter(store.states.values()))
                    else:
                        row = json.loads(store.conn.execute('SELECT payload FROM finding_state').fetchone()[0])
                    self.assertEqual(row['state'], 'resolved')
                    self.assertEqual(row['state_reason'], 'source-absent')
                finally:
                    service.close(); store.close()

    def test_replaced_or_missing_parent_cannot_prove_absence(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore
        with tempfile.TemporaryDirectory(prefix='leakguard-absence-parent-') as folder:
            root = Path(folder)
            corpus = root / 'corpus'; corpus.mkdir()
            source = corpus / 'candidate.txt'; source.write_text('synthetic')
            store = MemoryScanStore()
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=store)
            try:
                with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                    service.scan((m.FileInput(source),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1))
                corpus.rename(root / 'original-corpus')
                corpus.mkdir()
                self.assertFalse(service.confirm_absent(source, root=corpus, limits=m.ScanLimits(30, 1)))
                self.assertEqual(store.query_findings()[0]['state'], 'unknown')
            finally:
                service.close()

    def test_newer_generation_fences_an_older_absence_confirmation(self):
        from leakguard_core import models as m, backends
        from leakguard_core.sources import confirm_absence
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with tempfile.TemporaryDirectory(prefix='leakguard-absence-fence-') as folder:
                root = Path(folder)
                source = root / 'candidate.txt'; source.write_text('synthetic')
                store = store_type(root / 'store') if store_type is SQLiteScanStore else store_type()
                service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=store)
                try:
                    with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                        report = service.scan((m.FileInput(source),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1))
                    ref = report.results[0].source
                    source.unlink()
                    old_generation = store.reserve(ref)
                    proof = confirm_absence(source, root, store.source_anchor(ref))
                    store.reserve(ref)
                    self.assertFalse(store.confirm_absent(proof, generation=old_generation))
                    self.assertEqual(store.query_findings()[0]['state'], 'active')
                finally:
                    service.close(); store.close()

    def test_successful_reconciliation_marks_lost_delete_event_unknown(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with tempfile.TemporaryDirectory(prefix='leakguard-reconcile-') as folder:
                root = Path(folder)
                corpus = root / 'corpus'; corpus.mkdir()
                source = corpus / 'candidate.txt'; source.write_text('synthetic')
                store = store_type(root / 'store') if store_type is SQLiteScanStore else store_type()
                service = engine.ScanService({'audit_scopes': {'synthetic': str(corpus)}, 'gitleaks_executable': str(engine.EXE)}, store=store)
                try:
                    with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                        first = service.audit('synthetic', limits=m.ScanLimits(30, 10))
                    self.assertEqual(first.decision.verdict, m.DecisionVerdict.BLOCK)
                    self.assertEqual(store.query_findings()[0]['state'], 'active')
                    source.unlink()  # Deliberately no watcher event.
                    second = service.audit('synthetic', limits=m.ScanLimits(30, 10))
                    self.assertTrue(second.coverage.enumeration_complete)
                    self.assertEqual(store.query_findings()[0]['state'], 'unknown')
                    self.assertEqual(store.query_findings()[0]['state_reason'], 'source-unavailable')
                finally:
                    service.close(); store.close()


class IdentityBudgetServiceTests(unittest.TestCase):
    def test_identity_failure_before_admission_is_explicit_and_does_not_read_input(self):
        from leakguard_core import models as m, scan_policy
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        def inputs():
            raise AssertionError('input admitted after identity failure')
            yield
        try:
            for code in ('budget-exhausted', 'cancelled', 'source-unavailable'):
                with self.subTest(code=code), patch.object(scan_policy, 'runtime_identity', side_effect=scan_policy.RuntimeIdentityError(code)):
                    report = service.scan(inputs(), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1))
                self.assertEqual(report.results, ())
                self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                self.assertTrue(any(issue.code.value == code and issue.required for issue in report.issues))
        finally:
            service.close()

    def test_final_identity_failure_keeps_positive_and_revokes_verification(self):
        from leakguard_core import models as m, scan_policy, backends
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            with patch.object(scan_policy, 'runtime_identity', side_effect=[(service._runtime, True), scan_policy.RuntimeIdentityError('budget-exhausted')]), patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                report = service.scan((m.BytesInput(b'synthetic', 'candidate.txt'),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1))
            self.assertEqual(report.counts.findings, 1)
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
            self.assertIsNone(report.results[0].last_verified_at)
            self.assertEqual(report.results[0].coverage, m.CoverageState.INCOMPLETE)
        finally:
            service.close()

    def test_budget_consumed_by_backend_prevents_remaining_plugin_startups(self):
        import time
        from leakguard_core import models as m, scan_policy, backends, plugins
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        service._plugins = [object() for _ in range(20)]
        def detect(*args, **kwargs):
            time.sleep(0.03)
            return (backends.BackendFinding('literal-password', 1, 1),)
        try:
            with patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)), patch.object(backends, 'detect', side_effect=detect), patch.object(plugins, 'detect') as plugin_detect:
                report = service.scan((m.BytesInput(b'synthetic', 'candidate.txt'),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(0.02, 1))
            plugin_detect.assert_not_called()
            # The backend spent the whole budget before any item was admitted.
            self.assertEqual(report.counts.findings, 0)
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
        finally:
            service.close()


class ReconciliationFenceTests(unittest.TestCase):
    def test_reconciliation_fences_older_publish_but_preserves_newer_reservation(self):
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            for newer in (False, True):
                with self.subTest(store=store_type.__name__, newer=newer), tempfile.TemporaryDirectory(prefix='leakguard-reconcile-fence-') as folder:
                    store = store_type(folder) if store_type is SQLiteScanStore else store_type()
                    result = StoreLifecycleTests.make_result(self)
                    try:
                        store.record_result(result, generation=store.reserve(result.source))
                        if not newer:
                            generation = store.reserve(result.source)
                        lease = store.acquire_cycle('synthetic', None, lease_seconds=60)
                        if newer:
                            generation = store.reserve(result.source)
                        store.reconcile_cycle(lease, '/synthetic')
                        self.assertEqual(store.query_findings()[0]['state'], 'active' if newer else 'unknown')
                        store.record_result(result, generation=generation)
                        self.assertEqual(store.query_findings()[0]['state'], 'active' if newer else 'unknown')
                    finally:
                        store.close()


class MaterialEventTests(unittest.TestCase):
    def test_delete_and_rename_hints_keep_material_and_location_presence_unknown(self):
        from leakguard_core import catalog
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            for kind in ('deleted', 'renamed'):
                with self.subTest(store=store_type.__name__, kind=kind), tempfile.TemporaryDirectory(prefix='leakguard-material-event-') as folder:
                    store = store_type(folder) if store_type is SQLiteScanStore else store_type()
                    path = '/synthetic/candidate.txt'
                    try:
                        if store_type is MemoryScanStore:
                            store.locations[path] = {'present': True}
                            store.material_locations[('private-registration', path)] = {'present': True}
                        else:
                            store.conn.execute('INSERT INTO locations(host,path,present) VALUES(?,?,1)', (catalog.HOST, path))
                            store.conn.execute('INSERT INTO material_locations(host,name,path,present) VALUES(?,?,?,1)', (catalog.HOST, 'private-registration', path))
                            store.conn.commit()
                        store.record_event(path if kind == 'deleted' else '/synthetic/new.txt', kind, old_path=path if kind == 'renamed' else None)
                        if store_type is MemoryScanStore:
                            self.assertIsNone(store.locations[path]['present'])
                            self.assertIsNone(store.material_locations[('private-registration', path)]['present'])
                        else:
                            self.assertIsNone(store.conn.execute('SELECT present FROM locations').fetchone()[0])
                            self.assertIsNone(store.conn.execute('SELECT present FROM material_locations').fetchone()[0])
                    finally:
                        store.close()


class PersistedReportCountsTests(unittest.TestCase):
    def test_decoder_rejects_false_or_noninteger_counts(self):
        import copy
        from leakguard_core import models as m
        from leakguard_core.scan_store import _report_from, StateError
        result = StoreLifecycleTests.make_result(self)
        report = m.ScanReport(1, 'synthetic-run', result.observed_at, result.observed_at, 'policy', (result,), m.CoverageSummary(True, True, 0), m.PolicyDecision(m.DecisionVerdict.BLOCK, (), 'policy'))
        self.assertEqual(_report_from(report.to_dict()), report)
        for bad in (0, True, '1'):
            payload = copy.deepcopy(report.to_dict())
            payload['counts']['findings'] = bad
            with self.subTest(value=bad), self.assertRaises(StateError):
                _report_from(payload)


class ReconciliationFailureTests(unittest.TestCase):
    def test_state_failure_never_completes_cycle_and_keeps_positive(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore, StateError
        class BrokenReportStore(MemoryScanStore):
            def record_report(self, report, **kwargs):
                raise StateError()
        class BrokenReconciliationStore(MemoryScanStore):
            def reconcile_cycle(self, lease, root):
                raise StateError()
        for store_type in (BrokenReportStore, BrokenReconciliationStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-cycle-state-failure-') as folder:
                root = Path(folder)
                (root / 'candidate.txt').write_text('synthetic')
                store = store_type()
                service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}, 'gitleaks_executable': str(engine.EXE)}, store=store)
                try:
                    with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                        report = service.audit('synthetic', limits=m.ScanLimits(30, 10))
                    self.assertEqual(report.counts.findings, 1)
                    self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                    self.assertIsNone(store.cycles['audit:synthetic']['completed'])
                finally:
                    service.close()


class HookReplacementTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'POSIX link and mode semantics')
    def test_symlink_target_is_rejected_and_original_is_unchanged(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-hook-link-') as folder:
            root = Path(folder)
            target = root / 'original'; target.write_bytes(b'#!/bin/sh\nexit 7\n')
            directory = root / 'hooks'; directory.mkdir()
            (directory / 'pre-commit').symlink_to(target)
            with self.assertRaises(RuntimeError):
                hooks.install_at(directory)
            self.assertEqual(target.read_bytes(), b'#!/bin/sh\nexit 7\n')
            self.assertTrue((directory / 'pre-commit').is_symlink())

    @unittest.skipIf(os.name == 'nt', 'POSIX link and mode semantics')
    def test_hardlink_is_replaced_atomically_and_upgrade_keeps_backup(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-hook-hardlink-') as folder:
            root = Path(folder)
            original = root / 'original'; original.write_bytes(b'#!/bin/sh\nexit 7\n'); original.chmod(0o640)
            directory = root / 'hooks'; directory.mkdir()
            os.link(original, directory / 'pre-commit')
            hooks.install_at(directory)
            self.assertEqual(original.read_bytes(), b'#!/bin/sh\nexit 7\n')
            self.assertEqual(original.stat().st_mode & 0o777, 0o640)
            self.assertEqual((directory / 'pre-commit').stat().st_mode & 0o777, 0o751)
            self.assertEqual((directory / 'pre-commit.before-leakguard').read_bytes(), original.read_bytes())
            before = (directory / 'pre-commit').read_bytes()
            hooks.install_at(directory)
            self.assertEqual((directory / 'pre-commit').read_bytes(), before)
            self.assertEqual((directory / 'pre-commit.before-leakguard').read_bytes(), original.read_bytes())

    @unittest.skipIf(os.name == 'nt', 'POSIX FIFO semantics')
    def test_fifo_is_rejected_without_opening(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-hook-fifo-') as folder:
            directory = Path(folder)
            os.mkfifo(directory / 'pre-commit')
            with self.assertRaises(RuntimeError):
                hooks.install_at(directory)


class OptionalAbsenceStoreTests(unittest.TestCase):
    def test_file_only_store_does_not_receive_absence_extension_kwargs(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore
        class FileOnlyStore:
            def __init__(self):
                self.memory = MemoryScanStore()
            def reserve(self, source): return self.memory.reserve(source)
            def get_cached(self, key): return self.memory.get_cached(key)
            def record_result(self, result, *, generation, cache_key=None):
                return self.memory.record_result(result, generation=generation, cache_key=cache_key)
            def record_report(self, report): return self.memory.record_report(report)
        with tempfile.TemporaryDirectory(prefix='leakguard-optional-absence-') as folder:
            path = Path(folder) / 'candidate.txt'; path.write_text('synthetic')
            store = FileOnlyStore()
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE)}, store=store)
            try:
                with patch.object(backends, 'detect', return_value=()):
                    report = service.scan((m.FileInput(path),), policy=m.ScanPolicy.git(), limits=m.ScanLimits(30, 1))
                self.assertEqual(report.decision.verdict, m.DecisionVerdict.ALLOW)
                self.assertEqual(len(store.memory.results), 1)
            finally:
                service.close()


class AggregateReportBudgetTests(unittest.TestCase):
    def test_oversized_later_input_preserves_earlier_positive_with_exact_cap(self):
        from leakguard_core import models as m, backends
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                report = service.scan((m.BytesInput(b'synthetic', 'first.txt'), m.BytesInput(b'synthetic', 'x' * 4000)), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10, max_report_bytes=8192))
            self.assertEqual(report.counts.findings, 1)
            self.assertEqual(report.results[0].source.path, 'first.txt')
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
            self.assertLessEqual(len(report.to_json().encode()), 8192)
        finally:
            service.close()

    def test_result_keeps_bounded_positive_prefix_and_marks_truncation(self):
        from leakguard_core import models as m, backends
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            findings = tuple(backends.BackendFinding('synthetic-rule-' + str(index), 1, 1) for index in range(30))
            with patch.object(backends, 'detect', return_value=findings):
                report = service.scan((m.BytesInput(b'synthetic', 'candidate.txt'),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10, max_report_bytes=8192))
            self.assertGreater(report.counts.findings, 0)
            self.assertLess(report.counts.findings, 30)
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
            self.assertLessEqual(len(report.to_json().encode()), 8192)
            self.assertTrue(any(issue.code is m.ErrorCode.DETECTOR_OUTPUT_LIMIT for issue in report.issues))
        finally:
            service.close()

    def test_enumeration_issues_and_minimum_report_are_bounded(self):
        from leakguard_core import models as m
        with tempfile.TemporaryDirectory(prefix='leakguard-report-issues-') as folder:
            paths = []
            for index in range(60):
                path = Path(folder) / (str(index) + 'x' * 170) / 'blocked'; path.mkdir(parents=True)
                paths.append(path)
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE), 'exclude_components': ['blocked']})
            try:
                for maximum in (2048, 8192):
                    report = service.scan_paths(paths, policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 100, max_report_bytes=maximum))
                    self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                    self.assertFalse(report.coverage.enumeration_complete)
                    self.assertLessEqual(len(report.to_json().encode()), maximum)
                    self.assertTrue(any(issue.code is m.ErrorCode.DETECTOR_OUTPUT_LIMIT for issue in report.issues))
            finally:
                service.close()


class FindingAdmissionTests(unittest.TestCase):
    def test_classification_deadline_keeps_accepted_positive_and_stops_items(self):
        import time
        from leakguard_core import models as m, backends, scan_policy
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        original = service._finding
        calls = []
        def classify(*args, **kwargs):
            calls.append(1)
            finding = original(*args, **kwargs)
            time.sleep(0.03)
            return finding
        try:
            with patch.object(backends, 'detect', return_value=tuple(backends.BackendFinding('literal-password', 1, 1) for _ in range(10000))), patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)), patch.object(service, '_finding', side_effect=classify):
                report = service.scan((m.BytesInput(b'synthetic', 'candidate.txt'),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(0.02, 1))
            self.assertEqual(len(calls), 1)
            self.assertEqual(report.counts.findings, 1)
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
        finally:
            service.close()

    def test_metadata_proof_failure_retains_original_blocking_detection(self):
        from leakguard_core import models as m, backends
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)), patch.object(engine.finding_details, 'describe', side_effect=ValueError('synthetic parser failure')):
                report = service.scan((m.BytesInput(b'synthetic', 'candidate.json'),), policy=m.ScanPolicy.git(), limits=m.ScanLimits(30, 1))
            self.assertEqual(report.counts.findings, 1)
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.BLOCK)
            self.assertEqual(report.results[0].findings[0].severity, m.FindingSeverity.BLOCK)
        finally:
            service.close()


class SourceAdmissionTests(unittest.TestCase):
    def test_normalized_source_path_overflow_is_a_fixed_incomplete_issue(self):
        from leakguard_core import models as m
        service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
        try:
            source = m.FileInput(Path('x' * (m.MAX_PROVENANCE_STRING_LENGTH - 1)))
            report = service.scan((source,), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1))
            self.assertEqual(report.results, ())
            self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
            self.assertTrue(any(issue.code is m.ErrorCode.INPUT_LIMIT and issue.required for issue in report.issues))
            self.assertLess(len(report.to_json()), 2048)
        finally:
            service.close()


class IncrementalReportAdmissionTests(unittest.TestCase):
    def test_long_provenance_many_findings_never_serializes_complete_candidate(self):
        from dataclasses import replace
        from leakguard_core import models as m, scan_store
        base = StoreLifecycleTests.make_result(self)
        source = m.SourceRef(m.SourceKind.FILESYSTEM, '/' + 'x' * 4000)
        finding = replace(base.findings[0], source=source)
        # The source string is shared in memory, but whole-candidate JSON would
        # repeat it 100,000 times and allocate hundreds of megabytes.
        candidate = replace(base, source=source, findings=(finding,) * 100000)
        serialized_counts = []
        actual = scan_store._result_json
        def guarded(result):
            serialized_counts.append(len(result.findings))
            if len(result.findings) > 20:
                raise AssertionError('unadmitted result materialized')
            return actual(result)
        with patch.object(scan_store, '_result_json', side_effect=guarded):
            admitted, size, truncated = engine._admit_result(candidate, 65536)
        self.assertTrue(truncated)
        self.assertGreater(len(admitted.findings), 0)
        self.assertLessEqual(len(admitted.findings), 20)
        self.assertLessEqual(size, 65536)
        self.assertEqual(size, len(actual(admitted).encode()))
        self.assertTrue(all(count <= 20 for count in serialized_counts))


class AdvertisedDeadlineFailureTests(unittest.TestCase):
    def test_failed_budget_setup_makes_no_further_store_calls_or_input_admission(self):
        from leakguard_core import models as m
        from leakguard_core.scan_store import MemoryScanStore, StateError
        class BrokenDeadlineStore(MemoryScanStore):
            def __init__(self):
                super().__init__()
                self.calls = []
            def set_deadline(self, deadline):
                self.calls.append('set_deadline')
                raise StateError()
            def material_snapshot(self, **kwargs):
                raise AssertionError('store used after failed setup')
            def acquire_cycle(self, *args, **kwargs):
                raise AssertionError('queue used after failed setup')
            def record_report(self, *args, **kwargs):
                raise AssertionError('report written after failed setup')
        def inputs():
            raise AssertionError('input admitted after failed setup')
            yield
        with tempfile.TemporaryDirectory(prefix='leakguard-deadline-setup-') as folder:
            store = BrokenDeadlineStore()
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE), 'audit_scopes': {'synthetic': folder}}, store=store)
            try:
                reports = [service.scan(inputs(), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1)), service.audit('synthetic', limits=m.ScanLimits(30, 1)), service.drain(limits=m.ScanLimits(30, 1)), service.scan_git(folder, request=m.GitRequest(m.GitRequestKind.INDEX), limits=m.ScanLimits(30, 1))]
                self.assertEqual(store.calls, ['set_deadline'] * 4)
                for report in reports:
                    self.assertEqual(report.results, ())
                    self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                    self.assertEqual(tuple(issue.code for issue in report.issues), (m.ErrorCode.STATE_FAILED,))
                    self.assertLess(len(report.to_json()), 2048)
            finally:
                service.close()


class DirectoryMutationTests(unittest.TestCase):
    @staticmethod
    def buffered_scandir(original):
        from contextlib import contextmanager
        @contextmanager
        def buffered(path):
            with original(path) as entries:
                snapshot = tuple(entries)
            yield iter(snapshot)
        return buffered

    def test_path_enumeration_change_after_first_yield_is_incomplete(self):
        from leakguard_core import models as m, backends, scan_policy
        with tempfile.TemporaryDirectory(prefix='leakguard-directory-change-') as folder:
            root = Path(folder)
            (root / 'first.txt').write_text('synthetic first')
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
            original = os.scandir
            def detect(*args, **kwargs):
                (root / 'late.txt').write_text('synthetic late')
                return (backends.BackendFinding('literal-password', 1, 1),)
            try:
                with patch('os.scandir', side_effect=self.buffered_scandir(original)), patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)), patch.object(backends, 'detect', side_effect=detect):
                    report = service.scan_paths((root,), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                self.assertEqual(report.counts.findings, 1)
                self.assertFalse(report.coverage.enumeration_complete)
                self.assertEqual(report.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                self.assertGreater(report.coverage.pending_directories, 0)
                self.assertTrue(any(issue.code is m.ErrorCode.INPUT_CHANGED for issue in report.issues))
            finally:
                service.close()

    def test_completed_directory_is_revalidated_after_later_detection(self):
        from leakguard_core import models as m, backends, scan_policy
        with tempfile.TemporaryDirectory(prefix='leakguard-directory-final-') as folder:
            root = Path(folder)
            first = root / 'first'; first.mkdir()
            second = root / 'second'; second.mkdir()
            (first / 'candidate.txt').write_text('first')
            (second / 'candidate.txt').write_text('second')
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
            def detect(text, **kwargs):
                if text == 'second':
                    (first / 'late.txt').write_text('synthetic late')
                return (backends.BackendFinding('literal-password', 1, 1),)
            try:
                with patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)), patch.object(backends, 'detect', side_effect=detect):
                    report = service.scan_paths((second, first), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                self.assertEqual(report.counts.findings, 2)
                self.assertFalse(report.coverage.enumeration_complete)
                self.assertTrue(any(issue.code is m.ErrorCode.INPUT_CHANGED for issue in report.issues))
            finally:
                service.close()

    def test_audit_change_stays_pending_across_store_restart_then_rescans(self):
        from leakguard_core import models as m, backends, scan_policy
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-audit-directory-change-') as folder:
                root = Path(folder)
                corpus = root / 'corpus'; corpus.mkdir()
                (corpus / 'first.txt').write_text('synthetic first')
                state = root / 'state'
                store = store_type(state) if store_type is SQLiteScanStore else store_type()
                config = {'gitleaks_executable': str(engine.EXE), 'audit_scopes': {'synthetic': str(corpus)}}
                service = engine.ScanService(config, store=store)
                original = os.scandir
                def detect(*args, **kwargs):
                    (corpus / 'late.txt').write_text('synthetic late')
                    return (backends.BackendFinding('literal-password', 1, 1),)
                try:
                    with patch('os.scandir', side_effect=self.buffered_scandir(original)), patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)), patch.object(backends, 'detect', side_effect=detect):
                        changed = service.audit('synthetic', limits=m.ScanLimits(30, 10))
                    self.assertEqual(changed.counts.findings, 1)
                    self.assertFalse(changed.coverage.enumeration_complete)
                    self.assertGreater(changed.coverage.pending_directories, 0)
                    self.assertEqual(changed.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                    service.close()
                    if store_type is SQLiteScanStore:
                        store.close()
                        store = store_type(state)
                    service = engine.ScanService(config, store=store)
                    with patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)), patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                        resumed = service.audit('synthetic', limits=m.ScanLimits(30, 10), use_cache=False)
                    self.assertTrue(resumed.coverage.enumeration_complete)
                    self.assertIn(str(corpus / 'late.txt'), {result.source.path for result in resumed.results})
                finally:
                    service.close(); store.close()


class DirectoryValidationPagingTests(unittest.TestCase):
    def test_validation_pages_resume_across_sqlite_restart_and_memory_leases(self):
        from leakguard_core import models as m, scan_policy
        from leakguard_core.sources import directory_signature
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-directory-pages-') as folder:
                root = Path(folder)
                corpus = root / 'corpus'; corpus.mkdir()
                paths = [corpus]
                for index in range(3):
                    path = corpus / str(index); path.mkdir(); paths.append(path)
                state = root / 'state'
                store = store_type(state) if store_type is SQLiteScanStore else store_type()
                lease = store.acquire_cycle('audit:synthetic', None, lease_seconds=60)
                store.enqueue_work(lease, tuple((str(path), 'directory', 0) for path in paths))
                for _ in paths:
                    claim = store.claim_work(lease)
                    store.finish_directory(claim, success=True, signature=directory_signature(claim.path))
                store.release_cycle(lease, allow_complete=False)
                counts = []
                try:
                    for _ in paths:
                        if store_type is SQLiteScanStore:
                            store.close(); store = store_type(state)
                        service = engine.ScanService({'gitleaks_executable': str(engine.EXE), 'audit_scopes': {'synthetic': str(corpus)}}, store=store)
                        try:
                            with patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)):
                                report = service.audit('synthetic', limits=m.ScanLimits(30, 1, max_directory_entries=1))
                            counts.append(report.coverage.pending_directories)
                        finally:
                            service.close()
                    self.assertEqual(counts, [3, 2, 1, 0])
                    self.assertTrue(report.coverage.enumeration_complete)
                finally:
                    store.close()

    def test_new_work_revokes_previously_checked_directory_signature(self):
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        from leakguard_core.sources import directory_signature
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-directory-invalidation-') as folder:
                root = Path(folder)
                store = store_type(root / 'state') if store_type is SQLiteScanStore else store_type()
                try:
                    lease = store.acquire_cycle('synthetic', None, lease_seconds=60)
                    store.enqueue_work(lease, ((str(root), 'directory', 0),))
                    claim = store.claim_work(lease)
                    store.finish_directory(claim, success=True, signature=directory_signature(root))
                    page = store.directory_page(lease, limit=1)
                    store.record_directory_checks(lease, ((page[0].path, page[0].signature, True),))
                    self.assertEqual(store.directory_page(lease), ())
                    store.release_cycle(lease, allow_complete=False)
                    lease = store.acquire_cycle('synthetic', None, lease_seconds=60)
                    store.enqueue_work(lease, ((str(root / 'new.txt'), 'file', 0),))
                    self.assertEqual(store.directory_page(lease, limit=1)[0].path, str(root))
                    self.assertFalse(store.cycle_status(lease)['complete'])
                    page = store.directory_page(lease, limit=1)
                    store.record_directory_checks(lease, ((page[0].path, page[0].signature, True),))
                    claim = store.claim_work(lease)
                    from dataclasses import replace
                    from leakguard_core import models as m
                    source = m.SourceRef(m.SourceKind.FILESYSTEM, claim.path)
                    result = StoreLifecycleTests.make_result(self)
                    result = replace(result, source=source, findings=(replace(result.findings[0], source=source),))
                    store.record_result(result, generation=store.reserve(source), work=claim)
                    self.assertEqual(store.directory_page(lease, limit=1)[0].path, str(root))
                    # A superseded lease cannot certify the final traversal.
                    old = lease
                    if store_type is MemoryScanStore:
                        store.cycles['synthetic']['lease_until'] = 0
                    else:
                        store.conn.execute('UPDATE audit_cycles SET lease_until=0'); store.conn.commit()
                    lease = store.acquire_cycle('synthetic', None, lease_seconds=60)
                    from leakguard_core.scan_store import StateError
                    with self.assertRaises(StateError):
                        store.record_directory_checks(old, ((page[0].path, page[0].signature, True),))
                    self.assertEqual(store.directory_page(lease, limit=1)[0].path, str(root))
                finally:
                    store.close()

    def test_unavailable_directory_signature_is_explicit_incomplete_coverage(self):
        from leakguard_core import models as m, backends, scan_policy, sources
        with tempfile.TemporaryDirectory(prefix='leakguard-directory-unavailable-') as folder:
            root = Path(folder)
            (root / 'candidate.txt').write_text('synthetic')
            expected = sources.directory_signature(root)
            service = engine.ScanService({'gitleaks_executable': str(engine.EXE)})
            try:
                with patch.object(sources, 'directory_signature', side_effect=(expected, expected, sources.AcquisitionError('source-unavailable'))), patch.object(scan_policy, 'runtime_identity', return_value=(service._runtime, True)), patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                    report = service.scan_paths((root,), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 10))
                self.assertEqual(report.counts.findings, 1)
                self.assertFalse(report.coverage.enumeration_complete)
                self.assertTrue(any(issue.code is m.ErrorCode.SOURCE_UNAVAILABLE for issue in report.issues))
            finally:
                service.close()


class FinalStateAcceptanceTests(unittest.TestCase):
    def test_two_sqlite_connections_publish_only_newest_reserved_generation(self):
        from concurrent.futures import ThreadPoolExecutor
        from dataclasses import replace
        import threading
        from leakguard_core.scan_store import SQLiteScanStore
        with tempfile.TemporaryDirectory(prefix='leakguard-final-concurrency-') as folder:
            initial = SQLiteScanStore(folder); initial.close()
            base = StoreLifecycleTests.make_result(self)
            gate = threading.Barrier(2)
            def publish(number):
                store = SQLiteScanStore(folder)
                try:
                    finding = replace(base.findings[0], id=str(number) * 64)
                    result = replace(base, findings=(finding,))
                    generation = store.reserve(result.source)
                    gate.wait(timeout=5)
                    store.record_result(result, generation=generation)
                    return generation, finding.id
                finally:
                    store.close()
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(publish, number) for number in (1, 2)]
                expected = max(future.result(timeout=10) for future in futures)[1]
            store = SQLiteScanStore(folder)
            try:
                self.assertEqual([row['id'] for row in store.query_findings()], [expected])
                self.assertEqual(store.query_findings()[0]['state'], 'active')
                self.assertEqual(len(store.query_findings(state='history')), 2)
            finally:
                store.close()

    def test_actual_timeout_and_offline_root_do_not_resolve_prior_evidence(self):
        from leakguard_core import models as m, backends
        from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
        for store_type in (MemoryScanStore, SQLiteScanStore):
            with self.subTest(store=store_type.__name__), tempfile.TemporaryDirectory(prefix='leakguard-final-lifecycle-') as folder:
                root = Path(folder)
                corpus = root / 'corpus'; corpus.mkdir()
                candidate = corpus / 'candidate.txt'; candidate.write_text('synthetic')
                store = store_type(root / 'state') if store_type is SQLiteScanStore else store_type()
                service = engine.ScanService({'gitleaks_executable': str(engine.EXE), 'audit_scopes': {'synthetic': str(corpus)}}, store=store)
                try:
                    with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
                        service.scan((m.FileInput(candidate),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1), use_cache=False)
                    with patch.object(backends, 'detect', side_effect=backends.BackendError('detector-timeout')):
                        timeout = service.scan((m.FileInput(candidate),), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(30, 1), use_cache=False)
                    self.assertEqual(timeout.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                    self.assertEqual(store.query_findings()[0]['state'], 'unknown')
                    corpus.rename(root / 'offline-corpus')
                    offline = service.audit('synthetic', limits=m.ScanLimits(30, 1))
                    self.assertEqual(offline.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                    self.assertEqual(store.query_findings()[0]['state'], 'unknown')
                    self.assertTrue(any(issue.code is m.ErrorCode.SOURCE_UNAVAILABLE for issue in offline.issues))
                finally:
                    service.close(); store.close()
