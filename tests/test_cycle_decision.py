"""Completed audit decisions include accepted earlier slices; counts stay local."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import api, backends, cli, engine, models as m, presentation
from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore


class CycleDecisionTests(unittest.TestCase):
    def setUp(self):
        self.runtime_value = 'runtime'
        runtime = patch('leakguard_core.scan_policy.runtime_identity', side_effect=lambda *a, **k: (self.runtime_value, True))
        runtime.start(); self.addCleanup(runtime.stop)

    def make(self, base, kind='memory'):
        root = base / 'source'; root.mkdir()
        (root / 'a.txt').write_text('positive synthetic')
        (root / 'b.txt').write_text('clean synthetic')
        config = {'audit_scopes': {'synthetic': str(root)}}
        store = MemoryScanStore() if kind == 'memory' else SQLiteScanStore(base / 'state')
        return root, config, store

    @staticmethod
    def detect(text, **kwargs):
        return (backends.BackendFinding('literal-password', 1, 1),) if text.startswith('positive') else ()

    def test_earlier_positive_blocks_completed_clean_slice_in_both_stores(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-cycle-') as folder:
                root, config, store = self.make(Path(folder), kind)
                with patch.object(backends, 'detect', side_effect=self.detect):
                    first_service = engine.ScanService(config, store=store)
                    first = first_service.audit('synthetic', limits=m.ScanLimits(5, 1))
                    first_service.close()
                    if kind == 'sqlite':
                        store.close(); store = SQLiteScanStore(Path(folder) / 'state')
                    service = engine.ScanService(config, store=store)
                    published = []
                    publish = store.record_report
                    def record(report, **kwargs):
                        published.append(report)
                        return publish(report, **kwargs)
                    with patch.object(store, 'record_report', side_effect=record):
                        final = service.audit('synthetic', limits=m.ScanLimits(5, 1))
                self.assertTrue(all(not report.coverage.required_complete or report.decision.verdict is m.DecisionVerdict.BLOCK for report in published))
                self.assertFalse(first.coverage.required_complete)
                self.assertTrue(final.coverage.required_complete)
                self.assertEqual(final.counts.findings, 0)
                self.assertEqual(final.decision.verdict, m.DecisionVerdict.BLOCK)
                self.assertTrue(any(i.code is m.ErrorCode.AUDIT_CYCLE_EVIDENCE and not i.required for i in final.issues))
                self.assertEqual(store.latest_report(), final)
                rendered = presentation.render_scan_report(final)
                self.assertIn('this slice', rendered)
                self.assertIn('completed audit cycle', rendered)
                self.assertEqual(api.parse_report(final.to_json()), final)
                service.close(); store.close()

    def test_earlier_omission_survives_final_clean_slice(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-cycle-') as folder:
                root, config, store = self.make(Path(folder), kind)
                (root / 'a.txt').write_bytes(b'\x00binary')
                service = engine.ScanService(config, store=store)
                with patch.object(backends, 'detect', return_value=()):
                    service.audit('synthetic', limits=m.ScanLimits(5, 1))
                    final = service.audit('synthetic', limits=m.ScanLimits(5, 1))
                self.assertTrue(final.coverage.required_complete)
                self.assertEqual(final.coverage.omission_count, 0)
                self.assertEqual(final.decision.verdict, m.DecisionVerdict.ALLOW_WITH_OMISSIONS)
                service.close(); store.close()

    def test_policy_reset_does_not_count_stale_unknown_positive(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-cycle-') as folder:
                root, config, store = self.make(Path(folder), kind)
                self.runtime_value = 'old-runtime'
                service = engine.ScanService(config, store=store)
                with patch.object(backends, 'detect', side_effect=self.detect):
                    first = service.audit('synthetic', limits=m.ScanLimits(5, 1))
                previous = first.results[0].findings[0].id
                service.close(); self.runtime_value = 'new-runtime'
                service = engine.ScanService(config, store=store)
                with patch.object(backends, 'detect', return_value=()):
                    for _ in range(3):
                        final = service.audit('synthetic', limits=m.ScanLimits(5, 1))
                        if final.coverage.required_complete:
                            break
                self.assertTrue(final.coverage.required_complete)
                self.assertEqual(final.decision.verdict, m.DecisionVerdict.ALLOW)
                stale = next(row for row in store.query_findings() if row['id'] == previous)
                self.assertEqual(stale['state'], 'unknown')
                self.assertIsNone(stale['resolved_at'])
                service.close(); store.close()

    def test_prior_required_failure_cannot_complete_after_later_clean_file(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-cycle-') as folder:
            root, config, store = self.make(Path(folder))
            service = engine.ScanService(config, store=store)
            def detect(text, **kwargs):
                if text.startswith('positive'):
                    raise backends.BackendError('detector-failed')
                return ()
            with patch.object(backends, 'detect', side_effect=detect):
                reports = [service.audit('synthetic', limits=m.ScanLimits(5, 1)) for _ in range(4)]
            self.assertTrue(any(r.results and r.results[0].source.path.endswith('b.txt') for r in reports))
            self.assertTrue(all(not r.coverage.required_complete and r.decision.verdict is m.DecisionVerdict.INCOMPLETE for r in reports))
            service.close()

    def test_missing_accepted_result_link_fails_closed(self):
        for kind in ('memory', 'sqlite'):
            with self.subTest(store=kind), tempfile.TemporaryDirectory(prefix='leakguard-cycle-') as folder:
                root, config, store = self.make(Path(folder), kind)
                service = engine.ScanService(config, store=store)
                with patch.object(backends, 'detect', side_effect=self.detect):
                    service.audit('synthetic', limits=m.ScanLimits(5, 1))
                    if kind == 'memory':
                        for key, row in store.work.items():
                            if key[2].endswith('a.txt'):
                                row['result_scan_id'] = None
                    else:
                        with store.conn:
                            store.conn.execute("UPDATE audit_work SET result_scan_id=NULL WHERE path=?", (str(root / 'a.txt'),))
                        service.close(); store.close()
                        store = SQLiteScanStore(Path(folder) / 'state')
                        self.assertIsNotNone(store.conn.execute('SELECT work_identity FROM audit_cycles').fetchone()[0])
                        service = engine.ScanService(config, store=store)
                    final = service.audit('synthetic', limits=m.ScanLimits(5, 1))
                self.assertFalse(final.coverage.required_complete)
                self.assertEqual(final.decision.verdict, m.DecisionVerdict.INCOMPLETE)
                self.assertTrue(any(i.required and i.code is m.ErrorCode.STATE_FAILED for i in final.issues))
                self.assertTrue(store.query_findings())
                service.close(); store.close()

    def test_old_schema_reopen_replays_done_work_without_losing_evidence(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-cycle-') as folder:
            root, config, store = self.make(Path(folder), 'sqlite')
            service = engine.ScanService(config, store=store)
            with patch.object(backends, 'detect', side_effect=self.detect):
                first = service.audit('synthetic', limits=m.ScanLimits(5, 1))
            previous = first.results[0].findings[0].id
            service.close()
            with store.conn:
                store.conn.execute('ALTER TABLE audit_work DROP COLUMN result_scan_id')
            old_scan_count = store.conn.execute('SELECT count(*) FROM input_scans').fetchone()[0]
            store.close(); store = SQLiteScanStore(Path(folder) / 'state')
            self.assertIsNone(store.conn.execute('SELECT work_identity FROM audit_cycles').fetchone()[0])
            self.assertEqual(store.conn.execute('SELECT count(*) FROM input_scans').fetchone()[0], old_scan_count)
            seen = []
            service = engine.ScanService(config, store=store)
            with patch.object(backends, 'detect', side_effect=self.detect):
                for _ in range(3):
                    final = service.audit('synthetic', limits=m.ScanLimits(5, 1))
                    seen.extend(result.source.path for result in final.results)
                    if final.coverage.required_complete:
                        break
            self.assertTrue(final.coverage.required_complete)
            self.assertEqual(final.decision.verdict, m.DecisionVerdict.BLOCK)
            self.assertEqual(set(seen), {str(root / 'a.txt'), str(root / 'b.txt')})
            self.assertTrue(any(row['id'] == previous and row['state'] != 'resolved' for row in store.query_findings()))
            service.close(); store.close()

    def test_cli_fail_on_block_honors_cycle_verdict_with_zero_slice_findings(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-cycle-') as folder:
            root, config, store = self.make(Path(folder))
            path = Path(folder) / 'config.json'; path.write_text(json.dumps(config))
            def open_scanner(**kwargs):
                return api.Scanner(engine.ScanService(kwargs['config'].to_mapping(), store=store))
            arguments = ['audit', 'synthetic', '--config', str(path), '--format', 'json', '--max-files', '1', '--budget-seconds', '5', '--fail-on', 'block']
            with patch.object(api.Scanner, 'open', side_effect=open_scanner), patch.object(backends, 'detect', side_effect=self.detect), redirect_stderr(io.StringIO()):
                with redirect_stdout(io.StringIO()):
                    first = cli.main(arguments)
                output = io.StringIO()
                with redirect_stdout(output):
                    final = cli.main(arguments)
            report = json.loads(output.getvalue())
            self.assertEqual((first, final), (2, 1))
            self.assertEqual(report['counts']['block_findings'], 0)
            self.assertEqual(report['decision']['verdict'], 'block')
