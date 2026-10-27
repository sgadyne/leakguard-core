"""Compact synthetic checks for ordered execution and the store owner boundary."""
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, models as m
from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.runtime = patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic-runtime', True))
        self.runtime.start()
        self.addCleanup(self.runtime.stop)

    @staticmethod
    def signature(report):
        return [(r.source, r.content, r.coverage, r.findings, r.issues) for r in report.results], report.coverage, report.decision.verdict

    def test_two_workers_overlap_but_publish_in_order_on_store_owner(self):
        owner = threading.get_ident()
        calls = []
        class OwnerStore(MemoryScanStore):
            def reserve(self, *args, **kwargs):
                calls.append(threading.get_ident()); return super().reserve(*args, **kwargs)
            def get_cached(self, *args, **kwargs):
                calls.append(threading.get_ident()); return super().get_cached(*args, **kwargs)
            def record_result(self, *args, **kwargs):
                calls.append(threading.get_ident()); return super().record_result(*args, **kwargs)
            def record_report(self, *args, **kwargs):
                calls.append(threading.get_ident()); return super().record_report(*args, **kwargs)
        inputs = tuple(m.BytesInput(str(i).encode(), f'{i}.txt') for i in range(4))
        barrier = threading.Barrier(2)
        active = 0
        peak = 0
        lock = threading.Lock()
        def detect(text, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1; peak = max(peak, active)
            if int(text) < 2:
                barrier.wait(timeout=2)
            if text == '0':
                time.sleep(0.01)
            with lock:
                active -= 1
            return (backends.BackendFinding('literal-password', 1, 1),)
        store = OwnerStore()
        with patch.object(backends, 'detect', side_effect=detect):
            service = engine.ScanService({'scan_workers': 2}, store=store)
            report = service.scan(inputs, policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 4))
            service.close()
        self.assertEqual(peak, 2, report.to_json())
        self.assertEqual([r.source.path for r in report.results], [f'{i}.txt' for i in range(4)])
        self.assertTrue(report.coverage.required_complete, report.to_json())
        self.assertTrue(calls)
        self.assertEqual(set(calls), {owner})
        with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)):
            reference = engine.ScanService({'scan_workers': 1})
            expected = reference.scan(inputs, policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 4))
            reference.close()
        self.assertEqual(self.signature(report), self.signature(expected))

    def test_sqlite_cache_replays_positives_and_reads_changed_content(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-execution-') as folder:
            root = Path(folder)
            files = [root / f'{i}.txt' for i in range(2)]
            for file in files:
                file.write_text('synthetic')
            store = SQLiteScanStore(root / 'state')
            service = engine.ScanService({'scan_workers': 2}, store=store)
            with patch.object(backends, 'detect', return_value=(backends.BackendFinding('literal-password', 1, 1),)) as detector:
                options = dict(policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 2))
                cold = service.scan_paths(files, **options)
                warm = service.scan_paths(files, **options)
                self.assertTrue(all(r.outcome is m.ScanOutcome.REUSED for r in warm.results))
                self.assertEqual(self.signature(cold), self.signature(warm))
                self.assertEqual(detector.call_count, 2)
                files[0].write_text('different')
                changed = service.scan_paths(files, **options)
                self.assertEqual(detector.call_count, 3)
                self.assertEqual([r.outcome for r in changed.results], [m.ScanOutcome.REUSED, m.ScanOutcome.SCANNED])
            service.close(); store.close()

    def test_cancel_joins_two_workers_and_stops_input_admission(self):
        stopped = threading.Event()
        entered = threading.Barrier(3)
        consumed = []
        active = []
        def inputs():
            for index in range(100):
                consumed.append(index)
                yield m.BytesInput(b'synthetic', f'{index}.txt')
        def detect(text, *, cancel, **kwargs):
            active.append(1)
            try:
                entered.wait(timeout=2)
                while not cancel():
                    time.sleep(0.001)
                raise backends.BackendError('cancelled')
            finally:
                active.pop()
        def cancel_later():
            entered.wait(timeout=2)
            stopped.set()
        controller = threading.Thread(target=cancel_later)
        service = engine.ScanService({'scan_workers': 2})
        controller.start()
        started = time.monotonic()
        with patch.object(backends, 'detect', side_effect=detect):
            report = service.scan(inputs(), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 100), cancel=stopped.is_set)
        controller.join(timeout=2)
        service.close()
        self.assertLess(time.monotonic() - started, 2)
        self.assertLessEqual(len(consumed), 2)
        self.assertEqual(active, [])
        self.assertFalse(report.coverage.required_complete)
        self.assertTrue(any(i.code is m.ErrorCode.CANCELLED for i in report.issues))

    def test_backend_rule_setup_is_once_per_job(self):
        from leakguard_core import _rules
        service = engine.ScanService({'scan_workers': 2})
        with patch.object(_rules, 'inspect', wraps=_rules.inspect) as inspect, patch.object(backends, 'detect', return_value=()):
            report = service.scan(tuple(m.BytesInput(b'synthetic', f'{i}.txt') for i in range(5)), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 5))
        service.close()
        self.assertEqual(inspect.call_count, 1)
        self.assertEqual(len(report.results), 5)

    def test_path_and_audit_enumerators_share_worker_callback_serialization(self):
        for mode in ('paths', 'audit'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='leakguard-execution-') as folder:
                root = Path(folder)
                for number in range(5):
                    (root / f'{number}.txt').write_text('synthetic')
                lock = threading.Lock()
                active = 0
                maximum = 0
                def callback():
                    nonlocal active, maximum
                    with lock:
                        active += 1
                        maximum = max(maximum, active)
                    time.sleep(0.002)
                    with lock:
                        active -= 1
                    return False
                def detect(text, *, cancel, **kwargs):
                    for _ in range(4):
                        cancel()
                    return ()
                store = MemoryScanStore()
                service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=store)
                with patch.object(backends, 'detect', side_effect=detect):
                    report = (service.audit('synthetic', limits=m.ScanLimits(5, 10), cancel=callback)
                              if mode == 'audit' else service.scan_paths((root,), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 10), cancel=callback))
                self.assertTrue(report.coverage.required_complete)
                self.assertEqual(maximum, 1)
                service.close(); store.close()

    def test_path_and_audit_cancellation_callbacks_stay_latched(self):
        for mode in ('paths', 'audit'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='leakguard-execution-') as folder:
                root = Path(folder); (root / 'source.txt').write_text('synthetic')
                calls = 0
                def callback():
                    nonlocal calls
                    calls += 1
                    return calls == 1
                store = MemoryScanStore()
                service = engine.ScanService({'audit_scopes': {'synthetic': str(root)}}, store=store)
                report = (service.audit('synthetic', limits=m.ScanLimits(5, 10), cancel=callback)
                          if mode == 'audit' else service.scan_paths((root,), policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 10), cancel=callback))
                self.assertFalse(report.coverage.required_complete)
                self.assertEqual(calls, 1)
                self.assertTrue(any(issue.code is m.ErrorCode.CANCELLED for issue in report.issues))
                service.close(); store.close()

    def test_waiting_callback_is_not_invoked_after_concurrent_cancellation(self):
        from leakguard_core.execution import Cancellation
        entered = threading.Event()
        callback_calls = []
        cancellation = Cancellation(lambda: callback_calls.append(1) or True)
        class Gate:
            def __enter__(self):
                entered.set()
                gate.acquire()
            def __exit__(self, *args):
                gate.release()
        gate = threading.Lock()
        cancellation._lock = Gate()
        gate.acquire()
        answers = []
        waiter = threading.Thread(target=lambda: answers.append(cancellation()))
        waiter.start()
        self.assertTrue(entered.wait(timeout=2))
        cancellation.stop()
        gate.release()
        waiter.join(timeout=2)
        self.assertFalse(waiter.is_alive())
        self.assertEqual(answers, [True])
        self.assertEqual(callback_calls, [])
