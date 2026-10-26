"""Private L1 correctness: no secret payloads, stale publication or shared cancellation."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, models as m, sources
from leakguard_core._result_cache import CacheScope, ObservationCache, OBSERVATIONS
from leakguard_core._supervision import WorkerResult


ROWS = (('literal-password', 1, 1, 'block'),)
KEY = hashlib.sha256(b'synthetic identity').hexdigest()


class CacheTests(unittest.TestCase):
    def test_hit_scope_identity_and_both_budgets(self):
        cache = ObservationCache(max_bytes=2048, max_entries=2)
        first, other = CacheScope(), CacheScope()
        calls = []
        def get(scope, key=KEY):
            return cache.get_or_compute(scope, key, domain=None, check=lambda: None,
                                        compute=lambda: calls.append(1) or ROWS)
        self.assertEqual(get(first), ROWS)
        self.assertEqual(get(first), ROWS)
        self.assertEqual(len(calls), 1)
        get(other)
        get(first, hashlib.sha256(b'changed bytes').hexdigest())
        metrics = cache.metrics()
        self.assertEqual(metrics['hits'], 1)
        self.assertEqual(metrics['entries'], 2)
        self.assertLessEqual(metrics['bytes'], 2048)
        self.assertGreater(metrics['evictions'], 0)
        cache.close_scope(first)
        self.assertEqual(cache.metrics()['entries'], 1)
        self.assertEqual(get(first), ROWS)  # Closed scope can never retain writes.
        self.assertEqual(cache.metrics()['entries'], 1)

    def test_oversize_invalid_and_failed_values_are_not_retained(self):
        cache, scope = ObservationCache(max_bytes=256), CacheScope()
        cache.get_or_compute(scope, KEY, domain=None, check=lambda: None, compute=lambda: ROWS)
        self.assertEqual(cache.metrics()['entries'], 0)
        for value in ([ROWS], (('not a rule or secret payload', 1, 1, 'block'),)):
            cache.get_or_compute(scope, KEY, domain=None, check=lambda: None, compute=lambda: value)
            self.assertEqual(cache.metrics()['entries'], 0)
        def fail():
            raise RuntimeError('synthetic-failure')
        with self.assertRaises(RuntimeError):
            cache.get_or_compute(scope, KEY, domain=object(), check=lambda: None, compute=fail)
        self.assertEqual(cache.metrics()['flights'], 0)

    def test_singleflight_waiter_cancel_isolated_and_late_close_fenced(self):
        cache, scope, domain = ObservationCache(), CacheScope(), object()
        started, release, cancelled = threading.Event(), threading.Event(), threading.Event()
        calls = []
        def produce():
            calls.append(1); started.set(); release.wait(2); return ROWS
        def wait_check():
            if cancelled.is_set():
                raise RuntimeError('cancelled')
        with ThreadPoolExecutor(max_workers=3) as pool:
            leader = pool.submit(cache.get_or_compute, scope, KEY, domain=domain,
                                 check=lambda: None, compute=produce)
            self.assertTrue(started.wait(1))
            waiter = pool.submit(cache.get_or_compute, scope, KEY, domain=domain,
                                 check=wait_check, compute=produce)
            until = time.monotonic() + 1
            while cache.metrics()['waits'] == 0 and time.monotonic() < until:
                time.sleep(.005)
            cancelled.set()
            with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                waiter.result(1)
            # An unrelated invocation does not wait on another caller's worker.
            separate = pool.submit(cache.get_or_compute, scope, KEY, domain=object(),
                                   check=lambda: None, compute=lambda: ())
            self.assertEqual(separate.result(1), ())
            cache.close_scope(scope)
            release.set()
            self.assertEqual(leader.result(1), ROWS)
        self.assertEqual(len(calls), 1)
        self.assertEqual(cache.metrics()['entries'], 0)
        self.assertEqual(cache.metrics()['flights'], 0)

    def test_reset_fences_active_producer_and_next_call_recomputes(self):
        cache, scope = ObservationCache(), CacheScope()
        def produce():
            cache.reset()
            return ROWS
        self.assertEqual(cache.get_or_compute(scope, KEY, domain=object(), check=lambda: None,
                                             compute=produce), ROWS)
        self.assertEqual(cache.metrics()['entries'], 0)


class NativeCacheIntegrationTests(unittest.TestCase):
    def setUp(self):
        OBSERVATIONS.reset()
        self.addCleanup(OBSERVATIONS.reset)

    def test_actual_content_rules_limits_runtime_and_permissions_invalidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'backend'
            binary.write_text('synthetic executable'); binary.chmod(0o700)
            rules = root / 'rules.toml'; rules.write_text('title="synthetic"')
            scope = CacheScope()
            raw = json.dumps([dict(RuleID='literal-password', StartLine=1, EndLine=1)]).encode()
            def detect(text='same synthetic bytes', runtime='r1', maximum=100):
                return backends.detect(text, binary=binary, rules=rules, cache_scope=scope,
                                       cache_identity=runtime, max_findings=maximum)
            with patch.object(backends, 'run_worker', return_value=WorkerResult(raw, 1)) as worker:
                self.assertEqual(detect(), (backends.BackendFinding('literal-password', 1, 1),))
                self.assertEqual(detect(), detect())
                self.assertEqual(worker.call_count, 1)
                detect('changed synthetic bytes')
                detect(runtime='r2')
                detect(maximum=101)
                rules.write_text('title="changed synthetic"')
                detect()
                binary.write_text('changed executable')
                detect()
                self.assertEqual(worker.call_count, 6)
                binary.chmod(0o600)
                detect()
                self.assertEqual(worker.call_count, 7)
            OBSERVATIONS.close_scope(scope)

    def test_external_rules_and_backend_failures_never_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'backend'; binary.write_text('synthetic'); binary.chmod(0o700)
            parent = root / 'parent.toml'; parent.write_text('title="parent"')
            rules = root / 'rules.toml'; rules.write_text('[extend]\npath=' + json.dumps(str(parent)))
            scope = CacheScope()
            with patch.object(backends, 'run_worker', return_value=WorkerResult(b'[]', 0)) as worker:
                for _ in range(2):
                    backends.detect('synthetic', binary=binary, rules=rules, cache_scope=scope,
                                    cache_identity='runtime')
                self.assertEqual(worker.call_count, 2)
            self.assertEqual(OBSERVATIONS.metrics()['entries'], 0)

            rules.write_text('title="closed rules"')
            with patch.object(backends, 'run_worker', return_value=WorkerResult(b'[]', 2)) as worker:
                for _ in range(2):
                    with self.assertRaises(backends.BackendError):
                        backends.detect('synthetic', binary=binary, rules=rules, cache_scope=scope,
                                        cache_identity='runtime')
                self.assertEqual(worker.call_count, 2)
            self.assertEqual(OBSERVATIONS.metrics()['entries'], 0)

    def test_prepared_native_cache_executes_its_immutable_binary_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'backend'; binary.write_bytes(b'original synthetic executable'); binary.chmod(0o700)
            rules = root / 'rules.toml'; rules.write_text('title="closed rules"')
            with backends.prepare(binary=binary, rules=rules, cache_native=True) as prepared:
                self.assertNotEqual(Path(prepared.executable), binary)
                self.assertEqual(Path(prepared.executable).read_bytes(), b'original synthetic executable')
                identity = prepared.cache_identity
                binary.write_bytes(b'replacement synthetic executable')
                self.assertEqual(Path(prepared.executable).read_bytes(), b'original synthetic executable')
                with patch.object(backends, 'run_worker', return_value=WorkerResult(b'[]', 0)) as worker:
                    backends.detect('synthetic', prepared=prepared, cache_scope=CacheScope(), cache_identity='runtime')
                    self.assertEqual(worker.call_args.args[0][0], prepared.executable)
                self.assertEqual(prepared.cache_identity, identity)

    def test_duplicate_native_parts_do_not_reuse_plugin_or_source_findings(self):
        from leakguard_core import plugins
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'backend'
            binary.write_text('synthetic'); binary.chmod(0o700)
            raw = b'[{"RuleID":"literal-password","StartLine":1,"EndLine":1}]'
            with patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', True)), patch.object(plugins, 'load', return_value=[object()]), patch.object(plugins, 'detect', return_value=()) as plugin, patch.object(backends, 'run_worker', return_value=WorkerResult(raw, 1)) as worker:
                service = engine.ScanService({'gitleaks_executable': str(binary), 'scan_workers': 2})
                try:
                    inputs = (m.BytesInput(b'synthetic example', 'first.txt'),
                              m.BytesInput(b'synthetic example', 'second.txt'))
                    options = dict(policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 2))
                    report = service.scan(inputs, **options)
                    self.assertTrue(report.coverage.required_complete)
                    self.assertEqual(worker.call_count, 1)
                    self.assertEqual(plugin.call_count, 2)
                    self.assertEqual([r.source.path for r in report.results], ['first.txt', 'second.txt'])
                    self.assertEqual([f.source.path for r in report.results for f in r.findings], ['first.txt', 'second.txt'])
                    self.assertTrue(all(not r.identity.cache_eligible for r in report.results))
                    service.scan(inputs, use_cache=False, **options)
                    self.assertEqual(worker.call_count, 3)
                    self.assertEqual(plugin.call_count, 4)
                    service.clear_cache()
                    self.assertEqual(OBSERVATIONS.metrics()['entries'], 0)
                finally:
                    service.close()

    def test_snapshot_digest_once_and_final_source_validation_retained(self):
        snapshot = sources.acquire_bytes(b'synthetic bytes', 'fixture.txt', max_bytes=100)
        with patch.object(sources, 'content_identity', wraps=sources.content_identity) as digest:
            created = sources.SnapshotInput(snapshot.source, snapshot.data, snapshot.context)
            first = created.content
            for _ in range(20):
                self.assertIs(created.content, first)
            self.assertEqual(digest.call_count, 1)
        with self.assertRaises(TypeError):
            sources.SnapshotInput(snapshot.source, bytearray(b'unsafe mutable'), snapshot.context)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'fixture.txt'; path.write_bytes(b'original synthetic')
            before = path.stat()
            def detect(*args, **kwargs):
                path.write_bytes(b'modified synthetic')
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                return (backends.BackendFinding('literal-password', 1, 1),)
            with patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', True)), patch.object(backends, 'detect', side_effect=detect):
                service = engine.ScanService({'scan_workers': 1})
                self.addCleanup(service.close)
                report = service.scan_paths([path], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 1))
            result = report.results[0]
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(result.coverage, m.CoverageState.INCOMPLETE)
            self.assertIn(m.ErrorCode.INPUT_CHANGED, tuple(i.code for i in result.issues))
            self.assertFalse(report.coverage.required_complete)


if __name__ == '__main__':
    unittest.main()
