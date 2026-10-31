"""Prepared detector lifetime never owns a partition's mutable publisher."""
from contextlib import nullcontext
from threading import Event, Thread
from unittest.mock import patch

import pytest
from leakguard_core import api, backends, engine, models as m, scan_policy
from leakguard_core.scan_store import MemoryScanStore, StateError


@pytest.fixture
def prepared():
    with patch.object(scan_policy, 'runtime_identity', return_value=('synthetic-runtime', True)), \
         patch.object(engine.plugins, 'load', return_value=[]) as load, \
         patch.object(engine.plugins, 'close') as close, \
         patch.object(backends, 'prepare', return_value=nullcontext(None)), \
         patch.object(backends, 'detect', return_value=()):
        yield load, close


def options():
    return {'policy': m.ScanPolicy.inventory(), 'limits': m.ScanLimits(10, 1)}


def test_two_store_bindings_prepare_once_and_keep_publication_independent(prepared):
    load, close = prepared
    config = api.ScanConfig.from_mapping({})
    first, second = MemoryScanStore(), MemoryScanStore()
    with api.RuntimeSession.open(config=config) as session:
        for store, label in ((first, 'first.txt'), (second, 'second.txt')):
            with api.Scanner.open(config=config, store=store, runtime_session=session) as scanner:
                report = scanner.scan([m.BytesInput(b'ordinary synthetic text', label)], **options())
                assert report.coverage.required_complete
        assert load.call_count == 1
        assert close.call_count == 0
        assert {r.source.path for r in first.results.values()} == {'first.txt'}
        assert {r.source.path for r in second.results.values()} == {'second.txt'}
    session.close()
    assert close.call_count == 1
    # Child closing never closes its caller-owned store.
    assert first.reserve(m.SourceRef(m.SourceKind.BYTES, 'still-open.txt'))


def test_binding_exclusion_config_separation_and_failed_bind_does_not_poison_session(prepared):
    config = api.ScanConfig.from_mapping({})
    other = api.ScanConfig.from_mapping({'scan_workers': 1})
    with api.RuntimeSession.open(config=config) as session:
        with api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=session):
            with pytest.raises(StateError, match='runtime-session-busy'):
                api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=session)
        with pytest.raises(StateError, match='runtime-session-config-changed'):
            api.Scanner.open(config=other, store=MemoryScanStore(), runtime_session=session)
        with api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=session):
            pass


def test_navigation_constructor_failure_releases_binding_and_does_not_close_shared_workers(prepared):
    load, close = prepared
    config = api.ScanConfig.from_mapping({})
    with api.RuntimeSession.open(config=config) as session:
        with patch('leakguard_core.navigation.Navigation', side_effect=RuntimeError('synthetic-failure')):
            with pytest.raises(RuntimeError, match='synthetic-failure'):
                api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=session)
        assert close.call_count == 0
        with api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=session):
            pass
    assert load.call_count == close.call_count == 1


def test_partial_plugin_preparation_failure_closes_and_next_owner_is_fresh(prepared):
    load, close = prepared
    config = api.ScanConfig.from_mapping({})
    with patch.object(scan_policy, 'runtime_identity', side_effect=RuntimeError('synthetic-failure')):
        with pytest.raises(RuntimeError, match='synthetic-failure'):
            api.RuntimeSession.open(config=config)
    assert close.call_count == 1
    with api.RuntimeSession.open(config=config):
        pass
    assert load.call_count == close.call_count == 2


def test_distinct_owner_scopes_and_close_fence_held_binding_without_deadlock(prepared):
    config = api.ScanConfig.from_mapping({})
    a, b = api.RuntimeSession.open(config=config), api.RuntimeSession.open(config=config)
    with api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=a) as first:
        with api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=b) as second:
            assert first._service._observation_scope is not second._service._observation_scope
        a.close()
        assert first._service._observation_scope.closed
        report = first.scan([m.BytesInput(b'ordinary synthetic text', 'cancelled.txt')], **options())
        assert not report.coverage.required_complete
    with pytest.raises(StateError, match='state-closed'):
        api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=a)
    b.close()


def test_shared_identity_revalidates_exact_runtime_and_scan_keeps_pre_post_checks(prepared):
    config = api.ScanConfig.from_mapping({})
    with api.RuntimeSession.open(config=config) as session:
        with api.Scanner.open(config=config, store=MemoryScanStore(), runtime_session=session) as scanner:
            with patch.object(scan_policy, 'runtime_identity', return_value=('changed-same-size-runtime', True)):
                with pytest.raises(scan_policy.RuntimeIdentityError):
                    scanner.work_identity(**options())
                report = scanner.scan([m.BytesInput(b'ordinary synthetic text', 'changed.txt')], **options())
                assert not report.coverage.required_complete
            with patch.object(scan_policy, 'runtime_identity', return_value=('synthetic-runtime', True)) as identity:
                report = scanner.scan([m.BytesInput(b'ordinary synthetic text', 'current.txt')], **options())
                assert report.coverage.required_complete
                assert identity.call_count == 2


def test_session_close_during_detection_cannot_publish_clean_or_reusable_result(prepared):
    config = api.ScanConfig.from_mapping({})
    store = MemoryScanStore()
    started, release = Event(), Event()
    results = []
    with api.RuntimeSession.open(config=config) as session:
        scanner = api.Scanner.open(config=config, store=store, runtime_session=session)
        def detect(*args, **kwargs):
            started.set()
            assert release.wait(2)
            return ()
        def run():
            try:
                results.append(scanner.scan([m.BytesInput(b'ordinary synthetic text', 'active.txt')], **options()))
            finally:
                scanner.close()
        with patch.object(backends, 'detect', side_effect=detect):
            thread = Thread(target=run)
            thread.start()
            assert started.wait(1)
            session.close()
            release.set()
            thread.join(3)
            assert not thread.is_alive()
        assert not results[0].coverage.required_complete
        assert all(r.coverage is m.CoverageState.INCOMPLETE for r in results[0].results)
        assert not store.cache


def test_failed_partition_publication_does_not_poison_next_partition(prepared):
    class Failing(MemoryScanStore):
        def record_result(self, *args, **kwargs):
            raise StateError()
    config = api.ScanConfig.from_mapping({})
    with api.RuntimeSession.open(config=config) as session:
        for store, complete in ((Failing(), False), (MemoryScanStore(), True)):
            with api.Scanner.open(config=config, store=store, runtime_session=session) as scanner:
                report = scanner.scan([m.BytesInput(b'ordinary synthetic text', 'same.txt')], **options())
                assert report.coverage.required_complete is complete
                assert all(r.coverage is m.CoverageState.COMPLETE for r in report.results) is complete


def test_host_stop_waits_for_admitted_partition_publication_before_store_lock(tmp_path, prepared):
    """Close is cooperative; the host stop fence drains an admitted callback."""
    from leakguard_core.scan_store import SQLiteScanStore
    from leakguard_host.scheduler import HostService
    from leakguard_vault import EncryptedScanStore
    root = tmp_path/'inputs'; root.mkdir()
    (root/'ordinary.txt').write_text('ordinary synthetic text')
    config = api.ScanConfig.from_mapping({})
    store = EncryptedScanStore.create(tmp_path/'observations.lgo', 'synthetic-session-publication')
    host = HostService(config=config, scan_store=store)
    source = host.add_source(root); host.manage_source(source['id']); host.submit(source['id'])
    admitted, release, stopped = Event(), Event(), Event()
    original = SQLiteScanStore.record_result
    errors = []
    def publish(child, result, **kwargs):
        admitted.set()
        assert release.wait(3)
        return original(child, result, **kwargs)
    def tick():
        try: host.tick()
        except BaseException as error: errors.append(error)
    def stop():
        try:
            host.stop(timeout=3)
            stopped.set()
        except BaseException as error: errors.append(error)
    try:
        with patch.object(SQLiteScanStore, 'record_result', publish):
            producer = Thread(target=tick); producer.start()
            assert admitted.wait(2)
            stopper = Thread(target=stop); stopper.start()
            assert not stopped.wait(.05), 'stop returned while publication still held the partition'
            release.set()
            producer.join(3); stopper.join(3)
            assert not producer.is_alive() and not stopper.is_alive()
        assert not errors and stopped.is_set()
        assert host._discovery._runtime_session is None
        store.close()
        # The publication was drained before closure; there is no late producer.
        assert not producer.is_alive()
    finally:
        release.set()
        if not stopped.is_set():
            host.stop(timeout=3)
        store.close()
