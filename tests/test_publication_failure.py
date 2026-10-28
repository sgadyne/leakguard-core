"""Result publication failures cannot certify durable per-file coverage."""
from unittest.mock import patch
import pytest
from leakguard_core import backends, engine, models as m
from leakguard_core.scan_store import MemoryScanStore, StateError


@pytest.mark.parametrize('reuse',[False,True])
def test_failed_result_publication_has_incomplete_file_coverage(tmp_path,reuse):
    class FailingStore(MemoryScanStore):
        fail = False
        def record_result(self, result, **kwargs):
            if self.fail:raise StateError('state-failed')
            return super().record_result(result,**kwargs)
    store = FailingStore()
    file=tmp_path/'fixture.txt';file.write_text('ordinary synthetic text')
    with patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic-runtime', True)), patch.object(backends, 'detect', return_value=()):
        service = engine.ScanService({}, store=store)
        try:
            options={'policy':m.ScanPolicy.inventory(),'limits':m.ScanLimits(10,1)}
            if reuse:
                first=service.scan((m.FileInput(file),),**options)
                assert first.results[0].coverage is m.CoverageState.COMPLETE
            store.fail=True
            report = service.scan((m.FileInput(file),),**options)
        finally:
            service.close()
    assert not report.coverage.required_complete
    assert report.results[0].coverage is m.CoverageState.INCOMPLETE
    assert report.results[0].last_verified_at is None
    assert m.ErrorCode.STATE_FAILED in {i.code for i in report.results[0].issues}
    if reuse:assert report.results[0].outcome is m.ScanOutcome.ERROR
    store.close()
