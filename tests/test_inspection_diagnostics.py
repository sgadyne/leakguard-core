"""Real pipeline exception injection: fixed stages, no messages, no clean result."""
from contextlib import ExitStack
import json
from unittest.mock import patch
import pytest
from leakguard_core import backends, engine, models as m
from leakguard_core.diagnostics import event,retain
from leakguard_core.scan_store import MemoryScanStore,StateError

SENTINEL = 'synthetic-private-value /private/synthetic/path'
class PrivateNamedError(RuntimeError):
    code = SENTINEL


class CollectingStore(MemoryScanStore):
    def __init__(self):
        super().__init__()
        self.evidence={}
        self.fail_result=False
        self.fail_report=False
    def record_diagnostic(self,value):
        retain(self.evidence,value)
    def record_result(self,*args,**kwargs):
        if self.fail_result:raise StateError(SENTINEL)
        return super().record_result(*args,**kwargs)
    def record_report(self,*args,**kwargs):
        if self.fail_report:raise StateError(SENTINEL)
        return super().record_report(*args,**kwargs)


@pytest.mark.parametrize('stage,boundary',[
    ('acquire','acquire'),('parse','parse'),('recognize','recognize'),
    ('publish','result'),('publish','report'),('enumerate','enumerate')])
def test_injected_stage_failures_are_redacted_and_never_clean(stage,boundary):
    store=CollectingStore()
    with ExitStack() as stack:
        stack.enter_context(patch('leakguard_core.scan_policy.runtime_identity',return_value=('synthetic-runtime',True)))
        stack.enter_context(patch.object(backends,'detect',return_value=()))
        if boundary=='acquire':
            stack.enter_context(patch('leakguard_core.sources.acquire_bytes',side_effect=PrivateNamedError(SENTINEL)))
        elif boundary=='parse':
            stack.enter_context(patch('leakguard_core.extraction.extract',side_effect=PrivateNamedError(SENTINEL)))
        elif boundary=='recognize':
            stack.enter_context(patch.object(backends,'detect',side_effect=PrivateNamedError(SENTINEL)))
        store.fail_result=boundary=='result'
        store.fail_report=boundary=='report'
        def inputs():
            if boundary=='enumerate':raise PrivateNamedError(SENTINEL)
            yield m.BytesInput(b'ordinary synthetic text','fixture.txt')
        service=engine.ScanService({},store=store)
        try:
            report=service.scan(inputs(),policy=m.ScanPolicy.inventory(),limits=m.ScanLimits(10,1))
        finally:service.close()
    assert not report.coverage.required_complete
    events=store.evidence['diagnostics']
    assert any(row['stage']==stage for row in events)
    assert all(row['exception_type'] in {'Exception','StateError'} for row in events)
    assert SENTINEL not in json.dumps(events)
    assert 'PrivateNamedError' not in json.dumps(events)
    assert len(events)<=8
    store.close()


def test_retention_and_retry_counts_are_bounded_and_do_not_use_exception_args():
    job={}
    for _ in range(100):
        retain(job,event('recognize',SENTINEL,PrivateNamedError(SENTINEL)))
    assert len(job['diagnostics'])==8
    assert job['diagnostics'][-1]['retry_count']==30
    assert len(json.dumps(job))<2048
    assert SENTINEL not in json.dumps(job)
