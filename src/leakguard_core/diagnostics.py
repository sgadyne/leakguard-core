"""Small value-free diagnostics shared by optional host evidence collectors."""
from __future__ import annotations
import math
import time
from .models import ErrorCode

STAGES = frozenset({'enumerate','acquire','parse','recognize','publish','shutdown','unknown'})
_FALLBACK = {'enumerate':'enumeration-failed','acquire':'input-unreadable',
             'parse':'extract-failed','recognize':'detector-failed',
             'publish':'state-failed','shutdown':'shutdown-failed','unknown':'scan-failed'}
_CODES = frozenset(x.value for x in ErrorCode) | frozenset(_FALLBACK.values()) | {'worker-still-running'}
_TYPES = frozenset({'Exception','OSError','PermissionError','FileNotFoundError',
                    'TimeoutError','ValueError','TypeError','RuntimeError','StateError','HostError',
                    'AcquisitionError','WorkerError','BackendError'})
_EXACT = {OSError:'OSError',PermissionError:'PermissionError',FileNotFoundError:'FileNotFoundError',
          TimeoutError:'TimeoutError',ValueError:'ValueError',TypeError:'TypeError',RuntimeError:'RuntimeError'}


def event(stage, code=None, error=None):
    stage = stage if stage in STAGES else 'unknown'
    exception_type = None
    if error is not None:
        exception_type = _EXACT.get(type(error),'Exception')
        # Only known product exception types, never arbitrary class names.
        cls = type(error)
        if cls.__module__ in {'leakguard_core.scan_store','leakguard_host.errors',
                'leakguard_core.sources','leakguard_core._supervision','leakguard_core.backends'} and cls.__name__ in _TYPES:
            exception_type = cls.__name__
    return {'code':code if type(code) is str and code in _CODES else _FALLBACK[stage],
            'stage':stage,'exception_type':exception_type,'at':time.time(),
            'retry_count':0,'recovered':False}


def retain(job, value):
    """Accept only the fixed projection; bounded journal-independent retention."""
    stage=value.get('stage')
    stage=stage if type(stage) is str and stage in STAGES else 'unknown'
    code=value.get('code')
    code=code if type(code) is str and code in _CODES else _FALLBACK[stage]
    exception_type=value.get('exception_type')
    exception_type=exception_type if exception_type is None or type(exception_type) is str and exception_type in _TYPES else 'Exception'
    at=value.get('at')
    at=at if type(at) in {int,float} and math.isfinite(at) and at>=0 else time.time()
    previous=job.get('diagnostics',[])
    retries=max((x['retry_count']+1 for x in previous if x['stage']==stage and x['code']==code and not x['recovered']),default=0)
    row={'code':code,'stage':stage,'exception_type':exception_type,'at':at,
         'retry_count':min(30,retries),'recovered':False}
    job['diagnostics']=[*previous[-7:],row]
    return row


def recover(job, *, stages=STAGES):
    for row in job.get('diagnostics',[]):
        if row['stage'] in stages:
            row['recovered']=True
