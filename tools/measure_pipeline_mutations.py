#!/usr/bin/env python3
"""Bounded synthetic cache mutation controls; no private files or SSH.

Requires the four-format synthetic fixture used by measure_pipeline_cost.py.
Each state is checked against an uncached scan of identical bytes, with no
timing threshold. An already-cancelled call checks explicit incomplete reporting;
it is not a mid-worker cancellation experiment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import time

from measure_pipeline_cost import fixture, instrumentation, Meter, difference, signature, json_digest, read_bounded

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fixture',type=Path,required=True)
    ap.add_argument('--config',type=Path,required=True)
    ap.add_argument('--backend',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    files,fixture_sha=fixture(args.fixture)
    if 'text.txt' not in {f['name'] for f in files}:
        raise ValueError('fixture must contain text.txt')
    from leakguard_core.api import ScanConfig,Scanner
    from leakguard_core.models import ScanLimits,ScanPolicy
    config=ScanConfig.from_file(args.config).to_mapping()
    config['gitleaks_executable']=str(args.backend.resolve(strict=True))
    config['scan_workers']=1
    limits=ScanLimits(120,len(files),max_file_bytes=1_000_000)
    meter=Meter()
    receipt={'synthetic_only':True,'fixture_sha256':fixture_sha,
             'config_raw_sha256':hashlib.sha256(read_bounded(args.config,1_000_000)).hexdigest(),
             'backend_sha256':hashlib.sha256(read_bounded(args.backend,512*1024*1024)).hexdigest(),
             'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'instrument_sha256':hashlib.sha256(Path(__file__).with_name('measure_pipeline_cost.py').read_bytes()).hexdigest(),
             'stages':[]}
    with tempfile.TemporaryDirectory(prefix='leakguard-mutation-') as folder:
        root=Path(folder)/'fixture';root.mkdir()
        for f in files:(root/f['name']).write_bytes(f['payload'])
        def measure(scanner,label,policy):
            pair=[]
            for use_cache in (True,False):
                before=meter.snapshot();cache_before=scanner.capabilities().get('observation_cache')
                start=time.perf_counter_ns()
                report=scanner.scan_paths([root],policy=policy,limits=limits,use_cache=use_cache)
                elapsed=time.perf_counter_ns()-start
                sig,count,findings=signature(report,root)
                pair.append({'use_cache':use_cache,'wall_ns':elapsed,'signature_sha256':sig,
                    'result_count':count,'finding_count':findings,
                    'required_complete':report.coverage.required_complete,
                    'enumeration_complete':report.coverage.enumeration_complete,
                    'omission_count':report.coverage.omission_count,'decision':report.decision.verdict.value,
                    'measurement':difference(meter.snapshot(),before),
                    'cache_before':cache_before,'cache_after':scanner.capabilities().get('observation_cache')})
            equal=pair[0]['signature_sha256']==pair[1]['signature_sha256']
            valid=equal and all(x['result_count']==len(files) and x['required_complete'] and x['enumeration_complete'] for x in pair)
            receipt['stages'].append({'label':label,'equal':equal,'valid':valid,'pair':pair})
            if not valid:raise AssertionError('paired output or coverage mismatch: '+label)
        default=ScanPolicy.inventory()
        with instrumentation(meter):
            with Scanner.open(config=ScanConfig.from_mapping(config)) as scanner:
                receipt['initial_runtime_id']=scanner._service._runtime
                measure(scanner,'cold',default)
                measure(scanner,'warm',default)
                path=root/'text.txt';original=path.read_bytes()
                if not original:raise ValueError('text fixture must be nonempty')
                changed=bytes([original[0]^1])+original[1:]
                path.write_bytes(changed)
                measure(scanner,'same-size-edit',default)
                path.rename(root/'renamed.txt')
                measure(scanner,'rename',default)
                policy=ScanPolicy.inventory(required_formats=('text',))
                measure(scanner,'policy-change',policy)
                cancelled=scanner.scan_paths([root],policy=default,limits=limits,cancel=lambda:True)
                receipt['cancelled']={'required_complete':cancelled.coverage.required_complete,
                    'enumeration_complete':cancelled.coverage.enumeration_complete,
                    'decision':cancelled.decision.verdict.value,
                    'issue_codes':sorted(i.code.value for i in cancelled.issues)}
                if cancelled.coverage.required_complete or cancelled.decision.verdict.value!='incomplete':
                    raise AssertionError('cancellation appeared complete')
                measure(scanner,'after-cancel',default)
            config['scope_aliases']={'synthetic':['synthetic-alias']}
            with Scanner.open(config=ScanConfig.from_mapping(config)) as scanner:
                receipt['alias_config_sha256']=json_digest(ScanConfig.from_mapping(config).to_mapping())
                receipt['alias_runtime_id']=scanner._service._runtime
                measure(scanner,'restart-alias-config',default)
    with args.output.open('x',encoding='utf-8') as out:
        json.dump(receipt,out,indent=2,sort_keys=True);out.write('\n')

if __name__=='__main__':
    main()
