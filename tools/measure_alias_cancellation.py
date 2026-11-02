#!/usr/bin/env python3
"""Synthetic alias retarget and real parser-worker cancellation controls.

Only the attested fixture is staged in temporary directories. The cancel callback
is armed after the parser Popen succeeds; no child survives the scan lifecycle.
"""
import argparse, hashlib, json, os, subprocess, tempfile, threading, time
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from measure_pipeline_cost import fixture, Meter, instrumentation, difference, json_digest

def semantic(report, root):
    rows=[]
    for result in report.results:
        findings=sorted([{'part':f.part_id,'rule':f.rule,'detector':f.detector_id,
            'detector_severity':f.detector_severity.value,'severity':f.severity.value,
            'classification':f.classification.value,'lines':[f.start_line,f.end_line],
            'analysis':asdict(f.analysis) if f.analysis else None} for f in result.findings],
            key=lambda x:json.dumps(x,sort_keys=True))
        issues=sorted((i.code.value,i.required,i.omission_id or '',i.part_id or '') for i in result.issues)
        rows.append((str(Path(result.source.path).relative_to(root)),result.content.digest if result.content else '',
                     result.coverage.value,findings,issues))
    return json_digest({'rows':sorted(rows,key=lambda x:x[0]),
        'issues':sorted((i.code.value,i.required,i.omission_id or '',i.part_id or '') for i in report.issues),
        'enumeration_complete':report.coverage.enumeration_complete,
        'required_complete':report.coverage.required_complete,
        'omission_count':report.coverage.omission_count,'decision':report.decision.verdict.value})

class ParserLaunch:
    def __init__(self,event):self.event,self.children=event,[]
    def __getattr__(self,name):return getattr(subprocess,name)
    def Popen(self,*args,**kwargs):
        process=subprocess.Popen(*args,**kwargs)
        if 'leakguard_core.extract_worker' in args[0]:
            self.children.append(process)
            self.event.set()
        return process

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for option in ('fixture','config','backend','output'):ap.add_argument('--'+option,required=True,type=Path)
    args=ap.parse_args()
    files,fixture_sha=fixture(args.fixture)
    payload=next(f['payload'] for f in files if f['name']=='text.txt')
    pdf=next(f['payload'] for f in files if f['name']=='doc.pdf')
    from leakguard_core import _supervision,policies
    from leakguard_core.api import ScanConfig,Scanner
    from leakguard_core.models import ScanLimits,ScanPolicy
    config=ScanConfig.from_file(args.config).to_mapping()
    config['gitleaks_executable']=str(args.backend.resolve(strict=True))
    config['scan_workers']=1
    policy=ScanPolicy.inventory();limits=ScanLimits(60,1,max_file_bytes=1_000_000)
    receipt={'synthetic_only':True,'fixture_sha256':fixture_sha,
        'config_raw_sha256':hashlib.sha256(args.config.read_bytes()).hexdigest(),
        'backend_sha256':hashlib.sha256(args.backend.read_bytes()).hexdigest(),
        'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'instrument_sha256':hashlib.sha256(Path(__file__).with_name('measure_pipeline_cost.py').read_bytes()).hexdigest(),
        'samples':[]}
    for sample in range(3):
        with tempfile.TemporaryDirectory(prefix='leakguard-alias-cancel-') as tmp:
            root=Path(tmp);a=root/'target-a';b=root/'target-b';a.mkdir();b.mkdir()
            for target in (a,b):
                (target/'scope').mkdir()
                (target/'scope'/'data.txt').write_bytes(payload)
            alias=root/'alias';alias.symlink_to(a,target_is_directory=True)
            scope=alias/'scope';logical=scope/'data.txt'
            conf=dict(config);conf['audit_scopes']={'shared':str(a/'scope'/'data.txt')}
            conf['scope_aliases']={'shared':[str(logical)]}
            sample_out={'alias':[]};meter=Meter()
            def pair(scanner,label):
                results=[]
                for use_cache in (True,False):
                    before=meter.snapshot();start=time.perf_counter_ns()
                    report=scanner.scan_within(scope,[logical],policy=policy,limits=limits,use_cache=use_cache)
                    elapsed=time.perf_counter_ns()-start
                    results.append({'use_cache':use_cache,'wall_ns':elapsed,
                       'semantic_sha256':semantic(report,scope),'results':len(report.results),
                       'findings':sum(len(r.findings) for r in report.results),
                       'issue_codes':sorted({i.code.value for i in report.issues} | {i.code.value for r in report.results for i in r.issues}),
                       'required_complete':report.coverage.required_complete,
                       'enumeration_complete':report.coverage.enumeration_complete,
                       'measurement':difference(meter.snapshot(),before)})
                assert results[0]['semantic_sha256']==results[1]['semantic_sha256']
                assert all(x['results']==1 and x['required_complete'] and x['enumeration_complete'] for x in results), json.dumps(results)
                sample_out['alias'].append({'label':label,'effective_config_sha256':json_digest(scanner._service.config),
                    'runtime_id':scanner._service._runtime,'pair':results})
            with instrumentation(meter):
                with Scanner.open(config=ScanConfig.from_mapping(conf)) as scanner:
                    assert policies.canonical(str(logical),scanner._service.config)==str(a/'scope'/'data.txt')
                    pair(scanner,'target-a')
                    alias.unlink();alias.symlink_to(b,target_is_directory=True)
                    pair(scanner,'retargeted-b')
                conf['audit_scopes']={'shared':str(b/'scope'/'data.txt')}
                with Scanner.open(config=ScanConfig.from_mapping(conf)) as scanner:
                    assert policies.canonical(str(logical),scanner._service.config)==str(b/'scope'/'data.txt')
                    pair(scanner,'changed-alias-config')
            assert len({x['pair'][0]['semantic_sha256'] for x in sample_out['alias']})==1
            sample_out['alias_resolution_verified']=True
            # Isolated PDF stage: observe actual parser Popen then cancel.
            docroot=root/'pdf';docroot.mkdir();(docroot/'doc.pdf').write_bytes(pdf)
            with Scanner.open(config=ScanConfig.from_mapping(config)) as scanner:
                before=scanner.scan_paths([docroot],policy=policy,limits=limits,use_cache=False)
                assert before.coverage.required_complete and before.coverage.enumeration_complete
                expected=semantic(before,docroot)
            event=threading.Event();proxy=ParserLaunch(event)
            with Scanner.open(config=ScanConfig.from_mapping(config)) as scanner:
                with patch.object(_supervision,'subprocess',proxy):
                    cancelled=scanner.scan_paths([docroot],policy=policy,limits=limits,
                                                 use_cache=False,cancel=event.is_set)
                assert event.is_set() and proxy.children
                assert all(child.returncode is not None for child in proxy.children)
                codes=sorted({i.code.value for i in cancelled.issues} |
                             {i.code.value for r in cancelled.results for i in r.issues})
                assert not cancelled.coverage.required_complete and cancelled.decision.verdict.value=='incomplete'
                event.clear()
                same_cached=scanner.scan_paths([docroot],policy=policy,limits=limits,use_cache=True)
                same_uncached=scanner.scan_paths([docroot],policy=policy,limits=limits,use_cache=False)
                assert same_cached.coverage.required_complete and same_uncached.coverage.required_complete
                assert semantic(same_cached,docroot)==semantic(same_uncached,docroot)==expected
            with Scanner.open(config=ScanConfig.from_mapping(config)) as scanner:
                after=scanner.scan_paths([docroot],policy=policy,limits=limits,use_cache=False)
                recovered=semantic(after,docroot)
                assert after.coverage.required_complete and after.coverage.enumeration_complete and recovered==expected
            sample_out['cancel']={'parser_children_started':len(proxy.children),
                'all_parser_children_reaped':all(child.returncode is not None for child in proxy.children),
                'required_complete':cancelled.coverage.required_complete,'decision':cancelled.decision.verdict.value,
                'issue_codes':codes,'before_sha256':expected,'same_scanner_cached_sha256':semantic(same_cached,docroot),
                'same_scanner_uncached_sha256':semantic(same_uncached,docroot),'recovered_sha256':recovered}
            receipt['samples'].append(sample_out)
    with args.output.open('x',encoding='utf-8') as f:json.dump(receipt,f,indent=2,sort_keys=True);f.write('\n')

if __name__=='__main__':main()
