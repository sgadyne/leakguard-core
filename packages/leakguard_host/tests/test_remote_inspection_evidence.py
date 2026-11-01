"""Controlled SSH snapshots prove safe routing and actual stage collection."""
import base64
from contextlib import ExitStack
import hashlib
import json
from unittest.mock import patch
import pytest
from leakguard_core import backends
from leakguard_core.api import ScanConfig
from leakguard_core.scan_store import StateError
from leakguard_host.discovery import DiscoveryCoordinator
from leakguard_host.discovery_remote import RemoteDiscovery
from leakguard_host.protection import defaults
from leakguard_vault import EncryptedScanStore


@pytest.mark.parametrize('failure_stage',['acquire','parse','recognize','publish',None])
def test_remote_snapshot_stage_diagnostics_and_observed_completion(tmp_path,failure_stage):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-remote-evidence-passphrase')
    logical='ssh://synthetic/home/synthetic/ordinary.txt'
    source={'id':'synthetic','kind':'ssh','root':'ssh://synthetic/home/synthetic',
            'remote_root':'/home/synthetic','ssh_target':'synthetic','exclusions':[],
            'remote_identity':{'machine':'synthetic-machine','device':1}}
    job={'inventory_generation':7,'inventory_complete':True,'reconcile_cursor':256,
         'slices':1,'files_scanned':0,'new_findings':0,'content_cursor':0}
    store.inventory_put([(logical,'synthetic','file','v1','pending',100,7,24,None,'content-version-refresh-during-backfill')])
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}))
    owner.identity=lambda settings:{'policy_id':'synthetic-policy','runtime_id':'synthetic-runtime'}
    owner.inventory_page=lambda _source,_job,kind,state,**kw:store.inventory_selected('synthetic','file',('pending','changed'),[logical],7) if kind=='file' else []
    remote=RemoteDiscovery(owner)
    data=b'ordinary synthetic text';digest=hashlib.sha256(data).hexdigest()
    private='synthetic-private-exception /private/synthetic/path'
    def request(_source,op,**kw):
        if failure_stage=='acquire':raise RuntimeError(private)
        row={'path':'/home/synthetic/ordinary.txt','status':'available','signature':[1,2,3]}
        if op=='read':row.update(data=base64.b64encode(data).decode(),sha256=digest)
        return {'entries':[row]}
    try:
        with ExitStack() as stack:
            stack.enter_context(patch.object(remote,'_request',side_effect=request))
            stack.enter_context(patch('leakguard_core.scan_policy.runtime_identity',return_value=('synthetic-runtime',True)))
            stack.enter_context(patch.object(backends,'detect',return_value=()))
            if failure_stage=='parse':stack.enter_context(patch('leakguard_core.extraction.extract',side_effect=RuntimeError(private)))
            if failure_stage=='recognize':stack.enter_context(patch.object(backends,'detect',side_effect=RuntimeError(private)))
            if failure_stage=='publish':stack.enter_context(patch('leakguard_host.discovery_remote._Evidence.record_result',side_effect=StateError(private)))
            if failure_stage in {'acquire','publish'}:
                with pytest.raises((RuntimeError,StateError)):remote.tick(source,job,defaults(),cancel=lambda:False)
            else:remote.tick(source,job,defaults(),cancel=lambda:False)
        store.checkpoint()
        evidence=store.inspection_evidence()
        if failure_stage is not None:
            assert any(row['stage']==failure_stage for row in job['diagnostics'])
            assert private not in json.dumps(job['diagnostics'])
            assert sum(evidence['completed'][key] for key in ('ordinary','observed_change','reserved_oldest'))==0
        else:
            assert evidence['completed']['observed_change']==1
            assert evidence['completed']['ordinary']==0
            assert evidence['completed']['reserved_oldest']==0
    finally:owner.close();store.close()
