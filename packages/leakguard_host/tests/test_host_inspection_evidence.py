"""Recorded failure survives recovery, encrypted restart and status projection."""
import json
from unittest.mock import patch
import pytest
from leakguard_core import backends
from leakguard_core.api import ScanConfig
from leakguard_host.discovery import _sig
from leakguard_host.scheduler import HostService
from leakguard_host.errors import HostError
from leakguard_vault import EncryptedScanStore


def test_managed_failure_recovery_and_shutdown_remain_recorded_across_reopen(tmp_path):
    root=tmp_path/'source';root.mkdir()
    item=root/'ordinary.txt';item.write_text('ordinary synthetic text')
    path=tmp_path/'observations.lgo';phrase='synthetic-recorded-recovery-passphrase'
    store=EncryptedScanStore.create(path,phrase)
    host=HostService(config=ScanConfig.from_mapping({}),scan_store=store,clock=lambda:1000)
    source=host.add_source(root);host.manage_source(source['id'])
    submitted=host.submit(source['id']);job=host._job(submitted['id'])
    selected=host._source(source['id']);selected['next_run_at']='2100-01-01T00:00:00+00:00'
    host._discovery.begin(selected,job)
    job.update(inventory_complete=True,reconcile_cursor=256,empty_directory_pages=32)
    store.inventory_set(str(root),'enumerated')
    store.inventory_put([(str(item),source['id'],'file',_sig(item.stat()),'pending',100,job['inventory_generation'],item.stat().st_size,None,None)])
    host._discovery.identity=lambda settings:{'policy_id':'synthetic-policy','runtime_id':'synthetic-runtime'}
    private='synthetic-private-value /private/synthetic/path'
    with patch('leakguard_core.scan_policy.runtime_identity',return_value=('synthetic-runtime',True)):
        with patch.object(backends,'detect',side_effect=RuntimeError(private)):
            for _ in range(40):
                host.tick()
                if host._job(submitted['id']).get('diagnostics'):break
        recorded=host.job(submitted['id'])['diagnostics']
        assert recorded[-1]['stage']=='recognize' and not recorded[-1]['recovered']
        assert host.job(submitted['id'])['state']!='completed'
        with patch.object(backends,'detect',return_value=()):
            for _ in range(40):
                host.tick()
                if host.job(submitted['id'])['state']=='completed':break
        assert host.job(submitted['id'])['state']=='completed'
        assert host.job(submitted['id'])['diagnostics'][-1]['recovered']
        assert host.status()['inspection_evidence']['completed']['reserved_oldest'] + host.status()['inspection_evidence']['completed']['ordinary'] == 1
        original=host._discovery.close
        with patch.object(host._discovery,'close',side_effect=RuntimeError(private)):
            with pytest.raises(HostError,match='shutdown-failed'):host.stop()
        original()
    assert host.job(submitted['id'])['diagnostics'][-1]['stage']=='shutdown'
    assert private not in json.dumps(host.status()['inspection_evidence'])
    host.stop();store.close()
    store=EncryptedScanStore.open(path,phrase)
    host=HostService(config=ScanConfig.from_mapping({}),scan_store=store)
    try:
        records=host.job(submitted['id'])['diagnostics']
        assert records[0]['recovered']
        assert records[-1]['stage']=='shutdown' and not records[-1]['recovered']
        assert len(host.status()['inspection_evidence']['diagnostics'])==len(records)
    finally:host.stop();store.close()
