from pathlib import Path
import os
import pytest
from leakguard_core.api import ScanConfig
from leakguard_core.models import ScanLimits
from leakguard_host import HostService
from leakguard_vault import EncryptedScanStore

@pytest.mark.parametrize('positive',[False,True])
def test_earlier_slice_omission_survives_encrypted_restart_and_missing_ui_counter(tmp_path,positive):
 binary=os.environ.get('LEAKGUARD_GITLEAKS')
 if not binary:pytest.skip('local pinned native backend required')
 root=tmp_path/'inputs';root.mkdir();(root/'a.bin').write_bytes(b'\0\xff\0\x01');(root/'z.txt').write_text('password=synthetic-only-literal\n' if positive else 'ordinary text\n')
 values={'gitleaks_executable':binary,'worker_policy':'supervised-alpha'};config=ScanConfig.from_mapping(values);limits=ScanLimits(30,1,max_directory_entries=500)
 path=tmp_path/'scan.lgo';phrase='synthetic-omission-test-passphrase';store=EncryptedScanStore.create(path,phrase,config=values);host=HostService(config=config,scan_store=store,limits=limits);source=host.add_source(root);job=host.submit(source['id']);first=host.tick()
 assert first['status']=='queued';assert host.job(job['id'])['omission_count']>0
 # Model an older host checkpoint that retained core evidence but lost its UI
 # omission accumulator. The accepted earlier cycle result remains authoritative.
 state=store.load_host_state();state['jobs'][job['id']]['omission_count']=0;store.save_host_state(state);host.stop();store.close()
 store=EncryptedScanStore.open(path,phrase,config=values);host=HostService(config=config,scan_store=store,limits=limits);assert host.job(job['id'])['state']=='paused';host.resume(job['id']);result=host.tick()
 assert result['status']=='completed';assert host.job(job['id'])['coverage']=='incomplete';assert host.job(job['id'])['policy_resets']==0
 report=store.latest_report();assert any(i.omission_id=='audit-cycle-omissions' for i in report.issues)
 assert report.decision.verdict.value==('block' if positive else 'allow-with-omissions')
 host.stop();store.close()
