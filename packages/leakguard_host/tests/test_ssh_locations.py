from pathlib import Path
import hashlib,json
import pytest
from leakguard_host.ssh_locations import uri,remote_path,SSHLocations
from leakguard_host.ssh import SSHRunner
from leakguard_core import policies
from leakguard_core.api import ScanConfig
from leakguard_host import HostService
from test_host import SessionStore


def test_remote_namespaces_are_distinct_and_do_not_become_local_paths():
 a=uri('devbox','/home/dev/Unicode name\nfile.env');b=uri('paumanok-lab','/home/dev/Unicode name\nfile.env')
 assert a!=b and '%0A' in a and '%20' in a
 assert policies.canonical(a,{})==a
 source={'ssh_target':'devbox','remote_root':'/home/dev'}
 assert remote_path(source,a)=='/home/dev/Unicode name\nfile.env'
 with pytest.raises(Exception):remote_path(source,'ssh://devbox/etc/passwd')


def test_fixed_remote_helper_is_isolated_and_never_selects_remote_repo_module():
 runner=SSHRunner(port=None);command=runner._command('devbox','/usr/bin/python3','print(1)',isolated=True)
 assert '-p' not in command
 assert 'UpdateHostKeys=no' in command
 assert "-I -S -B -c" in command[-1]


def test_offline_vm_location_persists_one_source_without_probing_or_file_jobs():
 store=SessionStore();h=HostService(config=ScanConfig.from_mapping({}),scan_store=store)
 source=h.add_source('/home/dev',kind='ssh',target='devbox');h.manage_source(source['id'])
 assert source['root']=='ssh://devbox/home/dev';assert len(h.sources())==1;assert h.jobs()==[]
 restored=HostService(config=ScanConfig.from_mapping({}),scan_store=store)
 assert restored.sources()[0]['ssh_target']=='devbox'
 restored.update_source(source['id'],ssh_port=1)
 assert restored.sources()[0]['ssh_port']==1
 restored.update_source(source['id'],ssh_port=None)
 assert restored.sources()[0]['ssh_port'] is None


def test_missing_remote_results_have_bounded_per_file_retries():
 from leakguard_host.discovery_remote import RemoteDiscovery
 class Store:
  def __init__(self):self.rows={}
  def inventory_set(self,path,state,**kwargs):self.rows[path]=(state,kwargs['detail'])
 owner=type('Owner',(),{'store':Store(),'config':None})()
 remote=RemoteDiscovery(owner);job={};row=['ssh://devbox/home/dev/bad.env','vm','file','sig','pending',0,1,10,None,None]
 for _ in range(7):
  remote._retry_missing([row],set(),job)
  row[4],row[9]=owner.store.rows[row[0]]
 assert job['content_batch_limit']==1 and row[4]=='inspection-error'
 assert json.loads(row[9])['attempts']==7
 remote._retry_missing([row],{row[0]},job)
 assert json.loads(owner.store.rows[row[0]][1])['attempts']==7


@pytest.mark.parametrize('recovers',[True,False])
def test_partial_remote_report_retries_alone_after_encrypted_restart(tmp_path,recovers):
 from datetime import datetime,timezone
 from types import SimpleNamespace
 from leakguard_host.discovery_remote import RemoteDiscovery
 from leakguard_core.models import CoverageState,ErrorCode
 from leakguard_vault import EncryptedScanStore
 path=tmp_path/'observations.lgo';phrase='synthetic-remote-partial-recovery'
 logical='ssh://devbox/home/dev/operator.env';sibling='ssh://devbox/home/dev/ordinary.txt'
 store=EncryptedScanStore.create(path,phrase)
 store.inventory_put([(logical,'vm','file','sig','pending',0,1,20,None,None),(sibling,'vm','file','sig','inspected',10,1,20,None,None)])
 job={};snapshot={'sha256':'a'*64,'signature':[1,2,3]}
 for attempt in range(3):
  result=SimpleNamespace(coverage=CoverageState.COMPLETE if recovers and attempt==2 else CoverageState.INCOMPLETE,issues=() if recovers and attempt==2 else (SimpleNamespace(code=ErrorCode.PLUGIN_TIMEOUT,omission_id=None),),identity=SimpleNamespace(runtime_id='runtime',policy_id='policy'),observed_at=datetime.now(timezone.utc))
  bucket=store._partitions.bucket(logical,'i')
  previous=store._partitions.get(bucket).conn.execute('SELECT detail FROM inventory WHERE path=?',(logical,)).fetchone()[0]
  RemoteDiscovery(SimpleNamespace(store=store,config=None))._record_inventory_outcome(logical,snapshot,result,True,job,previous)
  store.checkpoint();store.close();store=EncryptedScanStore.open(path,phrase)
  state,detail=store._partitions.get(bucket).conn.execute('SELECT status,detail FROM inventory WHERE path=?',(logical,)).fetchone()
  assert state==('pending' if attempt<2 else 'inspected' if recovers else 'inspection-error')
  assert json.loads(detail)['attempts']==(0 if recovers and attempt==2 else attempt+1)
  assert store.inventory_counts().get('inspected')==(2 if recovers and attempt==2 else 1)
 assert job['content_batch_limit']==1
 assert json.loads(detail)['previous_failure_codes']==['plugin-timeout']
 if not recovers:
  # A newly qualified runtime re-admits the old error; it cannot make it clean.
  store.invalidate_location({'id':'vm','root':'ssh://devbox/home/dev'},int(bucket[1:],16))
  assert store.inventory_counts()=={'pending':1,'inspected':1}
 store.close()


def test_isolated_helper_omits_link_without_losing_regular_sibling(tmp_path):
 import subprocess,sys
 from leakguard_host import ssh_location_worker
 root=tmp_path/'scope';root.mkdir();regular=root/'ordinary.txt';regular.write_text('synthetic ordinary text')
 (root/'link.txt').symlink_to(tmp_path/'outside.txt');(tmp_path/'outside.txt').write_text('outside scope')
 def request(value):
  result=subprocess.run([sys.executable,'-I','-S','-B',ssh_location_worker.__file__],input=json.dumps(value).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10)
  return json.loads(result.stdout)
 probe=request({'op':'probe','root':str(root)})
 result=request({'op':'read','root':str(root),'expected':probe['identity'],'paths':[str(root/'link.txt'),str(regular)],'max_file_bytes':1000})
 entries={Path(x['path']).name:x for x in result['entries']}
 assert entries['ordinary.txt']['status']=='available'
 assert entries['link.txt']['status']!='available'


def test_remote_acquisition_rechecks_device_before_reading(tmp_path):
 import subprocess,sys
 from leakguard_host import ssh_location_worker
 root=tmp_path/'scope';root.mkdir()
 for name in ('foreign.txt','ordinary.txt'):(root/name).write_text('synthetic fixture')
 # Simulate a file mount that appears after metadata admission. No mounts or
 # system services are changed by this acquisition-boundary regression.
 script="""import os,runpy,sys
original=os.stat
def observed(path,*args,**kwargs):
 info=original(path,*args,**kwargs)
 if str(path)=='foreign.txt':
  values=list(info);values[2]+=1;return os.stat_result(values)
 return info
os.stat=observed
runpy.run_path(sys.argv[1],run_name='__main__')
"""
 request={'op':'read','root':str(root),'paths':[str(root/'foreign.txt'),str(root/'ordinary.txt')],'max_file_bytes':1000}
 result=subprocess.run([sys.executable,'-I','-S','-B','-c',script,ssh_location_worker.__file__],input=json.dumps(request).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10)
 entries={Path(x['path']).name:x for x in json.loads(result.stdout)['entries']}
 assert entries['foreign.txt']['status']=='unsupported' and 'data' not in entries['foreign.txt']
 assert entries['ordinary.txt']['status']=='available'
