from datetime import datetime,timezone
import threading,time
from leakguard_core.api import ScanConfig
from leakguard_core.models import ScanReport,CoverageSummary,PolicyDecision,DecisionVerdict,CoverageIssue,ErrorCode
from leakguard_host import HostService
from leakguard_vault import EncryptedScanStore


def test_user_pause_checkpoints_while_a_partition_scan_owns_no_global_lock(tmp_path):
 root=tmp_path/'inputs';root.mkdir();(root/'credential.env').write_text('synthetic ordinary fixture')
 entered=threading.Event()
 class Scanner:
  def __enter__(self):return self
  def __exit__(self,*args):pass
  def work_identity(self,**kwargs):return {'policy_id':'synthetic-policy','runtime_id':'synthetic-runtime'}
  def scan_within(self,*args,**kwargs):
   entered.set();deadline=time.monotonic()+3
   while not kwargs['cancel']():
    assert time.monotonic()<deadline,'pause could not reach the scan callback'
    time.sleep(.01)
   now=datetime.now(timezone.utc)
   return ScanReport(1,'synthetic-control-report',now,now,'synthetic-policy',(),CoverageSummary(False,False,0,1,0),PolicyDecision(DecisionVerdict.INCOMPLETE,(ErrorCode.CANCELLED,),'synthetic-policy'),(CoverageIssue(ErrorCode.CANCELLED,required=True),))
 store=EncryptedScanStore.create(tmp_path/'s.lgo','synthetic-control-test-passphrase');host=HostService(config=ScanConfig.from_mapping({}),scan_store=store,scanner_factory=lambda **kwargs:Scanner());host.configure_automatic((str(root),));results=[]
 thread=threading.Thread(target=lambda:results.append(host.tick()),daemon=True);thread.start();assert entered.wait(3)
 job=host.jobs()[0];start=time.monotonic();host.pause(job['id']);assert time.monotonic()-start<2;thread.join(3);assert not thread.is_alive();assert host.job(job['id'])['state']=='paused';assert store.load_host_state()['jobs'][job['id']]['state']=='paused';host.stop();store.close()
