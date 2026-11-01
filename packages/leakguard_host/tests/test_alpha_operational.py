"""Regressions for measured bounded scheduling and continuation failures."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch

from leakguard_core.api import ScanConfig
from leakguard_core.models import CoverageState, ScanReport, CoverageSummary, PolicyDecision, DecisionVerdict
from leakguard_core.scan_store import MemoryScanStore
from leakguard_host.discovery import DiscoveryCoordinator
from leakguard_host.discovery_remote import RemoteDiscovery
from leakguard_host.scheduler import HostService
from leakguard_host.errors import HostError


class Clock:
    def __init__(self):self.now=0
    def __call__(self):return self.now


class Inventory:
    def __init__(self, root):
        self.root=str(root);self.state='enumerating';self.cursor=None;self.paths=set();self.details=[];self.admitted=[]
    def inventory_page(self,*args,**kw):
        row=(self.root,'synthetic','directory',None,self.state,0,1,0,self.cursor,None)
        return ([row] if self.state=='enumerating' else []),0
    def physical_visit(self,*args):return True
    def inventory_admitted(self,paths):self.admitted.extend(paths)
    def inventory_put(self,entries):self.paths.update(x[0] for x in entries)
    def inventory_set(self,path,state,*,cursor=None,detail=None,**kw):
        assert path==self.root
        self.state=state;self.cursor=cursor;self.details.append(detail)


def directory_fixture(tmp_path):
    root=tmp_path/'root';root.mkdir()
    store=Inventory(root);clock=Clock();names=[f'entry-{i}.txt' for i in range(500)]
    handles={'open':0,'reads':0}
    info=root.stat()
    file_info=SimpleNamespace(st_dev=info.st_dev,st_ino=123,st_mode=stat.S_IFREG|0o600,
        st_size=10,st_mtime_ns=1,st_ctime_ns=1,st_flags=0)
    @contextmanager
    def scandir(path,scope,expected):
        handles['open']+=1
        try:
            def entries():
                for name in names:
                    clock.now+=.01;handles['reads']+=1
                    yield SimpleNamespace(name=name,stat=lambda **kw:file_info)
            yield entries()
        finally:handles['open']-=1
    coordinator=DiscoveryCoordinator(store,ScanConfig.from_mapping({}),clock=clock)
    source={'id':'synthetic','root':str(root),'kind':'local','exclusions':[]}
    job={'inventory_generation':1,'inventory_cursor':0,'slices':1,'metadata_enumerated':0}
    return root,store,clock,names,handles,scandir,coordinator,source,job


def test_wide_directory_prefix_exceeding_slice_budget_makes_forward_progress(tmp_path):
    root,store,clock,names,handles,scandir,coordinator,source,job=directory_fixture(tmp_path)
    with patch('leakguard_host.discovery.navigation._scoped_scandir',scandir),patch('leakguard_host.discovery.time.monotonic',clock):
        for _ in range(12):
            coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+1)
            if store.state=='enumerated':break
    coordinator.close()
    assert store.state=='enumerated'
    assert store.paths=={str(root/name) for name in names}
    assert handles['reads']<=len(names)+12,'completed prefixes were replayed repeatedly'
    assert handles['open']==0


def test_directory_mutation_discards_stream_and_revalidates_prefix(tmp_path):
    root,store,clock,names,handles,scandir,coordinator,source,job=directory_fixture(tmp_path)
    with patch('leakguard_host.discovery.navigation._scoped_scandir',scandir),patch('leakguard_host.discovery.time.monotonic',clock):
        coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+1)
        (root/'mutation').write_text('safe synthetic metadata change')
        names.insert(0,'new-first.txt')
        for _ in range(12):
            coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+1)
            if store.state=='enumerated':break
    coordinator.close()
    assert store.state=='enumerated'
    assert str(root/'new-first.txt') in store.paths
    assert handles['open']==0


def test_reopened_coordinator_replays_durable_prefix_in_bounded_chunks(tmp_path):
    root,store,clock,names,handles,scandir,coordinator,source,job=directory_fixture(tmp_path)
    # A valid durable prefix can be larger than one fresh process's slice.
    import hashlib
    prefix=hashlib.sha256()
    for name in names[:300]:prefix.update(name.encode()+b'\0')
    from leakguard_host.discovery import _sig
    store.cursor=json.dumps({'signature':_sig(root.stat()),'entries':300,'prefix':prefix.hexdigest()})
    with patch('leakguard_host.discovery.navigation._scoped_scandir',scandir),patch('leakguard_host.discovery.time.monotonic',clock):
        for _ in range(12):
            coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+1)
            if store.state=='enumerated':break
    coordinator.close()
    assert store.state=='enumerated'
    assert store.paths=={str(root/name) for name in names[300:]}
    assert handles['reads']<=len(names)+12
    assert handles['open']==0


def remote_fixture():
    writes=[]
    store=SimpleNamespace(inventory_set=lambda *a,**kw:writes.append((a,kw)))
    owner=SimpleNamespace(store=store,config=ScanConfig.from_mapping({}))
    return RemoteDiscovery(owner),writes


def test_remote_batch_recovers_only_after_three_complete_batches():
    remote,writes=remote_fixture();job={'content_batch_limit':1}
    for _ in range(2):remote._record_batch_outcome(job,True)
    assert job['content_batch_limit']==1
    remote._record_batch_outcome(job,True)
    assert job['content_batch_limit']==2
    remote._record_batch_outcome(job,False)
    assert job['content_success_streak']==0
    for _ in range(60):remote._record_batch_outcome(job,True)
    assert job['content_batch_limit']==25


def test_remote_failed_file_retry_semantics_survive_batch_recovery():
    remote,writes=remote_fixture();job={'content_batch_limit':12,'content_success_streak':2}
    result=SimpleNamespace(coverage=CoverageState.INCOMPLETE,issues=(),identity=SimpleNamespace(runtime_id='runtime',policy_id='policy'),observed_at=datetime.now(timezone.utc))
    snapshot={'sha256':'a'*64,'signature':[1,2,3]}
    remote._record_inventory_outcome('ssh://synthetic/home/credential.env',snapshot,result,True,job,None)
    assert job['content_batch_limit']==1
    assert job['content_success_streak']==0
    assert writes[-1][0][1]=='pending'
    previous=writes[-1][1]['detail']
    remote._record_inventory_outcome('ssh://synthetic/home/credential.env',snapshot,result,True,job,previous)
    previous=writes[-1][1]['detail']
    remote._record_inventory_outcome('ssh://synthetic/home/credential.env',snapshot,result,True,job,previous)
    assert writes[-1][0][1]=='inspection-error'
    assert json.loads(writes[-1][1]['detail'])['attempts']==3


class HostStore(MemoryScanStore):
    def __init__(self):super().__init__();self.host={}
    def load_host_state(self):return deepcopy(self.host)
    def save_host_state(self,value):self.host=deepcopy(value)
    def reset_cycle(self,*args):pass


class StubScanner:
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def work_identity(self,**kwargs):return {'policy_id':'synthetic','runtime_id':'synthetic'}
    def audit(self,*args,**kwargs):
        now=datetime.now(timezone.utc)
        return ScanReport(1,'synthetic',now,now,'synthetic',(),CoverageSummary(True,True,0),PolicyDecision(DecisionVerdict.ALLOW,(),'synthetic'))


def test_ssh_probe_preserves_safe_cause_and_recovers_transiently():
    clock=Clock();store=HostStore()
    host=HostService(config=ScanConfig.from_mapping({}),scan_store=store,clock=clock,scanner_factory=lambda **kw:StubScanner())
    source=host.add_source('/home/synthetic',kind='ssh',target='synthetic-host')
    job=host.submit(source['id'])
    with patch('leakguard_host.ssh_locations.SSHLocations.probe',side_effect=HostError('ssh-timeout')):
        assert host.tick()['status']=='backoff'
    assert host.job(job['id'])['last_error']=='ssh-timeout'
    assert host.job(job['id'])['coverage']=='incomplete'
    clock.now+=6
    probe={'identity':{'machine':'synthetic','device':1,'inode':1},'python_version':[3,11,2]}
    with patch('leakguard_host.ssh_locations.SSHLocations.probe',return_value=probe):
        assert host.tick()['status']=='completed'
    assert host.job(job['id'])['last_error'] is None
    host.stop();store.close()


def test_interrupted_inventory_publication_cannot_advance_cached_cursor(tmp_path):
    root,store,clock,names,handles,scandir,coordinator,source,job=directory_fixture(tmp_path)
    original=store.inventory_put;fail=[True]
    def publish(entries):
        if fail[0]:
            fail[0]=False
            raise RuntimeError('synthetic failed metadata publication')
        original(entries)
    store.inventory_put=publish
    with patch('leakguard_host.discovery.navigation._scoped_scandir',scandir),patch('leakguard_host.discovery.time.monotonic',clock):
        import pytest
        with pytest.raises(RuntimeError):coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+1)
        assert store.paths==set()
        for _ in range(12):
            coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+1)
            if store.state=='enumerated':break
    coordinator.close()
    assert store.paths=={str(root/name) for name in names}
    assert handles['open']==0


def test_scope_ancestry_is_revalidated_before_cached_stream_resumes(tmp_path):
    selected=tmp_path/'scope';parent=selected/'parent';inside=parent/'inside';inside.mkdir(parents=True)
    outside=tmp_path/'outside';(outside/'inside').mkdir(parents=True)
    for i in range(20):(inside/f'allowed-{i}.txt').write_text('safe')
    (outside/'inside'/'outside-only.env').write_text('password="synthetic-not-authorized"')
    store=Inventory(inside);clock=Clock();coordinator=DiscoveryCoordinator(store,ScanConfig.from_mapping({}),clock=clock)
    source={'id':'synthetic','root':str(selected),'kind':'local','exclusions':[]}
    job={'inventory_generation':1,'inventory_cursor':0,'slices':1,'metadata_enumerated':0,'unknown_descendants':0}
    import leakguard_host.navigation as navigation
    original=navigation._scoped_scandir
    @contextmanager
    def slow(path,scope,expected):
        with original(path,scope,expected) as entries:
            def slowed():
                for entry in entries:
                    clock.now+=.1
                    yield entry
            yield slowed()
    with patch('leakguard_host.discovery.navigation._scoped_scandir',slow),patch('leakguard_host.discovery.time.monotonic',clock):
        coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+.3)
        assert coordinator._iterators
        parent.rename(selected/'saved-parent');parent.symlink_to(outside,target_is_directory=True)
        coordinator._enumerate(source,job,{'exclusions':[]},lambda:False,clock.now+.3)
    coordinator.close()
    assert not any('outside-only.env' in path for path in store.paths)
    assert store.state=='inaccessible'
    assert not coordinator._iterators


def test_directory_stream_cache_is_bounded_and_shutdown_closes_all(tmp_path):
    coordinator=DiscoveryCoordinator(SimpleNamespace(),ScanConfig.from_mapping({}));handles={'open':0}
    @contextmanager
    def scoped(*args):
        handles['open']+=1
        try:yield iter(())
        finally:handles['open']-=1
    with patch('leakguard_host.discovery.navigation._scoped_scandir',scoped):
        for i in range(12):
            path=tmp_path/str(i);path.mkdir();info=path.stat()
            from leakguard_host.discovery import _sig
            coordinator._directory_stream(('source',str(path)),path,tmp_path,info,_sig(info),None,1)
            assert len(coordinator._iterators)<=8
            assert handles['open']<=8
    coordinator.close()
    assert handles['open']==0


def test_unknown_ssh_error_details_are_not_published():
    store=HostStore();host=HostService(config=ScanConfig.from_mapping({}),scan_store=store)
    source=host.add_source('/home/synthetic',kind='ssh',target='synthetic-host')
    with patch('leakguard_host.ssh_locations.SSHLocations.probe',side_effect=HostError('synthetic-private-detail')):
        assert host._available(source)=='source-unavailable'
    for code in ('ssh-timeout','ssh-execution-failed','ssh-output-limit','ssh-worker-invalid','remote-report-invalid'):
        with patch('leakguard_host.ssh_locations.SSHLocations.probe',side_effect=HostError(code)):
            assert host._available(source)==code
    host.stop();store.close()
