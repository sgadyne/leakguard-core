"""Existing findings lose current trust when bounded metadata is unavailable."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import os,threading
import pytest
from leakguard_host.discovery import DiscoveryCoordinator
from leakguard_host import mounted_worker


def test_descriptor_metadata_never_opens_file_content_and_rejects_links(tmp_path,monkeypatch):
    from leakguard_core.sources import FilesystemBoundary
    if os.name!='posix' or os.stat not in os.supports_dir_fd:pytest.skip('descriptor metadata unavailable')
    root=tmp_path/'root';root.mkdir();present=root/'present.txt';present.write_text('ordinary synthetic content')
    outside=tmp_path/'outside';outside.mkdir();(outside/'private.txt').write_text('synthetic outside scope')
    (root/'linked').symlink_to(outside,target_is_directory=True)
    (root/'linked-file').symlink_to(outside/'private.txt')
    os.mkfifo(root/'fifo')
    opened=[];original=os.open
    def directories_only(path,flags,*args,**kwargs):
        assert flags & os.O_DIRECTORY, 'metadata polling attempted a file content open'
        opened.append(str(path));return original(path,flags,*args,**kwargs)
    monkeypatch.setattr(os,'open',directories_only)
    # supports_dir_fd membership must retain the capability of the wrapped call.
    monkeypatch.setattr(os,'supports_dir_fd',os.supports_dir_fd|{directories_only})
    paths=[present,root/'missing',root/'linked/private.txt',root/'linked-file',root/'fifo']
    result=mounted_worker.availability(root,[str(p) for p in paths])
    assert result['capability']=='descriptor-metadata'
    assert [r['status'] for r in result['entries']]==['present','absent','unavailable','unavailable','unavailable']
    assert opened and all('outside' not in p for p in opened)


def test_availability_worker_honors_root_identity_and_reaps(tmp_path):
    present=tmp_path/'present';present.write_text('synthetic ordinary metadata fixture')
    info=tmp_path.lstat();expected=[info.st_dev,info.st_ino]
    result=mounted_worker.call({'op':'availability','root':str(tmp_path),'paths':[str(present),str(tmp_path/'absent')],'expected':expected},timeout=2)
    if result['capability']!='descriptor-metadata':pytest.skip(result['capability'])
    assert [r['status'] for r in result['entries']]==['present','absent']
    from leakguard_host.errors import HostError
    with pytest.raises(HostError):mounted_worker.call({'op':'availability','root':str(tmp_path),'paths':[str(present)],'expected':[info.st_dev,info.st_ino+1]},timeout=2)


class Store:
    def __init__(self,root):
        self.root=root;self.events=[];self.deadlines=[];self._mutex=threading.RLock()
    def query_findings_page(self,**kwargs):
        self.query=kwargs
        rows=[{'source':{'path':str(p)},'state':'active'} for p in (self.root/'present',self.root/'absent',self.root/'absent',self.root.parent/'outside')]
        rows.append({'source':{'path':str(self.root/'old')},'state':'resolved'})
        return SimpleNamespace(rows=rows,next_cursor='synthetic-opaque-cursor')
    @contextmanager
    def partition(self,bucket):yield self
    def set_deadline(self,value):self.deadlines.append(value)
    def record_event(self,path,event):
        assert self._mutex._is_owned(), 'publication bypassed the profile owner mutex'
        self.events.append((Path(path).name,event))


def metadata_entry(root,path,status):
    parent=mounted_worker.info(root.stat())
    value=dict(parent,st_mode=0o100600,st_size=7) if status=='present' else None
    return {'path':path,'status':status,'info':value,'parent_info':parent}


def test_known_missing_observation_downgrades_without_positive_content_revalidation(tmp_path,monkeypatch):
    store=Store(tmp_path);owner=DiscoveryCoordinator(store,None);job={};requests=[]
    def call(request,**kwargs):
        requests.append((request,kwargs))
        return {'capability':'descriptor-metadata','entries':[metadata_entry(tmp_path,p,'absent' if p.endswith('/absent') else 'present') for p in request['paths']]}
    monkeypatch.setattr(mounted_worker,'call',call)
    owner._known_availability({'kind':'local','root':str(tmp_path),'id':'source','root_identity':[1,2],'exclusions':[]},job,{'exclusions':[]},lambda:False)
    assert store.events==[('absent','deleted')]
    assert store.deadlines==[None]
    assert job['known_availability_checked']==2 and job['known_availability_unknown']==1
    assert job['known_availability_cursor']=='synthetic-opaque-cursor'
    assert store.query=={'limit':25,'cursor':None}
    assert requests[0][1]['timeout']==2
    assert requests[0][0]['expected']==[1,2]
    assert requests[0][0]['paths']==[str(tmp_path/'absent'),str(tmp_path/'present')]


@pytest.mark.parametrize('mode',['worker-error','invalid-path','invalid-item','invalid-metadata'])
def test_unavailable_or_invalid_worker_response_fails_closed(tmp_path,monkeypatch,mode):
    from leakguard_host.errors import HostError
    store=Store(tmp_path);owner=DiscoveryCoordinator(store,None);job={}
    def call(*args,**kwargs):
        if mode=='worker-error':raise HostError('source-unavailable')
        entries=[1] if mode=='invalid-item' else [{'path':'/wrong','status':'present'}]
        if mode=='invalid-metadata':entries=[{'path':p,'status':'present','info':'invalid','parent_info':None} for p in args[0]['paths']]
        return {'capability':'descriptor-metadata','entries':entries}
    monkeypatch.setattr(mounted_worker,'call',call)
    owner._known_availability({'kind':'local','root':str(tmp_path),'exclusions':[]},job,{'exclusions':[]},lambda:False)
    assert store.events==[('absent','changed'),('present','changed')]
    assert job['known_availability_capability']=='worker-unavailable'


def test_cancelled_availability_cannot_publish_events(tmp_path,monkeypatch):
    store=Store(tmp_path);owner=DiscoveryCoordinator(store,None);cancelled=False
    def call(*args,**kwargs):
        nonlocal cancelled
        cancelled=True
        return {'capability':'descriptor-metadata','entries':[{'path':p,'status':'absent','info':None,'parent_info':None} for p in args[0]['paths']]}
    monkeypatch.setattr(mounted_worker,'call',call)
    owner._known_availability({'kind':'local','root':str(tmp_path),'exclusions':[]},{},{'exclusions':[]},lambda:cancelled)
    assert store.events==[]


def test_unsupported_descriptor_capability_is_explicit(tmp_path,monkeypatch):
    store=Store(tmp_path);owner=DiscoveryCoordinator(store,None);job={}
    monkeypatch.setattr(mounted_worker,'call',lambda *a,**k:{'capability':'descriptor-metadata-unsupported','entries':[]})
    owner._known_availability({'kind':'local','root':str(tmp_path),'exclusions':[]},job,{'exclusions':[]},lambda:False)
    assert store.events==[] and job['known_availability_capability']=='descriptor-metadata-unsupported'


def test_known_current_metadata_enqueues_only_fenced_existing_versions(tmp_path,monkeypatch):
    store=Store(tmp_path);owner=DiscoveryCoordinator(store,None);observations=[]
    def observe(*args):observations.append(args);return True
    store.inventory_observed=observe
    metadata=mounted_worker.info(tmp_path.stat());file_metadata=dict(metadata,st_mode=0o100600,st_size=7)
    def call(request,**kwargs):
        return {'capability':'descriptor-metadata','entries':[{'path':p,'status':'present','info':file_metadata,'parent_info':metadata} for p in request['paths']]}
    monkeypatch.setattr(mounted_worker,'call',call);job={'inventory_generation':123}
    owner._known_availability({'kind':'local','root':str(tmp_path),'id':'source','exclusions':[]},job,{'exclusions':[]},lambda:False)
    assert len(observations)==3  # One shared parent, two distinct current files.
    assert observations[0][:4]==(str(tmp_path),'source',123,'directory')
    assert {args[0] for args in observations[1:]}=={str(tmp_path/'absent'),str(tmp_path/'present')}
    assert all(args[1:3]==('source',123) for args in observations)
    assert job['known_availability_changed']==3 and store.events==[]
