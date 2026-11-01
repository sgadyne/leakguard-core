"""Synthetic discovery admission and durable-publication regressions."""
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from unittest.mock import patch
import json
import pytest

from leakguard_core import backends
from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.scan_store import SQLiteScanStore, StateError
from leakguard_host.discovery import DiscoveryCoordinator, _sig
from leakguard_host.protected_paths import protected_store
from leakguard_host.protection import defaults
from leakguard_vault import EncryptedScanStore


@pytest.mark.parametrize('path', [
    '/Users/example/Library/Application Support/Firefox/Profiles/example.default/logins.json',
    '/fixture/Firefox/Profiles/example.default/logins-backup.json',
    '/fixture/Firefox/Profiles/example.default/logins.json.corrupt',
    '/home/example/.mozilla/firefox/example.default/logins.json',
    '/home/example/.librewolf/example.default/logins-backup.json',
])
def test_firefox_profile_store_is_protected_in_both_discovery_namespaces(path):
    assert protected_store(Path(path))
    assert protected_store(PurePosixPath(path), remote=True)


@pytest.mark.parametrize('path', ['/app/logins.json', '/app/logins-backup.json',
    '/app/Firefox/logins.json', '/app/Profiles/example/logins.json',
    '/app/Firefox/Profiles/example/settings.json'])
def test_ordinary_json_is_not_a_protected_store(path):
    assert not protected_store(Path(path))
    assert not protected_store(PurePosixPath(path), remote=True)


def seeded(store, root, files, *, kind='local'):
    source={'id':'synthetic-source','root':str(root),'kind':kind}
    job={'inventory_generation':1,'inventory_complete':True,'slices':0,'content_cursor':0,
         'files_scanned':0,'new_findings':0,'reconcile_cursor':256}
    store.inventory_put([(str(p),source['id'],'file',_sig(p.lstat()),'pending',0,1,p.stat().st_size,None,None) for p in files])
    return source, job


def status(store, path):
    child=store._partitions.get(store._partitions.bucket(str(path)))
    return child.conn.execute('SELECT status,detail FROM inventory WHERE path=?',(str(path),)).fetchone()


def findings(store):
    rows=[];cursor=None
    while True:
        page=store.query_findings_page(cursor=cursor);rows.extend(page.rows)
        cursor=page.next_cursor
        if cursor is None:return rows


def advance(owner,source,job):
    before=job['files_scanned']
    for _ in range(40):
        owner.tick(source,job,defaults(),cancel=lambda:False)
        if job['files_scanned']>before:return
    raise AssertionError('synthetic pending file not inspected')


def test_stale_pending_firefox_rows_never_enter_local_scanner(tmp_path):
    browser=tmp_path/'Firefox/Profiles/example.default';browser.mkdir(parents=True)
    protected=[browser/name for name in ('logins.json','logins-backup.json')]
    ordinary=browser/'settings.json'
    for p in [*protected,ordinary]:p.write_text('ordinary synthetic text')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-protected-test')
    admitted=[]
    class Tracking:
        def __init__(self, scanner):self.scanner=scanner
        def __enter__(self):return self
        def __exit__(self,*args):return self.scanner.__exit__(*args)
        def __getattr__(self,name):return getattr(self.scanner,name)
        def scan_within(self,root,paths,**kwargs):
            admitted.extend(paths)
            return self.scanner.scan_within(root,paths,**kwargs)
    try:
        source,job=seeded(store,tmp_path,[*protected,ordinary])
        owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}),scanner_factory=lambda **kw:Tracking(Scanner.open(**kw)))
        with patch('leakguard_core.scan_policy.runtime_identity',return_value=('synthetic-runtime',True)), patch.object(backends,'detect',return_value=()):
            advance(owner,source,job)
            for _ in range(40):
                if all(status(store,p)[0]=='protected' for p in protected):break
                owner.tick(source,job,defaults(),cancel=lambda:False)
        assert admitted==[ordinary]
        assert all(status(store,p)[0]=='protected' for p in protected)
        assert status(store,ordinary)[0]=='inspected'
    finally:store.close()


def test_ssh_host_protects_firefox_stale_rows_before_any_helper_content_request(tmp_path):
    import base64,hashlib
    from leakguard_host.discovery_remote import RemoteDiscovery
    from leakguard_host.ssh_locations import uri
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-remote-store-test')
    target='synthetic-host';root='/home/synthetic';browser=root+'/.mozilla/firefox/example.default/'
    files=[browser+'logins.json',browser+'logins-backup.json',browser+'settings.json']
    source={'id':'synthetic-source','kind':'ssh','root':uri(target,root),'remote_root':root,
            'ssh_target':target,'remote_identity':{'machine':'synthetic-machine','device':1},'exclusions':[]}
    job={'inventory_generation':1,'inventory_complete':True,'slices':0,'content_cursor':0,
         'files_scanned':0,'new_findings':0,'reconcile_cursor':256}
    signature=[1,2,3,4,5,6,0];data=b'ordinary synthetic text';requested=[]
    store.inventory_put([(uri(target,p),source['id'],'file',json.dumps(signature),'pending',0,1,len(data),None,None) for p in files])
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}));remote=RemoteDiscovery(owner)
    def request(source,op,**kwargs):
        assert kwargs['paths']==[files[-1]]
        requested.append(op)
        item={'path':files[-1],'status':'available','signature':signature}
        if op=='read':item.update(data=base64.b64encode(data).decode(),sha256=hashlib.sha256(data).hexdigest())
        return {'entries':[item]}
    try:
        with patch.object(remote,'_request',side_effect=request), patch('leakguard_core.scan_policy.runtime_identity',return_value=('synthetic-runtime',True)), patch.object(backends,'detect',return_value=()):
            for _ in range(40):
                remote.tick(source,job,defaults(),cancel=lambda:False)
                if job['files_scanned'] and all(status(store,uri(target,p))[0]=='protected' for p in files[:-1]):break
        assert requested==['read','check']
        assert all(status(store,uri(target,p))[0]=='protected' for p in files[:-1])
        assert status(store,uri(target,files[-1]))[0]=='inspected'
    finally:store.close()


@pytest.mark.parametrize('mounted',[False,True])
def test_failed_publication_checkpoint_reopen_retries_without_false_resolution(tmp_path,mounted):
    root=tmp_path/'inputs';root.mkdir();file=root/'operator.env';file.write_text('synthetic positive')
    path=tmp_path/'observations.lgo';phrase='synthetic-publication-test';values={}
    store=EncryptedScanStore.create(path,phrase,config=values)
    config=ScanConfig.from_mapping(values)
    source,job=seeded(store,root,[file],kind='mounted' if mounted else 'local')
    # The mount worker's report is created with an in-memory store, as in the
    # product; only the host's encrypted evidence publication is faulted.
    def mounted_call(request,**kwargs):
        from leakguard_core.scan_store import MemoryScanStore
        from leakguard_core.models import ScanLimits,ScanPolicy
        with Scanner.open(config=config,store=MemoryScanStore()) as scanner:
            report=scanner.scan_within(root,[file],policy=ScanPolicy.inventory(),limits=ScanLimits(10,1))
        return {'report':report.to_json()}
    runtime=patch('leakguard_core.scan_policy.runtime_identity',return_value=('synthetic-runtime',True))
    worker=patch('leakguard_host.mounted_worker.call',side_effect=mounted_call)
    try:
        with runtime, worker:
            owner=DiscoveryCoordinator(store,config)
            with patch.object(backends,'detect',return_value=(backends.BackendFinding('literal-password',1,1),)):
                advance(owner,source,job)
            assert status(store,file)[0]=='inspected'
            assert findings(store)[0]['state']=='active'
            file.write_text('synthetic clean');store.inventory_set(str(file),'pending');job['content_cursor']=0
            # Fail after SQL finding transitions, before transaction commit.
            with patch.object(backends,'detect',return_value=()), patch.object(SQLiteScanStore,'_record_location',side_effect=StateError()):
                if mounted:
                    with pytest.raises(StateError):advance(owner,source,job)
                else:advance(owner,source,job)
            assert status(store,file)[0]=='pending'
            assert findings(store)
            assert all(r['state']!='resolved' for r in findings(store))
            if not mounted:assert 'state-failed' in json.loads(status(store,file)[1])['issues']
            store.checkpoint();store._dispose()  # crash/reopen at published gap
            store=EncryptedScanStore.open(path,phrase,config=values)
            assert status(store,file)[0]=='pending'
            assert findings(store)
            assert all(r['state']!='resolved' for r in findings(store))
            owner=DiscoveryCoordinator(store,config);job['content_cursor']=0
            with patch.object(backends,'detect',return_value=()):advance(owner,source,job)
            assert status(store,file)[0]=='inspected'
            assert not findings(store)
    finally:store.close()


def test_failed_report_publication_preserves_pending_and_does_not_count_completion(tmp_path):
    root=tmp_path/'source';root.mkdir();file=root/'ordinary.txt';file.write_text('ordinary synthetic text')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-report-publication-passphrase')
    source,job=seeded(store,root,[file])
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}))
    try:
        with patch('leakguard_core.scan_policy.runtime_identity',return_value=('synthetic-runtime',True)), patch.object(backends,'detect',return_value=()):
            with patch.object(SQLiteScanStore,'record_report',side_effect=StateError('state-failed')):
                advance(owner,source,job)
            assert status(store,file)[0]=='pending'
            assert job['diagnostics'][-1]['stage']=='publish'
            store.checkpoint()
            assert sum(store.inspection_evidence()['completed'][key] for key in ('ordinary','observed_change','reserved_oldest'))==0
            job['content_cursor']=0
            advance(owner,source,job)
            assert status(store,file)[0]=='inspected'
    finally:owner.close();store.close()
