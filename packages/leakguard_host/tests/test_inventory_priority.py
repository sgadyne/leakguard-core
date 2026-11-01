from pathlib import Path
from leakguard_host.discovery import _priority
from leakguard_vault import EncryptedScanStore


def test_credential_filenames_outrank_runtime_branding_and_dependency_caches():
    credential=Path('/Users/example/projects/service/operator.env')
    runtime=Path('/Users/example/Applications/Password Buddy.app/Contents/Resources/python/smtplib.py')
    cached=Path('/Users/example/Library/Application Support/Password Buddy/runtime/site-packages/password_prompt.py')
    assert _priority(credential)==0
    assert _priority(Path('/Users/example/.codex/auth.json'))==0
    assert _priority(runtime)>_priority(credential)
    assert _priority(cached)==200
    assert _priority(Path('/Users/example/.cache/service/.env'))==0


def test_partial_reweight_checkpoint_reopens_without_dropping_pending_files(tmp_path):
    path=tmp_path/'observations.lgo';phrase='synthetic-priority-recovery-passphrase'
    source={'id':'this-mac','root':'/'}
    credential='/Users/example/projects/service/operator.env'
    rows=[(f'/Users/example/Applications/Password Buddy.app/Contents/Resources/python/module{i}.py',source['id'],'file','sig','pending',0,1,20,None,None) for i in range(200)]
    rows.append((credential,source['id'],'file','sig','pending',100,1,20,None,None))
    store=EncryptedScanStore.create(path,phrase);store.inventory_put(rows)
    for index in range(128):store.reprioritize_location(source,index,_priority)
    store.checkpoint();store.close();store=EncryptedScanStore.open(path,phrase)
    for index in range(128,256):store.reprioritize_location(source,index,_priority)
    store.checkpoint();store.close();store=EncryptedScanStore.open(path,phrase)
    assert store.inventory_counts()=={'pending':201}
    admitted,_=store.inventory_page(source['id'],'file','pending',limit=1)
    assert admitted[0][0]==credential
    store.close()


def test_refresh_slot_falls_back_without_skipping_regular_cursor():
    from leakguard_host.discovery import DiscoveryCoordinator
    class Store:
        def __init__(self):self.calls=[]
        def inventory_page(self,*args,**kwargs):
            self.calls.append((args,kwargs))
            return ([],8) if kwargs.get('queue_class') else ([('backlog',)],17)
    store=Store();owner=DiscoveryCoordinator(store,None);job={'slices':5,'inventory_cursor':9,'content_cursor':11}
    assert owner.inventory_page({'id':'source'},job,'directory','enumerating',limit=1)==[('backlog',)]
    assert len(store.calls)==2
    assert store.calls[0][1]['cursor']==0 and store.calls[0][1]['queue_class']=='refresh'
    assert store.calls[1][1]['cursor']==9 and store.calls[1][1]['prefer_priority'] is False
    assert job['refresh_inventory_cursor']==8 and job['inventory_cursor']==17
    assert job['navigation_profile']['version']=='bounded-refresh-v1'
    job['slices']=6;store.calls.clear()
    owner.inventory_page({'id':'source'},job,'file',('pending','changed'),limit=25)
    assert len(store.calls)==1 and store.calls[0][1]['prefer_priority'] is True


def test_partial_refresh_tags_new_content_and_preserves_metadata_cursor(tmp_path):
    import json,time
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    root=tmp_path/'inputs';root.mkdir()
    for name in ('first.env','second.env'):(root/name).write_text('synthetic ordinary refresh fixture')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-refresh-test-passphrase')
    source={'id':'source','root':str(root),'kind':'local','exclusions':[]}
    job={'slices':5,'inventory_generation':1,'inventory_cursor':0,'content_cursor':0,'metadata_enumerated':0,'unknown_descendants':0}
    store.inventory_put([(str(root),'source','directory',_sig(root.lstat()),'enumerating',0,1,0,None,'metadata-refresh-during-backfill')])
    owner=DiscoveryCoordinator(store,None);calls=0
    def cancel():
        nonlocal calls
        calls+=1
        return calls>=3
    try:
        owner._enumerate(source,job,{'exclusions':[]},cancel,time.monotonic()+2)
        with store.partition(store._partitions.bucket(str(root),'i')) as child:
            row=child.conn.execute('SELECT * FROM inventory WHERE path=?',(str(root),)).fetchone()
        assert row[4]=='enumerating' and row[9]=='metadata-refresh-during-backfill'
        assert json.loads(row[8])['entries']==1
        refreshed=[]
        for _ in range(32):
            rows,_=store.inventory_page('source','file','pending',cursor=_%32*8,queue_class='refresh',prefer_priority=False)
            refreshed.extend(rows)
        assert len({r[0] for r in refreshed})==1
        owner._enumerate(source,job,{'exclusions':[]},lambda:False,time.monotonic()+2)
        assert store.inventory_counts()=={'enumerated':1,'pending':2}
    finally:
        owner.close();store.close()
