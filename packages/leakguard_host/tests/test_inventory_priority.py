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
    assert store.calls[1][1]['cursor']==0 and store.calls[1][1]['prefer_priority'] is False
    assert job['refresh_inventory_cursor']==8 and job['fair_inventory_cursor']==17 and job['inventory_cursor']==9
    assert job['navigation_profile']['version']=='bounded-observed-refresh-v5'
    job['slices']=6;store.calls.clear()
    owner.inventory_page({'id':'source'},job,'file',('pending','changed'),limit=25)
    assert len(store.calls)==1 and store.calls[0][1]['prefer_priority'] is True


@__import__('pytest').mark.parametrize('tag',['metadata-refresh-during-backfill','metadata-version-refresh-during-backfill'])
def test_partial_refresh_tags_new_content_and_preserves_metadata_cursor(tmp_path,tag):
    import json,time
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    root=tmp_path/'inputs';root.mkdir()
    for name in ('first.env','second.env'):(root/name).write_text('synthetic ordinary refresh fixture')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-refresh-test-passphrase')
    source={'id':'source','root':str(root),'kind':'local','exclusions':[]}
    job={'slices':5,'inventory_generation':1,'inventory_cursor':0,'content_cursor':0,'metadata_enumerated':0,'unknown_descendants':0}
    store.inventory_put([(str(root),'source','directory',_sig(root.lstat()),'enumerating',0,1,0,None,tag)])
    owner=DiscoveryCoordinator(store,None);calls=0
    def cancel():
        nonlocal calls
        calls+=1
        return calls>=3
    try:
        owner._enumerate(source,job,{'exclusions':[]},cancel,time.monotonic()+2)
        with store.partition(store._partitions.bucket(str(root),'i')) as child:
            row=child.conn.execute('SELECT * FROM inventory WHERE path=?',(str(root),)).fetchone()
        assert row[4]=='enumerating' and row[9]==tag
        assert json.loads(row[8])['entries']==1
        refreshed=[]
        for _ in range(32):
            rows,_=store.inventory_page('source','file','pending',cursor=_%32*8,queue_class='refresh',prefer_priority=False)
            refreshed.extend(rows)
        assert len({r[0] for r in refreshed})==1
        expected='content-version-refresh-during-backfill' if tag=='metadata-version-refresh-during-backfill' else 'content-refresh-during-backfill'
        assert all(r[9]==expected for r in refreshed)
        owner._enumerate(source,job,{'exclusions':[]},lambda:False,time.monotonic()+2)
        assert store.inventory_counts()=={'enumerated':1,'pending':2}
    finally:
        owner.close();store.close()


def test_nested_create_and_unstable_local_refresh_keep_reserved_admission(tmp_path,monkeypatch):
    import time
    from leakguard_host import discovery
    root=tmp_path/'inputs';root.mkdir();nested=root/'new-folder';nested.mkdir();(nested/'fresh.env').write_text('synthetic ordinary refresh fixture')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-refresh-retry-passphrase')
    source={'id':'source','root':str(root),'kind':'local','exclusions':[]}
    job={'slices':5,'inventory_generation':1,'inventory_cursor':0,'content_cursor':0,'metadata_enumerated':0,'unknown_descendants':0}
    store.inventory_put([(str(root),'source','directory',discovery._sig(root.lstat()),'enumerating',0,1,0,None,'metadata-refresh-during-backfill')])
    owner=discovery.DiscoveryCoordinator(store,None);original=discovery._sig;root_inode=root.lstat().st_ino;calls=0
    def unstable_once(info):
        nonlocal calls
        if info.st_ino==root_inode:
            calls+=1
            if calls==2:return 'changed-during-enumeration'
        return original(info)
    monkeypatch.setattr(discovery,'_sig',unstable_once)
    try:
        # Stop after the unstable first page, then retry through normal routing.
        owner._enumerate(source,job,{'exclusions':[]},lambda:calls>=2,time.monotonic()+2)
        with store.partition(store._partitions.bucket(str(root),'i')) as child:
            row=child.conn.execute('SELECT * FROM inventory WHERE path=?',(str(root),)).fetchone()
        assert row[4]=='enumerating' and row[8] is None and row[9]=='metadata-refresh-during-backfill'
        assert job['refresh_metadata_restarts']==1
        owner._enumerate(source,job,{'exclusions':[]},lambda:False,time.monotonic()+2)
        assert store.inventory_counts()=={'enumerated':2,'pending':1}
        with store.partition(store._partitions.bucket(str(nested/'fresh.env'),'i')) as child:
            row=child.conn.execute('SELECT * FROM inventory WHERE path=?',(str(nested/'fresh.env'),)).fetchone()
        assert row[9]=='content-refresh-during-backfill'
    finally:owner.close();store.close()


def test_interrupted_observed_directory_page_resumes_after_encrypted_reopen(tmp_path,monkeypatch):
    import json
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    root=tmp_path/'inputs';nested=root/'nested';nested.mkdir(parents=True)
    file=nested/'ordinary.txt';file.write_text('ordinary synthetic deferred metadata')
    path=tmp_path/'observations.lgo';phrase='synthetic-deferred-directory'
    store=EncryptedScanStore.create(path,phrase)
    source={'id':'source','kind':'local','root':str(root),'exclusions':[]}
    store.inventory_put([(str(root),'source','directory',_sig(root.stat()),'enumerating',20,1,0,None,None)])
    job={'inventory_generation':1,'inventory_complete':False,'slices':1,'metadata_enumerated':0,'unknown_descendants':0}
    owner=DiscoveryCoordinator(store,None);owner.inventory_page=lambda *a,**k:[]
    clock=[0.];monkeypatch.setattr('leakguard_host.discovery.time.monotonic',lambda:clock[0])
    original=store.inventory_put
    def publish_then_expire(rows):
        original(rows);clock[0]=3.
    store.inventory_put=publish_then_expire
    try:
        owner._enumerate(source,job,{'exclusions':[]},lambda:False,2,observed=[(str(root),'directory')],content_followup=[])
        assert job.get('metadata_remainder')==[str(nested)]
        store.save_host_state({'job':job});store.checkpoint();owner.close();store.close()
        store=EncryptedScanStore.open(path,phrase);job=store.load_host_state()['job']
        owner=DiscoveryCoordinator(store,None);owner.inventory_page=lambda *a,**k:[];clock[0]=0.
        owner._enumerate(source,job,{'exclusions':[]},lambda:False,2)
        child=store._partitions.get(store._partitions.bucket(str(file)))
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(file),)).fetchone()[0]=='pending'
        assert not job['metadata_remainder']
    finally:owner.close();store.close()


def test_unstable_remote_refresh_retains_slot_and_tags_nested_directory(tmp_path):
    from leakguard_host.discovery import DiscoveryCoordinator
    from leakguard_host.discovery_remote import RemoteDiscovery
    from leakguard_host.ssh_locations import uri
    root=uri('fixture-host','/fixture')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-remote-refresh-passphrase')
    source={'id':'source','kind':'ssh','root':root,'remote_root':'/fixture','ssh_target':'fixture-host','remote_identity':{'machine':'synthetic-machine','device':1},'exclusions':[]}
    job={'slices':5,'inventory_generation':1,'inventory_cursor':0,'content_cursor':0,'metadata_enumerated':0,'unknown_descendants':0,'files_scanned':0,'new_findings':0,'inventory_complete':False}
    store.inventory_put([(root,'source','directory','sig','enumerating',0,1,0,None,'metadata-refresh-during-backfill')])
    owner=DiscoveryCoordinator(store,None);owner.identity=lambda settings:{'policy_id':'synthetic-policy','runtime_id':'synthetic-runtime'}
    remote=RemoteDiscovery(owner)
    info={'st_dev':1,'st_ino':2,'st_mode':0o40700,'st_size':0,'st_mtime_ns':1,'st_ctime_ns':1,'st_flags':0}
    remote._request=lambda *args,**kwargs:{'info':info,'entries':[{'name':'new-folder','info':dict(info,st_ino=3)}],'stable':False,'complete':False,'position':1,'prefix':'synthetic-prefix'}
    try:
        remote.tick(source,job,{'new_content':'inventory'},cancel=lambda:False)
        assert job['refresh_metadata_restarts']==1 and not job['inventory_complete']
        for path in (root,root+'/new-folder'):
            with store.partition(store._partitions.bucket(path,'i')) as child:
                row=child.conn.execute('SELECT * FROM inventory WHERE path=?',(path,)).fetchone()
            assert row[4]=='enumerating' and row[8] is None and row[9]=='metadata-refresh-during-backfill'
    finally:owner.close();store.close()


def test_priority_traffic_cannot_reset_oldest_work_rotation(tmp_path):
    from leakguard_host.discovery import DiscoveryCoordinator
    # Keep a priority row permanently active, as with a wide directory or a
    # continuing high-priority workload. Ordinary work lives in a later bucket.
    groups={}
    from leakguard_vault.partitions import EncryptedPartitions
    for number in range(1000):
        path=str(tmp_path/f'item-{number}')
        groups.setdefault(EncryptedPartitions.bucket(path),path)
    early,middle,late=sorted(groups)[10],sorted(groups)[64],sorted(groups)[-10]
    hot,blocker,old=groups[early],groups[middle],groups[late]
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-independent-fair-cursor')
    owner=DiscoveryCoordinator(store,None);source={'id':'source'}
    try:
        for kind,state in [('directory','enumerating'),('file','pending')]:
            store.inventory_put([(hot,'source',kind,'hot',state,0,1,1,None,None),(blocker,'source',kind,'blocker',state,100,1,1,None,None),(old,'source',kind,'old',state,200,1,1,None,None)])
            job={'slices':0,'inventory_cursor':0,'content_cursor':0};fair=[]
            for step in range(21):
                job['slices']=step
                rows=owner.inventory_page(source,job,kind,state,limit=1)
                if step%10==0:fair.extend(r[0] for r in rows)
                elif step%10!=5:assert rows[0][0]==hot
            assert old in fair, 'priority cursor reset starved another hash bucket'
    finally:owner.close();store.close()


@__import__('pytest').mark.parametrize('cutoff',['byte-budget','scanner-budget'])
def test_byte_truncated_fair_page_executes_its_tail_before_new_priority_traffic(tmp_path,monkeypatch,cutoff):
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    from leakguard_core.api import ScanConfig
    from leakguard_core import backends
    from leakguard_host.protection import defaults
    from leakguard_vault.partitions import EncryptedPartitions
    groups={}
    for number in range(4096):
        path=tmp_path/f'input-{number:04}.txt'
        group=groups.setdefault(EncryptedPartitions.bucket(str(path)),[]);group.append(path)
        if len(group)==6:paths=sorted(group);break
    for path in paths:path.write_text('ordinary synthetic budget control')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-execution-fairness')
    source={'id':'source','root':str(tmp_path),'kind':'local','exclusions':[]}
    job={'inventory_generation':1,'inventory_complete':True,'slices':0,'content_cursor':0,'files_scanned':0,'new_findings':0,'reconcile_cursor':256}
    def row(path,priority):
        # Model metadata admission exhausting 32 MiB after one file; actual
        # scanner inputs remain small, real, source-bound regular files.
        return (str(path),'source','file',_sig(path.stat()),'pending',priority,1,20_000_000 if cutoff=='byte-budget' else path.stat().st_size,None,None)
    store.inventory_put([row(path,200) for path in paths[:3]])
    child=store._partitions.get(EncryptedPartitions.bucket(str(paths[0])))
    age=child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(paths[1]),)).fetchone()[0]
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}))
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',lambda *a,**k:('synthetic-runtime',True))
    monkeypatch.setattr(backends,'detect',lambda *a,**k:())
    if cutoff=='scanner-budget':
        from dataclasses import replace
        from leakguard_core.api import Scanner
        from leakguard_core.models import CoverageIssue,ErrorCode
        original=Scanner.scan_within
        def partial(self,root,files,**kwargs):
            report=original(self,root,files[:1],**kwargs)
            from leakguard_core.scan_policy import evaluate
            issues=(*report.issues,CoverageIssue(ErrorCode.BUDGET_EXHAUSTED,required=True))
            coverage,decision=evaluate(report.results,policy=kwargs['policy'],policy_id=report.policy_id,enumeration_complete=False,issues=issues)
            return replace(report,coverage=coverage,decision=decision,issues=issues)
        monkeypatch.setattr(Scanner,'scan_within',partial)
    try:
        owner.tick(source,job,defaults(),cancel=lambda:False)
        assert job['files_scanned']==1
        child=store._partitions.get(EncryptedPartitions.bucket(str(paths[0])))
        assert child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(paths[1]),)).fetchone()[0]==age
        for step in (1,2):
            store.inventory_put([row(paths[step+2],0)])
            job['slices']=step
            owner.tick(source,job,defaults(),cancel=lambda:False)
        child=store._partitions.get(EncryptedPartitions.bucket(str(paths[0])))
        assert all(child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(path),)).fetchone()[0]=='inspected' for path in paths[:3])
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(paths[3]),)).fetchone()[0]=='pending'
    finally:owner.close();store.close()


def test_deadline_before_execution_retains_page_without_aging_unattempted_work(tmp_path,monkeypatch):
    from contextlib import contextmanager
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    from leakguard_core.api import ScanConfig
    from leakguard_host.protection import defaults
    file=tmp_path/'ordinary.txt';file.write_text('ordinary synthetic deadline control')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-deadline-fairness')
    store.inventory_put([(str(file),'source','file',_sig(file.stat()),'pending',200,1,file.stat().st_size,None,None)])
    source={'id':'source','root':str(tmp_path),'kind':'local','exclusions':[]}
    job={'inventory_generation':1,'inventory_complete':True,'slices':0,'content_cursor':0,'files_scanned':0,'new_findings':0,'reconcile_cursor':256}
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}));owner.identity=lambda settings:{'runtime_id':'synthetic','policy_id':'synthetic'}
    clock=[0.];monkeypatch.setattr('leakguard_host.discovery.time.monotonic',lambda:clock[0])
    @contextmanager
    def delayed_scanner(view):
        clock[0]=11.
        yield None
    owner.scanner=delayed_scanner
    try:
        child=store._partitions.get(store._partitions.bucket(str(file)))
        age=child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(file),)).fetchone()[0]
        owner.tick(source,job,defaults(),cancel=lambda:False)
        assert job['files_scanned']==0 and job['content_remainder']==[str(file)]
        child=store._partitions.get(store._partitions.bucket(str(file)))
        assert child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(file),)).fetchone()[0]==age
        assert store.inventory_counts()=={'pending':1}
    finally:owner.close();store.close()


@__import__('pytest').mark.parametrize('slot',[0,1,5])
def test_observed_parent_change_executes_bounded_followup_before_unrelated_backfill(tmp_path,monkeypatch,slot):
    from types import SimpleNamespace
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    from leakguard_core.api import ScanConfig
    from leakguard_core import backends
    from leakguard_host.protection import defaults
    root=tmp_path/'inputs';root.mkdir();low=root/'node_modules';low.mkdir()
    known=root/'known.env';known.write_text('ordinary synthetic known-version control')
    negative=low/'ordinary.txt';negative.write_text('ordinary synthetic negative')
    oldest=root/'oldest.txt';oldest.write_text('ordinary synthetic oldest control')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-observed-followup')
    source={'id':'source','root':str(root),'kind':'local','exclusions':[]}
    store.inventory_put([(str(root),'source','directory',_sig(root.stat()),'enumerated',20,1,0,None,None),
                         (str(low),'source','directory',_sig(low.stat()),'enumerating',200,1,0,None,None),
                         (str(known),'source','file',_sig(known.stat()),'inspected',0,1,known.stat().st_size,None,None),
                         (str(negative),'source','file',_sig(negative.stat()),'pending',200,1,negative.stat().st_size,None,None),
                         (str(oldest),'source','file',_sig(oldest.stat()),'pending',200,1,oldest.stat().st_size,None,None)])
    new=root/'genuinely-new.env';new.write_text('ordinary synthetic new-version control')
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}))
    # Model a large unrelated backlog whose ordinary page cannot reach this
    # parent's shard in this slice. The metadata worker and scanner stay real.
    def unrelated_page(source,job,kind,status,**kwargs):
        return store.inventory_selected(source['id'],'file',status,[str(oldest)],1) if kind=='file' else []
    owner.inventory_page=unrelated_page
    store.query_findings_page=lambda **kwargs:SimpleNamespace(rows=[{'source':{'path':str(known)},'state':'unknown'}],next_cursor=None)
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',lambda *a,**k:('synthetic-runtime',True))
    monkeypatch.setattr(backends,'detect',lambda *a,**k:())
    job={'inventory_generation':1,'inventory_complete':False,'slices':slot,'content_cursor':0,'files_scanned':0,'new_findings':0,'metadata_enumerated':0,'unknown_descendants':0,'reconcile_cursor':256}
    try:
        owner.tick(source,job,defaults(),cancel=lambda:False)
        for path in (new,negative):
            child=store._partitions.get(store._partitions.bucket(str(path)))
            row=child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(path),)).fetchone()
            assert (not row or row[0]!='inspected') if slot==0 else (row and row[0]=='inspected'), 'observed changes must progress without consuming the oldest slot'
        child=store._partitions.get(store._partitions.bucket(str(oldest)))
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(oldest),)).fetchone()[0]=='inspected'
        assert job['files_scanned']==(1 if slot==0 else 3)
        if slot==0:
            job['slices']=1
            owner.tick(source,job,defaults(),cancel=lambda:False)
            for path in (new,negative):
                child=store._partitions.get(store._partitions.bucket(str(path)))
                assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(path),)).fetchone()[0]=='inspected', 'a deferred metadata event was lost between slices'
            assert job['files_scanned']==3
    finally:owner.close();store.close()


@__import__('pytest').mark.parametrize('tail_size',[1,100])
def test_observed_arrivals_cannot_consume_every_reserved_oldest_slot(tmp_path,monkeypatch,tail_size):
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    from leakguard_core.api import ScanConfig
    from leakguard_core import backends
    from leakguard_host.protection import defaults
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-replenished-tail')
    oldest=tmp_path/'oldest.txt';oldest.write_text('ordinary synthetic oldest control')
    hot=[tmp_path/f'priority-{i:03}.env' for i in range(tail_size+12)]
    for path in hot:path.write_text('ordinary synthetic observed arrival')
    def row(path,priority):return (str(path),'source','file',_sig(path.stat()),'pending',priority,1,path.stat().st_size,None,None)
    store.inventory_put([row(oldest,200),*[row(path,0) for path in hot[:tail_size]]])
    source={'id':'source','root':str(tmp_path),'kind':'local','exclusions':[]}
    job={'inventory_generation':1,'inventory_complete':True,'slices':0,'content_cursor':0,'fair_content_cursor':int(store._partitions.bucket(str(oldest))[1:],16),'content_remainder':[str(path) for path in hot[:tail_size]],'content_batch':1,'files_scanned':0,'new_findings':0,'reconcile_cursor':256}
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}))
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',lambda *a,**k:('synthetic-runtime',True))
    monkeypatch.setattr(backends,'detect',lambda *a,**k:())
    child=store._partitions.get(store._partitions.bucket(str(hot[tail_size-1])))
    age=child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(hot[tail_size-1]),)).fetchone()[0]
    try:
        for step in range(12):
            store.inventory_put([row(hot[tail_size+step],0)])
            owner._known_availability=lambda *a,**k:[(str(hot[tail_size+step]),'file')]
            job['slices']=step
            owner.tick(source,job,defaults(),cancel=lambda:False)
            assert len(job['content_remainder'])<=100
            if step==0 and tail_size==100:
                child=store._partitions.get(store._partitions.bucket(str(hot[tail_size-1])))
                assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(hot[tail_size-1]),)).fetchone()[0]=='pending'
                assert child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(hot[tail_size-1]),)).fetchone()[0]==age
        child=store._partitions.get(store._partitions.bucket(str(oldest)))
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(oldest),)).fetchone()[0]=='inspected', 'observed replenishment consumed every oldest-work execution slot'
    finally:owner.close();store.close()


def test_incomplete_result_keeps_source_fenced_retry_on_saved_page(tmp_path,monkeypatch):
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    from leakguard_core.api import ScanConfig
    from leakguard_core import backends
    from leakguard_host.protection import defaults
    file=tmp_path/'retry.env';file.write_text('ordinary synthetic retry control')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-incomplete-retry')
    source={'id':'source','root':str(tmp_path),'kind':'local','exclusions':[]}
    store.inventory_put([(str(file),'source','file',_sig(file.stat()),'pending',0,1,file.stat().st_size,None,None)])
    job={'inventory_generation':1,'inventory_complete':True,'slices':0,'content_cursor':0,'files_scanned':0,'new_findings':0,'reconcile_cursor':256}
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}));calls=[]
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',lambda *a,**k:('synthetic-runtime',True))
    def interrupted_once(*args,**kwargs):
        calls.append(True)
        if len(calls)==1:raise backends.BackendError('budget-exhausted')
        return ()
    monkeypatch.setattr(backends,'detect',interrupted_once)
    try:
        owner.tick(source,job,defaults(),cancel=lambda:False)
        child=store._partitions.get(store._partitions.bucket(str(file)))
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(file),)).fetchone()[0]=='pending'
        assert job.get('content_remainder')==[str(file)], 'an incomplete actual result lost its immediate retry'
        owner.inventory_page=lambda *a,**k:[];job['slices']=1
        owner.tick(source,job,defaults(),cancel=lambda:False)
        child=store._partitions.get(store._partitions.bucket(str(file)))
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(file),)).fetchone()[0]=='inspected'
        assert not job['content_remainder'] and len(calls)==2
    finally:owner.close();store.close()


def test_new_metadata_version_executes_despite_full_saved_page_and_completed_siblings(tmp_path,monkeypatch):
    from contextlib import contextmanager
    from leakguard_host import discovery
    from leakguard_core.api import ScanConfig
    from leakguard_core import backends
    from leakguard_host.protection import defaults
    root=tmp_path/'inputs';root.mkdir();low=root/'node_modules';low.mkdir()
    completed=[root/f'a-{i:02}.env' for i in range(30)]
    backlog=[low/f'old-{i:03}.txt' for i in range(100)]
    for path in [*completed,*backlog]:path.write_text('ordinary synthetic saved-page control')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-full-saved-page')
    source={'id':'source','root':str(root),'kind':'local','exclusions':[]}
    def row(path,state):return (str(path),'source','file',discovery._sig(path.stat()),state,discovery._priority(path),1,path.stat().st_size,None,None)
    store.inventory_put([row(path,'inspected') for path in completed]+[row(path,'pending') for path in backlog])
    store.inventory_put([(str(root),'source','directory',discovery._sig(root.stat()),'enumerating',20,1,0,None,'metadata-version-refresh-during-backfill')])
    new=root/'z-new.env';new.write_text('ordinary synthetic genuinely new version')
    original=discovery.navigation._scoped_scandir
    @contextmanager
    def ordered(*args):
        with original(*args) as iterator:yield iter(sorted(iterator,key=lambda entry:entry.name))
    monkeypatch.setattr(discovery.navigation,'_scoped_scandir',ordered)
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',lambda *a,**k:('synthetic-runtime',True))
    monkeypatch.setattr(backends,'detect',lambda *a,**k:())
    job={'inventory_generation':1,'inventory_complete':False,'slices':1,'content_batch':4,'content_remainder':[str(path) for path in backlog],'files_scanned':0,'new_findings':0,'metadata_enumerated':0,'unknown_descendants':0,'reconcile_cursor':256}
    owner=discovery.DiscoveryCoordinator(store,ScanConfig.from_mapping({}))
    owner.inventory_page=lambda *a,**k:[]
    owner._known_availability=lambda *a,**k:[(str(root),'directory')]
    child=store._partitions.get(store._partitions.bucket(str(backlog[-1])))
    age=child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(backlog[-1]),)).fetchone()[0]
    try:
        owner.tick(source,job,defaults(),cancel=lambda:False)
        child=store._partitions.get(store._partitions.bucket(str(new)))
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(new),)).fetchone()[0]=='inspected', 'a discovered new version was hidden behind a saturated saved page'
        assert len(job['content_remainder'])<=100
        child=store._partitions.get(store._partitions.bucket(str(backlog[-1])))
        assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(backlog[-1]),)).fetchone()[0]=='pending'
        assert child.conn.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(str(backlog[-1]),)).fetchone()[0]==age
    finally:owner.close();store.close()


def test_deferred_observed_version_keeps_fifo_execution_under_new_events(tmp_path,monkeypatch):
    from contextlib import contextmanager
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    from leakguard_core.api import ScanConfig
    from leakguard_core import backends
    from leakguard_host.protection import defaults
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-observed-event-fifo')
    backlog=[tmp_path/f'old-{i:03}.txt' for i in range(100)]
    events=[tmp_path/f'new-{i:03}.env' for i in range(3)]
    for path in [*backlog,*events]:path.write_text('ordinary synthetic event fairness control')
    def row(path):return (str(path),'source','file',_sig(path.stat()),'pending',0,1,path.stat().st_size,None,None)
    store.inventory_put([row(path) for path in [*backlog,*events]])
    source={'id':'source','root':str(tmp_path),'kind':'local','exclusions':[]}
    job={'inventory_generation':1,'inventory_complete':True,'slices':1,'content_batch':1,'content_remainder':[str(path) for path in backlog],'files_scanned':0,'new_findings':0,'reconcile_cursor':256}
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}));original=owner.scanner
    owner.identity=lambda settings:{'runtime_id':'synthetic-runtime','policy_id':'synthetic-policy'}
    owner.inventory_page=lambda *a,**k:[]
    owner._known_availability=lambda *a,**k:[(str(events[0]),'file')]
    clock=[0.];monkeypatch.setattr('leakguard_host.discovery.time.monotonic',lambda:clock[0])
    @contextmanager
    def delayed(view):
        clock[0]=11.
        yield None
    owner.scanner=delayed
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',lambda *a,**k:('synthetic-runtime',True))
    monkeypatch.setattr(backends,'detect',lambda *a,**k:())
    try:
        owner.tick(source,job,defaults(),cancel=lambda:False)
        assert job['files_scanned']==0 and str(events[0]) in job['content_remainder']
        # Budget-truncated event admission survives a serialized scheduler
        # checkpoint; subsequent events cannot repeatedly overtake it.
        job=__import__('json').loads(__import__('json').dumps(job));owner.scanner=original
        for step in (1,2):
            clock[0]=0.;job['slices']=step+1
            owner._known_availability=lambda *a,**k:[(str(events[step]),'file')]
            owner.tick(source,job,defaults(),cancel=lambda:False)
            child=store._partitions.get(store._partitions.bucket(str(events[step-1])))
            assert child.conn.execute('SELECT status FROM inventory WHERE path=?',(str(events[step-1]),)).fetchone()[0]=='inspected', 'new events overtook an unexecuted observed version'
            assert len(job['content_remainder'])<=100
    finally:owner.close();store.close()


def test_later_metadata_pages_do_not_overtake_an_earlier_changed_version(tmp_path):
    import time
    from leakguard_host.discovery import DiscoveryCoordinator,_sig
    first=tmp_path/'z-first';later=tmp_path/'a-later';first.mkdir();later.mkdir()
    initial=first/'initial.env';initial.write_text('ordinary synthetic first metadata page')
    for number in range(30):(later/f'{number:02}.env').write_text('ordinary synthetic later metadata page')
    store=EncryptedScanStore.create(tmp_path/'observations.lgo','synthetic-metadata-event-fifo')
    source={'id':'source','root':str(tmp_path),'kind':'local','exclusions':[]}
    store.inventory_put([(str(path),'source','directory',_sig(path.stat()),'enumerating',0,1,0,None,None) for path in (first,later)])
    job={'inventory_generation':1,'slices':1,'metadata_enumerated':0,'unknown_descendants':0}
    owner=DiscoveryCoordinator(store,None);owner.inventory_page=lambda *a,**k:[];followup=[]
    try:
        owner._enumerate(source,job,{'exclusions':[]},lambda:False,time.monotonic()+2,observed=[(str(path),'directory') for path in (first,later)],content_followup=followup)
        assert len(followup)==25 and followup[0]==str(initial), 'later metadata pages replaced an unexecuted changed version'
    finally:owner.close();store.close()
