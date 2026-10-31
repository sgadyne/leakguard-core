"""New/changed content is admitted on refresh while initial backlog persists."""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.models import BytesInput, ScanLimits, ScanPolicy
from leakguard_host.discovery import DiscoveryCoordinator, _sig
from leakguard_host.discovery_remote import RemoteDiscovery, sig
from leakguard_host.protection import defaults
from leakguard_host.scheduler import HostService
from leakguard_vault import EncryptedScanStore


def row(store,path):
    child=store._partitions.get(store._partitions.bucket(str(path)))
    return child.conn.execute('SELECT * FROM inventory WHERE path=?',(str(path),)).fetchone()


def test_refresh_keeps_generation_active_cursor_and_pending_content(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'store.lgo','synthetic-backfill-store-passphrase')
    source={'id':'synthetic','root':str(tmp_path),'kind':'local','exclusions':[]}
    root=str(tmp_path/'known');active=str(tmp_path/'backlog');pending=str(tmp_path/'pending.env')
    cursor=json.dumps({'signature':'synthetic','entries':200000,'prefix':'a'*64})
    store.inventory_put([(root,source['id'],'directory','known','enumerated',0,7,0,None,None),
                         (active,source['id'],'directory','active','enumerating',200,7,0,cursor,None),
                         (pending,source['id'],'file','pending','pending',200,7,10,None,None)])
    job={'inventory_generation':7,'inventory_complete':False,'refresh_requested':True}
    coordinator=DiscoveryCoordinator(store,ScanConfig.from_mapping({}),clock=lambda:100)
    coordinator._refresh_metadata(source,job)
    assert job['inventory_generation']==7
    assert job['inventory_complete'] is False
    assert job['refresh_requested'] is False
    assert row(store,root)[4]=='enumerating'
    assert row(store,active)[8]==cursor
    assert row(store,pending)[4]=='pending'
    # Re-observing the active child from its refreshed parent must not reset it.
    store.inventory_put([(active,source['id'],'directory','active','enumerating',200,7,0,None,None)])
    assert row(store,active)[8]==cursor
    store.checkpoint();store.close()
    store=EncryptedScanStore.open(tmp_path/'store.lgo','synthetic-backfill-store-passphrase')
    assert row(store,active)[8]==cursor
    assert row(store,pending)[4]=='pending'
    store.close();coordinator.close()


def test_changed_directory_resets_cursor_despite_backfill_preservation(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'store.lgo','synthetic-backfill-store-passphrase')
    active=str(tmp_path/'active')
    store.inventory_put([(active,'synthetic','directory','old','enumerating',200,7,0,'old-cursor',None)])
    store.inventory_put([(active,'synthetic','directory','new','enumerating',200,7,0,None,None)])
    assert row(store,active)[8] is None
    store.close()


def test_local_new_and_changed_metadata_precedes_remaining_backlog(tmp_path):
    root=tmp_path/'source';root.mkdir();backlog=root/'backlog';backlog.mkdir()
    old=root/'changed.env';old.write_text('password="synthetic-before"')
    old_signature=_sig(old.stat())
    store=EncryptedScanStore.create(tmp_path/'store.lgo','synthetic-backfill-store-passphrase')
    source={'id':'synthetic','root':str(root),'kind':'local','exclusions':[]}
    active_cursor=json.dumps({'signature':_sig(backlog.stat()),'entries':0,'prefix':hashlib.sha256().hexdigest()})
    store.inventory_put([(str(root),source['id'],'directory',_sig(root.stat()),'enumerated',0,7,0,None,None),
        (str(backlog),source['id'],'directory',_sig(backlog.stat()),'enumerating',200,7,0,active_cursor,None),
        (str(old),source['id'],'file',old_signature,'inspected',0,7,10,None,None)])
    new=root/'new.env';new.write_text('password="synthetic-new"');old.write_text('password="synthetic-changed-longer"')
    coordinator=DiscoveryCoordinator(store,ScanConfig.from_mapping({}))
    job={'inventory_generation':7,'inventory_complete':False,'refresh_requested':True,
         'inventory_cursor':0,'content_cursor':0,'slices':1,'metadata_enumerated':0,'unknown_descendants':0}
    coordinator._refresh_metadata(source,job)
    import leakguard_host.navigation as navigation
    original=navigation._scoped_scandir;clock=[0.]
    @contextmanager
    def bounded(path,scope,expected):
        if path==backlog:
            def entries():
                for i in range(100000):
                    clock[0]+=.1
                    yield SimpleNamespace(name=f'pending-{i}.txt',stat=lambda **kw:old.stat())
            yield entries()
        else:
            with original(path,scope,expected) as entries:yield entries
    with patch('leakguard_host.discovery.navigation._scoped_scandir',bounded),patch('leakguard_host.discovery.time.monotonic',lambda:clock[0]):
        coordinator._enumerate(source,job,defaults(),lambda:False,1)
    assert row(store,new)[4]=='pending'
    assert row(store,old)[4]=='changed'
    assert row(store,backlog)[4]=='enumerating'
    assert job['inventory_complete'] is False
    # Real source-boundary/native scanning admits the refreshed file versions,
    # independently of the many lower-priority pending metadata entries.
    binary=os.environ.get('LEAKGUARD_GITLEAKS')
    if binary:
        config=ScanConfig.from_mapping({'gitleaks_executable':binary})
        with Scanner.open(config=config) as scanner:
            report=scanner.scan_within(root,[new,old],policy=ScanPolicy.inventory(),limits=ScanLimits(20,2),use_cache=False)
        assert len(report.results)==2
        assert all(r.findings and r.coverage.value=='complete' for r in report.results)
    coordinator.close();store.close()


def test_remote_refresh_discovers_new_and_changed_metadata_with_backlog(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'store.lgo','synthetic-backfill-store-passphrase')
    source={'id':'synthetic','root':'ssh://synthetic/home/test','remote_root':'/home/test',
            'kind':'ssh','ssh_target':'synthetic','exclusions':[],
            'remote_identity':{'machine':'safe','device':1},'remote_python_version':[3,11,2]}
    info=dict(st_dev=1,st_ino=2,st_mode=0o40700,st_size=0,st_mtime_ns=1,st_ctime_ns=1,st_flags=0)
    file_info={**info,'st_mode':0o100600,'st_size':40,'st_ino':3}
    root=source['root'];active=root+'/backlog';old=root+'/changed.env';new=root+'/new.env'
    active_cursor=json.dumps({'signature':sig(info),'entries':200000,'prefix':'a'*64})
    store.inventory_put([(root,source['id'],'directory',json.dumps(sig(info)),'enumerated',0,7,0,None,None),
        (active,source['id'],'directory',json.dumps(sig(info)),'enumerating',200,7,0,active_cursor,None),
        (old,source['id'],'file',json.dumps(sig(file_info)),'inspected',0,7,40,None,None)])
    owner=DiscoveryCoordinator(store,ScanConfig.from_mapping({}));owner.identity=lambda settings:{'policy_id':'safe','runtime_id':'safe'}
    remote=RemoteDiscovery(owner)
    def request(source,op,**kw):
        assert op=='enumerate'
        assert kw['path']=='/home/test'
        return {'info':info,'stable':True,'complete':True,'position':2,'prefix':'safe',
                'entries':[{'name':'changed.env','info':{**file_info,'st_mtime_ns':2}},
                           {'name':'new.env','info':{**file_info,'st_ino':4}}]}
    remote._request=request
    job={'inventory_generation':7,'inventory_complete':False,'refresh_requested':True,
         'inventory_cursor':0,'content_cursor':0,'slices':1,'metadata_enumerated':0,
         'unknown_descendants':0,'files_scanned':0,'new_findings':0}
    settings=defaults();settings['new_content']='inventory'
    result=remote.tick(source,job,settings,cancel=lambda:False)
    assert row(store,new)[4]=='pending'
    assert row(store,old)[4]=='changed'
    assert row(store,active)[8]==active_cursor
    assert result['inventory_complete'] is False
    assert job['inventory_generation']==7
    owner.close();store.close()


def test_manual_scan_now_requests_refresh_for_active_managed_backfill(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'store.lgo','synthetic-backfill-store-passphrase')
    host=HostService(config=ScanConfig.from_mapping({}),scan_store=store)
    source=host.add_source(tmp_path);host.manage_source(source['id']);job=host.submit(source['id'])
    host._state['jobs'][job['id']]['slices']=1
    first=host.submit(source['id']);second=host.submit(source['id'])
    assert first['id']==second['id']==job['id']
    assert second['refresh_requested'] is True
    assert second['refresh_revision']>=2
    host.stop();store.close()


@pytest.mark.skipif(not os.environ.get('LEAKGUARD_GITLEAKS'),reason='pinned native backend required')
def test_scheduled_refresh_publishes_new_and_changed_findings_before_backfill_finishes(tmp_path):
    root=tmp_path/'source';root.mkdir();backlog=root/'backlog';backlog.mkdir()
    changed=root/'changed.env';changed.write_text('password="synthetic-before"')
    previous_signature=_sig(changed.stat());root_signature=_sig(root.stat())
    config=ScanConfig.from_mapping({'gitleaks_executable':os.environ['LEAKGUARD_GITLEAKS']})
    phrase='synthetic-integrated-backfill-passphrase';path=tmp_path/'observations.lgo'
    store=EncryptedScanStore.create(path,phrase,config=config.to_mapping())
    wall=[10000.]
    host=HostService(config=config,scan_store=store,clock=lambda:wall[0])
    source=host.add_source(root);host.manage_source(source['id']);submitted=host.submit(source['id'])
    selected=host._source(source['id']);job=host._job(submitted['id'])
    host._discovery.begin(selected,job);generation=job['inventory_generation'];job['slices']=1
    selected['next_run_at']='1970-01-01T00:00:00+00:00'
    active_cursor=json.dumps({'signature':_sig(backlog.stat()),'entries':0,'prefix':hashlib.sha256().hexdigest()})
    store.inventory_put([(str(root),source['id'],'directory',root_signature,'enumerated',0,generation,0,None,None),
        (str(backlog),source['id'],'directory',_sig(backlog.stat()),'enumerating',200,generation,0,active_cursor,None),
        (str(changed),source['id'],'file',previous_signature,'inspected',0,generation,changed.stat().st_size,None,None)])
    new=root/'new.env';new.write_text('password="synthetic-new"');changed.write_text('password="synthetic-changed-value"')
    job['content_batch']=1
    import leakguard_host.navigation as navigation
    original=navigation._scoped_scandir;file_info=changed.stat()
    @contextmanager
    def wide(path,scope,expected):
        with original(path,scope,expected) as actual:
            if path==backlog:
                def entries():
                    for i in range(100000):
                        yield SimpleNamespace(name=f'pending-{i:06}.txt',stat=lambda **kw:file_info)
                yield entries()
            else:yield actual
    try:
        with patch('leakguard_host.discovery.navigation._scoped_scandir',wide):
            for tick in range(6):
                host.tick()
                if row(store,new) and row(store,new)[4]=='inspected' and row(store,changed)[4]=='inspected':break
        assert row(store,new)[4]=='inspected'
        assert row(store,changed)[4]=='inspected'
        current=host.job(submitted['id'])
        assert current['inventory_generation']==generation
        assert current['inventory_complete'] is False
        assert current['state']=='queued'
        assert current['pending_directories']>0 and current['pending_files']>0
        findings=[];cursor=None
        while True:
            page=store.query_findings_page(limit=100,cursor=cursor)
            findings.extend(page.rows);cursor=page.next_cursor
            if cursor is None:break
        for target in (new,changed):
            assert any(f['source']['path']==str(target) and f['state']=='active' and f['rule']=='literal-password' for f in findings)
        assert current.get('refresh_requested') is False,'a consumed request requeued itself'
    finally:host.stop();store.close()
    reopened=EncryptedScanStore.open(path,phrase,config=config.to_mapping())
    assert row(reopened,new)[4]=='inspected' and row(reopened,changed)[4]=='inspected'
    reopened.close()
