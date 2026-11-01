"""Synthetic durable chronology and constant-work read projection controls."""
from unittest.mock import patch
import json
import pytest
from leakguard_vault import EncryptedScanStore
from leakguard_vault.partitions import EncryptedPartitions


PHRASE = 'synthetic-inspection-evidence-passphrase'


def entry(path='/synthetic/pending.txt', signature='v1', generation=7, location='synthetic', state='pending'):
    return (path,location,'file',signature,state,100,generation,16,None,None)


def chronology(store,path):
    child=store._partitions.get(EncryptedPartitions.bucket(path))
    return child.conn.execute('SELECT pending_since,last_complete_at FROM inventory_chronology WHERE path=?',(path,)).fetchone()


def put(store, row, at):
    with patch('leakguard_vault.inspection.time.time',return_value=at):
        store.inventory_put([row])


def test_unchanged_rediscovery_admission_retry_and_reopen_preserve_pending_age(tmp_path):
    path=tmp_path/'observations.lgo'
    store=EncryptedScanStore.create(path,PHRASE)
    put(store,entry(),100)
    put(store,entry(),200)
    store.inventory_admitted(['/synthetic/pending.txt'])
    store.inventory_set('/synthetic/pending.txt','pending',detail='bounded-retry')
    assert chronology(store,'/synthetic/pending.txt') == (100,None)
    store.checkpoint()
    before=store.inspection_evidence()
    store.close()
    store=EncryptedScanStore.open(path,PHRASE)
    try:
        assert chronology(store,'/synthetic/pending.txt') == (100,None)
        assert store.inspection_evidence() == before
        assert before['pending'] == {'with_known_age':1,'with_unknown_age':0,'oldest_observed_pending_at':100}
        assert before['completed']['ordinary'] == 0
    finally:store.close()


@pytest.mark.parametrize('changes', [
    {'signature':'v2'}, {'generation':8}, {'location':'replacement-source'}])
def test_new_content_generation_or_source_cannot_inherit_old_pending_age(tmp_path,changes):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    try:
        put(store,entry(),100)
        put(store,entry(**changes),500)
        assert chronology(store,'/synthetic/pending.txt') == (500,None)
    finally:store.close()


def test_legacy_pending_remains_unknown_until_a_real_new_version(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    legacy='/synthetic/legacy.txt'
    with store.partition(EncryptedPartitions.bucket(legacy)) as child:
        child.conn.execute('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?)',entry(legacy))
    store.checkpoint()
    with patch('leakguard_vault.inspection.time.time',return_value=500):
        store.inventory_put([entry(legacy)])
    assert chronology(store,legacy) == (None,None)
    store.checkpoint()
    evidence=store.inspection_evidence()
    assert evidence['pending']['with_unknown_age'] == 1
    assert evidence['pending']['oldest_observed_pending_at'] is None
    store.close()
    store=EncryptedScanStore.open(tmp_path/'observations.lgo',PHRASE)
    try:
        assert chronology(store,legacy) == (None,None)
        put(store,entry(legacy,signature='changed'),800)
        assert chronology(store,legacy) == (800,None)
    finally:store.close()


def test_only_complete_published_inspections_increment_disjoint_route_counters(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    try:
        for index,route in enumerate(('ordinary','observed_change','reserved_oldest')):
            name=f'/synthetic/{index}.txt'
            put(store,entry(name),100+index)
            with patch('leakguard_vault.inspection.time.time',return_value=300):
                store.inventory_set(name,'inspected',completion_route=route)
                store.inventory_set(name,'inspected',completion_route=route) # no double counting
            assert chronology(store,name) == (None,300)
        put(store,entry('/synthetic/omitted.docx'),100)
        store.inventory_set('/synthetic/omitted.docx','inspected-with-omissions',completion_route='ordinary')
        put(store,entry('/synthetic/terminal.txt'),100)
        store.inventory_set('/synthetic/terminal.txt','inspection-error')
        put(store,entry('/synthetic/deferred.txt'),100)
        store.checkpoint()
        evidence=store.inspection_evidence()
        assert evidence['completed'] == {'ordinary':1,'observed_change':1,'reserved_oldest':1,'oldest_observed_wait_seconds':200}
        assert evidence['last_complete_inspection_at'] == 300
        assert evidence['pending']['with_known_age'] == 1
        assert chronology(store,'/synthetic/deferred.txt') == (100,None)
        # New generation cannot relabel a previous inspection as complete now.
        put(store,entry('/synthetic/0.txt',generation=8),600)
        assert chronology(store,'/synthetic/0.txt')[1] is None
    finally:store.close()


def test_status_projection_opens_no_partitions_and_executes_no_inventory_queries(tmp_path,monkeypatch):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    for i in range(300):
        put(store,entry(f'/synthetic/{i}.txt'),100)
    store.checkpoint()
    expected=store.inspection_evidence()
    def forbidden(*args,**kwargs):raise AssertionError('polling must read catalog metadata only')
    monkeypatch.setattr(store._partitions,'get',forbidden)
    for child,_,_ in store._partitions.cache.values():
        child.conn.set_authorizer(lambda *args: 1) # deny every SQL operation
    try:
        for _ in range(50):
            assert store.inspection_evidence() == expected
        assert expected['pending']['with_known_age'] == 300
        assert len(json.dumps(expected)) < 4096
    finally:
        for child,_,_ in store._partitions.cache.values():child.conn.set_authorizer(None)
        store._dispose()


def test_chronology_journal_replays_against_old_base_and_crash_rolls_back(tmp_path):
    path=tmp_path/'observations.lgo'
    store=EncryptedScanStore.create(path,PHRASE)
    put(store,entry(),100)
    store.checkpoint()
    bucket=EncryptedPartitions.bucket('/synthetic/pending.txt')
    base=store._partitions.catalog[bucket]['base']
    put(store,entry(signature='v2'),500)
    store.checkpoint()
    assert store._partitions.catalog[bucket]['base'] == base
    assert store._partitions.catalog[bucket]['logs']
    put(store,entry(signature='uncommitted-v3'),800)
    store._partitions.prepare()
    store._dispose() # simulated crash before publishing owner catalog
    store=EncryptedScanStore.open(path,PHRASE)
    try:
        assert chronology(store,'/synthetic/pending.txt') == (500,None)
        for encrypted in [path,*path.with_name(path.name+'.parts').glob('*.lgo')]:
            assert b'/synthetic/pending.txt' not in encrypted.read_bytes()
    finally:store.close()


def test_failed_chronology_write_rolls_back_inventory_and_replay_journal(tmp_path):
    import sqlite3
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    put(store,entry(),100);store.checkpoint()
    bucket=EncryptedPartitions.bucket('/synthetic/pending.txt')
    child=store._partitions.get(bucket)
    child.conn.execute("CREATE TRIGGER reject_chronology BEFORE UPDATE ON inventory_chronology BEGIN SELECT RAISE(ABORT,'synthetic-chronology-failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        store.inventory_set('/synthetic/pending.txt','inspected',completion_route='ordinary')
    assert child.conn.execute("SELECT status FROM inventory WHERE path='/synthetic/pending.txt'").fetchone() == ('pending',)
    assert chronology(store,'/synthetic/pending.txt') == (100,None)
    store.checkpoint();store.close()
    store=EncryptedScanStore.open(tmp_path/'observations.lgo',PHRASE)
    try:
        assert chronology(store,'/synthetic/pending.txt') == (100,None)
        assert store.inspection_evidence()['completed']['ordinary'] == 0
    finally:store.close()


def test_replacement_source_with_identical_signature_cannot_inherit_inspected_state(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    try:
        put(store,entry(location='source-a'),100)
        with patch('leakguard_vault.inspection.time.time',return_value=200):
            store.inventory_set('/synthetic/pending.txt','inspected',completion_route='ordinary')
        put(store,entry(location='source-b',generation=8),500)
        child=store._partitions.get(EncryptedPartitions.bucket('/synthetic/pending.txt'))
        assert child.conn.execute('SELECT location,status,generation FROM inventory').fetchone()==('source-b','pending',8)
        assert chronology(store,'/synthetic/pending.txt')==(500,None)
        store.checkpoint()
        evidence=store.inspection_evidence()
        assert evidence['pending']['with_known_age']==1
        assert evidence['completed']['ordinary']==1 # historical source-a event only
    finally:store.close()


def test_same_source_exact_version_reconciliation_retains_classification_without_new_inspection_time(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    try:
        put(store,entry(),100)
        with patch('leakguard_vault.inspection.time.time',return_value=200):
            store.inventory_set('/synthetic/pending.txt','inspected',completion_route='ordinary')
        put(store,entry(generation=8),500)
        child=store._partitions.get(EncryptedPartitions.bucket('/synthetic/pending.txt'))
        assert child.conn.execute('SELECT status,generation FROM inventory').fetchone()==('inspected',8)
        assert chronology(store,'/synthetic/pending.txt')==(None,None)
        store.checkpoint()
        assert store.inspection_evidence()['completed']['ordinary']==1
    finally:store.close()


def test_regular_inventory_page_fences_generation_without_opening_old_content(tmp_path):
    store=EncryptedScanStore.create(tmp_path/'observations.lgo',PHRASE)
    try:
        put(store,entry(),100)
        old,_=store.inventory_page('synthetic','file','pending',generation=7)
        assert len(old)==1
        new,_=store.inventory_page('synthetic','file','pending',generation=8)
        assert new==[]
    finally:store.close()
