from pathlib import Path
import json
import pytest
from leakguard_core.scan_store import StateError
from leakguard_vault import EncryptedScanStore

PASS='synthetic-partition-test-passphrase'
def rows(count,first=0):
 return [(f'/synthetic/configuration/project-{i%91}/file-{i}.env','mac','file',str(i),'pending',10,1,64,None,None) for i in range(first,first+count)]

def test_encrypted_partition_restart_and_bounded_cache(tmp_path):
 p=tmp_path/'s.lgo';s=EncryptedScanStore.create(p,PASS)
 s.inventory_put(rows(10000));s.checkpoint()
 assert len(s._partitions.cache)<=8
 assert sum(s.inventory_counts().values())==10000
 for r in rows(20):s.inventory_set(r[0],'inspected')
 s.checkpoint();s.close()
 s=EncryptedScanStore.open(p,PASS)
 assert s.inventory_counts()['inspected']==20
 assert sum(s.inventory_counts('mac').values())==10000
 for f in p.with_name(p.name+'.parts').iterdir():assert b'/synthetic/configuration' not in f.read_bytes()
 s.close()

def test_unpublished_partition_transaction_cannot_replace_durable_catalog(tmp_path):
 p=tmp_path/'s.lgo';s=EncryptedScanStore.create(p,PASS);s.inventory_put(rows(100));s.checkpoint()
 s.inventory_put(rows(100,100));s._partitions.prepare();s._dispose() # crash before owner publication
 s=EncryptedScanStore.open(p,PASS)
 assert sum(s.inventory_counts().values())==100
 s.checkpoint();referenced={n for x in s._partitions.catalog.values() for n in [x['base'],*x['logs']] if n}
 assert {x.name for x in s._partitions.directory.glob('*.lgo')}==referenced
 s.close()

def test_missing_partition_fails_without_empty_reinitialization(tmp_path):
 p=tmp_path/'s.lgo';s=EncryptedScanStore.create(p,PASS);r=rows(1)[0];s.inventory_put([r]);s.checkpoint();bucket=s._partitions.bucket(r[0]);name=s._partitions.catalog[bucket]['base'];s.close()
 (p.with_name(p.name+'.parts')/name).unlink();s=EncryptedScanStore.open(p,PASS)
 with pytest.raises(StateError,match='state-partition-unavailable'):
  with s.partition(bucket):pass
 s._dispose()

def test_changed_metadata_requeues_and_repeated_metadata_retains_inspection(tmp_path):
 p=tmp_path/'s.lgo';s=EncryptedScanStore.create(p,PASS);r=rows(1)[0];s.inventory_put([r]);s.inventory_set(r[0],'inspected');s.inventory_put([r]);assert s.inventory_counts()['inspected']==1
 changed=list(r);changed[3]='new-signature';s.inventory_put([tuple(changed)]);assert s.inventory_counts()['changed']==1;s.close()

def test_partition_backup_cannot_silently_omit_inventory(tmp_path):
 s=EncryptedScanStore.create(tmp_path/'s.lgo',PASS);s.inventory_put(rows(1))
 with pytest.raises(StateError,match='state-partition-backup-required'):s.backup(tmp_path/'bad.lgb',PASS)
 s.close()

def test_control_checkpoint_never_publishes_half_a_partition_transaction(tmp_path):
 p=tmp_path/'s.lgo';s=EncryptedScanStore.create(p,PASS);s.inventory_put(rows(100));s.save_host_state({'control':'running'})
 with s.transaction():
  s.inventory_put(rows(100,100))
  s.save_host_state({'control':'paused'})
 s._dispose() # Loss of the in-flight scan after a durable user-control response.
 s=EncryptedScanStore.open(p,PASS)
 assert s.load_host_state()=={'control':'paused'}
 assert sum(s.inventory_counts().values())==100
 s.close()


def test_json_encoded_journal_overhead_compacts_without_false_capacity_failure(tmp_path):
 from leakguard_vault import partitions as module
 p=tmp_path/'s.lgo';s=EncryptedScanStore.create(p,PASS);r=rows(1)[0];s.inventory_put([r]);s.checkpoint()
 bucket=s._partitions.bucket(r[0]);old_base=s._partitions.catalog[bucket]['base'];child=s._partitions.get(bucket);journal=s._partitions.cache[bucket][1];size=s._partitions.cache[bucket][2]
 count=0
 with child.conn:
  while size[0]<module._MAX_JOURNAL-512:
   child.conn.execute('INSERT INTO physical VALUES(?,?,?)',('synthetic-escaping-'+str(count),1,'\\'*100));count+=1
 assert size[0]<module._MAX_JOURNAL
 assert len(module.envelope.canonical(journal))>module._MAX_JOURNAL
 s.checkpoint()
 assert s._partitions.catalog[bucket]['base']!=old_base
 assert not s._partitions.catalog[bucket]['logs']
 s.close();s=EncryptedScanStore.open(p,PASS)
 assert s._partitions.get(bucket).conn.execute("SELECT count(*) FROM physical WHERE identity LIKE 'synthetic-escaping-%'").fetchone()[0]==count
 assert s.inventory_counts()=={'pending':1}
 s.close()
