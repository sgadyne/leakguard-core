from pathlib import Path
import json
import pytest
from leakguard_buddy.backend import BuddyBackend
from leakguard_buddy.storage import StorageError

PASS='synthetic-storage-test-passphrase'

def backend(tmp_path):
 c=tmp_path/'config.json';c.write_text('{}')
 return BuddyBackend(state_dir=tmp_path/'profile',config_path=c,discovery_roots=())

def test_credentials_relocation_preserves_bytes_and_missing_destination_is_not_empty(tmp_path):
 b=backend(tmp_path);b.credential_create(PASS);entry=b.credential_save({'title':'Synthetic','secret':'synthetic-only-value'});b.credential_lock()
 original=b.credential_path;before=original.read_bytes();destination=tmp_path/'moved';destination.mkdir(mode=0o700)
 result=b.relocate_storage({'kind':'credentials','path':str(destination/'credentials.lgv')})
 assert original.read_bytes()==b.credential_path.read_bytes()==before
 assert result['credential_vault_locked']
 b.credential_unlock(PASS);assert b.credential_reveal(entry['id'])['secret']=='synthetic-only-value';b.close()
 moved=destination/'credentials.lgv';moved.rename(destination/'offline.lgv')
 b=backend(tmp_path)
 assert b.credential_status()['created'] and not b.credential_status()['available']
 with pytest.raises(StorageError,match='storage-unavailable'):b.credential_create(PASS)
 b.close()

def test_scan_partition_relocation_retains_unlocked_store_and_queue(tmp_path):
 b=backend(tmp_path);b.observation_create(PASS)
 store=b._observation_store;store.inventory_put([('/synthetic/fixture.env','local','file','sig','pending',10,1,12,None,None)]);store.checkpoint()
 old=b.observation_path;target=tmp_path/'new-scan';target.mkdir(mode=0o700)
 result=b.relocate_storage({'kind':'observations','path':str(target/'scan.lgo')})
 assert result['relocated'] and b.observation_status()['unlocked']
 assert b._observation_store.inventory_counts()['pending']==1
 assert old.read_bytes()==b.observation_path.read_bytes()
 b.close();b=backend(tmp_path);b.observation_unlock(PASS);assert b._observation_store.inventory_counts()['pending']==1;b.close()

def test_failed_relocation_preserves_configuration_and_original(tmp_path):
 b=backend(tmp_path);b.credential_create(PASS);old=b.credential_path;before=old.read_bytes();target=tmp_path/'exists.lgv';target.write_bytes(b'synthetic-existing-file')
 with pytest.raises(StorageError,match='storage-destination-exists'):b.relocate_storage({'kind':'credentials','path':str(target)})
 assert b.credential_path==old and old.read_bytes()==before
 b.credential_unlock(PASS);assert b.credential_status()['unlocked'];b.close()

def test_staged_vm_preferences_import_once_after_unlock(tmp_path,monkeypatch):
 from leakguard_host import HostService
 monkeypatch.setattr(HostService,'start',lambda self:None)
 profile=tmp_path/'profile';profile.mkdir()
 pending=profile/'pending-locations.json'
 choices=[{'kind':'ssh','target':'devbox','root':'/home/dev','label':'Dev VM'}]
 pending.write_text(json.dumps(choices))
 b=backend(tmp_path)
 assert b.settings()['pending_locations']==choices
 b.observation_create(PASS)
 assert not pending.exists()
 assert len(b._host.sources())==1
 assert b._host.sources()[0]['root']=='ssh://devbox/home/dev'
 b.close()
 # An interrupted import may retain the preferences after encrypted registration.
 pending.write_text(json.dumps(choices));b=backend(tmp_path);b.observation_unlock(PASS)
 assert len(b._host.sources())==1 and not pending.exists()
 b.close()
