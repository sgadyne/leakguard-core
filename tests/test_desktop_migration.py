import importlib.util,json
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('beta_bootstrap',Path(__file__).parents[1]/'deploy/desktop/bootstrap.py');bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)

def test_profile_backup_rollback_and_exclusive_owner(tmp_path):
 profile=tmp_path/'profile';state=profile/'state';state.mkdir(parents=True)
 (state/'observations.lgo').write_bytes(b'synthetic ciphertext scan bytes');(state/'credentials.lgv').write_bytes(b'synthetic ciphertext credential bytes');(state/'annotations.json').write_text('{"synthetic":"reviewed"}')
 bootstrap.atomic_json(profile/'desktop-runtime.json',{'runtimeId':'a'*64,'status':'ready'})
 lock=bootstrap.PreparationLock(state/'.buddy-owner.lock')
 with pytest.raises(bootstrap.PreparationError,match='profile-in-use'):bootstrap.PreparationLock(state/'.buddy-owner.lock','profile-in-use')
 before=bootstrap.records(profile);backup=bootstrap.migration_backup(tmp_path,profile,{'runtimeId':'a'*64},{'runtimeId':'b'*64})
 (state/'annotations.json').write_text('{"synthetic":"changed"}');(state/'new-candidate-file').write_bytes(b'synthetic addition');bootstrap.atomic_json(profile/'desktop-runtime.json',{'runtimeId':'b'*64,'status':'preparing'})
 bootstrap.restore_migration(tmp_path,profile,backup);assert bootstrap.records(profile)==before
 with pytest.raises(bootstrap.PreparationError,match='profile-in-use'):bootstrap.PreparationLock(state/'.buddy-owner.lock','profile-in-use')
 lock.close()
