"""Compact alpha regressions for persistence and credential capability boundaries."""
from pathlib import Path
import struct

import pytest

from leakguard_core.models import SourceKind, SourceRef
from leakguard_core.scan_store import StateError
from leakguard_vault import CredentialVault, EncryptedScanStore, NativeKeyring, VaultError
from leakguard_vault import _envelope as envelope
from leakguard_vault import _files

PASS = "synthetic-vault-passphrase"
SECRET = "synthetic-secret-7ff89f2967"


def assert_no_plaintext(root, *values):
    for path in root.rglob('*'):
        if path.is_file():
            content = path.read_bytes()
            for value in values:
                assert value.encode() not in content


def test_explicit_crud_lock_restart_and_capability(tmp_path):
    vault = CredentialVault(tmp_path / 'credentials.lgv')
    session = vault.create(PASS)
    entry = session.save_entry(title='Example', secret=SECRET, username='private-username', notes='private-notes', finding_id='finding-1')
    assert not {'secret', 'username', 'notes'} & entry.keys()
    assert_no_plaintext(tmp_path, SECRET, PASS, 'private-username', 'private-notes')
    assert session.reveal_entry(entry['id'])['secret'] == SECRET
    session.update_metadata(entry['id'], title='Renamed', finding_id=None)
    assert session.reveal_entry(entry['id'])['secret'] == SECRET
    assert session.reveal_entry(entry['id'])['username'] == 'private-username'
    vault.lock()
    with pytest.raises(VaultError, match='vault-locked'):
        session.reveal_entry(entry['id'])
    reopened = CredentialVault(tmp_path / 'credentials.lgv')
    unlocked = reopened.unlock(PASS)
    assert unlocked.list_entries()[0]['title'] == 'Renamed'
    unlocked.delete_entry(entry['id'])
    assert unlocked.list_entries() == ()
    reopened.lock()


def test_wrong_password_tamper_and_bounded_header(tmp_path):
    path = tmp_path / 'credentials.lgv'
    vault = CredentialVault(path)
    session = vault.create(PASS)
    session.save_entry(title='Example', secret=SECRET)
    vault.lock()
    original = path.read_bytes()
    with pytest.raises(VaultError, match='vault-authentication-failed'):
        vault.unlock('wrong-password')
    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(VaultError, match='vault-authentication-failed'):
        vault.unlock(PASS)
    header, _, ciphertext = envelope.parse(original, 'credentials')
    header['kdf']['memory_kib'] = 999999999
    encoded = envelope.canonical(header)
    path.write_bytes(envelope.MAGIC + struct.pack('>I', len(encoded)) + encoded + ciphertext)
    with pytest.raises(VaultError, match='vault-format-invalid'):
        vault.unlock(PASS)


def test_credential_portable_backup_and_exclusive_restore(tmp_path):
    source = CredentialVault(tmp_path / 'one.lgv')
    session = source.create(PASS)
    entry = session.save_entry(title='Example', secret=SECRET)
    session.backup(tmp_path / 'backup.lgb', 'portable-recovery-passphrase')
    source.lock()
    restored = CredentialVault(tmp_path / 'two.lgv')
    restored_session = restored.restore(tmp_path / 'backup.lgb', 'portable-recovery-passphrase', 'new-machine-passphrase')
    assert restored_session.reveal_entry(entry['id'])['secret'] == SECRET
    restored.lock()
    with pytest.raises(VaultError, match='vault-already-created'):
        restored.restore(tmp_path / 'backup.lgb', 'portable-recovery-passphrase', PASS)
    assert_no_plaintext(tmp_path, SECRET, PASS, 'portable-recovery-passphrase')


def test_credential_interrupted_replace_keeps_last_commit(tmp_path, monkeypatch):
    path = tmp_path / 'credentials.lgv'
    vault = CredentialVault(path)
    session = vault.create(PASS)
    entry = session.save_entry(title='Example', secret=SECRET)
    original = path.read_bytes()
    def fail(*args):
        raise OSError('synthetic private error')
    with monkeypatch.context() as patch:
        patch.setattr(_files.os, 'replace', fail)
        with pytest.raises(VaultError, match='vault-io-failed'):
            session.save_entry(entry_id=entry['id'], title='Changed', secret='replacement-synthetic-value')
    assert path.read_bytes() == original
    assert not list(tmp_path.glob('*.tmp'))
    recovered = vault.unlock(PASS)
    assert recovered.reveal_entry(entry['id'])['secret'] == SECRET
    vault.lock()


def test_single_process_owner_and_separate_keys(tmp_path):
    vault = CredentialVault(tmp_path / 'credentials.lgv')
    session = vault.create(PASS)
    with pytest.raises(VaultError, match='vault-busy'):
        CredentialVault(tmp_path / 'credentials.lgv').unlock(PASS)
    observations = EncryptedScanStore.create(tmp_path / 'observations.lgo', PASS)
    assert bytes(session._key) != bytes(observations._key)
    assert not hasattr(observations, 'reveal_entry')
    assert not hasattr(observations, 'conn')
    observations.close()
    vault.lock()


def test_observations_state_annotations_checkpoint_reopen(tmp_path):
    path = tmp_path / 'observations.lgo'
    store = EncryptedScanStore.create(path, PASS)
    store.save_host_state({'source': 'synthetic-private-location', 'progress': 1})
    store.set_annotation('finding-1', 'dismissed')
    source = SourceRef(SourceKind.FILESYSTEM, '/synthetic/private-path')
    assert store.reserve(source) == 1
    store.checkpoint()
    store.close()
    reopened = EncryptedScanStore.open(path, PASS)
    assert reopened.load_host_state()['progress'] == 1
    assert reopened.reserve(source) == 2
    assert reopened.get_annotation('finding-1')['state'] == 'dismissed'
    assert reopened.query_findings() == ()
    assert not reopened.status()['unattended_available']
    assert list(tmp_path.glob('*.sqlite*')) == []
    assert_no_plaintext(tmp_path, 'synthetic-private-location', '/synthetic/private-path', PASS)
    reopened.close()


def test_observation_backup_preserves_material_identity(tmp_path):
    store = EncryptedScanStore.create(tmp_path / 'one.lgo', PASS)
    key = store._store._memory_material_key
    store.save_host_state({'progress': 7})
    store.backup(tmp_path / 'backup.lgb', PASS)
    store.close()
    restored = EncryptedScanStore.restore(tmp_path / 'backup.lgb', PASS, tmp_path / 'two.lgo', 'new-machine-passphrase')
    assert restored._store._memory_material_key == key
    assert restored.load_host_state() == {'progress': 7}
    restored.close()
    reopened = EncryptedScanStore.open(tmp_path / 'two.lgo', 'new-machine-passphrase')
    assert reopened._store._memory_material_key == key
    reopened.close()


def test_observation_failed_checkpoint_never_acknowledges_progress(tmp_path, monkeypatch):
    path = tmp_path / 'observations.lgo'
    store = EncryptedScanStore.create(path, PASS)
    store.save_host_state({'progress': 1})
    def fail(*args):
        raise OSError('synthetic private error')
    with monkeypatch.context() as patch:
        patch.setattr(_files.os, 'replace', fail)
        with pytest.raises(StateError, match='state-checkpoint-failed'):
            store.save_host_state({'progress': 2})
        with pytest.raises(StateError, match='state-checkpoint-failed'):
            store.load_host_state()
        assert store.status()['healthy'] is False
    store.close()
    reopened = EncryptedScanStore.open(path, PASS)
    assert reopened.load_host_state() == {'progress': 1}
    reopened.close()


def test_native_keyring_rejects_unsupported_platform(monkeypatch):
    from leakguard_vault import keyring
    monkeypatch.setattr(keyring.sys, 'platform', 'unsupported')
    with pytest.raises(VaultError, match='observation-keyring-unavailable'):
        NativeKeyring()


@pytest.mark.parametrize('memory', [True, False])
def test_cycle_reset_preserves_evidence_and_refuses_live_owner(tmp_path, memory):
    from leakguard_core.scan_store import MemoryScanStore, SQLiteScanStore
    store = MemoryScanStore() if memory else SQLiteScanStore.from_memory()
    try:
        lease = store.acquire_cycle('scope', tmp_path, lease_seconds=60)
        with pytest.raises(StateError, match='state-cycle-busy'):
            store.reset_cycle('scope')
        store.release_cycle(lease, allow_complete=False)
        store.reset_cycle('scope')
        new_lease = store.acquire_cycle('scope', tmp_path, lease_seconds=60)
        assert not store.lease_valid(lease)
        assert store.lease_valid(new_lease)
        assert store.cycle_status(new_lease)['pending_directories'] == 1
    finally:
        store.close()
