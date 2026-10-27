"""Synthetic daily workflows and recovery failures, without real credentials."""
import concurrent.futures
import string

import pytest

from leakguard_vault import CredentialVault, VaultError, generate_password
from leakguard_vault import _files

OLD = 'synthetic-master-original'
NEW = 'synthetic-master-replacement'
RECOVERY = 'synthetic-recovery-passphrase'


def test_generator_policy_and_rekey_recovery(tmp_path):
    values = [generate_password() for _ in range(100)]
    assert len(set(values)) == len(values)
    for value in values:
        assert len(value) == 24
        assert any(c in string.ascii_lowercase for c in value)
        assert any(c in string.ascii_uppercase for c in value)
        assert any(c in string.digits for c in value)
        assert any(c in '!#$%&()*+,-./:;<=>?@[]^_{|}~' for c in value)
    for invalid in (True, 15, 129, '24'):
        with pytest.raises(VaultError, match='vault-password-policy-invalid'):
            generate_password(invalid)
    vault = CredentialVault(tmp_path / 'profile-a' / 'credentials.lgv')
    session = vault.create(OLD)
    entry = session.save_entry(title='Service A', location='example.invalid', secret=values[0], username='synthetic-user')
    backup = tmp_path / 'portable.lgbak'
    session.backup(backup, RECOVERY)
    with pytest.raises(VaultError, match='vault-authentication-failed'):
        session.change_passphrase(NEW, current_passphrase='synthetic-wrong-master')
    assert session.reveal_entry(entry['id'])['secret'] == values[0]
    session.change_passphrase(NEW, current_passphrase=OLD)
    vault.lock()
    with pytest.raises(VaultError, match='vault-authentication-failed'):
        vault.unlock(OLD)
    session = vault.unlock(NEW)
    assert session.reveal_entry(entry['id'])['secret'] == values[0]
    vault.lock()
    independent = CredentialVault(tmp_path / 'profile-b' / 'credentials.lgv')
    restored = independent.restore(backup, RECOVERY, OLD)
    assert restored.reveal_entry(entry['id'])['secret'] == values[0]
    independent.lock()
    for path in tmp_path.rglob('*'):
        if path.is_file():
            data = path.read_bytes()
            for value in (values[0], OLD, NEW, RECOVERY, 'synthetic-user'):
                assert value.encode() not in data


def test_bad_backups_do_not_replace_existing_vault(tmp_path):
    source = CredentialVault(tmp_path / 'source.lgv')
    session = source.create(OLD)
    session.save_entry(title='source', secret='synthetic-source-secret')
    backup = tmp_path / 'backup.lgbak'
    session.backup(backup, RECOVERY)
    source.lock()
    target = CredentialVault(tmp_path / 'target.lgv')
    session = target.create(NEW)
    entry = session.save_entry(title='existing', secret='synthetic-existing-secret')
    target.lock()
    original = target.path.read_bytes()
    data = backup.read_bytes()
    for contents, password in ((data, 'synthetic-wrong-recovery'), (data[:-7], RECOVERY), (b'bad-format', RECOVERY), (data[:-1] + bytes([data[-1] ^ 1]), RECOVERY)):
        candidate = tmp_path / 'candidate.lgbak'
        candidate.write_bytes(contents)
        with pytest.raises(VaultError):
            target.restore(candidate, password, OLD, replace=True)
        assert target.path.read_bytes() == original
    assert target.unlock(NEW).reveal_entry(entry['id'])['secret'] == 'synthetic-existing-secret'
    target.lock()


def test_rekey_failed_write_and_concurrent_edits(tmp_path, monkeypatch):
    path = tmp_path / 'credentials.lgv'
    vault = CredentialVault(path)
    session = vault.create(OLD)
    entry = session.save_entry(title='before', secret='synthetic-persisted-value')
    original = path.read_bytes()
    def fail(*args):
        raise OSError('private details must not escape')
    with monkeypatch.context() as patch:
        patch.setattr(_files.os, 'replace', fail)
        with pytest.raises(VaultError, match='vault-io-failed'):
            session.change_passphrase(NEW, current_passphrase=OLD)
    assert path.read_bytes() == original
    assert not vault.status()['unlocked']
    with pytest.raises(VaultError, match='vault-locked'):
        session.reveal_entry(entry['id'])
    session = vault.unlock(OLD)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        ids = list(executor.map(lambda i: session.save_entry(title=f'entry-{i}', secret=f'synthetic-value-{i}')['id'], range(24)))
    assert len(set(ids)) == 24
    vault.lock()
    session = vault.unlock(OLD)
    assert len(session.list_entries()) == 25
    assert {session.reveal_entry(i)['secret'] for i in ids} == {f'synthetic-value-{i}' for i in range(24)}
    vault.lock()
