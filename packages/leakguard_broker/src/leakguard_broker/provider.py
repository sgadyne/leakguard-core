"""Narrow internal seam for the existing vault, never an agent capability."""
from pathlib import Path
from leakguard_vault import CredentialVault, VaultError
from .errors import BrokerError


class VaultProvider:
    def __init__(self, path: Path):
        self._vault = CredentialVault(Path(path))
        self._session = None

    def __repr__(self):
        return "VaultProvider(<private>)"

    def create(self, passphrase):
        try:
            self._session = self._vault.create(passphrase)
        except VaultError:
            raise BrokerError("vault-failed", 400) from None

    def unlock(self, passphrase):
        try:
            self._session = self._vault.unlock(passphrase)
        except VaultError:
            raise BrokerError("vault-failed", 400) from None

    def lock(self):
        self._vault.lock()
        self._session = None

    def get(self, entry_id):
        if self._session is None:
            raise BrokerError("locked", 423)
        try:
            return self._session.reveal_entry(entry_id)
        except VaultError:
            raise BrokerError("credential-unavailable", 403) from None

    def put(self, **kwargs):
        if self._session is None:
            raise BrokerError("locked", 423)
        try:
            return self._session.save_entry(**kwargs)
        except VaultError:
            raise BrokerError("vault-failed", 400) from None
