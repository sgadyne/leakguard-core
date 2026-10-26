"""Only verified native OS keyrings may hold an unattended observation key."""
from __future__ import annotations

import base64
import importlib
import secrets
import sys
import uuid

from .errors import VaultError

SERVICE = "leakguard-observations-v1"
_BACKENDS = {"darwin": ("keyring.backends.macOS", "Keyring"),
             "linux": ("keyring.backends.SecretService", "Keyring"),
             "win32": ("keyring.backends.Windows", "WinVaultKeyring")}


class NativeKeyring:
    """Select native classes directly; never accept plaintext/third-party fallbacks.

    Construction only checks native backend availability. Enabling requires an
    actual store/read/delete verification; doctor does not create keyring items.
    """

    def __init__(self):
        self._backend = None
        try:
            module_name, class_name = _BACKENDS[sys.platform]
            backend_type = getattr(importlib.import_module(module_name), class_name)
            if backend_type.__module__ != module_name or backend_type.__name__ != class_name:
                raise ValueError()
            backend = backend_type()
            if backend.priority <= 0:
                raise ValueError()
            self._backend = backend
        except Exception:
            raise VaultError("observation-keyring-unavailable") from None

    def __repr__(self):
        return "NativeKeyring(<native>)"

    @staticmethod
    def _account(account):
        try:
            if type(account) is not str or uuid.UUID(hex=account).hex != account:
                raise ValueError()
        except (ValueError, AttributeError):
            raise VaultError("observation-keyring-invalid") from None

    def status(self):
        return {"native_backend": self._backend.__class__.__module__, "verified": False,
                "message": "Enable unattended observations to verify native key storage."}

    def _verify(self):
        account = "probe-" + secrets.token_hex(16)
        value = base64.b64encode(secrets.token_bytes(32)).decode()
        created = False
        try:
            self._backend.set_password(SERVICE, account, value)
            created = True
            if self._backend.get_password(SERVICE, account) != value:
                raise ValueError()
            self._backend.delete_password(SERVICE, account)
            created = False
            if self._backend.get_password(SERVICE, account) is not None:
                raise ValueError()
        except Exception:
            raise VaultError("observation-keyring-unavailable") from None
        finally:
            if created:
                try:
                    self._backend.delete_password(SERVICE, account)
                except Exception:
                    pass

    def store(self, account: str, key: bytes):
        self._account(account)
        if type(key) is not bytes or len(key) != 32:
            raise VaultError("observation-keyring-invalid")
        self._verify()
        try:
            value = base64.b64encode(key).decode()
            self._backend.set_password(SERVICE, account, value)
            if self._backend.get_password(SERVICE, account) != value:
                raise ValueError()
        except Exception:
            try:
                self._backend.delete_password(SERVICE, account)
            except Exception:
                pass
            raise VaultError("observation-keyring-unavailable") from None

    def load(self, account: str):
        self._account(account)
        try:
            value = self._backend.get_password(SERVICE, account)
            if type(value) is not str or len(value) > 64:
                raise ValueError()
            key = base64.b64decode(value, validate=True)
            if len(key) != 32:
                raise ValueError()
            return key
        except Exception:
            raise VaultError("observation-keyring-unavailable") from None

    def delete(self, account: str):
        self._account(account)
        try:
            if self._backend.get_password(SERVICE, account) is not None:
                self._backend.delete_password(SERVICE, account)
            if self._backend.get_password(SERVICE, account) is not None:
                raise ValueError()
        except Exception:
            raise VaultError("observation-keyring-unavailable") from None
