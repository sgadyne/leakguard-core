"""Explicit credential capability. Scanners receive neither this object nor its keys."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import threading
import uuid

from . import _envelope as envelope
from ._files import FileLock, atomic_write, read_bounded
from .errors import VaultError

MAX_CREDENTIAL_BYTES = 16 * 1024 * 1024
_ENTRY_FIELDS = {"id", "title", "username", "secret", "location", "notes", "finding_id", "created_at", "updated_at"}
_OMITTED = object()


def _text(value, maximum, *, required=False):
    if type(value) is not str or len(value) > maximum or required and not value.strip():
        raise VaultError("vault-entry-invalid")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise VaultError("vault-entry-invalid") from None
    return value


def _metadata(entry):
    return {key: entry[key] for key in ("id", "title", "location", "finding_id", "created_at", "updated_at")}


def _decode_entries(value):
    data = envelope.load_json(value)
    if type(data) is not dict or set(data) != {"schema", "entries"} or type(data["schema"]) is not int or data["schema"] != 1 or type(data["entries"]) is not dict or len(data["entries"]) > 10000:
        raise VaultError("vault-format-invalid")
    try:
        for entry_id, entry in data["entries"].items():
            if type(entry) is not dict or set(entry) != _ENTRY_FIELDS or entry_id != entry["id"] or uuid.UUID(hex=entry_id).hex != entry_id:
                raise ValueError()
            for key, maximum in (("title", 256), ("secret", 65536), ("username", 2048), ("location", 4096), ("notes", 65536)):
                _text(entry[key], maximum, required=key in {"title", "secret"})
            if entry["finding_id"] is not None:
                _text(entry["finding_id"], 256, required=True)
            for key in ("created_at", "updated_at"):
                _text(entry[key], 64, required=True)
                if datetime.fromisoformat(entry[key]).tzinfo is None:
                    raise ValueError()
        if len(value) > MAX_CREDENTIAL_BYTES:
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise VaultError("vault-format-invalid") from None
    return data["entries"]


class CredentialVault:
    def __init__(self, path: Path):
        if not isinstance(path, Path):
            raise VaultError("vault-path-invalid")
        self.path = path
        self._mutex = threading.RLock()
        self._session = None

    def __repr__(self):
        return "CredentialVault(<private>)"

    def status(self):
        with self._mutex:
            return {"created": self.path.exists(), "unlocked": self._session is not None and self._session._active}

    def create(self, passphrase: str):
        with self._mutex:
            self._require_locked()
            lock = FileLock(self.path)
            try:
                if self.path.exists():
                    raise VaultError("vault-already-created")
                header, key = envelope.new_header("credentials", passphrase)
                session = CredentialSession(self, lock, header, key, {})
                session._persist({}, replace=False)
                self._session = session
                return session
            except Exception:
                lock.close()
                raise

    def unlock(self, passphrase: str):
        with self._mutex:
            self._require_locked()
            lock = FileLock(self.path)
            try:
                header, key, data = envelope.decrypt(read_bounded(self.path, envelope.MAX_FILE), "credentials", passphrase)
                entries = _decode_entries(data)
                session = CredentialSession(self, lock, header, key, entries)
                self._session = session
                return session
            except Exception:
                lock.close()
                raise

    def lock(self):
        with self._mutex:
            if self._session is not None:
                self._session._destroy()
                self._session = None

    def _require_locked(self):
        if self._session is not None and self._session._active:
            raise VaultError("vault-already-unlocked")

    def restore(self, backup_path: Path, backup_passphrase: str, new_passphrase: str, *, replace=False):
        if type(replace) is not bool:
            raise VaultError("vault-data-invalid")
        with self._mutex:
            self._require_locked()
            _, _, data = envelope.decrypt(read_bounded(backup_path, envelope.MAX_FILE), "credentials-backup", backup_passphrase)
            entries = _decode_entries(data)
            lock = FileLock(self.path)
            try:
                if self.path.exists() and not replace:
                    raise VaultError("vault-already-created")
                header, key = envelope.new_header("credentials", new_passphrase)
                session = CredentialSession(self, lock, header, key, entries)
                session._persist(entries, replace=replace)
                self._session = session
                return session
            except Exception:
                lock.close()
                raise


class CredentialSession:
    """Returned only by explicit create/unlock. Lock invalidates existing references."""

    def __init__(self, vault, lock, header, key, entries):
        self._vault = vault
        self._file_lock = lock
        self._header = header
        self._key = bytearray(key)
        self._entries = entries
        self._active = True

    def __repr__(self):
        return "CredentialSession(<private>)"

    def _ensure_active(self):
        if not self._active:
            raise VaultError("vault-locked")

    def _destroy(self):
        self._active = False
        self._key[:] = b"\x00" * len(self._key)
        self._entries.clear()
        self._file_lock.close()

    def lock(self):
        with self._vault._mutex:
            self._destroy()
            if self._vault._session is self:
                self._vault._session = None

    close = lock

    def _persist(self, entries, *, replace=True):
        self._ensure_active()
        plain = envelope.canonical({"schema": 1, "entries": entries})
        if len(plain) > MAX_CREDENTIAL_BYTES:
            raise VaultError("vault-capacity-limit")
        header, value = envelope.encode(self._header, bytes(self._key), plain)
        try:
            atomic_write(self._vault.path, value, replace=replace)
        except VaultError:
            # A failure after replacement has uncertain durability. Force reopen
            # instead of acknowledging or overwriting from a stale in-memory view.
            self._destroy()
            raise
        self._header = header
        self._entries = entries

    def list_entries(self):
        with self._vault._mutex:
            self._ensure_active()
            return tuple(_metadata(item) for item in sorted(self._entries.values(), key=lambda item: (item["title"].casefold(), item["id"])))

    def save_entry(self, *, title, secret=None, username="", location="", notes="", finding_id=None, entry_id=None):
        with self._vault._mutex:
            self._ensure_active()
            if entry_id is not None and (type(entry_id) is not str or entry_id not in self._entries):
                raise VaultError("vault-entry-not-found")
            if secret is None and entry_id is not None:
                secret = self._entries[entry_id]["secret"]
            for value, maximum, required in ((title, 256, True), (secret, 65536, True), (username, 2048, False), (location, 4096, False), (notes, 65536, False)):
                _text(value, maximum, required=required)
            if finding_id is not None:
                _text(finding_id, 256, required=True)
            if entry_id is None and len(self._entries) >= 10000:
                raise VaultError("vault-capacity-limit")
            now = datetime.now(timezone.utc).isoformat()
            identity = entry_id or uuid.uuid4().hex
            entry = {"id": identity, "title": title, "secret": secret, "username": username,
                     "location": location, "notes": notes, "finding_id": finding_id,
                     "created_at": self._entries[identity]["created_at"] if entry_id else now, "updated_at": now}
            updated = copy.deepcopy(self._entries)
            updated[identity] = entry
            self._persist(updated)
            return _metadata(entry)

    def update_metadata(self, entry_id, *, title=None, username=None, location=None, notes=None, finding_id=_OMITTED):
        with self._vault._mutex:
            self._ensure_active()
            if type(entry_id) is not str or entry_id not in self._entries:
                raise VaultError("vault-entry-not-found")
            old = self._entries[entry_id]
            return self.save_entry(entry_id=entry_id, title=old["title"] if title is None else title,
                                   username=old["username"] if username is None else username,
                                   location=old["location"] if location is None else location,
                                   notes=old["notes"] if notes is None else notes,
                                   finding_id=old["finding_id"] if finding_id is _OMITTED else finding_id)

    def update_secret(self, entry_id, secret):
        with self._vault._mutex:
            self._ensure_active()
            if type(entry_id) is not str or entry_id not in self._entries:
                raise VaultError("vault-entry-not-found")
            old = self._entries[entry_id]
            return self.save_entry(entry_id=entry_id, title=old["title"], secret=secret,
                                   username=old["username"], location=old["location"],
                                   notes=old["notes"], finding_id=old["finding_id"])

    def reveal_entry(self, entry_id):
        with self._vault._mutex:
            self._ensure_active()
            if type(entry_id) is not str or entry_id not in self._entries:
                raise VaultError("vault-entry-not-found")
            return copy.deepcopy(self._entries[entry_id])

    def delete_entry(self, entry_id):
        with self._vault._mutex:
            self._ensure_active()
            if type(entry_id) is not str or entry_id not in self._entries:
                raise VaultError("vault-entry-not-found")
            updated = copy.deepcopy(self._entries)
            del updated[entry_id]
            self._persist(updated)

    def backup(self, path: Path, passphrase: str):
        with self._vault._mutex:
            self._ensure_active()
            header, key = envelope.new_header("credentials-backup", passphrase)
            _, value = envelope.encode(header, key, envelope.canonical({"schema": 1, "entries": self._entries}))
            atomic_write(path, value, replace=False)

    def change_passphrase(self, passphrase: str):
        with self._vault._mutex:
            self._ensure_active()
            header, key = envelope.new_header("credentials", passphrase)
            old_header, old_key = self._header, self._key
            self._header, self._key = header, bytearray(key)
            try:
                self._persist(self._entries)
            except Exception:
                self._header = old_header
                self._destroy()
                raise
            finally:
                old_key[:] = b"\x00" * len(old_key)
