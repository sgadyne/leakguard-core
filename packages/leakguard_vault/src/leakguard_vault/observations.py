"""Single-writer encrypted checkpoints around core's in-memory SQLite semantics."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import hmac
from pathlib import Path
import sqlite3
import threading

from leakguard_core.scan_store import SQLiteScanStore, StateError

from . import _envelope as envelope
from ._files import FileLock, atomic_write, read_bounded
from .errors import VaultError

_METHODS = frozenset("reserve get_cached record_result record_report latest_report query_findings_page query_findings source_anchor confirm_absent material_snapshot acquire_cycle bind_cycle_identity reset_cycle lease_valid enqueue_work claim_work finish_directory get_directory_progress set_directory_progress directory_page record_directory_checks cycle_status cycle_decision_evidence release_cycle reconcile_cycle invalidate_scope record_event record_metadata".split())
_MUTATIONS = _METHODS - frozenset("get_cached latest_report query_findings_page query_findings source_anchor material_snapshot lease_valid get_directory_progress directory_page cycle_status cycle_decision_evidence".split())


class EncryptedScanStore:
    def __init__(self, path, header, key, plain, file_lock, *, config=None, max_bytes=envelope.MAX_STATE):
        self._path = path
        self._header = header
        self._key = bytearray(key)
        self._file_lock = file_lock
        self._mutex = threading.RLock()
        self._deadlines = {}
        self._closed = False
        self._poisoned = False
        self._unattended_verified = False
        self._dirty = plain is None
        self._max_bytes = max_bytes
        material_key = hmac.new(key, b"leakguard:observation-material-identity:v1", hashlib.sha256).digest()
        self._store = SQLiteScanStore.from_memory(plain, config=config, max_bytes=max_bytes, material_key=material_key)
        try:
            self._store.conn.execute('CREATE TABLE IF NOT EXISTS app_state(name TEXT PRIMARY KEY,payload TEXT NOT NULL)')
            self._store.conn.execute('CREATE TABLE IF NOT EXISTS finding_annotations(finding_id TEXT PRIMARY KEY,state TEXT NOT NULL)')
            saved_key = self._store.conn.execute("SELECT payload FROM app_state WHERE name='material-key'").fetchone()
            if saved_key:
                self._store._memory_material_key = envelope._unb64(saved_key[0], 32)
            else:
                self._persist_material_key()
                self._dirty = True
            self._store.conn.commit()
            from .partitions import EncryptedPartitions
            self._partitions = EncryptedPartitions(self)
        except Exception:
            self._store.close()
            raise StateError() from None

    def __repr__(self):
        return "EncryptedScanStore(<private>)"

    @classmethod
    def create(cls, path: Path, passphrase: str, *, config=None, max_bytes=envelope.MAX_STATE):
        lock = FileLock(path)
        instance = None
        try:
            if path.exists():
                raise VaultError("vault-already-created")
            header, key = envelope.new_header("observations", passphrase)
            instance = cls(path, header, key, None, lock, config=config, max_bytes=max_bytes)
            instance._checkpoint(replace=False)
            return instance
        except Exception:
            if instance is not None:
                instance._dispose()
            else:
                lock.close()
            raise

    @classmethod
    def open(cls, path: Path, passphrase: str, *, config=None, max_bytes=envelope.MAX_STATE):
        lock = FileLock(path)
        try:
            header, key, plain = envelope.decrypt(read_bounded(path, envelope.MAX_FILE), "observations", passphrase)
            return cls(path, header, key, plain, lock, config=config, max_bytes=max_bytes)
        except Exception:
            lock.close()
            raise

    @classmethod
    def keyring_status(cls, path: Path):
        """Read-only doctor probe: no lock file, key writes or checkpoints."""
        from .keyring import NativeKeyring
        status = {"unattended_available": False, "keyring_enabled": False,
                  "native_backend": None, "error_code": None}
        try:
            value = read_bounded(path, envelope.MAX_FILE)
            header, _, _ = envelope.parse(value, "observations")
            status["keyring_enabled"] = "keyring" in header
            if not status["keyring_enabled"]:
                raise VaultError("observation-keyring-not-enabled")
            provider = NativeKeyring()
            status["native_backend"] = provider.status()["native_backend"]
            envelope.decrypt_with_key(value, "observations", provider.load(header["id"]))
            status["unattended_available"] = True
        except VaultError as error:
            status["error_code"] = error.code
        return status

    @classmethod
    def open_keyring(cls, path: Path, *, keyring=None, config=None, max_bytes=envelope.MAX_STATE):
        from .keyring import NativeKeyring
        provider = keyring or NativeKeyring()
        if type(provider) is not NativeKeyring:
            raise VaultError("observation-keyring-invalid")
        lock = FileLock(path)
        try:
            value = read_bounded(path, envelope.MAX_FILE)
            header, _, _ = envelope.parse(value, "observations")
            if "keyring" not in header:
                raise VaultError("observation-keyring-not-enabled")
            key = provider.load(header["id"])
            header, key, plain = envelope.decrypt_with_key(value, "observations", key)
            instance = cls(path, header, key, plain, lock, config=config, max_bytes=max_bytes)
            instance._unattended_verified = True
            return instance
        except Exception:
            lock.close()
            raise

    def _ensure_open(self):
        if self._closed:
            raise StateError("state-locked")
        if self._poisoned:
            raise StateError("state-checkpoint-failed")

    def set_deadline(self, deadline):
        with self._mutex:
            self._ensure_open()
            if deadline is None:
                self._deadlines.pop(threading.get_ident(), None)
            else:
                self._deadlines[threading.get_ident()] = deadline

    def _invoke(self, name, *args, **kwargs):
        with self._mutex:
            self._ensure_open()
            self._store.set_deadline(self._deadlines.get(threading.get_ident()))
            if name in _MUTATIONS and self._size() >= self._max_bytes:
                raise StateError("state-capacity-limit")
            if name in _MUTATIONS:
                self._dirty = True
            try:
                result = getattr(self._store, name)(*args, **kwargs)
                if name == 'material_snapshot':
                    original = result
                    def valid():
                        with self._mutex:
                            if self._closed or self._poisoned:
                                return False
                            self._store.set_deadline(self._deadlines.get(threading.get_ident()))
                            return original.valid()
                    result = replace(result, validate=valid)
                return result
            except StateError:
                # SQLite FULL is intentionally redacted by core; preserve a
                # useful capacity reason when the profile reached its bound.
                if self._size() >= self._max_bytes:
                    raise StateError("state-capacity-limit") from None
                raise

    def _size(self):
        conn = self._store.conn
        return conn.execute('PRAGMA page_count').fetchone()[0] * conn.execute('PRAGMA page_size').fetchone()[0]

    def _checkpoint(self, *, replace=True):
        self._ensure_open()
        self._store.set_deadline(None)
        try:
            parts_committed=self._partitions.prepare()
            plain = self._store.serialize(max_bytes=self._max_bytes)
            header, value = envelope.encode(self._header, bytes(self._key), plain)
            atomic_write(self._path, value, replace=replace)
            self._header = header
            self._dirty = not parts_committed
            if parts_committed:self._partitions.committed()
        except VaultError as error:
            self._poisoned = True
            raise StateError("state-capacity-limit" if error.code == "vault-capacity-limit" else "state-checkpoint-failed") from None
        except StateError:
            self._poisoned = True
            raise

    def checkpoint(self):
        with self._mutex:
            self._checkpoint()

    def load_host_state(self):
        with self._mutex:
            self._ensure_open()
            self._store.set_deadline(None)
            try:
                row = self._store.conn.execute("SELECT payload FROM app_state WHERE name='host'").fetchone()
                state = envelope.load_json(row[0].encode()) if row else {}
                if type(state) is not dict:
                    raise StateError()
                return state
            except VaultError:
                raise StateError() from None

    def save_host_state(self, value):
        if type(value) is not dict:
            raise StateError("state-data-invalid")
        encoded = envelope.canonical(value)
        if len(encoded) > 1024 * 1024:
            raise StateError("state-capacity-limit")
        with self._mutex:
            self._ensure_open()
            self._store.set_deadline(None)
            try:
                with self._store.conn:
                    self._store.conn.execute("INSERT INTO app_state VALUES('host',?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload", (encoded.decode(),))
                self._checkpoint()
            except StateError:
                raise
            except Exception as error:
                self._poisoned = True
                if isinstance(error, sqlite3.Error) and getattr(error, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL:
                    raise StateError("state-capacity-limit") from None
                raise StateError("state-checkpoint-failed") from None

    def get_annotation(self, finding_id):
        if type(finding_id) is not str or not 1 <= len(finding_id) <= 256:
            raise StateError("state-query-invalid")
        with self._mutex:
            self._ensure_open()
            self._store.set_deadline(None)
            row = self._store.conn.execute('SELECT state FROM finding_annotations WHERE finding_id=?', (finding_id,)).fetchone()
            return {"finding_id": finding_id, "state": row[0] if row else "unreviewed"}

    def set_annotation(self, finding_id, state):
        if type(finding_id) is not str or not 1 <= len(finding_id) <= 256 or type(state) is not str or state not in {"unreviewed", "reviewed", "dismissed"}:
            raise StateError("state-query-invalid")
        with self._mutex:
            self._ensure_open()
            self._store.set_deadline(None)
            try:
                with self._store.conn:
                    self._store.conn.execute('INSERT INTO finding_annotations VALUES(?,?) ON CONFLICT(finding_id) DO UPDATE SET state=excluded.state', (finding_id, state))
                self._checkpoint()
            except StateError:
                raise
            except Exception as error:
                self._poisoned = True
                if isinstance(error, sqlite3.Error) and getattr(error, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL:
                    raise StateError("state-capacity-limit") from None
                raise StateError("state-checkpoint-failed") from None
            return {"finding_id": finding_id, "state": state}

    def status(self):
        with self._mutex:
            if self._closed:
                return {"unlocked": False, "unattended_available": False, "capacity_bytes": self._max_bytes}
            self._store.set_deadline(None)
            return {"unlocked": True, "healthy": not self._poisoned, "unattended_available": self._unattended_verified and not self._poisoned,
                    "keyring_enabled": "keyring" in self._header,
                    "serialized_bytes": self._size(), "capacity_bytes": self._max_bytes,
                    "partition_count":len(self._partitions.catalog),"partition_capacity_bytes":envelope.MAX_STATE,"inventory_counts":self._partitions.counts(),
                    "encrypted_disk_bytes":self._path.stat().st_size+sum(p.stat().st_size for p in self._partitions.directory.glob("*.lgo"))}

    def enable_keyring(self, *, keyring=None):
        from .keyring import NativeKeyring
        provider = keyring or NativeKeyring()
        if type(provider) is not NativeKeyring:
            raise VaultError("observation-keyring-invalid")
        with self._mutex:
            self._ensure_open()
            provider.store(self._header["id"], bytes(self._key))
            self._header["keyring"] = {"service": "leakguard-observations-v1", "account": self._header["id"]}
            try:
                self._checkpoint()
            except Exception:
                try:
                    provider.delete(self._header["id"])
                except VaultError:
                    pass
                raise
            self._unattended_verified = True

    def disable_keyring(self, *, keyring=None):
        from .keyring import NativeKeyring
        provider = keyring or NativeKeyring()
        if type(provider) is not NativeKeyring:
            raise VaultError("observation-keyring-invalid")
        with self._mutex:
            self._ensure_open()
            account = self._header["id"]
            # Remove key access first. A failed checkpoint leaves a stale marker,
            # never an unattended capability the UI falsely reports revoked.
            provider.delete(account)
            self._unattended_verified = False
            self._header.pop("keyring", None)
            self._checkpoint()

    def backup(self, path: Path, passphrase: str):
        with self._mutex:
            self._ensure_open()
            self._store.set_deadline(None)
            if self._partitions.catalog or self._partitions.cache:
                raise StateError("state-partition-backup-required")
            plain = self._store.serialize(max_bytes=self._max_bytes)
            header, key = envelope.new_header("observations-backup", passphrase)
            _, value = envelope.encode(header, key, plain)
            atomic_write(path, value, replace=False)

    @classmethod
    def restore(cls, backup_path: Path, backup_passphrase: str, path: Path, new_passphrase: str, *, replace=False, config=None, max_bytes=envelope.MAX_STATE):
        _, _, plain = envelope.decrypt(read_bounded(backup_path, envelope.MAX_FILE), "observations-backup", backup_passphrase)
        lock = FileLock(path)
        instance = None
        try:
            if path.exists() and not replace:
                raise VaultError("vault-already-created")
            header, key = envelope.new_header("observations", new_passphrase)
            instance = cls(path, header, key, plain, lock, config=config, max_bytes=max_bytes)
            instance._checkpoint(replace=replace)
            return instance
        except Exception:
            if instance is not None:
                instance._dispose()
            else:
                lock.close()
            raise

    def implementation_identity(self):
        artifacts=[]
        for path in sorted(Path(__file__).parent.glob('*.py')):
            data=path.read_bytes()
            if len(data)>1_000_000:raise StateError('state-data-invalid')
            artifacts.append([path.name,hashlib.sha256(data).hexdigest()])
        return hashlib.sha256(envelope.canonical(artifacts)).hexdigest()

    def rebind_path(self,path,file_lock):
        """Called only after verified ciphertext copy and durable config switch."""
        with self._mutex:
            self._ensure_open()
            old=self._file_lock
            self._path=path;self._file_lock=file_lock
            self._partitions.directory=path.with_name(path.name+'.parts')
            old.close()

    def transaction(self):
        """Defer partition publication while UI control state may checkpoint.

        The host applies copied progress only when this transaction ends. A
        durable user pause can therefore publish without committing half a scan.
        """
        from contextlib import contextmanager
        @contextmanager
        def transaction():
            with self._mutex:
                self._ensure_open()
                if self._partitions.active_transaction:raise StateError('state-cycle-busy')
                self._partitions.active_transaction=True
            try:yield
            finally:
                with self._mutex:self._partitions.active_transaction=False;self._dirty=True
        return transaction()

    def partition(self, bucket):
        """Pin a writer partition; individual operations use the owner mutex."""
        from contextlib import contextmanager
        @contextmanager
        def borrow():
            with self._mutex:
                self._ensure_open();self._dirty=True
                self._partitions.pinned.add(bucket)
                try:child=self._partitions.get(bucket)
                except BaseException:
                    self._partitions.pinned.discard(bucket);raise
            try:yield child
            finally:
                with self._mutex:self._partitions.pinned.discard(bucket)
        return borrow()

    def inventory_put(self, rows):
        with self._mutex:
            self._ensure_open()
            self._dirty = True
            return self._partitions.inventory_put(rows)

    def inventory_page(self, *args, **kwargs):
        with self._mutex:
            self._ensure_open()
            return self._partitions.inventory_page(*args, **kwargs)

    def queue_reconciliation(self, *args):
        with self._mutex:
            self._ensure_open();self._dirty=True
            return self._partitions.queue_reconciliation(*args)

    def invalidate_location(self, *args):
        with self._mutex:
            self._ensure_open();self._dirty=True
            return self._partitions.invalidate_location(*args)

    def reconcile_location(self, *args):
        with self._mutex:
            self._ensure_open();self._dirty=True
            return self._partitions.reconcile_location(*args)

    def inventory_set(self, *args, **kwargs):
        with self._mutex:
            self._ensure_open()
            self._dirty = True
            return self._partitions.inventory_set(*args, **kwargs)

    def physical_visit(self, *args):
        with self._mutex:
            self._ensure_open()
            self._dirty = True
            return self._partitions.physical_visit(*args)

    def inventory_counts(self, location=None):
        with self._mutex:
            self._ensure_open()
            return self._partitions.counts(location)

    def _source_freshness(self,rows,state):
        if state!='current':return rows
        host=self.load_host_state();sources=host.get('sources',{});jobs=host.get('jobs',{})
        stale=[]
        for key,source in sources.items():
            selected=[j for j in jobs.values() if j['source_id']==key]
            latest=max(selected,key=lambda j:(j['created_at'],j['id'])) if selected else {}
            if latest.get('last_error') in {'offline','source-unavailable','source-changed','permission-denied','unreadable'} or latest.get('invalidate_cursor',256)<256:
                stale.append((source['root'],'policy-obsolete' if latest.get('invalidate_cursor',256)<256 else 'source-unavailable'))
        output=[]
        for row in rows:
            row=dict(row);path_text=(row.get('source') or {}).get('path','');path=Path(path_text)
            for root,reason in stale:
                if (path_text==root or path_text.startswith(root.rstrip('/')+'/') if root.startswith('ssh://') else path.is_absolute() and path.is_relative_to(Path(root))) and row.get('state') in {'active','unknown'}:
                    row.update(state='unknown',state_reason=reason,resolved_at=None);break
            output.append(row)
        return tuple(output)

    def query_findings_page(self, *, state='current', profile=None, limit=1000, cursor=None):
        from leakguard_core.scan_store import FindingPage
        with self._mutex:
            self._ensure_open()
            bucket, inner = -1, None
            if cursor is not None:
                try:
                    value = envelope.load_json(__import__('base64').urlsafe_b64decode(cursor + '=' * (-len(cursor) % 4)))
                    bucket, inner, saved_state, saved_profile = value
                    if saved_state != state or saved_profile != profile or type(bucket) is not int or not -1 <= bucket <= 255:
                        raise ValueError()
                except Exception:
                    raise StateError('state-query-invalid') from None
            def token(b, c):
                return __import__('base64').urlsafe_b64encode(envelope.canonical([b,c,state,profile])).decode().rstrip('=')
            for _ in range(8):
                if bucket == -1:
                    store = self._store
                else:
                    name = f'e{bucket:02x}'
                    if name not in self._partitions.catalog and name not in self._partitions.cache:
                        bucket += 1
                        if bucket > 255: return FindingPage((), None)
                        continue
                    store = self._partitions.get(name)
                store.set_deadline(None)
                page = store.query_findings_page(state=state, profile=profile, limit=limit, cursor=inner)
                if page.next_cursor is not None:
                    return FindingPage(self._source_freshness(page.rows,state), token(bucket, page.next_cursor))
                bucket += 1
                inner = None
                if page.rows or bucket > 255:
                    return FindingPage(self._source_freshness(page.rows,state), token(bucket, None) if bucket <= 255 else None)
            return FindingPage((), token(bucket,inner))

    def query_findings(self, **kwargs):
        return self.query_findings_page(**kwargs).rows

    def _persist_material_key(self):
        with self._store.conn:
            self._store.conn.execute("INSERT INTO app_state VALUES('material-key',?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload", (envelope._b64(self._store._memory_material_key),))

    def _dispose(self):
        if not self._closed:
            self._closed = True
            self._key[:] = b"\x00" * len(self._key)
            try:
                self._partitions.close()
                self._store.close()
                self._store._memory_material_key = b""
            finally:
                self._file_lock.close()
            self._deadlines.clear()

    def close(self):
        with self._mutex:
            if self._closed:
                return
            try:
                if not self._poisoned and self._dirty:
                    self._checkpoint()
            finally:
                self._dispose()

    lock = close


def _forward(name):
    def method(self, *args, **kwargs):
        return self._invoke(name, *args, **kwargs)
    method.__name__ = name
    method.__qualname__ = "EncryptedScanStore." + name
    return method


# Real class attributes satisfy Python3.12+ runtime Protocol checks, which use
# static lookup rather than __getattr__. Keep one synchronized implementation.
for _name in _METHODS - {'query_findings_page', 'query_findings'}:
    setattr(EncryptedScanStore, _name, _forward(_name))
del _name
