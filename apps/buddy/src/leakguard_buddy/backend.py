"""Product adapter joining the supported host, core, and vault APIs."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import hashlib
from functools import wraps
from typing import Any


_BUDDY_CONFIG_FIELDS = ("detection_profile", "scan_workers")
_HOOK_ERRORS = {
    "hook-configuration-invalid", "hook-directory-shared", "hook-target-changed",
    "hook-target-nonregular", "hook-write-failed", "hook-import-path-limit",
    "git-command-failed", "git-path-invalid", "repository-not-found",
}


class BuddyOperationError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _backend_locked(method):
    @wraps(method)
    def invoke(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return invoke


class BuddyBackend:
    """Hold the encrypted observation capability and separate credential session.

    Only the host receives the observation store. The host and plugins never
    receive the CredentialSession; that capability remains private to methods
    which perform a deliberate vault operation.
    """

    def __init__(self, *, state_dir: Path | None = None, config_path: Path | None = None):
        from leakguard_core import settings
        from leakguard_core.api import ScanConfig
        from leakguard_vault import CredentialVault, EncryptedScanStore

        if config_path is not None:
            self.base_config_path = Path(config_path).expanduser().absolute()
            defaults = settings.read_config(self.base_config_path)
        else:
            defaults, self.base_config_path = settings.load()
        self.state_dir = Path(state_dir).expanduser().absolute() if state_dir else settings.state_directory().absolute()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        from .ownership import ProfileOwnership
        self._ownership = ProfileOwnership(self.state_dir / ".buddy-owner.lock")
        try:
            self._initialize(defaults, ScanConfig, EncryptedScanStore, CredentialVault)
        except BaseException:
            self._ownership.close()
            raise

    def _initialize(self, defaults, ScanConfig, EncryptedScanStore, CredentialVault):
        try:
            os.chmod(self.state_dir, 0o700)
        except OSError:
            pass
        self.observation_path = self.state_dir / "observations.lgo"
        self.credential_path = self.state_dir / "credentials.lgv"
        self.extension_registry_path = self.state_dir / "extensions"
        self._config_values = dict(defaults)
        # Buddy's selected profile and worker count must not rewrite the shared
        # LeakGuard CLI/Git configuration. Keep its overlay in private state.
        self.config_path = self.state_dir / "buddy-config.json"
        if self.config_path.is_file():
            try:
                buddy_values = json.loads(self.config_path.read_text(encoding="utf-8"))
                allowed = set(_BUDDY_CONFIG_FIELDS) | {"worker_policy"}
                if type(buddy_values) is not dict or set(buddy_values) - allowed:
                    raise ValueError()
                # Ignore a worker_policy left by an older Buddy build: that
                # policy is owned by the shared CLI config and cannot diverge.
                self._config_values.update({key: value for key, value in buddy_values.items() if key in _BUDDY_CONFIG_FIELDS})
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
                raise RuntimeError("buddy-config-invalid") from None
        # Initialize the private registry through core's public API before the
        # config references it. initialize() creates an empty registry once and
        # refuses to recreate a registry whose enabled state was lost.
        self._extension_registry().initialize()
        self._config_values["extension_registry"] = str(self.extension_registry_path.absolute())
        self._config_values["observation_backend"] = "encrypted"
        self._config_values["observation_path"] = str(self.observation_path.absolute())
        self._config = ScanConfig.from_mapping(self._config_values)
        self._ScanConfig = ScanConfig
        self._EncryptedScanStore = EncryptedScanStore
        self._vault = CredentialVault(self.credential_path)
        self._credential_session: object | None = None
        self._observation_store: object | None = None
        self._host: object | None = None
        self._lock = threading.RLock()
        self._keyring_probe: dict[str, Any] | None = None
        self._startup_observation_error: str | None = None
        self.runtime_config_path = self.state_dir / "buddy-active-config.json"
        self.hook_profiles_dir = self.state_dir / "hook-profiles"
        self._write_config(self._config_values)
        self._try_start_keyring_observations()

    def _try_start_keyring_observations(self) -> None:
        """Resume only after a prior explicit opt-in and a verified native key read."""
        if not self.observation_path.is_file():
            return
        probe = self._EncryptedScanStore.keyring_status(self.observation_path)
        self._keyring_probe = probe
        if probe.get("unattended_available") is not True:
            return
        store = None
        try:
            store = self._EncryptedScanStore.open_keyring(self.observation_path, config=self._config_values)
            self._start_host(store)
        except Exception as error:
            self._startup_observation_error = _safe_code(error) or "observation-keyring-unavailable"
            if store is not None:
                close = getattr(store, "close", None) or getattr(store, "lock", None)
                if callable(close):
                    try: close()
                    except Exception: pass

    def _start_host(self, store: object) -> None:
        from leakguard_host import HostService

        host = HostService(config=self._config, scan_store=store)
        host.start()
        self._observation_store = store
        self._host = host

    def _require_host(self):
        if self._host is None or self._observation_store is None:
            raise RuntimeError("observation-store-locked")
        return self._host

    def _require_credential_session(self):
        if self._credential_session is None:
            raise RuntimeError("credential-vault-locked")
        return self._credential_session

    def prepare_close(self) -> None:
        """Stop owned workers and stores; a failed stop retains every owner."""
        with self._lock:
            self._vault.lock()
            self._credential_session = None
            self._stop_host()

    def release_ownership(self) -> None:
        ownership = getattr(self, "_ownership", None)
        if ownership is not None:
            ownership.close()

    def close(self) -> None:
        self.prepare_close()
        self.release_ownership()

    def _stop_host(self) -> None:
        host, store = self._host, self._observation_store
        if host is not None:
            # The host may still own a worker in a blocking OS/fileshare call.
            # Keep both references and the encrypted store open until stop has
            # positively completed; closing early could lose durable progress.
            host.stop()
        if store is not None:
            close = getattr(store, "close", None) or getattr(store, "lock", None)
            if callable(close):
                close()
        self._host = None
        self._observation_store = None

    @_backend_locked
    def status(self) -> dict[str, Any]:
        with self._lock:
            observations = self.observation_status()
            host_status = self._host.status() if self._host is not None else {}
            if self._host is not None:
                capabilities = self._host.capabilities()
            else:
                from leakguard_host import capabilities as host_capabilities
                capabilities = host_capabilities()
            return {
                "observations": observations,
                "vault": self.credential_status(),
                "host": host_status,
                "capabilities": capabilities,
                "worker_policy": self._config_values.get("worker_policy", "strict"),
                "detection_profile": self._config_values.get("detection_profile", "credentials"),
            }

    @_backend_locked
    def observation_status(self) -> dict[str, Any]:
        created = self.observation_path.is_file()
        store_status = self._observation_store.status() if self._observation_store is not None else {}
        keyring = self._observation_keyring_status() if created else {
            "unattended_available": False, "keyring_enabled": False,
            "native_backend": None, "error_code": "observation-keyring-not-enabled",
        }
        return {
            "created": created,
            "unlocked": self._observation_store is not None,
            "keyring_enabled": bool(keyring.get("keyring_enabled")),
            "unattended_available": bool(keyring.get("unattended_available")),
            "native_backend": keyring.get("native_backend"),
            "keyring_error": keyring.get("error_code"),
            "startup_error": self._startup_observation_error,
            "healthy": store_status.get("healthy"),
            "serialized_bytes": store_status.get("serialized_bytes"),
            "capacity_bytes": store_status.get("capacity_bytes"),
        }

    def _observation_keyring_status(self) -> dict[str, Any]:
        if self._observation_store is not None:
            status = self._observation_store.status()
            if not status.get("keyring_enabled"):
                self._keyring_probe = {
                    "unattended_available": False, "keyring_enabled": False,
                    "native_backend": None, "error_code": "observation-keyring-not-enabled",
                }
            if status.get("unattended_available"):
                return {
                    "unattended_available": True,
                    "keyring_enabled": True,
                    "native_backend": (self._keyring_probe or {}).get("native_backend"),
                    "error_code": None,
                }
            if self._keyring_probe is None and status.get("keyring_enabled"):
                self._keyring_probe = self._probe_keyring()
        elif self._keyring_probe is None and self.observation_path.is_file():
            self._keyring_probe = self._probe_keyring()
        if self._keyring_probe is None:
            self._keyring_probe = {
                "unattended_available": False, "keyring_enabled": False,
                "native_backend": None, "error_code": "observation-keyring-not-enabled",
            }
        return dict(self._keyring_probe)

    def _probe_keyring(self) -> dict[str, Any]:
        try:
            return self._EncryptedScanStore.keyring_status(self.observation_path)
        except Exception:
            return {
                "unattended_available": False, "keyring_enabled": False,
                "native_backend": None, "error_code": "observation-keyring-unavailable",
            }

    @_backend_locked
    def observation_keyring(self, enabled: bool) -> dict[str, Any]:
        store = self._observation_store
        if store is None:
            raise RuntimeError("observation-store-locked")
        if enabled:
            store.enable_keyring()
        else:
            store.disable_keyring()
        self._startup_observation_error = None
        self._keyring_probe = self._EncryptedScanStore.keyring_status(self.observation_path)
        return self.observation_status()

    @_backend_locked
    def observation_create(self, passphrase: str) -> dict[str, Any]:
        with self._lock:
            if self.observation_path.exists():
                raise RuntimeError("observation-store-exists")
            self.observation_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            store = self._EncryptedScanStore.create(self.observation_path, passphrase, config=self._config_values)
            try:
                self._start_host(store)
            except BaseException:
                close = getattr(store, "lock", None) or getattr(store, "close", None)
                if callable(close): close()
                raise
            self._keyring_probe = {
                "unattended_available": False, "keyring_enabled": False,
                "native_backend": None, "error_code": "observation-keyring-not-enabled",
            }
            return self.observation_status()

    @_backend_locked
    def observation_unlock(self, passphrase: str) -> dict[str, Any]:
        with self._lock:
            if self._observation_store is not None:
                return self.observation_status()
            store = self._EncryptedScanStore.open(self.observation_path, passphrase, config=self._config_values)
            try:
                self._start_host(store)
            except BaseException:
                close = getattr(store, "lock", None) or getattr(store, "close", None)
                if callable(close): close()
                raise
            if store.status().get("keyring_enabled"):
                self._keyring_probe = self._probe_keyring()
            else:
                self._keyring_probe = {
                    "unattended_available": False, "keyring_enabled": False,
                    "native_backend": None, "error_code": "observation-keyring-not-enabled",
                }
            return self.observation_status()

    @_backend_locked
    def observation_lock(self) -> None:
        with self._lock:
            self._stop_host()

    @_backend_locked
    def roots(self):
        return self._require_host().roots()

    @_backend_locked
    def browse(self, query: dict[str, str]):
        limit = _int(query.get("limit", "100"), 100, 1, 500)
        return self._require_host().browse(query.get("path", ""), root=query.get("root"), cursor=query.get("cursor"), limit=limit)

    @_backend_locked
    def sources(self):
        return self._require_host().sources()

    @_backend_locked
    def jobs(self):
        return self._require_host().jobs()

    @_backend_locked
    def add_source(self, payload: dict[str, Any]):
        host = self._require_host()
        result = host.add_source(root=payload["root"], label=payload.get("label"), kind=payload.get("kind", "local"), exclusions=tuple(payload.get("exclusions", ())))
        seconds = payload.get("schedule_seconds")
        if seconds:
            source_id = _extract_id(result)
            if source_id:
                host.update_source(source_id, schedule_seconds=seconds, enabled=True)
                return next((item for item in _as_list(host.sources()) if item.get("id") == source_id), result)
        return result

    @_backend_locked
    def update_source(self, source_id: str, payload: dict[str, Any]):
        return self._require_host().update_source(source_id, **payload)

    @_backend_locked
    def remove_source(self, source_id: str):
        return self._require_host().remove_source(source_id)

    @_backend_locked
    def submit(self, source_id: str):
        return self._require_host().submit(source_id)

    @_backend_locked
    def pause(self, job_id: str): return self._require_host().pause(job_id)
    @_backend_locked
    def resume(self, job_id: str): return self._require_host().resume(job_id)
    @_backend_locked
    def cancel(self, job_id: str): return self._require_host().cancel(job_id)

    @_backend_locked
    def findings(self, query: dict[str, str]) -> dict[str, Any]:
        host = self._require_host()
        store = self._observation_store
        state = query.get("state", "current")
        annotation_state = query.get("annotation", "")
        profile = query.get("profile")
        limit = _int(query.get("limit", "100"), 100, 1, 500)
        needle_rule = query.get("rule", "").casefold()
        needle_source = query.get("source", "").casefold()
        needle_category = query.get("category", "").casefold()
        severity = query.get("severity")
        if state not in {"current", "history"} or annotation_state not in {"", "unreviewed", "reviewed", "dismissed"}:
            raise ValueError("state-query-invalid")
        if needle_category and needle_category not in {"credentials", "contact", "financial-identifier", "organization-identifier", "firm", "other"}:
            raise ValueError("state-query-invalid")
        filter_id = hashlib.sha256(json.dumps(
            [state, profile, severity, needle_rule, needle_source, needle_category, annotation_state],
            ensure_ascii=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        store_cursor = _decode_findings_cursor(query.get("cursor"), filter_id)
        rows: list[dict[str, Any]] = []
        next_store_cursor = store_cursor
        # The storage API intentionally filters by profile but not by display
        # fields. Walk a bounded number of full pages so display filters do not
        # silently hide matches behind an unrelated page boundary.
        for _ in range(8):
            page = store.query_findings_page(state=state, profile=profile, limit=limit, cursor=next_store_cursor)
            for raw in page.rows:
                row = dict(raw)
                row["category"] = _finding_category(row.get("rule", ""))
                row["annotation"] = store.get_annotation(row.get("id", ""))
                source = row.get("source") or {}
                path = source.get("path", "") if type(source) is dict else ""
                if severity and row.get("severity") != severity: continue
                if needle_rule and needle_rule not in str(row.get("rule", "")).casefold(): continue
                if needle_source and needle_source not in str(path).casefold(): continue
                if needle_category and needle_category != row["category"]: continue
                if annotation_state and row["annotation"].get("state") != annotation_state: continue
                rows.append(row)
            next_store_cursor = page.next_cursor
            if next_store_cursor is None or len(rows) >= limit:
                break
        host_status = host.status()
        source_rows = _as_list(host.sources())
        job_rows = _as_list(host.jobs())
        latest_jobs: dict[str, dict[str, Any]] = {}
        for job in job_rows:
            source_id = job.get("source_id")
            current = latest_jobs.get(source_id)
            if source_id and (current is None or str(job.get("updated_at", "")) > str(current.get("updated_at", ""))):
                latest_jobs[source_id] = job
        for row in rows:
            path = ((row.get("source") or {}).get("path") if type(row.get("source")) is dict else None) or ""
            row["source_id"] = _source_for_path(source_rows, path)
            latest_job = latest_jobs.get(row["source_id"])
            if latest_job is not None and latest_job.get("coverage") is not None:
                row["coverage"] = latest_job["coverage"]
        return {
            "findings": rows,
            "next_cursor": _encode_findings_cursor(next_store_cursor, filter_id) if next_store_cursor is not None else None,
            "state": state,
            "coverage": host_status.get("coverage") if type(host_status) is dict else None,
        }

    @_backend_locked
    def finding(self, finding_id: str) -> dict[str, Any]:
        store = self._observation_store
        if store is None:
            raise RuntimeError("observation-store-locked")
        for state in ("current", "history"):
            page = store.query_findings_page(state=state, limit=1000)
            for raw in page.rows:
                if raw.get("id") == finding_id:
                    row = dict(raw)
                    row["annotation"] = store.get_annotation(finding_id)
                    return row
        raise KeyError("finding-not-found")

    @_backend_locked
    def annotate_finding(self, finding_id: str, state: str):
        if state not in {"unreviewed", "reviewed", "dismissed"}:
            raise ValueError("annotation-invalid")
        self._require_host()
        return self._observation_store.set_annotation(finding_id, state)

    @_backend_locked
    def reveal_path(self, source_id: str, path: str):
        return self._require_host().reveal(path, source_id=source_id)

    @_backend_locked
    def git_hooks_status(self, repository: str):
        from leakguard_core import hooks
        result = self._hook_call(hooks.repository_status, repository)
        key = _repository_key(result["repository"])
        metadata_path = self.hook_profiles_dir / f"{key}.json"
        profile = None
        effective_config_path = None
        worker_policy = self._config_values.get("worker_policy", "strict")
        if metadata_path.is_file():
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                if type(metadata) is dict and metadata.get("repository") == result["repository"]:
                    profile = metadata.get("profile")
                    effective_config_path = metadata.get("config_path")
                    worker_policy = metadata.get("worker_policy", worker_policy)
            except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
                pass
        return {
            **result,
            "profile": profile,
            "effective_config_path": effective_config_path,
            "worker_policy": worker_policy,
            "base_config_path": str(self.base_config_path),
        }

    @_backend_locked
    def git_hooks_install(self, repository: str, profile: str):
        from leakguard_core import hooks
        if profile not in {"credentials", "sensitive", "firm"}:
            raise ValueError("profile-invalid")
        status = self._hook_call(hooks.repository_status, repository)
        key = _repository_key(status["repository"])
        self.hook_profiles_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        values = dict(self._config_values)
        values["detection_profile"] = profile
        from leakguard_core import settings as core_settings
        effective = core_settings.validate(values)
        profile_path = self.hook_profiles_dir / f"{key}-{profile}.json"
        _atomic_private_write(profile_path, json.dumps(effective, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8"))
        result = self._hook_call(hooks.install_repository, repository, config_path=profile_path, state_dir=self.state_dir)
        metadata = {
            "repository": result["repository"],
            "profile": profile,
            "config_path": str(profile_path),
            "worker_policy": effective.get("worker_policy", "strict"),
        }
        _atomic_private_write(self.hook_profiles_dir / f"{key}.json", json.dumps(metadata, ensure_ascii=True, sort_keys=True).encode("utf-8"))
        return {**result, "profile": profile, "effective_config_path": str(profile_path), "worker_policy": effective.get("worker_policy", "strict")}

    @_backend_locked
    def git_hooks_uninstall(self, repository: str):
        from leakguard_core import hooks
        result = self._hook_call(hooks.uninstall_repository, repository)
        if not result.get("uninstalled"):
            return {**result, "profile": None}
        key = _repository_key(result["repository"])
        if self.hook_profiles_dir.is_dir():
            owned_paths = [self.hook_profiles_dir / f"{key}.json"]
            owned_paths.extend(self.hook_profiles_dir / f"{key}-{profile}.json" for profile in ("credentials", "sensitive", "firm"))
            for path in owned_paths:
                try: path.unlink()
                except OSError: pass
        return {**result, "profile": None}

    @staticmethod
    def _hook_call(operation, repository: str, **kwargs):
        try:
            return operation(repository, **kwargs)
        except Exception as error:
            code = getattr(error, "code", None)
            if type(code) is not str or code not in _HOOK_ERRORS:
                code = str(error) if str(error) in _HOOK_ERRORS else "hook-operation-failed"
            raise BuddyOperationError(code) from None

    @_backend_locked
    def credential_status(self):
        status = self._vault.status()
        return {"created": bool(status.get("created")), "unlocked": self._credential_session is not None}

    @_backend_locked
    def credential_create(self, passphrase: str):
        with self._lock:
            self._credential_session = self._vault.create(passphrase)
            return self.credential_status()

    @_backend_locked
    def credential_unlock(self, passphrase: str):
        with self._lock:
            self._credential_session = self._vault.unlock(passphrase)
            return self.credential_status()

    @_backend_locked
    def credential_lock(self):
        with self._lock:
            self._vault.lock()
            self._credential_session = None

    @_backend_locked
    def credential_entries(self):
        return list(self._require_credential_session().list_entries())

    @_backend_locked
    def credential_save(self, payload: dict[str, Any]):
        session = self._require_credential_session()
        return session.save_entry(title=payload["title"], secret=payload["secret"], username=payload.get("username", ""), location=payload.get("location", ""), notes=payload.get("notes", ""), finding_id=payload.get("finding_id"))

    @_backend_locked
    def credential_update(self, entry_id: str, payload: dict[str, Any]):
        session = self._require_credential_session()
        fields = {key: payload[key] for key in ("title", "secret", "username", "location", "notes", "finding_id") if key in payload}
        return session.update_entry(entry_id, **fields)

    @_backend_locked
    def credential_reveal(self, entry_id: str):
        return self._require_credential_session().reveal_entry(entry_id)

    @_backend_locked
    def credential_delete(self, entry_id: str):
        return self._require_credential_session().delete_entry(entry_id)

    @_backend_locked
    def credential_backup(self, passphrase: str):
        session = self._require_credential_session()
        with tempfile.TemporaryDirectory(prefix="leakguard-buddy-") as temporary:
            path = Path(temporary) / "vault.lgbak"
            session.backup(path, passphrase)
            data = path.read_bytes()
        if len(data) > 16 * 1024 * 1024:
            raise ValueError("vault-backup-too-large")
        return {"filename": "leakguard-vault.lgbak", "backup_base64": base64.b64encode(data).decode("ascii")}

    @_backend_locked
    def credential_restore(self, payload: dict[str, Any]):
        raw = base64.b64decode(payload["backup"], validate=True)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("vault-backup-too-large")
        with self._lock:
            # Vault restore requires an absent credential session. Revoke the
            # current capability before replacing the encrypted file.
            self._credential_session = None
            self._vault.lock()
            with tempfile.TemporaryDirectory(prefix="leakguard-buddy-restore-") as temporary:
                path = Path(temporary) / "vault.lgbak"
                _private_write(path, raw)
                session = self._vault.restore(path, payload["backup_passphrase"], payload["new_passphrase"], replace=payload.get("replace", False))
            self._credential_session = session
            return self.credential_status()

    @_backend_locked
    def plugins(self):
        registry = self._extension_registry()
        entries = [_wire(entry) for entry in registry.list()]
        active_profile = self._config_values.get("detection_profile", "credentials")
        for entry in entries:
            if type(entry) is dict:
                entry["enabled"] = active_profile in entry.get("profiles", [])
        return {"plugins": entries, "active_profile": active_profile}

    @_backend_locked
    def plugin_install(self, payload: dict[str, Any]):
        if payload.get("reviewed") is not True:
            raise BuddyOperationError("plugin-review-required")
        filename = _safe_wheel_filename(payload.get("filename"))
        raw = base64.b64decode(payload["wheel"], validate=True)
        if not raw.startswith(b"PK\x03\x04") or len(raw) > 48_000_000:
            raise BuddyOperationError("plugin-invalid")
        with tempfile.TemporaryDirectory(prefix="leakguard-buddy-plugin-") as temporary:
            wheel = Path(temporary) / filename
            _private_write(wheel, raw)
            result = self._extension_registry().install_wheel(wheel)
            return _wire(result)

    @_backend_locked
    def plugin_set_enabled(self, payload: dict[str, Any], enabled: bool):
        registry = self._extension_registry()
        method = registry.enable if enabled else registry.disable
        result = method(payload["id"], profile=payload["profile"], **({"worker_policy": self._config_values.get("worker_policy", "strict")} if enabled else {}))
        return _wire(result)

    @_backend_locked
    def plugin_conformance(self, payload: dict[str, Any]):
        return _wire(self._extension_registry().check(payload["id"], worker_policy=self._config_values.get("worker_policy", "strict")))

    def _extension_registry(self):
        from leakguard_core.extensions import ExtensionRegistry
        return ExtensionRegistry(self.extension_registry_path)

    @_backend_locked
    def settings(self):
        return {
            "active_profile": self._config_values.get("detection_profile", "credentials"),
            "detection_profile": self._config_values.get("detection_profile", "credentials"),
            "profiles": self._config_values.get("profiles", {}),
            "worker_policy": self._config_values.get("worker_policy", "strict"),
            "scan_workers": self._config_values.get("scan_workers", 2),
            "max_file_bytes": self._config_values.get("max_file_bytes", 20_971_520),
            "scan_timeout_seconds": self._config_values.get("scan_timeout_seconds", 45),
        }

    @_backend_locked
    def save_settings(self, payload: dict[str, Any]):
        profile = payload.get("active_profile", self._config_values.get("detection_profile", "credentials"))
        if profile not in {"credentials", "sensitive", "firm"}:
            raise ValueError("profile-invalid")
        values = dict(self._config_values)
        values["detection_profile"] = profile
        scan_workers = payload.get("scan_workers", values.get("scan_workers", 2))
        if type(scan_workers) is not int or scan_workers not in {1, 2}:
            raise ValueError("settings-invalid")
        values["scan_workers"] = scan_workers
        checked = self._ScanConfig.from_mapping(values)
        host_restarted = self._replace_scan_config(values, checked)
        return {"settings": self.settings(), "observations_locked": False, "host_restarted": host_restarted}

    def _replace_scan_config(self, values: dict[str, Any], checked: object) -> bool:
        """Swap host configuration while retaining the unlocked encrypted store."""
        old_values, old_config = self._config_values, self._config
        store = self._observation_store
        host = self._host
        # stop() waits for the current bounded slice. Keep ownership references
        # until it succeeds; in particular, never close the store here.
        if host is not None:
            host.stop()
            self._host = None
        try:
            self._write_config(values)
            self._config_values, self._config = values, checked
            if store is not None:
                self._start_host(store)
            self._startup_observation_error = None
            return store is not None
        except BaseException:
            self._config_values, self._config = old_values, old_config
            try:
                self._write_config(old_values)
            except Exception:
                pass
            if store is not None and self._host is None:
                try:
                    # Reopen from the durable store to avoid reusing a stale
                    # scheduler snapshot if candidate construction checkpointed.
                    self._start_host(store)
                    self._startup_observation_error = None
                except Exception as error:
                    self._startup_observation_error = _safe_code(error) or "scheduler-failed"
            raise

    def _write_config(self, values: dict[str, Any] | None = None):
        from leakguard_core import settings as core_settings
        validated = core_settings.validate(dict(values if values is not None else self._config_values))
        self.config_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        runtime_content = json.dumps(validated, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8")
        _atomic_private_write(self.runtime_config_path, runtime_content)
        content = json.dumps({key: validated[key] for key in _BUDDY_CONFIG_FIELDS}, ensure_ascii=True, sort_keys=True, indent=2).encode("utf-8")
        _atomic_private_write(self.config_path, content)


def _private_write(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _safe_wheel_filename(value: Any) -> str:
    """Validate the PEP 427 basename before passing it to pip/core."""
    if (type(value) is not str or not 1 <= len(value) <= 255
            or not value.endswith(".whl") or "/" in value or "\\" in value
            or "\x00" in value or Path(value).name != value):
        raise BuddyOperationError("plugin-invalid")
    parts = value[:-4].split("-")
    if len(parts) == 6:
        distribution, version, build, python_tag, abi_tag, platform_tag = parts
        if not re.fullmatch(r"[0-9][A-Za-z0-9_]*", build, re.ASCII):
            raise BuddyOperationError("plugin-invalid")
    elif len(parts) == 5:
        distribution, version, python_tag, abi_tag, platform_tag = parts
    else:
        raise BuddyOperationError("plugin-invalid")
    if not re.fullmatch(r"[A-Za-z0-9_]+", distribution, re.ASCII):
        raise BuddyOperationError("plugin-invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.!+]+", version, re.ASCII):
        raise BuddyOperationError("plugin-invalid")
    for tag in (python_tag, abi_tag, platform_tag):
        if not tag or any(not re.fullmatch(r"[A-Za-z0-9_]+", alternative, re.ASCII)
                          for alternative in tag.split(".")):
            raise BuddyOperationError("plugin-invalid")
    try:
        from packaging.utils import parse_wheel_filename
    except ImportError:
        # The grammar above still prevents path components in minimal dev
        # environments; the private runtime also validates full wheel syntax.
        pass
    else:
        try:
            parse_wheel_filename(value)
        except (TypeError, ValueError):
            raise BuddyOperationError("plugin-invalid") from None
    return value


def _atomic_private_write(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".buddy-config-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try: os.fsync(directory)
            finally: os.close(directory)
        except OSError:
            pass
    finally:
        try: os.close(descriptor)
        except OSError: pass
        try: temporary.unlink()
        except OSError: pass


def _safe_code(error: Exception) -> str | None:
    code = getattr(error, "code", None)
    safe = _HOOK_ERRORS | {
        "observation-keyring-unavailable", "observation-keyring-not-enabled",
        "observation-keyring-invalid", "state-locked", "state-checkpoint-failed",
        "state-capacity-limit", "state-query-invalid", "state-cycle-busy",
    }
    if type(code) is str and code in safe:
        return code
    return None


def _encode_findings_cursor(cursor: str, filter_id: str) -> str:
    raw = json.dumps({"v": 1, "filter": filter_id, "cursor": cursor}, separators=(",", ":")).encode("ascii")
    return "lgf1." + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_findings_cursor(cursor: str | None, filter_id: str) -> str | None:
    if cursor is None:
        return None
    if type(cursor) is not str or not cursor.startswith("lgf1.") or len(cursor) > 4096:
        raise ValueError("state-query-invalid")
    encoded = cursor[5:]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", encoded):
        raise ValueError("state-query-invalid")
    try:
        value = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("state-query-invalid") from None
    if type(value) is not dict or set(value) != {"v", "filter", "cursor"} or value["v"] != 1 or value["filter"] != filter_id:
        raise ValueError("state-query-invalid")
    inner = value["cursor"]
    if inner is not None and (type(inner) is not str or len(inner) > 1024):
        raise ValueError("state-query-invalid")
    return inner


def _as_list(value: Any) -> list[dict[str, Any]]:
    return value if type(value) is list else value.get("sources", []) if type(value) is dict else []


def _extract_id(value: Any) -> str | None:
    if type(value) is dict and type(value.get("id")) is str:
        return value["id"]
    return None


def _wire(value: Any) -> Any:
    if callable(getattr(value, "to_dict", None)):
        return value.to_dict()
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import asdict
        return asdict(value)
    if type(value) in {dict, list, tuple, str, int, float, bool} or value is None:
        return list(value) if type(value) is tuple else value
    return {"status": "completed"}


def _source_for_path(sources: list[dict[str, Any]], path: str) -> str | None:
    if not path:
        return None
    best: tuple[int, str] | None = None
    candidate = os.path.normcase(os.path.abspath(path))
    for source in sources:
        root = source.get("root")
        source_id = source.get("id")
        if type(root) is not str or type(source_id) is not str:
            continue
        normalized = os.path.normcase(os.path.abspath(root))
        try:
            if os.path.commonpath((candidate, normalized)) != normalized:
                continue
        except ValueError:
            continue
        if best is None or len(normalized) > best[0]:
            best = (len(normalized), source_id)
    return best[1] if best else None


def _repository_key(path: str) -> str:
    return hashlib.sha256(os.path.normcase(os.path.abspath(path)).encode("utf-8", "surrogatepass")).hexdigest()


def _finding_category(rule: Any) -> str:
    """Map stable detector rule IDs to UI categories without inspecting values."""
    value = rule if type(rule) is str else ""
    if value.startswith("pii-contact-"):
        return "contact"
    if value.startswith("pii-financial-"):
        return "financial-identifier"
    if value.startswith("pii-identifier-"):
        return "organization-identifier"
    if value.startswith("firm-"):
        return "firm"
    if value.startswith(("literal-", "xml-", "credential-", "secret-", "password-", "gitleaks-")):
        return "credentials"
    return "other"


def _int(value: str, default: int, minimum: int, maximum: int) -> int:
    try: result = int(value, 10)
    except (TypeError, ValueError): result = default
    return max(minimum, min(maximum, result))
