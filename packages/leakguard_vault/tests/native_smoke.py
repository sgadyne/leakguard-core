"""Framework-free synthetic storage acceptance for one installed native runtime.

Run in an owned scratch directory. Prints redacted booleans/counts only; no
keyring writes or real user files are involved.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

from leakguard_core.models import SourceKind, SourceRef
from leakguard_core.scan_store import ScanStore
from leakguard_vault import CredentialVault, EncryptedScanStore, VaultError


def run(parent: Path):
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = {"old_capability_revoked": False, "wrong_passphrase_rejected": False,
              "tampered_ciphertext_rejected": False}
    with tempfile.TemporaryDirectory(prefix="vault-native-", dir=parent) as folder:
        root = Path(folder)
        phrase = "synthetic-native-recovery-passphrase"
        marker = "synthetic-native-secret-f129e7aa4"
        vault = CredentialVault(root / "credentials.lgv")
        session = vault.create(phrase)
        entry = session.save_entry(title="Synthetic example", secret=marker, username="synthetic-user", notes="synthetic-note", finding_id="synthetic-finding")
        checks["metadata_redacted"] = not {"secret", "username", "notes"} & set(entry)
        session.update_metadata(entry["id"], title="Renamed")
        session.update_secret(entry["id"], marker)
        checks["hidden_fields_preserved"] = session.reveal_entry(entry["id"])["username"] == "synthetic-user"
        session.backup(root / "credentials-backup.lgb", phrase)
        vault.lock()
        try:
            session.reveal_entry(entry["id"])
        except VaultError as error:
            checks["old_capability_revoked"] = error.code == "vault-locked"
        try:
            vault.unlock("synthetic-wrong-passphrase")
        except VaultError as error:
            checks["wrong_passphrase_rejected"] = error.code == "vault-authentication-failed"
        session = vault.unlock(phrase)
        checks["restart_unlock"] = session.reveal_entry(entry["id"])["secret"] == marker
        vault.lock()
        original = (root / "credentials.lgv").read_bytes()
        (root / "credentials.lgv").write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        try:
            vault.unlock(phrase)
        except VaultError as error:
            checks["tampered_ciphertext_rejected"] = error.code == "vault-authentication-failed"
        (root / "credentials.lgv").write_bytes(original)
        restored = CredentialVault(root / "restored.lgv")
        restored_session = restored.restore(root / "credentials-backup.lgb", phrase, "synthetic-new-machine-passphrase")
        checks["portable_backup"] = restored_session.reveal_entry(entry["id"])["secret"] == marker
        restored.lock()
        path = root / "observations.lgo"
        store = EncryptedScanStore.create(path, phrase)
        checks["runtime_store_protocol"] = isinstance(store, ScanStore)
        store.save_host_state({"progress": 1, "root": "synthetic-private-root"})
        store.set_annotation("synthetic-finding", "dismissed")
        source = SourceRef(SourceKind.FILESYSTEM, "/synthetic/private-file")
        checks["initial_generation"] = store.reserve(source) == 1
        start = time.perf_counter()
        store.checkpoint()
        checkpoint_ms = round((time.perf_counter() - start) * 1000, 3)
        checkpoint_bytes = store.status()["serialized_bytes"]
        store.close()
        # A child loses its in-memory, unacknowledged reservation without close.
        # Passphrase is synthetic; pass over stdin, never process argv/env/logs.
        child = """import json,os,sys
from pathlib import Path
from leakguard_core.models import SourceKind,SourceRef
from leakguard_vault import EncryptedScanStore
value=json.loads(sys.stdin.read())
s=EncryptedScanStore.open(Path(value['path']),value['passphrase'])
s.reserve(SourceRef(SourceKind.FILESYSTEM,'/synthetic/private-file'))
os._exit(0)
"""
        process = subprocess.run([sys.executable, "-c", child], input=json.dumps({"path": str(path), "passphrase": phrase}), text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        checks["crash_child_exited"] = process.returncode == 0
        store = EncryptedScanStore.open(path, phrase)
        checks["unacknowledged_crash_replay"] = store.reserve(source) == 2
        checks["durable_job_progress"] = store.load_host_state()["progress"] == 1
        checks["annotation_overlay"] = store.get_annotation("synthetic-finding")["state"] == "dismissed" and store.query_findings() == ()
        store.backup(root / "observations-backup.lgb", phrase)
        material_key = store._store._memory_material_key
        store.close()
        recovered = EncryptedScanStore.restore(root / "observations-backup.lgb", phrase, root / "recovered.lgo", "synthetic-new-machine-passphrase")
        checks["observation_portability"] = recovered.load_host_state()["progress"] == 1 and recovered._store._memory_material_key == material_key
        recovered.close()
        before = path.read_bytes()
        probe = EncryptedScanStore.keyring_status(path)
        checks["keyring_fallback_honest"] = probe["unattended_available"] is False and probe["keyring_enabled"] is False
        checks["doctor_read_only"] = path.read_bytes() == before
        values = [marker.encode(), phrase.encode(), b"synthetic-private-root", b"/synthetic/private-file", b"synthetic-user", b"synthetic-note"]
        checks["no_plaintext_persistence"] = all(not any(value in file.read_bytes() for value in values) for file in root.iterdir() if file.is_file())
        checks["no_sqlite_or_key_mirrors"] = all(not any(token in file.name for token in ("sqlite", "material-key", "journal")) for file in root.iterdir())
        result = {"schema": 1, "platform": platform.system(), "machine": platform.machine(), "python": platform.python_version(),
                  "checks": checks, "passed": all(checks.values()), "checkpoint_bytes": checkpoint_bytes, "checkpoint_ms": checkpoint_ms,
                  "native_keyring_tested": False}
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.work)
    except Exception as error:
        code = getattr(error, "code", "storage-smoke-failed")
        result = {"schema": 1, "passed": False, "error_code": code if isinstance(code, str) and len(code) < 80 else "storage-smoke-failed"}
    rendered = json.dumps(result, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n")
    print(rendered)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
