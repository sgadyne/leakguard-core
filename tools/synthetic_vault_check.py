#!/usr/bin/env python3
"""Exercise installed vault create, save, lock, reopen and portable recovery."""
from pathlib import Path
import json
import tempfile

from leakguard_vault import CredentialVault

# Fixed, deliberately non-secret test inputs. Never point this at a real vault.
PASS = "synthetic-vault-passphrase-only"
RECOVERY = "synthetic-recovery-passphrase-only"
NEW = "synthetic-restored-passphrase-only"
MARKER = "synthetic-vault-value-only"


def main():
    with tempfile.TemporaryDirectory(prefix="lg-synthetic-vault-") as directory:
        root = Path(directory)
        vault = CredentialVault(root / "test.lgv")
        session = vault.create(PASS)
        entry = session.save_entry(title="synthetic", secret=MARKER)
        session.backup(root / "backup.lgb", RECOVERY)
        vault.lock()
        reopened = vault.unlock(PASS)
        assert reopened.reveal_entry(entry["id"])["secret"] == MARKER
        vault.lock()
        restored = CredentialVault(root / "restored.lgv")
        recovered = restored.restore(root / "backup.lgb", RECOVERY, NEW)
        assert recovered.reveal_entry(entry["id"])["secret"] == MARKER
        restored.lock()
        reopened_restored = restored.unlock(NEW)
        assert reopened_restored.reveal_entry(entry["id"])["secret"] == MARKER
        restored.lock()
    print(json.dumps({"synthetic_only": True, "create_save_lock_reopen": True,
                      "backup_restore_reopen": True, "temporary_data_removed": True}))


if __name__ == "__main__":
    main()
