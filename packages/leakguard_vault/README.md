# LeakGuard encrypted local storage

`leakguard-vault` provides two separate capabilities. CredentialVault requires an
explicit create/unlock and returns a CredentialSession. Only that capability can
save or reveal manually supplied secrets. EncryptedScanStore receives a different
random key and implements core ScanStore semantics without credential methods.
Locking credentials never stops an independently unlocked observation session.

```python
from pathlib import Path
from leakguard_vault import CredentialVault, EncryptedScanStore

# Obtain passphrases from a foreground protected input, never URLs or logs.
vault = CredentialVault(Path(private_state) / "credentials.lgv")
credentials = vault.create(credential_passphrase)
credentials.save_entry(title="Example", secret=manually_entered_secret)
vault.lock()

observations = EncryptedScanStore.create(
    Path(private_state) / "observations.lgo", observation_passphrase,
    config=scan_config.to_mapping(),
)
# Inject observations into Scanner.open(config=scan_config, store=observations).
# After a bounded scan slice:
observations.save_host_state(job_progress)  # checkpoints the same database
observations.close()
```

The host owns and serializes its observation session; all adapter calls are also
protected by one reentrant lock. SQLite uses `:memory:`, `temp_store=MEMORY` and
`journal_mode=MEMORY`. Only encrypted serialized checkpoints, encrypted backups,
and empty ownership lock files are written. The64MiB serialized database limit
is enforced by SQLite page admission and checked again before encryption.
Review/dismiss annotations are an encrypted overlay; they do not change engine
finding state or Git enforcement. An offline or failed job cannot resolve an
existing exposure. `reset_cycle(scope)` abandons inactive enumeration only.

The version1 binary envelope starts with `LGVA\\x01\\x00\\r\\n`, a4-byte
big-endian header length, bounded canonical JSON metadata and AES-256-GCM
ciphertext. The authenticated metadata includes kind/version/cipher, random
identifier, Argon2id parameters and salt, wrapped random data key and payload
nonce. Each write uses a fresh96-bit nonce. Passphrase wrapping uses a separate
fresh nonce and Argon2id default64MiB,3 passes,4 lanes,16-byte salt. Decoders bound
header/ciphertext size and KDF parameters before allocating KDF work. Credential
and observation keys are independently generated. Material identity keys stay
inside the encrypted observation database; no plaintext key file is created.

Primary writes flush the encrypted temporary file, atomically replace and fsync
the containing directory on POSIX. A write error invalidates the credential
session or poisons observation access, requiring reopen before further progress.
No failing checkpoint acknowledges durable job state. The last unacknowledged
slice may replay after a crash. An OS file lock prevents concurrent stale writers.

New passphrases require12–1024 characters. Credential metadata returned by list
excludes secret, username and notes. Title/location/finding links remain encrypted
at rest. `reveal_entry` returns values only to an explicit caller. `update_metadata`
preserves the secret without reveal. Backup creates a new envelope and data key
protected by a separately supplied recovery passphrase; recovery works without
machine keyring state. Restore refuses to overwrite unless `replace=True` is
explicit. Deleting a credential does not promise secure erasure of filesystem
snapshots, old encrypted backups or storage hardware remnants.

Unattended observation access is opt-in. `enable_keyring()` directly selects the
native macOS Keychain, Windows WinVault or Linux Secret Service backend, then
verifies store/read/delete and the actual key round trip. Third-party, plaintext,
null and chained keyring fallbacks are excluded. `open_keyring()` authenticates
the checkpoint with the recovered key. Missing/locked keyrings produce a stable
unavailable error; foreground passphrase unlock remains available. Credentials
never gain a keyring unlock path. A saved keyring marker alone is not treated as
proof of current unattended access. Native backend support is not a claim that
all platforms were tested; see the release platform matrix.

Python cannot guarantee erasure of every immutable string/key copy, prevent OS
swap/crash dumps, or isolate malicious same-account plugin code. Key bytearrays
are cleared on lock and app-owned references are dropped; this is a local
account-level alpha, with trusted plugins and no sandbox claim. Clipboard and
browser reveal lifetimes are handled by Buddy. Application logs/report files must
never include these inputs or reveal responses.

Building blocks: [cryptography AEAD](https://cryptography.io/en/stable/hazmat/primitives/aead/),
[Argon2id](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/),
[native keyring backends](https://keyring.readthedocs.io/en/stable/), and
[SQLite serialization](https://sqlite.org/c3ref/serialize.html).
