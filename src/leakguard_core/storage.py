"""Explicit observation-store selection for standalone and installed consumers.

The alpha profile never falls back to plaintext. Git enforcement can scan in
memory while the encrypted observation session is unavailable; queries must
instead fail so an unavailable store cannot look like an empty finding list.
"""
from pathlib import Path

from .scan_store import MemoryScanStore, SQLiteScanStore, StateError


def open_scan_store(state_dir, *, config, allow_ephemeral=True):
    if state_dir is None:
        return MemoryScanStore(config=config)
    if config.get('observation_backend', 'legacy') == 'legacy':
        return SQLiteScanStore(state_dir, config=config)
    try:
        from leakguard_vault import EncryptedScanStore
        path = Path(config.get('observation_path') or Path(state_dir) / 'observations.lgo')
        return EncryptedScanStore.open_keyring(path, config=config)
    except Exception:
        # No source bytes, exception strings, passphrases or key material escape.
        # Missing crypto, locked keyring, contention and corrupt envelopes all
        # leave enforcement ephemeral. Durable queries must report unavailable.
        if not allow_ephemeral:
            raise StateError() from None
        store = MemoryScanStore(config=config)
        store._leakguard_ephemeral_observations = True
        return store
