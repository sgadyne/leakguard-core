"""One synthetic real-engine/real-encrypted-store receipt, run at integration.

Usage: python encrypted_smoke.py /absolute/gitleaks /owned/scratch/receipt-root
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

from leakguard_core import ScanConfig, ScanLimits
from leakguard_host import HostService
from leakguard_vault import EncryptedScanStore


def main():
    binary, owned = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    owned.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = owned / "source"
    root.mkdir()
    secret = "SYNTHETIC_HOST_ONLY_94c89b0b9cae41eab0"
    for index in range(5):
        (root / f"example-{index}.txt").write_text(f'password = "{secret}"\n', encoding="utf-8")
    config = ScanConfig.from_mapping({"gitleaks_executable": str(binary)})
    path = owned / "observations.lgo"
    store = EncryptedScanStore.create(path, "Synthetic host integration passphrase 2026!", config=config.to_mapping())
    limits = ScanLimits(deadline_seconds=5, max_files=1, max_report_bytes=1_000_000)
    host = HostService(config=config, scan_store=store, limits=limits)
    source = host.add_source(root)
    job = host.submit(source["id"])
    first = host.tick()
    assert first["job"]["state"] == "queued", first
    assert first["job"]["pending_files"] > 0
    store.close()
    assert secret.encode() not in path.read_bytes()
    assert str(root).encode() not in path.read_bytes()
    store = EncryptedScanStore.open(path, "Synthetic host integration passphrase 2026!", config=config.to_mapping())
    host = HostService(config=config, scan_store=store, limits=limits)
    assert host.job(job["id"])["state"] == "paused"
    host.resume(job["id"])
    states = []
    for _ in range(12):
        result = host.tick()
        states.append(result["status"])
        if result["status"] in {"completed", "failed", "backoff"}:
            break
    assert states[-1] == "completed", states
    findings = store.query_findings()
    assert len(findings) == 5, len(findings)
    assert secret not in json.dumps(findings)
    assert secret not in store.latest_report().to_json()
    complete = host.job(job["id"])
    assert complete["files_scanned"] == 5, complete
    assert host.status()["unattended_available"] is False
    # A fresh explicit job abandons prior cycle state, preserving cached evidence.
    second = host.submit(source["id"])
    assert second["id"] != job["id"]
    host.cancel(second["id"])
    host.stop()
    store.close()
    persisted = [str(item.relative_to(owned)) for item in owned.rglob("*") if item.is_file() and root not in item.parents]
    assert not any(name.endswith((".json", ".sqlite3", ".db")) for name in persisted), persisted
    assert secret.encode() not in path.read_bytes()
    print(json.dumps({"encrypted_resume": "passed", "findings": len(findings), "files": 5,
                      "states_after_restart": states, "plaintext_observation_files": 0,
                      "source_unchanged": all(secret in item.read_text() for item in root.iterdir()),
                      "platform": sys.platform}, sort_keys=True))


if __name__ == "__main__":
    main()
