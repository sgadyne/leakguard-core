"""A resumed policy change must rescan files completed by the old policy."""
import json
from pathlib import Path
import sys

from leakguard_core import ScanConfig, ScanLimits
from leakguard_host import HostService
from leakguard_vault import EncryptedScanStore

owned, binary = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
owned.mkdir(mode=0o700, parents=True, exist_ok=False)
source_root = owned / "source"
source_root.mkdir()
value = "SYNTHETIC_POLICY_FENCE_9a58df612fd94bc7"
for index in range(5):
    (source_root / f"example-{index}.txt").write_text(f'password = "{value}"\n')
base = {"gitleaks_executable": str(binary)}
config = ScanConfig.from_mapping(base)
limits = ScanLimits(deadline_seconds=5, max_files=1, max_report_bytes=1_000_000)
path = owned / "observations.lgo"
passphrase = "Synthetic policy migration integration passphrase!"
store = EncryptedScanStore.create(path, passphrase, config=config.to_mapping())
host = HostService(config=config, scan_store=store, limits=limits)
source = host.add_source(source_root)
job = host.submit(source["id"])
assert host.tick()["status"] == "queued"
initial = store.query_findings()
assert len(initial) == 1
assert initial[0]["severity"] == "block"
rule = initial[0]["rule"]
host.stop()
store.close()
changed = ScanConfig.from_mapping({**base, "review_only_rules": [rule]})
store = EncryptedScanStore.open(path, passphrase, config=changed.to_mapping())
host = HostService(config=changed, scan_store=store, limits=limits)
host.resume(job["id"])
states = []
for _ in range(12):
    result = host.tick()
    states.append(result["status"])
    if result["status"] in {"completed", "failed", "backoff", "paused"}:
        break
assert states[-1] == "completed", states
final = host.job(job["id"])
assert final["policy_resets"] == 1
assert final["files_scanned"] == 5
findings = store.query_findings()
assert len(findings) == 5
assert all(row["severity"] == "review" and row["state"] == "active" for row in findings)
assert value not in json.dumps(findings)
assert value.encode() not in path.read_bytes()
host.stop()
store.close()
print(json.dumps({"policy_change_resume": "rescanned-all-files", "policy_resets": 1,
                  "files_under_new_policy": 5, "review_findings": 5, "old_block_findings": 0,
                  "encrypted": True, "platform": sys.platform}, sort_keys=True))
