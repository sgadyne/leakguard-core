"""Encrypted cursor progress must survive restart without host false stalls."""
import json
from pathlib import Path
import sys

from leakguard_core import ScanConfig, ScanLimits
from leakguard_host import HostService
from leakguard_vault import EncryptedScanStore

owned, binary = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
owned.mkdir(mode=0o700, parents=True, exist_ok=False)
root = owned / "source"
root.mkdir()
names = [f"excluded-{index}.txt" for index in range(18)]
for name in names:
    (root / name).write_text("benign synthetic operator-excluded fixture\n")
config = ScanConfig.from_mapping({"gitleaks_executable": str(binary)})
path = owned / "observations.lgo"
passphrase = "Synthetic encrypted directory cursor passphrase!"
limits = ScanLimits(deadline_seconds=3, max_files=2, max_directory_entries=3, max_report_bytes=1_000_000)
store = EncryptedScanStore.create(path, passphrase, config=config.to_mapping())
host = HostService(config=config, scan_store=store, limits=limits)
source = host.add_source(root, exclusions=names)
job = host.submit(source["id"])
states = []
for _ in range(12):
    result = host.tick()
    states.append(result["status"])
    assert result["status"] not in {"paused", "failed", "backoff"}, result["job"].get("last_error")
    if result["status"] == "completed":
        break
    host.stop()
    store.close()
    store = EncryptedScanStore.open(path, passphrase, config=config.to_mapping())
    host = HostService(config=config, scan_store=store, limits=limits)
    host.resume(job["id"])
assert states[-1] == "completed", states
assert host.job(job["id"])["files_scanned"] == 0
assert host.job(job["id"])["policy_resets"] == 0
assert host.sources()[0]["last_success_at"]
host.stop()
store.close()
print(json.dumps({"encrypted_directory_cursor": "passed", "all_excluded_progress": "completed-without-false-stall",
                  "operator_excluded_files": len(names), "files_read": 0, "slices": len(states),
                  "same_policy_resets": 0, "platform": sys.platform}, sort_keys=True))
