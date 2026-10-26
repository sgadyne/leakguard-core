"""Encrypted resumed-claim acceptance for selected-root ancestor substitution."""
import json
from pathlib import Path
import sys
from unittest.mock import patch

from leakguard_core import ScanConfig, ScanLimits, Scanner
from leakguard_core import sources
from leakguard_vault import EncryptedScanStore

owned, binary = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
owned.mkdir(mode=0o700, parents=True, exist_ok=False)
selected, outside = owned / "selected", owned / "outside"
selected.mkdir()
outside.mkdir()
child = selected / "child"
child.mkdir()
(child / "fixture.txt").write_text("benign synthetic placeholder\n")
(outside / "fixture.txt").write_text('password = "SYNTHETIC_BOUNDARY_ONLY_c98e1d875ad44706"\n')
config = ScanConfig.from_mapping({"gitleaks_executable": str(binary), "audit_scopes": {"selected": str(selected)}})
path = owned / "observations.lgo"
passphrase = "Synthetic selected-root resume test passphrase!"
store = EncryptedScanStore.create(path, passphrase, config=config.to_mapping())
lease = store.acquire_cycle("audit:selected", selected, lease_seconds=1)
store.enqueue_work(lease, ((str(child / "fixture.txt"), "file", 100),))
store.release_cycle(lease, allow_complete=False)
store.checkpoint()
store.close()
child.rename(owned / "parked")
child.symlink_to(outside, target_is_directory=True)
store = EncryptedScanStore.open(path, passphrase, config=config.to_mapping())
original = sources._bounded_file
escaped_reads = []
def checked(path, maximum, *args, **kwargs):
    if Path(path).absolute().is_relative_to(selected) and not Path(path).resolve().is_relative_to(selected):
        escaped_reads.append(True)
        raise AssertionError("outside-selected-root-read-attempt")
    return original(path, maximum, *args, **kwargs)
with patch.object(sources, "_bounded_file", checked):
    with Scanner.open(config=config, store=store) as scanner:
        report = scanner.audit("selected", limits=ScanLimits(3, 10, max_report_bytes=1_000_000))
assert escaped_reads == [], "outside-selected-root-read-attempt"
assert not report.coverage.required_complete
assert not report.counts.findings
assert not store.query_findings()
store.close()
print(json.dumps({"encrypted_resumed_ancestor_escape": "rejected-before-read", "outside_read_attempts": 0,
                  "coverage": "incomplete", "outside_findings": 0, "platform": sys.platform}, sort_keys=True))
