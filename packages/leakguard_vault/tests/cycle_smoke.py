"""Real-backend encrypted audit continuation for the repaired cycle verdict.

Only an owned synthetic two-file source is read. Run with the exact installed
runtime and backend at an integration checkpoint; reports remain value-free.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import platform
import tempfile

from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.models import DecisionVerdict, ScanLimits
from leakguard_vault import EncryptedScanStore


def run(work: Path, backend: Path, worker_policy: str):
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    checks = {}
    with tempfile.TemporaryDirectory(prefix="encrypted-cycle-", dir=work) as temporary:
        root = Path(temporary)
        source = root / "source"
        source.mkdir(mode=0o700)
        marker = "synthetic-encrypted-cycle-secret-9725dc"
        (source / "a-positive.txt").write_text(f'password="{marker}"\n')
        (source / "b-clean.txt").write_text("ordinary synthetic document\n")
        before = {path.name: hashlib.sha256(path.read_bytes()).digest() for path in source.iterdir()}
        config = ScanConfig.from_mapping({"audit_scopes": {"synthetic": str(source)},
                                          "gitleaks_executable": str(backend),
                                          "worker_policy": worker_policy, "scan_workers": 1})
        path = root / "observations.lgo"
        phrase = "synthetic-encrypted-cycle-passphrase"
        store = EncryptedScanStore.create(path, phrase, config=config.to_mapping())
        try:
            with Scanner.open(config=config, store=store) as scanner:
                first = scanner.audit("synthetic", limits=ScanLimits(10, 1))
            checks["positive_first_slice_incomplete"] = not first.coverage.required_complete and first.counts.findings > 0
            store.save_host_state({"phase": 1})
        finally:
            store.close()
        store = EncryptedScanStore.open(path, phrase, config=config.to_mapping())
        try:
            checks["encrypted_progress_recovered"] = store.load_host_state() == {"phase": 1}
            published = []
            record_report = store.record_report
            def record(report, **kwargs):
                published.append(report)
                return record_report(report, **kwargs)
            store.record_report = record
            with Scanner.open(config=config, store=store) as scanner:
                final = scanner.audit("synthetic", limits=ScanLimits(10, 1))
            checks["clean_last_slice_complete"] = final.coverage.required_complete and final.counts.findings == 0
            checks["prior_positive_blocks_final_verdict"] = final.decision.verdict is DecisionVerdict.BLOCK
            checks["all_final_publications_block"] = bool(published) and all(not report.coverage.required_complete or report.decision.verdict is DecisionVerdict.BLOCK for report in published)
            checks["saved_final_report_matches"] = store.latest_report() == final
            checks["cycle_evidence_explained"] = any(issue.code.value == "audit-cycle-evidence" for issue in final.issues)
            store.save_host_state({"phase": 2})
        finally:
            store.close()
        store = EncryptedScanStore.open(path, phrase, config=config.to_mapping())
        try:
            checks["durable_final_report_blocks"] = store.latest_report().decision.verdict is DecisionVerdict.BLOCK
            checks["positive_remains_active"] = any(row["state"] == "active" for row in store.query_findings())
        finally:
            store.close()
        checks["source_unchanged"] = before == {p.name: hashlib.sha256(p.read_bytes()).digest() for p in source.iterdir()}
        private_markers = [marker.encode(), phrase.encode(), str(source).encode()]
        checks["no_plaintext_state"] = all(not any(value in p.read_bytes() for value in private_markers) for p in root.iterdir() if p.is_file())
        checks["no_sqlite_mirror"] = sorted(p.name for p in root.iterdir() if p.is_file()) == ["observations.lgo", "observations.lgo.lock"]
    return {"schema": 1, "platform": platform.system(), "python": platform.python_version(),
            "worker_policy": worker_policy, "checks": checks, "passed": all(checks.values())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--gitleaks", type=Path, required=True)
    parser.add_argument("--worker-policy", choices=("strict", "supervised-alpha"), required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = run(args.work, args.gitleaks, args.worker_policy)
    except Exception as error:
        code = getattr(error, "code", "encrypted-cycle-failed")
        result = {"schema": 1, "passed": False, "error_code": code if type(code) is str and len(code) < 80 else "encrypted-cycle-failed"}
    rendered = json.dumps(result, sort_keys=True)
    if args.output:
        args.output.write_text(rendered + "\n")
    print(rendered)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
