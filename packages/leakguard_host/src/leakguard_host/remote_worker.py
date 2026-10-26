"""Memory-only remote scan endpoint; stdout is the redacted core report only."""
from __future__ import annotations

import json
from pathlib import Path
import sys

from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.models import ScanLimits, ScanPolicy
from leakguard_core.scan_store import MemoryScanStore


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(65_537)
        if len(payload) > 65_536:
            raise ValueError()
        request = json.loads(payload)
        if type(request) is not dict or set(request) != {"version", "root", "config_path", "max_seconds", "max_files"} or request["version"] != 1:
            raise ValueError()
        root = Path(request["root"])
        if not root.is_absolute() or not root.is_dir():
            raise ValueError()
        root = root.resolve(strict=True)
        seconds, files = request["max_seconds"], request["max_files"]
        if type(seconds) is not int or not 1 <= seconds <= 120 or type(files) is not int or not 1 <= files <= 1000:
            raise ValueError()
        config_path = request["config_path"]
        if config_path is not None and (type(config_path) is not str or not Path(config_path).is_absolute()):
            raise ValueError()
        config = ScanConfig.from_file(Path(config_path)) if config_path is not None else ScanConfig.from_mapping({})
        values = config.to_mapping()
        # No configured audit scope/priority root can widen the chosen target.
        values["audit_scopes"] = {"remote": str(root)}
        values["priority_paths"] = {}
        config = ScanConfig.from_mapping(values)
        store = MemoryScanStore(config=values)
        limits = ScanLimits(deadline_seconds=seconds, max_files=files, max_file_bytes=values["max_file_bytes"],
                            max_report_bytes=4_000_000, max_directory_entries=10_000,
                            detector_timeout_seconds=min(seconds, values["scan_timeout_seconds"]))
        with Scanner.open(config=config, store=store) as scanner:
            report = scanner.audit("remote", limits=limits)
        sys.stdout.write(report.to_json() + "\n")
        return 0
    except Exception:
        # Exception details and source bytes are never part of the protocol.
        sys.stderr.write("remote-scan-failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
