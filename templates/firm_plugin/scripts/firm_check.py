"""Fixed-argv script-check example for a synthetic firm marker."""
from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if (type(request) is not dict
                or set(request) != {"schema_version", "logical_path", "part_id", "format_id", "text"}
                or type(request["schema_version"]) is not int or request["schema_version"] != 1
                or any(type(request[key]) is not str for key in ("logical_path", "part_id", "format_id", "text"))):
            return 2
        findings = []
        for line_number, line in enumerate(request["text"].splitlines(), 1):
            if "FIRM-SCRIPT-REVIEW-MARKER" in line:
                findings.append({"rule": "firm-script-marker", "line": line_number, "severity": "review"})
        sys.stdout.write(json.dumps({"schema_version": 1, "findings": findings}, separators=(",", ":")))
        return 0
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
