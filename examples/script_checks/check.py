"""Synthetic fixed-argv script-check example implementing protocol v1."""
import json
import sys


MAX_REQUEST_BYTES = 16_000_000
MAX_RESPONSE_BYTES = 1_000_000


def main() -> int:
    request_bytes = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(request_bytes) > MAX_REQUEST_BYTES:
        return 2
    try:
        request = json.loads(request_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return 2
    if not isinstance(request, dict) or request.get("protocol_version") != 1:
        return 2
    text = request.get("text")
    if not isinstance(text, str):
        return 2
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if "FIRM-DEMO-MARKER" in line:
            findings.append({"rule": "firm-demo-marker", "line": line_number, "severity": "review"})
    response = json.dumps(
        {"schema_version": 1, "findings": findings},
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if len(response) > MAX_RESPONSE_BYTES:
        return 2
    sys.stdout.buffer.write(response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
