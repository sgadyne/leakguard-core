#!/usr/bin/env python3
"""Score a small, independently labelled synthetic credential set.

Receipts contain case IDs, labels, rule IDs, and hashes only. Fixture text is
never copied into the result.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "tests" / "fixtures" / "independent_literal_labels.json"
RULES = ROOT / "src" / "leakguard_core" / "rules.toml"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
from _safe_inputs import source_identity


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("receipt-write-failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _catalog() -> tuple[dict, bytes]:
    raw = CATALOG.read_bytes()
    data = json.loads(raw)
    if type(data) is not dict or set(data) != {"schema_version", "labeling", "cases"}:
        raise ValueError("label-catalog-invalid")
    cases = data["cases"]
    if data["schema_version"] != 1 or type(cases) is not list or len(cases) != 12:
        raise ValueError("label-catalog-invalid")
    ids = set()
    positive = negative = 0
    for item in cases:
        if type(item) is not dict or not {"case_id", "category", "expected", "text"} <= set(item):
            raise ValueError("label-catalog-invalid")
        case_id, text = item["case_id"], item["text"]
        if (type(case_id) is not str or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", case_id) is None
                or case_id in ids or type(text) is not str or not text or "\n" in text or "\r" in text
                or len(text.encode("utf-8")) > 2048):
            raise ValueError("label-catalog-invalid")
        ids.add(case_id)
        if item["expected"] == "finding":
            positive += 1
            rule = item.get("expected_rule")
            if type(rule) is not str or re.fullmatch(r"literal-(?:client-secret|password)", rule) is None:
                raise ValueError("label-catalog-invalid")
        elif item["expected"] == "none":
            negative += 1
            if "expected_rule" in item:
                raise ValueError("label-catalog-invalid")
        else:
            raise ValueError("label-catalog-invalid")
    if positive != 6 or negative != 6:
        raise ValueError("label-balance-invalid")
    return data, raw


def run(backend: Path, timeout: float) -> dict:
    from leakguard_core import backends

    catalog, catalog_bytes = _catalog()
    if backend.is_symlink():
        raise ValueError("backend-invalid")
    backend = backend.resolve(strict=True)
    backend_stat = backend.stat()
    if not stat.S_ISREG(backend_stat.st_mode) or not os.access(backend, os.X_OK):
        raise ValueError("backend-invalid")
    if RULES.is_symlink() or not RULES.is_file():
        raise ValueError("rules-invalid")

    started = time.monotonic()
    case_rows = []
    counts = {name: 0 for name in ("true_positive", "false_positive", "true_negative", "false_negative")}
    failed = 0
    for item in catalog["cases"]:
        # Keep each label boundary isolated. Concatenating unrelated cases lets
        # a keyword in one example satisfy a context-sensitive rule in another.
        matches = backends.detect(item["text"], binary=backend, rules=RULES, timeout=timeout)
        rules = sorted({match.rule for match in matches})
        expected = item["expected"]
        predicted_positive = bool(rules)
        expected_positive = expected == "finding"
        if predicted_positive and expected_positive:
            counts["true_positive"] += 1
        elif predicted_positive:
            counts["false_positive"] += 1
        elif expected_positive:
            counts["false_negative"] += 1
        else:
            counts["true_negative"] += 1
        expected_rule = item.get("expected_rule")
        rule_matches = (expected_rule in rules) if expected_positive else not rules
        passed = rule_matches
        failed += not passed
        case_rows.append({
            "case_id": item["case_id"], "category": item["category"],
            "boundary": "isolated-input",
            "expected": expected, "actual": "finding" if predicted_positive else "none",
            "expected_rule": expected_rule, "observed_rules": rules,
            "status": "passed" if passed else "failed",
            "fixture_sha256": _sha(item["text"].encode("utf-8")),
        })

    source_commit, source_digest = source_identity(ROOT)
    return {
        "outcome": "passed" if failed == 0 else "failed",
        "source_commit": source_commit, "source_digest": source_digest,
        "catalog_sha256": _sha(catalog_bytes), "case_count": len(case_rows),
        "evaluation_boundary": "isolated-input",
        "label_counts": {"positive": 6, "negative": 6},
        "counts": {**counts, "failed": failed},
        "cases": case_rows,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--gitleaks", default=shutil.which("gitleaks"))
    parser.add_argument("--timeout-seconds", type=float, default=20.0)
    args = parser.parse_args(argv)
    output = Path(args.output).absolute()
    started = dt.datetime.now(dt.timezone.utc)
    source_commit = source_digest = "unknown"
    try:
        if args.gitleaks is None or not 1 <= args.timeout_seconds <= 120:
            raise ValueError("arguments-invalid")
        if output.is_symlink() or output.exists():
            raise ValueError("receipt-path-invalid")
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        revision_before, digest_before = source_identity(ROOT)
        details = run(Path(args.gitleaks), args.timeout_seconds)
        source_commit, source_digest = revision_before, digest_before
        revision_after, digest_after = source_identity(ROOT)
        source_stable = (revision_before, digest_before) == (revision_after, digest_after)
        if not source_stable and details["outcome"] == "passed":
            details["outcome"] = "failed"
            details["source_stable"] = False
        else:
            details["source_stable"] = source_stable
        exit_code = 0 if details["outcome"] == "passed" else 1
    except Exception:
        details = {"outcome": "setup-failed", "source_commit": source_commit,
                   "source_digest": source_digest, "case_count": 0,
                   "label_counts": {"positive": 6, "negative": 6},
                   "counts": {"true_positive": 0, "false_positive": 0,
                              "true_negative": 0, "false_negative": 0,
                              "failed": 1}, "cases": [], "source_stable": False}
        exit_code = 2
    receipt = {
        "schema_version": 1, "run_id": uuid.uuid4().hex,
        "lane": "evidence", "host_label": platform.system().lower(),
        "python": sys.version.split()[0], "started_utc": started.isoformat(),
        "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(), **details,
    }
    try:
        _write_new(output, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except Exception:
        return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
