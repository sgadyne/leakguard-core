"""Build and validate the checked-in grouped split/label manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from .corpus import (CORPUS_VERSION, DEFAULT_SEED, build_adversarial_cases,
                     build_cases, canonical_label_bytes, fixture_digest)
from .auxiliary import build_auxiliary_cases


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = Path(__file__).with_name("split_manifest.json")


def make_manifest(seed: int = DEFAULT_SEED) -> dict:
    cases = build_cases(seed)
    adversarial = build_adversarial_cases(seed)
    auxiliary = build_auxiliary_cases(seed)
    family_splits: dict[str, str] = {}
    seed_splits: dict[str, str] = {}
    rows = []
    for case in cases:
        if case.template_family in family_splits and family_splits[case.template_family] != case.split:
            raise ValueError("template family crosses splits")
        if case.seed_group in seed_splits and seed_splits[case.seed_group] != case.split:
            raise ValueError("seed group crosses splits")
        family_splits[case.template_family] = case.split
        seed_splits[case.seed_group] = case.split
        label = case.label_dict()
        rows.append({**label, "fixture_sha256": fixture_digest(case)})
    label_digest = hashlib.sha256(canonical_label_bytes(cases)).hexdigest()
    auxiliary_label_digest = hashlib.sha256(canonical_label_bytes(auxiliary)).hexdigest()
    split_counts = {name: sum(row["split"] == name for row in rows) for name in ("dev", "holdout")}
    positive_counts = {name: sum(row["split"] == name and row["format_outcome"] == "positive" for row in rows) for name in split_counts}
    negative_counts = {name: sum(row["split"] == name and row["format_outcome"] == "negative" for row in rows) for name in split_counts}
    development_counts = {name: sum(row["development_partition"] == name for row in rows) for name in ("train", "validation")}
    auxiliary_rows = [{**case.label_dict(), "fixture_sha256": fixture_digest(case)} for case in auxiliary]
    auxiliary_counts = {name: sum(row["split"] == name for row in auxiliary_rows) for name in ("dev", "holdout")}
    auxiliary_family_splits: dict[str, str] = {}
    auxiliary_seed_splits: dict[str, str] = {}
    for case in auxiliary:
        if case.template_family in auxiliary_family_splits and auxiliary_family_splits[case.template_family] != case.split:
            raise ValueError("auxiliary template family crosses splits")
        if case.seed_group in auxiliary_seed_splits and auxiliary_seed_splits[case.seed_group] != case.split:
            raise ValueError("auxiliary seed group crosses splits")
        auxiliary_family_splits[case.template_family] = case.split
        auxiliary_seed_splits[case.seed_group] = case.split
    return {
        "schema_version": 1,
        "corpus_version": CORPUS_VERSION,
        "corpus_seed": seed,
        "labeling": {
            "format_outcome": "positive means RFC 7516 compact serialization with a supported intact algorithm profile; negative means a spec-defined non-JWE or benign lookalike; malformed derivatives are separately adversarial and never negatives/TNs",
            "actionability": "exposure context is labeled independently from compact-format structure; standalone is unknown; public documentation examples are public",
            "span": "half-open Unicode codepoint offsets covering exactly the compact JWE candidate",
            "grouping": "template_family and seed_id values each belong to dev or holdout only once; holdout groups are absent from dev",
            "development_partition": "dev includes predeclared train and validation development partitions; holdout remains a frozen group-disjoint partition",
        },
        "counts": {"total": len(cases), "positive": sum(row["format_outcome"] == "positive" for row in rows),
                   "negative": sum(row["format_outcome"] == "negative" for row in rows),
                   "split": split_counts, "development_partition": development_counts,
                   "positive_by_split": positive_counts,
                   "negative_by_split": negative_counts,
                   "adversarial_separate": len(adversarial),
                   "auxiliary_context_preset": len(auxiliary),
                   "auxiliary_positive": sum(row["format_outcome"] == "positive" for row in auxiliary_rows),
                   "auxiliary_negative": sum(row["format_outcome"] == "negative" for row in auxiliary_rows),
                   "auxiliary_split": auxiliary_counts},
        "family_splits": dict(sorted(family_splits.items())),
        "seed_split_digest": hashlib.sha256(json.dumps(seed_splits, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "labels_sha256": label_digest,
        "auxiliary_labels_sha256": auxiliary_label_digest,
        "auxiliary_family_splits": dict(sorted(auxiliary_family_splits.items())),
        "auxiliary_seed_split_digest": hashlib.sha256(json.dumps(auxiliary_seed_splits, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "cases": rows,
        "auxiliary_cases": auxiliary_rows,
        "adversarial_cases": [
            {**case.label_dict(), "fixture_sha256": fixture_digest(case)}
            for case in adversarial
        ],
    }


def validate_manifest(manifest: dict, seed: int = DEFAULT_SEED) -> list:
    expected = make_manifest(seed)
    if manifest != expected:
        raise ValueError("frozen split/label manifest does not match deterministic generator")
    return build_cases(seed)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--check", action="store_true", help="compare generated labels to the frozen manifest")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    target = Path(args.output)
    manifest = make_manifest(args.seed)
    if args.check:
        current = json.loads(target.read_text(encoding="utf-8"))
        if current != manifest:
            print("frozen split/label manifest mismatch", file=sys.stderr)
            return 1
        print(json.dumps({"ok": True, "counts": manifest["counts"], "labels_sha256": manifest["labels_sha256"]}, sort_keys=True))
        return 0
    target.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(target), "counts": manifest["counts"], "labels_sha256": manifest["labels_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
