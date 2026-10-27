"""Freeze and validate the V2 true-template grouped corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from .auxiliary_v2 import build_auxiliary_cases
from .auxiliary import build_auxiliary_cases as build_v1_auxiliary_cases
from .corpus import DEFAULT_SEED as V1_SEED, build_cases as build_v1_cases
from .corpus_v2 import (ADVERSARIAL_COUNT, CLEAN_NEGATIVE_COUNT, CORPUS_VERSION,
                        DEFAULT_SEED, JWE_COUNT, JWS_COUNT, build_adversarial_cases,
                        build_cases, canonical_label_bytes, fixture_digest,
                        v1_normalized_rendering)

DEFAULT_OUTPUT = Path(__file__).with_name("split_manifest_v2.json")


def _check_groups(cases, label):
    family_split = {}
    seed_split = {}
    family_fingerprint = {}
    for case in cases:
        if case.split not in {"dev", "holdout"}:
            raise ValueError(f"{label} has invalid split")
        if case.template_family in family_split and family_split[case.template_family] != case.split:
            raise ValueError(f"{label} template family crosses splits")
        if case.seed_group in seed_split and seed_split[case.seed_group] != case.split:
            raise ValueError(f"{label} seed group crosses splits")
        if case.template_family in family_fingerprint and family_fingerprint[case.template_family] != case.template_fingerprint:
            raise ValueError(f"{label} template family has multiple actual rendering fingerprints")
        family_split[case.template_family] = case.split
        seed_split[case.seed_group] = case.split
        family_fingerprint[case.template_family] = case.template_fingerprint
    return family_split, seed_split, family_fingerprint


def holdout_authorized(contract_path: Path | None = None) -> bool:
    """Read the lead-owned run contract before allowing any sealed split run."""
    if contract_path is None:
        candidates = [parent / "control" / "interfaces" / "contract.json"
                      for parent in (Path(__file__).resolve(), *Path(__file__).resolve().parents)]
        contract_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if contract_path is None:
        return False
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        return contract.get("evaluation", {}).get("holdout_authorized") is True
    except (OSError, json.JSONDecodeError, AttributeError):
        return False


def make_manifest(seed: int = DEFAULT_SEED) -> dict:
    cases = build_cases(seed)
    auxiliary = build_auxiliary_cases(seed)
    adversarial = build_adversarial_cases(seed)
    family_splits, seed_splits, family_fingerprints = _check_groups(cases, "main corpus")
    aux_families, aux_seeds, aux_fingerprints = _check_groups(auxiliary, "auxiliary corpus")
    dev_fingerprints = {case.template_fingerprint for case in cases if case.split == "dev"}
    holdout_fingerprints = {case.template_fingerprint for case in cases if case.split == "holdout"}
    if dev_fingerprints & holdout_fingerprints:
        raise ValueError("normalized rendering fingerprints cross V2 splits")
    auxiliary_dev_fingerprints = {case.template_fingerprint for case in auxiliary if case.split == "dev"}
    auxiliary_holdout_fingerprints = {case.template_fingerprint for case in auxiliary if case.split == "holdout"}
    if auxiliary_dev_fingerprints & auxiliary_holdout_fingerprints:
        raise ValueError("normalized auxiliary rendering fingerprints cross V2 splits")
    if (dev_fingerprints | auxiliary_dev_fingerprints) & (holdout_fingerprints | auxiliary_holdout_fingerprints):
        raise ValueError("main/aux normalized rendering fingerprints cross V2 splits")

    # Audit actual normalized V1 DEV renderings, not family-name conventions.
    v1_dev = [case for case in build_v1_cases(V1_SEED) if case.split == "dev"]
    v1_auxiliary_dev = [case for case in build_v1_auxiliary_cases(V1_SEED) if case.split == "dev"]
    v1_dev.extend(v1_auxiliary_dev)
    prior_dev_surfaces = {v1_normalized_rendering(case) for case in v1_dev}
    overlapping_holdout = sorted(case.template_family for case in cases
                                 if case.split == "holdout"
                                 and case.normalized_template in prior_dev_surfaces)
    if overlapping_holdout:
        raise ValueError("V2 heldout normalized renderings appeared in V1 DEV")
    overlapping_aux_holdout = sorted(case.template_family for case in auxiliary
                                     if case.split == "holdout"
                                     and case.normalized_template in prior_dev_surfaces)
    if overlapping_aux_holdout:
        raise ValueError("V2 auxiliary heldout renderings appeared in V1 DEV")

    rows = [{**case.label_dict(), "fixture_sha256": fixture_digest(case)} for case in cases]
    auxiliary_rows = [{**case.label_dict(), "fixture_sha256": fixture_digest(case)} for case in auxiliary]
    adversarial_rows = [{**case.label_dict(), "fixture_sha256": fixture_digest(case)} for case in adversarial]
    split_counts = {name: sum(case.split == name for case in cases) for name in ("dev", "holdout")}
    def count_role(split, role):
        return sum(case.split == split and role(case) for case in cases)
    counts_by_split = {
        split: {
            "total": split_counts[split],
            "jwe_positive": count_role(split, lambda case: case.format_outcome == "positive"),
            "jws_candidate_positive": count_role(split, lambda case: bool(case.expected_other_spans)),
            "clean_all_jose_negative": count_role(split, lambda case: case.negative_kind not in {None, "jws-candidate"}),
        } for split in ("dev", "holdout")
    }
    expected_by_split = {
        "dev": {"total": 10_400, "jwe_positive": 1_600,
                "jws_candidate_positive": 800, "clean_all_jose_negative": 8_000},
        "holdout": {"total": 2_600, "jwe_positive": 400,
                    "jws_candidate_positive": 200, "clean_all_jose_negative": 2_000},
    }
    if counts_by_split != expected_by_split:
        raise AssertionError("v2 grouped class/split cardinality changed")
    if (len(cases) != JWE_COUNT + JWS_COUNT + CLEAN_NEGATIVE_COUNT
            or len(adversarial) != ADVERSARIAL_COUNT):
        raise AssertionError("v2 corpus cardinality changed")
    labels_hash = hashlib.sha256(canonical_label_bytes(cases)).hexdigest()
    auxiliary_hash = hashlib.sha256(canonical_label_bytes(auxiliary)).hexdigest()
    template_map = {**family_fingerprints,
                    **{f"aux:{name}": fingerprint for name, fingerprint in aux_fingerprints.items()}}
    template_hash = hashlib.sha256(json.dumps(template_map, sort_keys=True,
        separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "schema_version": 1,
        "corpus_version": CORPUS_VERSION,
        "corpus_seed": seed,
        "labeling": {
            "jwe_target": "positive is an intact supported five-part RFC 7516 compact JWE; JWS candidates remain JWE negatives and are separately labeled in other_spans",
            "jws_target": "intact supported three-part compact JWS candidate, measured separately from the JWE target",
            "clean_negative": "10,000 predeclared examples contain no valid compact JOSE structure; malformed derivatives are adversarial and never TNs",
            "actionability": "exposure is separate from structure; public documentation JWE examples remain format positives; standalone exposure stays unknown",
            "span": "half-open Unicode codepoint offsets around exactly the compact JWE/JWS candidate",
            "grouping": "template_family and seed_id are disjoint across dev and holdout; split labels are fixed before detector runs",
            "rendering_fingerprints": "computed from each concrete generated wrapper normalized only at known synthetic value spans plus the parsed protected-header member shape",
        },
        "counts": {
            "total": len(cases), "jwe_positive": JWE_COUNT, "jws_candidate_positive": JWS_COUNT,
            "clean_all_jose_negative": CLEAN_NEGATIVE_COUNT,
            "jwe_target_negative_including_jws": JWS_COUNT + CLEAN_NEGATIVE_COUNT,
            "joint_jose_positive": JWE_COUNT + JWS_COUNT,
            "split": split_counts, "by_split_and_class": counts_by_split,
            "adversarial_shared_regression": len(adversarial),
            "auxiliary_shared_context_preset": len(auxiliary),
            "auxiliary_split": {name: sum(case.split == name for case in auxiliary) for name in ("dev", "holdout")},
            "document_gate_scope": "72 generated files are shared integration/regression cases, not independent holdout performance data",
        },
        "family_splits": dict(sorted(family_splits.items())),
        "family_template_fingerprints": dict(sorted(template_map.items())),
        "seed_split_digest": hashlib.sha256(json.dumps(seed_splits, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest(),
        "template_fingerprints_sha256": template_hash,
        "labels_sha256": labels_hash,
        "auxiliary_labels_sha256": auxiliary_hash,
        "auxiliary_family_splits": dict(sorted(aux_families.items())),
        "auxiliary_seed_split_digest": hashlib.sha256(json.dumps(aux_seeds, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest(),
        "v1_dev_actual_render_fingerprints_sha256": hashlib.sha256(
            "\n".join(sorted(hashlib.sha256(surface.encode("utf-8")).hexdigest()
                              for surface in prior_dev_surfaces)).encode("ascii")).hexdigest(),
        "v2_holdout_vs_v1_dev_render_overlap": 0,
        "cases": rows,
        "auxiliary_cases": auxiliary_rows,
        "adversarial_cases": adversarial_rows,
    }


def validate_manifest(manifest: dict, seed: int = DEFAULT_SEED) -> list:
    expected = make_manifest(seed)
    if manifest != expected:
        raise ValueError("frozen V2 split/label manifest does not match deterministic generator")
    return build_cases(seed)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)
    target = Path(args.output)
    manifest = make_manifest(args.seed)
    if args.check:
        current = json.loads(target.read_text(encoding="utf-8"))
        if current != manifest:
            print("frozen V2 split/label manifest mismatch", file=sys.stderr)
            return 1
        print(json.dumps({"ok": True, "counts": manifest["counts"],
                          "labels_sha256": manifest["labels_sha256"],
                          "template_fingerprints_sha256": manifest["template_fingerprints_sha256"]}, sort_keys=True))
        return 0
    target.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(target), "counts": manifest["counts"],
                      "labels_sha256": manifest["labels_sha256"],
                      "template_fingerprints_sha256": manifest["template_fingerprints_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
