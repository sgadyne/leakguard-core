"""Separate small financial/identity context and preset ablation cases.

These values are generated from documented numeric formats and the task's
predeclared local-context hypotheses. They are independent of Presidio regexes
and are not folded into the compact-JWE confusion matrix.
"""
from __future__ import annotations

import hashlib
import random
import statistics

from .corpus import Case, DEFAULT_SEED, _derive
from .metrics import score_threshold_sweep


def _candidate_row(item, text_length: int) -> dict:
    valid = (item.start is not None and item.end is not None
             and 0 <= item.start < item.end <= text_length)
    return {"start": item.start if valid else None,
            "end": item.end if valid else None,
            "score": item.score, "severity": item.severity,
            "rule": item.rule, "entity": item.entity}


def _itin(rng: random.Random) -> str:
    range_code = rng.choice((range(50, 66), range(70, 89), range(90, 93), range(94, 100)))
    middle = rng.choice(tuple(range_code))
    return f"9{rng.randrange(10):01d}{rng.randrange(10):01d}-{middle:02d}-{rng.randrange(10_000):04d}"


def _bank(rng: random.Random) -> str:
    return str(rng.randrange(100_000_000, 1_000_000_000))


def build_auxiliary_cases(seed: int = DEFAULT_SEED) -> list[Case]:
    """Generate 160 labeled financial/identity and distance-context examples."""
    root_seed = hashlib.sha256(f"context-presets:{seed}".encode("ascii")).digest()
    result = []
    families = (
        ("bank-context", "US_BANK_NUMBER", True),
        ("itin-context", "US_ITIN", True),
        ("numeric-lookalike", None, False),
        ("distant-context", None, False),
    )
    for base_family, target_entity, positive in families:
        for variant in range(1, 5):
            family = f"{base_family}-v{variant}"
            split = "dev" if variant <= 2 else "holdout"
            for index in range(10):
                seed_group = f"aux/{family}/{index:02d}"
                rng_seed = int.from_bytes(_derive(root_seed, seed_group, 8), "big")
                rng = random.Random(rng_seed)
                selected_entity = target_entity
                if base_family == "bank-context":
                    value = _bank(rng)
                    text = f"bank account routing number: {value}"
                    span = (text.index(value), text.index(value) + len(value))
                    actionability = "exposed"
                    category = "financial-positive"
                elif base_family == "itin-context":
                    value = _itin(rng)
                    text = f"taxpayer identification number: {value}"
                    span = (text.index(value), text.index(value) + len(value))
                    actionability = "exposed"
                    category = "identity-positive"
                elif base_family == "numeric-lookalike":
                    selected_entity = ("US_BANK_NUMBER", "US_ITIN")[index % 2]
                    value = _bank(rng) if selected_entity == "US_BANK_NUMBER" else _itin(rng)
                    text = (f"build checksum={value} version=4.17.{index}"
                            if selected_entity == "US_BANK_NUMBER"
                            else f"record={value} fiscal year=2026 state=ready")
                    span = None
                    actionability = "unknown"
                    category = "misleading-numeric-context"
                else:
                    selected_entity = ("US_BANK_NUMBER", "US_ITIN")[index % 2]
                    value = _bank(rng) if selected_entity == "US_BANK_NUMBER" else _itin(rng)
                    distant = ("bank account routing number" if selected_entity == "US_BANK_NUMBER"
                               else "taxpayer identification number")
                    text = distant + ":\n" + ("ordinary synthetic record " * 10) + "\nvalue=" + value
                    span = None
                    actionability = "unknown"
                    category = "distant-context-negative"
                result.append(Case(
                    case_id=f"aux-{len(result):04d}", split=split,
                    template_family=family, seed_group=seed_group,
                    category=category, mode="embedded", text=text,
                    expected_spans=(span,) if span else (),
                    format_outcome="positive" if positive else "negative",
                    actionability=actionability, algorithm=None,
                    expected_entity=selected_entity,
                    development_partition="train" if split == "dev" else None,
                    logical_path="fixtures/context-presets/synthetic.txt",
                ))
    return result


def evaluate_auxiliary_cases(detector, cases: list[Case], *, bootstrap_seed=DEFAULT_SEED) -> dict:
    """Score only the target entity for each case, at the fixed review point."""
    from leakguard_core.plugins import DetectionContext
    from .adapter import _normalize
    from .metrics import _binary_counts, _family_bootstrap

    rows = []
    for case in cases:
        input_error = None
        try:
            context = DetectionContext(case.logical_path, case.part_id, case.format_id)
            raw = detector.detect(case.text, context)
        except Exception as error:
            raw = []
            input_error = type(error).__name__
        raw = [_normalize(item) for item in raw]
        target = [item for item in raw if item.entity == case.expected_entity]
        thresholded = [item for item in target if item.score is None or item.score >= detector.review_threshold]
        exact = any((item.start, item.end) == span for item in thresholded for span in case.expected_spans)
        alert = bool(thresholded)
        rows.append({
            "case_id": case.case_id, "split": case.split,
            "template_family": case.template_family, "seed_group": case.seed_group,
            "category": case.category, "expected_entity": case.expected_entity,
            "format_outcome": case.format_outcome, "actionability": case.actionability,
            "expected_spans": [list(span) for span in case.expected_spans],
            "candidate_spans": [[item.start, item.end] for item in target
                                if item.start is not None and item.end is not None
                                and 0 <= item.start < item.end <= len(case.text)],
            "candidate_count": len(target),
            "max_score": max((item.score for item in target if item.score is not None), default=None),
            "review_alert": alert, "block_alert": any(item.severity == "block" for item in target),
            "high_score_alert": False, "score_available": any(item.score is not None for item in target),
            "review_threshold": detector.review_threshold,
            "block_threshold": detector.block_threshold,
            "input_error": input_error,
            "candidates": [_candidate_row(item, len(case.text)) for item in target],
        })
    evaluable = [row for row in rows if not row["input_error"] or row["format_outcome"] == "positive"]
    review_predicate = lambda row: row["review_alert"]
    dev_rows = [row for row in evaluable if row["split"] == "dev"]
    result = {
        "population": {"cases": len(rows), "development": sum(row["split"] == "dev" for row in rows),
                       "holdout": sum(row["split"] == "holdout" for row in rows),
                       "positive": sum(row["format_outcome"] == "positive" for row in evaluable),
                       "negative": sum(row["format_outcome"] == "negative" for row in evaluable),
                       "incomplete": sum(bool(row["input_error"]) for row in rows)},
        "review_threshold": detector.review_threshold,
        "by_entity": {}, "by_category": {},
        "rows": rows,
        "dev_score_sweep": (score_threshold_sweep(
            dev_rows, group_fields=("category", "expected_entity", "actionability"),
            entity_types=tuple(sorted({row["expected_entity"] for row in dev_rows})))
            if dev_rows and all(case.split == "dev" for case in cases)
            else {"available": False, "reason": "development-only score sweep; use the dev split"}),
    }
    groupings = {
        "by_entity": lambda row: row["expected_entity"],
        "by_category": lambda row: row["category"],
    }
    for output_key, key_function in groupings.items():
        groups = {}
        for row in evaluable:
            groups.setdefault(key_function(row), []).append(row)
        result[output_key] = {}
        for name, group in sorted(groups.items()):
            result[output_key][name] = {
                "cases": len(group),
                **_binary_counts(group, review_predicate),
                "confidence_interval": _family_bootstrap(group, review_predicate, seed=bootstrap_seed),
                "score_summary": {
                    "positive_median": statistics.median(row["max_score"] for row in group
                        if row["format_outcome"] == "positive" and row["max_score"] is not None)
                        if any(row["format_outcome"] == "positive" and row["max_score"] is not None for row in group) else None,
                    "negative_median": statistics.median(row["max_score"] for row in group
                        if row["format_outcome"] == "negative" and row["max_score"] is not None)
                        if any(row["format_outcome"] == "negative" and row["max_score"] is not None for row in group) else None,
                },
            }
    return result
