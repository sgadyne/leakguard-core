"""Case, span, threshold-sweep, slice, and clustered uncertainty metrics."""
from __future__ import annotations

from collections import Counter, defaultdict
import math
import random
from typing import Any


PREDECLARED_SCORE_THRESHOLDS = (0.05, 0.35, 0.4, 0.5, 0.8, 0.93, 0.96, 0.99, 1.0)
JWE_ENTITIES = {"JOSE_COMPACT_JWE", "JOSE_COMPACT_UNVERIFIED"}


def _overlap(left, right) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _pr_auc(labels: list[bool], scores: list[float]) -> float | None:
    if not labels or not any(labels):
        return None
    order = sorted(range(len(scores)), key=lambda index: (-scores[index], index))
    positives = sum(labels)
    tp = 0
    fp = 0
    area = 0.0
    previous_recall = 0.0
    cursor = 0
    while cursor < len(order):
        score = scores[order[cursor]]
        while cursor < len(order) and scores[order[cursor]] == score:
            index = order[cursor]
            tp += bool(labels[index])
            fp += not labels[index]
            cursor += 1
        recall = tp / positives
        precision = tp / (tp + fp)
        area += (recall - previous_recall) * precision
        previous_recall = recall
    return area


def _roc_auc(labels: list[bool], scores: list[float]) -> float | None:
    positives = sum(labels)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return None
    # Mann-Whitney U with average ranks for ties.
    order = sorted(range(len(scores)), key=lambda index: scores[index])
    rank_sum = 0.0
    cursor = 0
    while cursor < len(order):
        end = cursor + 1
        while end < len(order) and scores[order[end]] == scores[order[cursor]]:
            end += 1
        average_rank = ((cursor + 1) + end) / 2
        rank_sum += sum(average_rank for index in order[cursor:end] if labels[index])
        cursor = end
    return (rank_sum - positives * (positives + 1) / 2) / (positives * negatives)


def _binary_counts(rows: list[dict], predicate) -> dict:
    tp = fp = tn = fn = 0
    for row in rows:
        expected = row["format_outcome"] == "positive"
        predicted = bool(predicate(row))
        if expected and predicted:
            tp += 1
        elif expected:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    def wilson(successes, total):
        if not total:
            return None
        z = 1.959963984540054
        rate = successes / total
        denominator = 1 + z * z / total
        center = (rate + z * z / (2 * total)) / denominator
        half = (z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total))
                / denominator)
        lower, upper = max(0.0, center - half), min(1.0, center + half)
        if successes == 0:
            lower = 0.0
        if successes == total:
            upper = 1.0
        return [lower, upper]

    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": precision, "recall": recall, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else None,
            "false_alerts_per_1000_negative_cases": 1000 * fp / (fp + tn) if fp + tn else None,
            "wilson_95": {"precision": wilson(tp, tp + fp),
                           "recall": wilson(tp, tp + fn),
                           "fpr": wilson(fp, fp + tn)}}


def score_threshold_sweep(rows: list[dict], *, group_fields=(), entity_types=()) -> dict:
    """Apply predeclared score thresholds to unfiltered raw candidate scores."""
    evaluable = [row for row in rows if row.get("format_outcome") in {"positive", "negative"}
                 and (not row.get("input_error") or row["format_outcome"] == "positive")]

    def table(group):
        return [{"threshold": threshold,
                 **_binary_counts(group, lambda row: row.get("max_score") is not None
                                  and row["max_score"] >= threshold)}
                for threshold in PREDECLARED_SCORE_THRESHOLDS]

    by_field = {}
    for field in group_fields:
        values = defaultdict(list)
        for row in evaluable:
            values[str(row.get(field) or "unknown")].append(row)
        by_field[field] = {name: table(group) for name, group in sorted(values.items())}

    by_entity = {}
    if entity_types:
        for entity in entity_types:
            entity_rows = []
            for row in evaluable:
                copy = dict(row)
                scores = [candidate.get("score") for candidate in row.get("candidates", [])
                          if candidate.get("entity") == entity and candidate.get("score") is not None]
                copy["max_score"] = max(scores) if scores else None
                entity_rows.append(copy)
            by_entity[entity] = table(entity_rows)

    return {"available": any(row.get("max_score") is not None for row in evaluable),
            "population": {"labeled_cases": len(evaluable),
                           "positive": sum(row["format_outcome"] == "positive" for row in evaluable),
                           "negative": sum(row["format_outcome"] == "negative" for row in evaluable),
                           "scored_cases": sum(row.get("max_score") is not None for row in evaluable)},
            "method": "raw maximum target candidate score >= threshold; missing candidate is no alert",
            "thresholds": list(PREDECLARED_SCORE_THRESHOLDS),
            "overall": table(evaluable), "by_slice": by_field, "by_entity": by_entity}


def _family_bootstrap(rows: list[dict], predicate, *, resamples=1000, seed=20261026) -> dict:
    """Stratified cluster bootstrap resampling whole held-out template families."""
    pos_by_family: dict[str, list[dict]] = defaultdict(list)
    neg_by_family: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        target = pos_by_family if row["format_outcome"] == "positive" else neg_by_family
        target[row["template_family"]].append(row)
    positives = list(pos_by_family.values())
    negatives = list(neg_by_family.values())
    if not positives or not negatives:
        return {"method": "stratified-template-family-bootstrap", "resamples": 0,
                "ci95": {"precision": None, "recall": None, "f1": None, "fpr": None}}
    rng = random.Random(seed)
    samples = {name: [] for name in ("precision", "recall", "f1", "fpr")}
    for _ in range(resamples):
        sampled = []
        for clusters in (positives, negatives):
            sampled.extend(case for _ in clusters for case in rng.choice(clusters))
        counts = _binary_counts(sampled, predicate)
        for name in samples:
            value = counts[name]
            if value is not None:
                samples[name].append(value)
    intervals = {}
    for name, values in samples.items():
        values.sort()
        intervals[name] = ([values[int(0.025 * (len(values) - 1))],
                             values[int(0.975 * (len(values) - 1))]] if values else None)
    return {"method": "stratified-template-family-bootstrap", "resamples": resamples,
            "positive_families": len(positives), "negative_families": len(negatives),
            "ci95": intervals}


def _maximum_span_matches(predicted, gold, matches):
    matched_gold = {}

    def assign(pred_index, seen):
        for gold_index, target in enumerate(gold):
            if gold_index in seen or not matches(predicted[pred_index], target):
                continue
            seen.add(gold_index)
            if gold_index not in matched_gold or assign(matched_gold[gold_index], seen):
                matched_gold[gold_index] = pred_index
                return True
        return False

    for pred_index in range(len(predicted)):
        assign(pred_index, set())
    return len(matched_gold)


def _span_metrics(rows: list[dict], *, prediction_key="candidate_spans",
                  score_count_key="span_score_count") -> dict:
    exact_tp = exact_fp = exact_fn = overlap_tp = overlap_fp = overlap_fn = 0
    for row in rows:
        gold = [tuple(value) for value in row["expected_spans"]]
        predicted = [tuple(value) for value in row.get(prediction_key, row["candidate_spans"])]
        exact = _maximum_span_matches(predicted, gold, lambda pred, target: pred == target)
        overlap = _maximum_span_matches(predicted, gold, _overlap)
        exact_tp += exact
        exact_fp += len(predicted) - exact
        exact_fn += len(gold) - exact
        overlap_tp += overlap
        overlap_fp += len(predicted) - overlap
        overlap_fn += len(gold) - overlap
    def pack(tp, fp, fn):
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
        return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}
    return {"prediction_source": "raw candidates" if prediction_key == "candidate_spans" else "review-threshold candidates",
            "exact": pack(exact_tp, exact_fp, exact_fn),
            "overlap": pack(overlap_tp, overlap_fp, overlap_fn),
            "span_scores_available": sum(row.get(score_count_key, 0) for row in rows)}


def _slice_metrics(rows: list[dict], key: str) -> dict:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        groups[str(row.get(key) or "unknown")].append(row)
    return {name: {"cases": len(items), **_binary_counts(items, lambda row: row["review_alert"])}
            for name, items in sorted(groups.items())}


def score_rows(rows: list[dict], *, bootstrap_seed=20261026) -> dict:
    # A detector exception on a positive is a miss. A detector exception on a
    # negative is incomplete and is excluded, so it can never inflate TN.
    metric_rows = [row for row in rows if row["format_outcome"] in {"positive", "negative"}
                   and (not row.get("input_error") or row["format_outcome"] == "positive")]
    review = lambda row: row["review_alert"]
    block = lambda row: row["block_alert"]
    high_score = lambda row: row["high_score_alert"]
    supported_jwe = lambda row: row.get("supported_jwe_alert", False)
    review_counts = _binary_counts(metric_rows, review)
    block_counts = _binary_counts(metric_rows, block)
    target_candidates = [candidate for row in metric_rows for candidate in row.get("candidates", [])
                         if candidate.get("entity") in JWE_ENTITIES]
    score_available = (bool(metric_rows)
                       and any(row.get("score_available") for row in metric_rows)
                       and all(candidate.get("score") is not None for candidate in target_candidates))
    result = {
        "population": {"labeled_cases": len(rows), "binary_metric_cases": len(metric_rows),
                       "positive": sum(row["format_outcome"] == "positive" for row in metric_rows),
                       "negative": sum(row["format_outcome"] == "negative" for row in metric_rows),
                       "incomplete_cases": sum(bool(row.get("input_error")) for row in rows)},
        "fixed_thresholds": {
            "review": {"score_threshold": rows[0].get("review_threshold") if rows else None, **review_counts},
            "block": {"decision": "returned severity is block", **block_counts},
        },
        "score_threshold_operating_points": {
            "review": {"threshold": rows[0].get("review_threshold") if rows else None, **review_counts},
            "high_score": {"threshold": rows[0].get("block_threshold") if rows else None,
                           **_binary_counts(metric_rows, high_score)},
            "score_is_not_calibrated_probability": True,
        },
        "supported_jwe_entity": _binary_counts(metric_rows, supported_jwe),
        "span_metrics": _span_metrics(metric_rows),
        "review_threshold_span_metrics": _span_metrics(
            metric_rows, prediction_key="review_candidate_spans",
            score_count_key="review_span_score_count"),
        "confidence_intervals": {
            "review": _family_bootstrap(metric_rows, review, seed=bootstrap_seed),
            "block": _family_bootstrap(metric_rows, block, seed=bootstrap_seed + 1),
        },
        "slices": {key: _slice_metrics(metric_rows, key) for key in
                   ("mode", "category", "algorithm", "actionability", "template_family")},
        "raw_scores": {"available": score_available,
                       "candidate_score_levels": sorted({candidate["score"] for candidate in target_candidates
                                                          if candidate.get("score") is not None}),
                       "missing_candidate_cases": sum(row.get("max_score") is None for row in metric_rows),
                       "pr_auc_average_precision": None, "roc_auc": None,
                       "ranking_scope": None,
                       "interpretation": "raw detector scores are ranking values, not calibrated probabilities"},
        "jwe_candidates_by_returned_severity": dict(Counter(candidate["severity"] for row in rows
            for candidate in row.get("candidates", [])
            if candidate.get("entity") in JWE_ENTITIES and candidate.get("severity"))),
    }
    if score_available:
        scores = [row["max_score"] if row["max_score"] is not None else 0.0 for row in metric_rows]
        labels = [row["format_outcome"] == "positive" for row in metric_rows]
        result["raw_scores"]["pr_auc_average_precision"] = _pr_auc(labels, scores)
        candidate_levels = result["raw_scores"]["candidate_score_levels"]
        if len(candidate_levels) > 1:
            result["raw_scores"]["roc_auc"] = _roc_auc(labels, scores)
            result["raw_scores"]["ranking_scope"] = "multiple distinct candidate score levels; synthetic case ranking only"
        else:
            result["raw_scores"]["ranking_scope"] = (
                "binary-like presence ranking: one distinct candidate score level plus missing-candidate absence; "
                "average precision is presence-equivalent and ROC AUC is omitted"
            )
    # Valid compact examples can be public. These are structure positives but
    # are a separate test of safe exposure classification.
    exposure_rows = [row for row in metric_rows if row["format_outcome"] == "positive"
                     and row["actionability"] in {"exposed", "public"}]
    exposure_labels = [row["actionability"] == "exposed" for row in exposure_rows]
    exposure_predictions = [row["block_alert"] for row in exposure_rows]
    exposed = sum(exposure_labels)
    exposed_tp = sum(a and b for a, b in zip(exposure_labels, exposure_predictions))
    exposed_fp = sum((not a) and b for a, b in zip(exposure_labels, exposure_predictions))
    exposed_tn = sum((not a) and (not b) for a, b in zip(exposure_labels, exposure_predictions))
    exposed_fn = sum(a and not b for a, b in zip(exposure_labels, exposure_predictions))
    result["actionability_on_valid_jwe"] = {
        "population": len(exposure_rows), "positives_exposed": exposed,
        "public_valid_examples": len(exposure_rows) - exposed,
        "block_decision": {"tp": exposed_tp, "fp": exposed_fp, "tn": exposed_tn, "fn": exposed_fn,
                           "precision": exposed_tp / (exposed_tp + exposed_fp) if exposed_tp + exposed_fp else None,
                           "recall": exposed_tp / (exposed_tp + exposed_fn) if exposed_tp + exposed_fn else None,
                           "public_block_rate": exposed_fp / (exposed_fp + exposed_tn) if exposed_fp + exposed_tn else None},
        "jwe_positive_unknown_actionability_excluded": sum(
            row["format_outcome"] == "positive" and row["actionability"] == "unknown"
            for row in metric_rows),
    }
    adversarial_rows = [row for row in rows if row["format_outcome"] == "adversarial"]
    target_candidates = lambda row: row.get("jwe_candidate_count", row["candidate_count"])
    target_candidate_cases = sum(target_candidates(row) > 0 for row in adversarial_rows)
    adversarial_by_reason = defaultdict(list)
    for row in adversarial_rows:
        adversarial_by_reason[str(row.get("adversarial_reason") or "unknown")].append(row)
    result["adversarial"] = {
        "cases": len(adversarial_rows),
        "any_detector_candidate_cases": sum(row["candidate_count"] > 0 for row in adversarial_rows),
        "any_detector_candidate_rate": (sum(row["candidate_count"] > 0 for row in adversarial_rows)
                                        / max(1, len(adversarial_rows))),
        "jwe_candidate_cases": target_candidate_cases,
        "jwe_candidate_rate": target_candidate_cases / max(1, len(adversarial_rows)),
        "input_errors": sum(bool(row.get("input_error")) for row in adversarial_rows),
        "by_reason": {reason: {
            "cases": len(group),
            "review_candidate_cases": sum(bool(row.get("review_alert")) for row in group),
            "any_detector_candidate_cases": sum(row["candidate_count"] > 0 for row in group),
            "jwe_candidate_cases": sum(target_candidates(row) > 0 for row in group),
            "input_errors": sum(bool(row.get("input_error")) for row in group),
        } for reason, group in sorted(adversarial_by_reason.items())},
        "jwe_candidates_by_reason": {reason: {
            "cases": len(group),
            "candidate_cases": sum(target_candidates(row) > 0 for row in group),
            "input_errors": sum(bool(row.get("input_error")) for row in group),
        } for reason, group in sorted(adversarial_by_reason.items())},
        "excluded_from_confusion_matrix": True,
    }
    jws_rows = [dict(row) for row in rows if row["format_outcome"] in {"positive", "negative"}
                and (not row.get("input_error") or row.get("expected_other_spans"))]
    for row in jws_rows:
        expected_spans = row.get("expected_other_spans", [])
        row["format_outcome"] = "positive" if expected_spans else "negative"
        candidates = [candidate for candidate in row.get("candidates", [])
                      if candidate.get("entity") == "JOSE_COMPACT_JWS_CANDIDATE"]
        row["review_alert"] = (row.get("binary_jws_alert", False) if row.get("binary_only") else
            any((candidate.get("score") is None and candidate.get("severity") in {"review", "block"}
                 or candidate.get("score") is not None
                 and candidate["score"] >= (row.get("review_threshold") or 0.35))
                for candidate in candidates))
        row["jws_review_alert"] = row["review_alert"]
        row["max_score"] = max((candidate["score"] for candidate in candidates
                                 if candidate.get("score") is not None), default=None)
        row["score_available"] = row["max_score"] is not None
        row["span_score_count"] = row.get("jws_span_score_count", 0)
        row["expected_spans"] = [[span[0], span[1]] for span in expected_spans]
        row["candidate_spans"] = row.get("jws_candidate_spans", []) if not row.get("binary_only") else []
        row["review_candidate_spans"] = (row.get("jws_review_candidate_spans", [])
                                          if not row.get("binary_only") else [])
    jws_candidates = [candidate for row in jws_rows for candidate in row.get("candidates", [])
                      if candidate.get("entity") == "JOSE_COMPACT_JWS_CANDIDATE"]
    jws_score_available = (bool(jws_rows) and any(row.get("score_available") for row in jws_rows)
                           and all(candidate.get("score") is not None for candidate in jws_candidates))
    jws_candidate_levels = sorted({candidate["score"] for candidate in jws_candidates
                                   if candidate.get("score") is not None})
    jws_raw_scores = {"available": jws_score_available,
                      "candidate_score_levels": jws_candidate_levels,
                      "missing_candidate_cases": sum(row.get("max_score") is None for row in jws_rows),
                      "pr_auc_average_precision": None, "roc_auc": None, "ranking_scope": None,
                      "interpretation": "raw candidate scores are ranking values, not calibrated probabilities"}
    if jws_score_available:
        jws_scores = [row["max_score"] if row["max_score"] is not None else 0.0 for row in jws_rows]
        jws_labels = [row["format_outcome"] == "positive" for row in jws_rows]
        jws_raw_scores["pr_auc_average_precision"] = _pr_auc(jws_labels, jws_scores)
        if len(jws_candidate_levels) > 1:
            jws_raw_scores["roc_auc"] = _roc_auc(jws_labels, jws_scores)
            jws_raw_scores["ranking_scope"] = "multiple distinct candidate score levels; synthetic case ranking only"
        else:
            jws_raw_scores["ranking_scope"] = (
                "binary-like presence ranking: one distinct candidate score level plus missing-candidate absence; "
                "average precision is presence-equivalent and ROC AUC is omitted"
            )
    result["jws_candidate_metrics"] = {
        "population": len(jws_rows),
        "expected_jws_cases": sum(bool(row.get("expected_other_spans")) for row in jws_rows),
        "counts": _binary_counts(jws_rows, lambda row: row["review_alert"]),
        "span_metrics": _span_metrics(jws_rows),
        "review_threshold_span_metrics": _span_metrics(
            jws_rows, prediction_key="review_candidate_spans",
            score_count_key="jws_review_span_score_count"),
        "raw_scores": jws_raw_scores,
        "interpretation": "three-part JWS candidates are a distinct target and are excluded from JWE false alerts when they match their predeclared span",
    }
    jwe_clean_rows = [row for row in metric_rows if row["format_outcome"] == "positive"
                      or not row.get("expected_other_spans")]
    jwe_on_jws_rows = [row for row in metric_rows if row["format_outcome"] == "negative"
                       and row.get("expected_other_spans")]
    result["jwe_vs_clean_negatives"] = {
        "counts": _binary_counts(jwe_clean_rows, review),
        "positive_jwe_cases": sum(row["format_outcome"] == "positive" for row in jwe_clean_rows),
        "clean_negative_cases": sum(row["format_outcome"] == "negative" for row in jwe_clean_rows),
        "jws_candidates_excluded_from_clean_negative_denominator": len(jwe_on_jws_rows),
        "interpretation": "class-conditional JWE operating point against only predeclared all-JOSE-clean negatives",
    }
    result["jwe_alerts_on_jws_candidates"] = {
        "cases": len(jwe_on_jws_rows),
        "jwe_review_alerts": sum(bool(row["review_alert"]) for row in jwe_on_jws_rows),
        "rate": (sum(bool(row["review_alert"]) for row in jwe_on_jws_rows) / len(jwe_on_jws_rows)
                 if jwe_on_jws_rows else None),
    }
    union_rows = []
    for row in rows:
        if row["format_outcome"] not in {"positive", "negative"}:
            continue
        if row.get("input_error") and not row.get("expected_spans") and not row.get("expected_other_spans"):
            continue
        converted = dict(row)
        is_jose = bool(row.get("expected_spans") or row.get("expected_other_spans"))
        converted["format_outcome"] = "positive" if is_jose else "negative"
        converted["review_alert"] = bool(row.get("review_alert") or row.get("jws_review_alert"))
        union_rows.append(converted)
    union_review = lambda row: row["review_alert"]
    result["jose_union_metrics"] = {
        "population": len(union_rows),
        "jose_positive_cases": sum(row["format_outcome"] == "positive" for row in union_rows),
        "clean_negative_cases": sum(row["format_outcome"] == "negative" for row in union_rows),
        "counts": _binary_counts(union_rows, union_review),
        "confidence_interval": _family_bootstrap(union_rows, union_review, seed=bootstrap_seed + 2),
        "interpretation": "case-level JOSE union: JWE or JWS expected span is positive; only clean non-JOSE examples are negatives",
    }
    union_scores_available = (bool(union_rows)
        and any(row.get("score_available") or row.get("jws_span_score_count", 0) for row in union_rows)
        and all(candidate.get("score") is not None for row in union_rows
                for candidate in row.get("candidates", [])
                if candidate.get("entity") in JWE_ENTITIES | {"JOSE_COMPACT_JWS_CANDIDATE"}))
    union_candidate_levels = sorted({candidate["score"] for row in union_rows
                                     for candidate in row.get("candidates", [])
                                     if candidate.get("entity") in JWE_ENTITIES | {"JOSE_COMPACT_JWS_CANDIDATE"}
                                     and candidate.get("score") is not None})
    union_raw_scores = {"available": union_scores_available,
                        "candidate_score_levels": union_candidate_levels,
                        "missing_candidate_cases": sum(not any(candidate.get("entity") in JWE_ENTITIES | {"JOSE_COMPACT_JWS_CANDIDATE"}
                                                               and candidate.get("score") is not None
                                                               for candidate in row.get("candidates", []))
                                                        for row in union_rows),
                        "pr_auc_average_precision": None, "roc_auc": None, "ranking_scope": None,
                        "interpretation": "maximum raw JWE or JWS candidate score; ranking value, not calibrated probability"}
    if union_scores_available:
        union_values = []
        union_labels = []
        for row in union_rows:
            scores = [candidate["score"] for candidate in row.get("candidates", [])
                      if candidate.get("entity") in JWE_ENTITIES | {"JOSE_COMPACT_JWS_CANDIDATE"}
                      and candidate.get("score") is not None]
            union_values.append(max(scores) if scores else 0.0)
            union_labels.append(row["format_outcome"] == "positive")
        union_raw_scores["pr_auc_average_precision"] = _pr_auc(union_labels, union_values)
        if len(union_candidate_levels) > 1:
            union_raw_scores["roc_auc"] = _roc_auc(union_labels, union_values)
            union_raw_scores["ranking_scope"] = "discrete candidate score levels; synthetic case ranking only"
        else:
            union_raw_scores["ranking_scope"] = (
                "binary-like presence ranking: one distinct candidate score level plus missing-candidate absence; "
                "average precision is presence-equivalent and ROC AUC is omitted"
            )
    result["jose_union_metrics"]["raw_scores"] = union_raw_scores
    return result
