"""Run an immutable grouped split through an eval-only raw-candidate adapter."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
import traceback

try:
    import resource
except ImportError:  # Windows
    resource = None

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "plugins" / "presidio_detector" / "src")]

from .adapter import DetectorAdapter
from .auxiliary import evaluate_auxiliary_cases
from .auxiliary_v2 import build_auxiliary_cases
from .corpus_v2 import (CORPUS_VERSION, DEFAULT_SEED, _make_jwe,
                        build_adversarial_cases, build_cases, fixture_digest)
from .documents import build_document_cases, evaluate_document_cases
from .freeze_v2 import DEFAULT_OUTPUT, holdout_authorized, validate_manifest
from .metrics import score_rows, score_threshold_sweep


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _exclusive_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
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


def _git_commit(path: Path = ROOT) -> str | None:
    try:
        return subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True, timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _configure_import_paths(source_root: Path) -> None:
    source_root = source_root.resolve(strict=True)
    paths = [str(source_root / "src"),
             str(source_root / "plugins" / "presidio_detector" / "src"),
             str(source_root / "plugins" / "jose_recognizers" / "src")]
    sys.path[:] = [item for item in sys.path if item not in paths]
    sys.path[:0] = paths


def _child_rss_bytes() -> int | None:
    if resource is None:
        return None
    try:
        value = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    except (AttributeError, OSError, ValueError):
        return None
    return int(value if sys.platform == "darwin" else value * 1024)


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    values = sorted(values)
    return values[max(0, math.ceil(percentile * len(values)) - 1)]


def _candidate_row(candidate, text_length: int) -> dict:
    valid = (candidate.start is not None and candidate.end is not None
             and 0 <= candidate.start < candidate.end <= text_length)
    return {
        "start": candidate.start if valid else None,
        "end": candidate.end if valid else None,
        "score": candidate.score,
        "severity": candidate.severity,
        "rule": candidate.rule,
        "entity": candidate.entity,
    }


def _run_one(detector, case, *, start_at: float = 0.0) -> tuple[dict, float]:
    from leakguard_core.plugins import DetectionContext

    latency_start = time.perf_counter()
    input_error = None
    try:
        context = DetectionContext(case.logical_path, case.part_id, case.format_id)
        candidates = detector.detect(case.text, context)
        candidates = [_candidate_row(item, len(case.text)) for item in candidates]
    except Exception as error:
        input_error = type(error).__name__
        candidates = []
    elapsed = time.perf_counter() - latency_start
    jwe_candidates = [item for item in candidates if item["entity"] in {"JOSE_COMPACT_JWE", "JOSE_COMPACT_UNVERIFIED"}]
    jws_candidates = [item for item in candidates if item["entity"] == "JOSE_COMPACT_JWS_CANDIDATE"]
    jwe_spans = [[item["start"], item["end"]] for item in jwe_candidates
                 if item["start"] is not None and item["end"] is not None]
    jws_spans = [[item["start"], item["end"]] for item in jws_candidates
                 if item["start"] is not None and item["end"] is not None]
    jwe_scores = [item["score"] for item in jwe_candidates if item["score"] is not None]
    max_jwe_score = max(jwe_scores) if jwe_scores else None
    has_score = bool(jwe_scores)
    review_threshold = detector.review_threshold
    block_threshold = detector.block_threshold
    review = (max_jwe_score >= review_threshold if jwe_scores
              else any(item["severity"] in {"review", "block"} for item in jwe_candidates))
    jws_scores = [item["score"] for item in jws_candidates if item["score"] is not None]
    max_jws_score = max(jws_scores) if jws_scores else None
    jws_review = (max_jws_score >= review_threshold if jws_scores
                  else any(item["severity"] in {"review", "block"} for item in jws_candidates))
    block = any(item["severity"] == "block" for item in jwe_candidates)
    high_score = max_jwe_score >= block_threshold if jwe_scores else False
    return ({
        "case_id": case.case_id,
        "split": case.split,
        "template_family": case.template_family,
        "seed_group": case.seed_group,
        "category": case.category,
        "negative_kind": getattr(case, "negative_kind",
                                  case.category if case.format_outcome == "negative" else None),
        "mode": case.mode,
        "algorithm": case.algorithm,
        "actionability": case.actionability,
        "adversarial_reason": case.adversarial_reason,
        "format_outcome": case.format_outcome,
        "expected_spans": [list(span) for span in case.expected_spans],
        "expected_other_spans": [[start, end, entity] for start, end, entity in case.expected_other_spans],
        "candidate_spans": jwe_spans,
        "review_candidate_spans": [[item["start"], item["end"]] for item in jwe_candidates
                                    if item["start"] is not None and item["end"] is not None
                                    and (item["score"] is None and item["severity"] in {"review", "block"}
                                         or item["score"] is not None and item["score"] >= review_threshold)],
        "jws_candidate_spans": jws_spans,
        "jws_review_candidate_spans": [[item["start"], item["end"]] for item in jws_candidates
                                        if item["start"] is not None and item["end"] is not None
                                        and (item["score"] is None and item["severity"] in {"review", "block"}
                                             or item["score"] is not None and item["score"] >= review_threshold)],
        "candidate_count": len(candidates),
        "jwe_candidate_count": len(jwe_candidates),
        "jws_candidate_count": len(jws_candidates),
        "span_score_count": len(jwe_scores),
        "review_span_score_count": sum(item["score"] is not None and item["score"] >= review_threshold
                                        for item in jwe_candidates),
        "jws_span_score_count": len(jws_scores),
        "jws_review_span_score_count": sum(item["score"] is not None and item["score"] >= review_threshold
                                            for item in jws_candidates),
        "score_available": has_score,
        "max_score": max_jwe_score,
        "max_jwe_score": max_jwe_score,
        "max_review_candidate_score": max_jwe_score,
        "review_threshold": review_threshold,
        "block_threshold": block_threshold,
        "review_alert": review,
        "jws_review_alert": jws_review,
        "block_alert": block,
        "high_score_alert": high_score,
        "supported_jwe_alert": any(item["entity"] == "JOSE_COMPACT_JWE"
                                    and (item["score"] is None or item["score"] >= review_threshold)
                                    for item in candidates),
        "candidates": candidates,
        "input_error": input_error,
        "fixture_sha256": fixture_digest(case),
        "latency_seconds": elapsed,
    }, elapsed)


def run(profile_path: Path, output: Path, *, split="dev", seed=DEFAULT_SEED,
        manifest_path=DEFAULT_OUTPUT, include_adversarial=True, document_gate=True,
        source_root=ROOT) -> dict:
    if split in {"holdout", "all"} and not holdout_authorized():
        raise PermissionError("holdout-not-authorized-by-lead-contract")
    _configure_import_paths(source_root)
    profile_bytes = profile_path.read_bytes()
    profile = json.loads(profile_bytes)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    all_cases = validate_manifest(manifest, seed)
    if split in {"dev", "holdout"}:
        cases = [case for case in all_cases if case.split == split]
    elif split == "all":
        cases = all_cases
    else:
        raise ValueError("split-invalid")
    adversarial = build_adversarial_cases(seed) if include_adversarial else []
    selected = cases + adversarial
    auxiliary_cases = [case for case in build_auxiliary_cases(seed)
                       if split == "all" or case.split == split]

    detector = DetectorAdapter(profile)
    started = dt.datetime.now(dt.timezone.utc)
    monotonic_start = time.perf_counter()
    latencies = []
    rows = []
    before_child_rss = _child_rss_bytes()
    try:
        for case in selected:
            row, elapsed = _run_one(detector, case)
            rows.append(row)
            latencies.append(elapsed)
        text_metrics = score_rows(rows, bootstrap_seed=seed)
        auxiliary = evaluate_auxiliary_cases(detector, auxiliary_cases, bootstrap_seed=seed)
        document_token_factory = lambda token_seed, *, algorithm: _make_jwe(
            token_seed, algorithm=algorithm, heldout_recipe=False)[0]
        documents = (evaluate_document_cases(
            detector, build_document_cases(seed, token_factory=document_token_factory))
            if document_gate else None)
    finally:
        detector.close()
    elapsed = time.perf_counter() - monotonic_start
    detector_call_elapsed = sum(latencies)
    after_child_rss = _child_rss_bytes()
    try:
        crypto_version = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        crypto_version = "unknown"
    try:
        extraction_versions = {name: importlib.metadata.version(name) for name in ("pypdf", "olefile")}
    except importlib.metadata.PackageNotFoundError:
        extraction_versions = {}
    try:
        git_status = subprocess.run(["git", "-C", str(ROOT), "status", "--short"],
                                    capture_output=True, text=True, check=True, timeout=3).stdout
        tree_clean = not bool(git_status.strip())
    except (OSError, subprocess.SubprocessError):
        tree_clean = False
    jws_dev_sweep = {"available": False,
                     "reason": "development-only score sweep; not computed on holdout"}
    if split == "dev":
        jws_rows = []
        for row in rows:
            if row["format_outcome"] not in {"positive", "negative"}:
                continue
            if row.get("input_error") and not row.get("expected_other_spans"):
                continue
            converted = dict(row)
            converted["format_outcome"] = "positive" if row.get("expected_other_spans") else "negative"
            converted["max_score"] = max((candidate["score"] for candidate in row.get("candidates", [])
                                           if candidate.get("entity") == "JOSE_COMPACT_JWS_CANDIDATE"
                                           and candidate.get("score") is not None), default=None)
            jws_rows.append(converted)
        jws_dev_sweep = score_threshold_sweep(
            jws_rows, group_fields=("mode", "category", "algorithm"),
            entity_types=("JOSE_COMPACT_JWS_CANDIDATE",))
    return {
        "schema_version": 1,
        "corpus_version": CORPUS_VERSION,
        "evaluation": "jose-compact-standalone-and-embedded",
        "profile_name": detector.name,
        "profile_sha256": _sha(profile_bytes),
        "evaluator_source_commit": _git_commit(ROOT),
        "detector_source_commit": _git_commit(Path(source_root)),
        "detector_source_root": str(Path(source_root).resolve()),
        "evaluator_tree_clean": tree_clean,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cryptography_version": crypto_version,
        "extraction_dependencies": extraction_versions,
        "started_utc": started.isoformat(),
        "elapsed_seconds": round(elapsed, 6),
        "throughput": {
            "main_and_adversarial_detector_calls": len(selected),
            "main_and_adversarial_detector_call_seconds": round(detector_call_elapsed, 6),
            "main_and_adversarial_detector_calls_per_call_second": (
                len(selected) / detector_call_elapsed if detector_call_elapsed else None),
            "harness_eval_units": {
                "main_and_adversarial_cases": len(selected),
                "auxiliary_context_cases": len(auxiliary_cases),
                "document_files": documents["files"] if documents else 0,
                "total": len(selected) + len(auxiliary_cases) + (documents["files"] if documents else 0),
            },
            "harness_eval_units_per_full_harness_second": (
                (len(selected) + len(auxiliary_cases) + (documents["files"] if documents else 0)) / elapsed
                if elapsed else None),
            "harness_elapsed_includes": ["main and adversarial evaluation", "auxiliary context evaluation",
                                         "document extraction gate", "metric and bootstrap calculation"],
        },
        "latency_seconds": {"samples": len(latencies), "median": statistics.median(latencies) if latencies else None,
                            "p95_nearest_rank": _percentile(latencies, 0.95),
                            "max": max(latencies) if latencies else None},
        "child_rss": {"before_bytes": before_child_rss, "after_bytes": after_child_rss,
                      "metric": "largest waited child lifetime high-water RSS; evaluation process is fresh"},
        "manifest_sha256": _sha(manifest_path.read_bytes()),
        "labels_sha256": manifest["labels_sha256"],
        "split": split,
        "split_cases": len(cases),
        "adversarial_cases": len(adversarial),
        "text_metrics": text_metrics,
        "dev_score_sweep": (score_threshold_sweep(
            [row for row in rows if row["split"] == "dev"],
            group_fields=("mode", "category", "algorithm", "actionability"),
            entity_types=("JOSE_COMPACT_JWE", "JOSE_COMPACT_UNVERIFIED"))
            if split == "dev" else {"available": False,
                                     "reason": "development-only score sweep; not computed on holdout"}),
        "jws_dev_score_sweep": jws_dev_sweep,
        "document_gate": documents,
        "document_gate_scope": "shared integration/regression cases, not independent holdout performance data",
        "adversarial_gate_scope": "shared malformed/unsupported regression cases, excluded from confusion metrics",
        "auxiliary_context_preset_gate": auxiliary,
        "cases": rows,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="JSON eval profile with factory and options")
    parser.add_argument("--output", required=True, help="new path for redacted raw metrics JSON")
    parser.add_argument("--manifest", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--source-root", default=str(ROOT), help="checkout whose core and detector packages are loaded")
    parser.add_argument("--split", choices=("dev", "holdout", "all"), default="dev")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--skip-adversarial", action="store_true")
    parser.add_argument("--skip-document-gate", action="store_true")
    args = parser.parse_args(argv)
    output = Path(args.output).absolute()
    if output.exists() or output.is_symlink():
        parser.error("output path must not already exist")
    try:
        result = run(Path(args.profile), output, split=args.split, seed=args.seed,
                     manifest_path=Path(args.manifest),
                     include_adversarial=not args.skip_adversarial,
                     document_gate=not args.skip_document_gate,
                     source_root=Path(args.source_root))
        _exclusive_write(output, (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        print(json.dumps({"outcome": "complete", "output": str(output),
                          "profile": result["profile_name"],
                          "counts": result["text_metrics"]["population"],
                          "elapsed_seconds": result["elapsed_seconds"]}, sort_keys=True))
        return 0
    except Exception as error:
        trace = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
                 for frame in traceback.extract_tb(error.__traceback__)]
        print(json.dumps({"outcome": "failed", "error": type(error).__name__, "trace": trace},
                         sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
