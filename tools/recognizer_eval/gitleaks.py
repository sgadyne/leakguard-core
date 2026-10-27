"""One-invocation binary Gitleaks comparison over the same grouped corpus."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

from .corpus_v2 import DEFAULT_SEED, build_adversarial_cases, build_cases
from .freeze_v2 import DEFAULT_OUTPUT, holdout_authorized, validate_manifest
from .metrics import score_rows

ROOT = Path(__file__).resolve().parents[2]


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _git_metadata() -> tuple[str | None, bool]:
    try:
        commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=True, timeout=3).stdout.strip()
        status = subprocess.run(["git", "-C", str(ROOT), "status", "--short"],
                                capture_output=True, text=True, check=True, timeout=3).stdout
        return commit, not bool(status.strip())
    except (OSError, subprocess.SubprocessError):
        return None, False


def _binary_version(binary: Path) -> str:
    result = subprocess.run([str(binary), "version"], capture_output=True,
                            text=True, timeout=10, check=True)
    return result.stdout.strip()


def _binary_alerts(rules: list[str]) -> tuple[bool, bool]:
    """Map rule IDs to targets without consulting the case's gold label.

    `jwt` alerts are JWS-target file alerts on every input; other rules remain
    generic JWE-target file alerts on every input. This keeps a JWT hit on a
    clean file visible as a JWS and JOSE-union false alert.
    Gitleaks 8.30.1 calls its compact JWT rule `jwt`; rule names are not treated
    as spans or scores.
    """
    unique_rules = set(rules)
    jws_alert = "jwt" in unique_rules
    jwe_review_alert = bool(unique_rules - {"jwt"})
    return jwe_review_alert, jws_alert


def _subprocess_environment() -> dict[str, str]:
    """Prevent inherited config from silently changing either baseline."""
    environment = os.environ.copy()
    environment.pop("GITLEAKS_CONFIG", None)
    environment.pop("GITLEAKS_CONFIG_TOML", None)
    return environment


def _binary_only_metric_semantics(metrics: dict) -> dict:
    """Remove native severity and score interpretations for rule-presence output."""
    unavailable = {
        "available": False,
        "reason": "Gitleaks JSON exposes binary file-level rule presence here; it does not provide this policy or a calibrated score",
    }
    metrics["fixed_thresholds"]["review"]["decision"] = "file has any applicable Gitleaks rule hit"
    metrics["fixed_thresholds"]["review"].pop("score_threshold", None)
    metrics["fixed_thresholds"]["block"] = dict(unavailable)
    metrics["score_threshold_operating_points"] = {
        "review": {"decision": "file has any applicable Gitleaks rule hit",
                   **metrics["fixed_thresholds"]["review"]},
        "high_score": dict(unavailable),
        "score_is_not_calibrated_probability": True,
    }
    metrics["supported_jwe_entity"] = dict(unavailable)
    metrics["actionability_on_valid_jwe"]["block_decision"] = dict(unavailable)
    metrics["jwe_candidates_by_returned_severity"] = dict(unavailable)
    metrics["confidence_intervals"]["block"] = dict(unavailable)
    metrics["span_metrics"] = {**unavailable, "reason": "binary file-level output has no token spans"}
    metrics["review_threshold_span_metrics"] = {
        **unavailable, "reason": "binary file-level output has no threshold-filtered token spans"}
    metrics["jws_candidate_metrics"]["span_metrics"] = dict(metrics["span_metrics"])
    metrics["jws_candidate_metrics"]["review_threshold_span_metrics"] = dict(
        metrics["review_threshold_span_metrics"])
    metrics["jws_candidate_metrics"]["raw_scores"] = {
        "available": False, "pr_auc_average_precision": None, "roc_auc": None,
        "interpretation": "binary file-level detection only; no continuous score ranking",
    }
    metrics["jose_union_metrics"]["raw_scores"] = {
        "available": False, "pr_auc_average_precision": None, "roc_auc": None,
        "interpretation": "binary file-level detection only; no continuous score ranking",
    }
    metrics["raw_scores"] = {
        "available": False,
        "pr_auc_average_precision": None,
        "roc_auc": None,
        "interpretation": "binary file-level detection only; no continuous score ranking",
    }
    return metrics


def run(binary: Path, *, split="dev", seed=DEFAULT_SEED, manifest_path=DEFAULT_OUTPUT,
        include_adversarial=True, config_path: Path | None = None) -> dict:
    if split in {"holdout", "all"} and not holdout_authorized():
        raise PermissionError("holdout-not-authorized-by-lead-contract")
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("gitleaks-binary-invalid")
    if config_path is not None:
        config_path = Path(config_path)
        if config_path.is_symlink() or not config_path.is_file():
            raise ValueError("gitleaks-config-invalid")
    version = _binary_version(binary)
    if version != "8.30.1":
        raise ValueError("gitleaks-version-mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    evaluator_commit, evaluator_tree_clean = _git_metadata()
    all_cases = validate_manifest(manifest, seed)
    if split not in {"dev", "holdout", "all"}:
        raise ValueError("split-invalid")
    cases = all_cases if split == "all" else [case for case in all_cases if case.split == split]
    adversarial = build_adversarial_cases(seed) if include_adversarial else []
    selected = cases + adversarial
    case_ids = {case.case_id: case for case in selected}
    with tempfile.TemporaryDirectory(prefix="leakguard-jose-eval-") as temporary:
        root = Path(temporary)
        source = root / "cases"
        source.mkdir(mode=0o700)
        report = root / "report.json"
        for case in selected:
            target = source / f"{case.case_id}.txt"
            target.write_bytes(case.text.encode("utf-8"))
            target.chmod(0o600)
        command = [str(binary), "dir", "--no-banner", "--redact=100",
                   "--report-format", "json", "--report-path", str(report),
                   "--timeout", "120", str(source)]
        if config_path is not None:
            command[2:2] = ["--config", str(config_path.resolve())]
        started_utc = dt.datetime.now(dt.timezone.utc)
        monotonic = time.perf_counter()
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=150, check=False, cwd=root,
                                   env=_subprocess_environment())
        elapsed = time.perf_counter() - monotonic
        if completed.returncode not in {0, 1}:
            raise RuntimeError("gitleaks-scan-failed")
        raw_findings = json.loads(report.read_text(encoding="utf-8")) if report.exists() else []
        if type(raw_findings) is not list:
            raise ValueError("gitleaks-report-invalid")
        by_case = {case_id: [] for case_id in case_ids}
        for finding in raw_findings:
            if type(finding) is not dict:
                raise ValueError("gitleaks-report-invalid")
            file_label = finding.get("File")
            if type(file_label) is not str:
                continue
            case_id = Path(file_label.replace("\\", "/")).name.removesuffix(".txt")
            if case_id in by_case:
                rule_id = finding.get("RuleID")
                by_case[case_id].append(rule_id if type(rule_id) is str else "gitleaks-unattributed")
        rows = []
        for case in selected:
            rules = sorted(set(by_case[case.case_id]))
            review_alert, jws_alert = _binary_alerts(rules)
            candidates = [{"start": None, "end": None, "score": None,
                           "rule": rule,
                           "entity": "binary-gitleaks"} for rule in rules]
            rows.append({
                "case_id": case.case_id, "split": case.split,
                "template_family": case.template_family, "seed_group": case.seed_group,
                "category": case.category, "mode": case.mode,
                "algorithm": case.algorithm, "actionability": case.actionability,
                "negative_kind": case.negative_kind,
                "adversarial_reason": case.adversarial_reason,
                "format_outcome": case.format_outcome,
                "expected_spans": [list(span) for span in case.expected_spans],
                "expected_other_spans": [[start, end, entity] for start, end, entity in case.expected_other_spans],
                "candidate_spans": [], "candidate_count": len(rules),
                "jwe_candidate_count": 0,
                "span_score_count": 0, "score_available": False,
                "max_score": None, "review_threshold": None, "block_threshold": None,
                # The binary scanner can produce a JWT/JWS alert on a valid
                # three-part sample. That is measured on the separate JWS
                # target and cannot become a false JWE alert.
                "review_alert": review_alert, "block_alert": None,
                "jws_review_alert": jws_alert,
                "supported_jwe_alert": False,
                "binary_jws_alert": jws_alert,
                "binary_only": True,
                "high_score_alert": None, "candidates": candidates,
                "input_error": None,
            })
        # score_rows is shared with native candidates; false is only an internal
        # placeholder so its generic counting helpers can run. The emitted
        # case rows remain null and every block/actionability aggregate is
        # replaced with an explicit unavailable marker immediately below.
        scoring_rows = [{**row, "block_alert": False, "high_score_alert": False} for row in rows]
        metrics = _binary_only_metric_semantics(score_rows(scoring_rows, bootstrap_seed=seed))
        return {
            "schema_version": 1,
            "detector": "gitleaks",
            "version": version,
            "binary_sha256": _sha_file(binary),
            "configuration": ("gitleaks-built-in-defaults" if config_path is None
                              else "explicit-config-file"),
            "config_sha256": _sha_file(config_path) if config_path is not None else None,
            "evaluator_source_commit": evaluator_commit,
            "evaluator_tree_clean": evaluator_tree_clean,
            "started_utc": started_utc.isoformat(),
            "split": split,
            "split_cases": len(cases),
            "adversarial_cases": len(adversarial),
            "invocations": 1,
            "elapsed_seconds": round(elapsed, 6),
            "elapsed_scope": "Gitleaks subprocess scan only; staging and report parsing are excluded",
            "throughput_cases_per_second": len(selected) / elapsed if elapsed else None,
            "throughput_scope": "staged main split plus shared adversarial files, one Gitleaks invocation",
            "command_profile": ["dir", "--no-banner", "--redact=100", "--report-format=json",
                                "explicit-config" if config_path is not None else "built-in-default-config"],
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "labels_sha256": manifest["labels_sha256"],
            "scores": {"continuous": False, "pr_auc_average_precision": None, "roc_auc": None},
            "metrics": metrics,
            "cases": rows,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--config", help="optional explicit Gitleaks TOML configuration")
    parser.add_argument("--manifest", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--split", choices=("dev", "holdout", "all"), default="dev")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output", required=True)
    parser.add_argument("--skip-adversarial", action="store_true")
    args = parser.parse_args(argv)
    output = Path(args.output).absolute()
    if output.exists() or output.is_symlink():
        parser.error("output path must not already exist")
    try:
        result = run(Path(args.gitleaks), split=args.split, seed=args.seed,
                     manifest_path=Path(args.manifest), include_adversarial=not args.skip_adversarial,
                     config_path=Path(args.config) if args.config else None)
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
        print(json.dumps({"outcome": "complete", "version": result["version"],
                          "elapsed_seconds": result["elapsed_seconds"],
                          "counts": result["metrics"]["population"]}, sort_keys=True))
        return 0
    except Exception as error:
        print(json.dumps({"outcome": "failed", "error": type(error).__name__}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
