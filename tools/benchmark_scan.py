#!/usr/bin/env python3
"""Measure bounded synthetic scan curves without returning fixture contents.

Each file-count case compares cold cached, warm cached and uncached reports.
Receipts contain only dimensions, timings, resource counts and stable identity
digests. Run under the shared heavy-job wrapper for local measurements.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
import re
from collections import Counter
from pathlib import Path
import platform
import random
try:
    import resource
except ImportError:  # Windows does not expose getrusage through this module.
    resource = None
import sys
import tempfile
import time
import uuid
import zipfile
import shutil
import subprocess
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
if __package__:
    from ._safe_inputs import read_empty_json_object, source_identity
else:
    from _safe_inputs import read_empty_json_object, source_identity
BENCHMARK_DEADLINE_SECONDS = 180


class BenchmarkFailure(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _rss_high_water_bytes() -> dict[str, int | None]:
    if resource is None:
        return {"parent_lifetime_high_water_bytes": None,
                "children_lifetime_high_water_bytes": None}

    def one(who):
        try:
            value = resource.getrusage(who).ru_maxrss
        except (AttributeError, OSError, ValueError):
            return None
        return int(value if sys.platform == "darwin" else value * 1024)

    return {"parent_lifetime_high_water_bytes": one(resource.RUSAGE_SELF),
            "children_lifetime_high_water_bytes": one(resource.RUSAGE_CHILDREN)}


def _exclusive_write(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _docx(part_count: int, seed: int) -> bytes:
    buffer = __import__("io").BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        content_types = (
            '<Types><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>"
        )
        members = [("[Content_Types].xml", content_types)]
        members.append(("word/document.xml", _word_xml(f"Benchmark fixture {seed} part 1; ordinary synthetic text.")))
        for index in range(1, part_count):
            member = f"word/comments-extra{index}.xml"
            info = zipfile.ZipInfo(member, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            text = f"Benchmark fixture {seed} part {index + 1}; no credential content."
            members.append((member, _word_xml(text)))
        for member, xml in members:
            info = zipfile.ZipInfo(member, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, xml)
    return buffer.getvalue()


def _word_xml(text: str) -> str:
    from xml.sax.saxutils import escape
    return ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>' + escape(text) + '</w:t></w:r></w:p></w:body></w:document>')


def _normalized(report) -> tuple[tuple, ...]:
    rows = []
    for result in report.results:
        findings = tuple(sorted((
            item.id, item.source.path, item.part_id, item.start_line, item.end_line,
            item.rule, item.detector_id, item.severity.value, item.classification.value,
            item.proof_id,
        ) for item in result.findings))
        issues = tuple(sorted(issue.code.value for issue in result.issues))
        content = result.content
        rows.append((result.source.path,
                     (content.algorithm, content.digest, content.size_bytes) if content else None,
                     result.coverage.value, findings, issues))
    return tuple(sorted(rows))


def _measure(service, sources, *, use_cache: bool) -> tuple[dict, tuple, object]:
    from leakguard_core import backends, models
    launches = 0
    original = backends.run_worker

    def counted(*args, **kwargs):
        nonlocal launches
        launches += 1
        return original(*args, **kwargs)

    statement_count = [0]
    connection = getattr(getattr(service, "store", None), "conn", None)
    trace_available = callable(getattr(connection, "set_trace_callback", None))
    if trace_available:
        connection.set_trace_callback(lambda _statement: statement_count.__setitem__(
            0, statement_count[0] + 1))
    started = time.perf_counter()
    try:
        with patch.object(backends, "run_worker", side_effect=counted):
            report = service.scan(
                sources, policy=models.ScanPolicy.inventory(),
                limits=models.ScanLimits(BENCHMARK_DEADLINE_SECONDS, max(1, len(sources))),
                use_cache=use_cache,
            )
    finally:
        if trace_available:
            connection.set_trace_callback(None)
    elapsed = time.perf_counter() - started
    rss = _rss_high_water_bytes()
    row = {
        "seconds": round(elapsed, 6), "backend_worker_launches": launches,
        "sqlite_statement_count": statement_count[0] if trace_available else None,
        "sqlite_statement_count_available": trace_available,
        "deadline_seconds": BENCHMARK_DEADLINE_SECONDS,
        "findings": sum(len(result.findings) for result in report.results),
        "results": len(report.results),
        "coverage_complete": all(result.coverage.value == "complete" for result in report.results),
        "required_complete": report.coverage.required_complete,
        "enumeration_complete": report.coverage.enumeration_complete,
        "named_omissions": sorted({issue.omission_id for result in report.results
                                    for issue in result.issues if issue.omission_id}),
        "outcomes": dict(Counter(result.outcome.value for result in report.results)),
        "coverage_states": dict(Counter(result.coverage.value for result in report.results)),
        "issue_codes": dict(Counter(issue.code.value for result in report.results for issue in result.issues)),
        "policy_verdict": report.decision.verdict.value,
        **rss,
        "policy_id": report.policy_id,
        "runtime_id": next((result.identity.runtime_id for result in report.results), None),
    }
    return row, _normalized(report), report


def _validate_config(path: Path) -> Path:
    try:
        read_empty_json_object(path)
        resolved = path.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        raise BenchmarkFailure("config-invalid")
    return resolved


def _part_curve_coverage(report) -> dict:
    from leakguard_core import models

    issues = tuple(issue for result in report.results for issue in result.issues)
    expected = ((models.ErrorCode.POLICY_OMISSION, "office-nontext", False),)
    actual = tuple(sorted(((issue.code, issue.omission_id, issue.required)
                           for issue in issues),
                          key=lambda row: (row[0].value, row[1] or "", row[2])))
    valid_result_states = all(result.coverage in {
        models.CoverageState.COMPLETE, models.CoverageState.OMITTED,
    } for result in report.results)
    required_complete = (report.coverage.enumeration_complete
                         and report.coverage.required_complete
                         and not any(issue.required for issue in issues)
                         and valid_result_states)
    return {
        "required_complete": required_complete,
        "named_omissions": sorted(issue.omission_id for issue in issues if issue.omission_id),
        "expected_nontext_omission_only": actual == expected,
    }


def _hook_latency_benchmark(*, root: Path, config: Path, backend: Path,
                            repetitions: int, marker: str) -> list[dict]:
    from leakguard_core import hooks

    result = []
    module_path = str(ROOT / "src")
    for repetition in range(repetitions):
        repository = root / f"hook-{repetition}"
        repository.mkdir(mode=0o700)
        git_env = dict(os.environ)
        git_env.pop("PYTHONHOME", None)
        git_env.pop("PYTHONPATH", None)
        git_env.update({
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(root / "gitconfig"),
            "GIT_TERMINAL_PROMPT": "0",
            "LEAKGUARD_CONFIG": str(config),
            "LEAKGUARD_STATE_DIR": str(root / f"hook-state-{repetition}"),
            "LEAKGUARD_GITLEAKS": str(backend),
            "PYTHONPATH": module_path,
        })

        def git(*arguments, check=True):
            return subprocess.run(["git", *arguments], cwd=repository, env=git_env,
                                  capture_output=True, timeout=180, check=check)

        git("-c", "init.templateDir=", "init", "-q")
        git("config", "user.name", "Synthetic Benchmark")
        git("config", "user.email", "benchmark@example.invalid")
        git("config", "commit.gpgsign", "false")
        git("config", "core.hooksPath", ".git/hooks")
        (repository / "seed.txt").write_text("synthetic seed\n", encoding="utf-8")
        git("add", "seed.txt")
        git("commit", "--no-verify", "-qm", "synthetic seed")
        hooks.install_at(repository / ".git" / "hooks")

        clean = repository / "clean.txt"
        clean.write_text("ordinary synthetic text\n", encoding="utf-8")
        git("add", "clean.txt")
        started = time.perf_counter()
        clean_commit = git("commit", "-qm", "synthetic clean", check=False)
        clean_seconds = time.perf_counter() - started

        positive = repository / "positive.txt"
        candidate = f'client_secret = "{marker}-{repetition:03d}"\n'
        positive.write_text(candidate, encoding="utf-8")
        git("add", "positive.txt")
        started = time.perf_counter()
        positive_commit = git("commit", "-qm", "synthetic positive", check=False)
        positive_seconds = time.perf_counter() - started
        combined = positive_commit.stdout + positive_commit.stderr
        result.append({
            "repetition": repetition,
            "clean_seconds": round(clean_seconds, 6),
            "clean_exit_code": clean_commit.returncode,
            "positive_seconds": round(positive_seconds, 6),
            "positive_exit_code": positive_commit.returncode,
            "positive_blocked": positive_commit.returncode != 0 and b"LeakGuard blocked" in combined,
            "positive_output_redacted": marker.encode("ascii") not in combined,
        })
    return result


def _aggregate_checks(benchmarks: list[dict], part_curve: list[dict],
                     hook_rows: list[dict]) -> tuple[dict[str, int], list[dict]]:
    """Aggregate case-local checks without assuming policy IDs are global.

    Scan limits are part of policy identity, so cases at different file counts
    may correctly have different policy IDs. The three measurements for one
    case must agree with each other; the receipt retains identities by case.
    """
    identity_cases = []
    for item in benchmarks:
        measurements = item["measurements"]
        policy_ids = {mode: measurements[mode]["policy_id"]
                      for mode in ("cold", "warm", "uncached")}
        runtime_ids = {mode: measurements[mode]["runtime_id"]
                       for mode in ("cold", "warm", "uncached")}
        identity_cases.append({
            "files": item["files"], "content": item["content"],
            "repetition": item["repetition"],
            "policy_ids": policy_ids, "runtime_ids": runtime_ids,
            "consistent_within_case": (len(set(policy_ids.values())) == 1
                                        and len(set(runtime_ids.values())) == 1),
        })

    return ({
        "equivalence_failures": sum(
            not all(item["equivalence"].values()) for item in benchmarks
        ),
        "cache_reuse_failures": sum(
            item["measurements"]["warm"]["backend_worker_launches"] != 0
            or item["warm_reused_results"] != item["files"]
            for item in benchmarks
        ),
        "coverage_failures": sum(
            not all(item["measurements"][mode]["coverage_complete"]
                    for mode in ("cold", "warm", "uncached"))
            for item in benchmarks
        ) + sum(not item["covered_text_surfaces_complete"] for item in part_curve),
        "installed_hook_failures": sum(
            item["clean_exit_code"] != 0 or not item["positive_blocked"]
            or not item["positive_output_redacted"] for item in hook_rows
        ),
        "scan_identity_failures": sum(
            not item["consistent_within_case"] for item in identity_cases
        ),
    }, identity_cases)


def run_benchmark(*, config: Path, state: Path, gitleaks: Path,
                  repetitions: int, seed: int, input_root: Path) -> dict:
    from leakguard_core import engine, models

    if state.is_symlink() or state.exists() and (not state.is_dir() or any(state.iterdir())):
        raise BenchmarkFailure("state-not-empty")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if gitleaks.is_symlink() or not gitleaks.is_file() or not os.access(gitleaks, os.X_OK):
        raise BenchmarkFailure("backend-invalid")
    rules = Path(engine.RULES).resolve(strict=True)
    service_open_started = time.perf_counter()
    service = engine.ScanService({
        "gitleaks_executable": str(gitleaks.resolve(strict=True)),
        "gitleaks_config": str(rules),
    }, state_dir=state)
    service_open_seconds = time.perf_counter() - service_open_started
    rules_digest = _sha(rules.read_bytes())
    backend_digest = _sha(gitleaks.read_bytes())
    rng = random.Random(seed)
    marker = "SyntheticOnly~M7kQ2vR9xL4nD8pS6aH3zB5cF1eG-" + hashlib.sha256(
        str(rng.getrandbits(256)).encode("ascii")).hexdigest()[:8]
    benchmarks = []
    try:
        for count in (1, 10, 50, 200):
            case_repetitions = repetitions if count < 200 else 1
            for content_kind in ("clean", "positive"):
                for repetition in range(case_repetitions):
                    case_root = input_root / f"files-{count}-{content_kind}-{repetition}"
                    case_root.mkdir(mode=0o700)
                    paths = []
                    for index in range(count):
                        path = case_root / f"fixture-{index:03d}.txt"
                        if content_kind == "positive":
                            text = f'# fixture {index}\nclient_secret = "{marker}-{index:03d}"\n'
                        else:
                            text = f"ordinary synthetic content for fixture {index}.\n"
                        path.write_text(text, encoding="utf-8")
                        paths.append(models.FileInput(path))
                    measurements = {}
                    normalized = {}
                    warm_reused = 0
                    for mode, use_cache in (("cold", True), ("warm", True), ("uncached", False)):
                        row, findings, report = _measure(service, paths, use_cache=use_cache)
                        measurements[mode] = row
                        normalized[mode] = findings
                        if mode == "warm":
                            warm_reused = sum(result.outcome is models.ScanOutcome.REUSED
                                              for result in report.results)
                    equivalence = {
                        "warm_matches_cold": normalized["warm"] == normalized["cold"],
                        "uncached_matches_cold": normalized["uncached"] == normalized["cold"],
                    }
                    benchmarks.append({
                        "files": count, "content": content_kind, "repetition": repetition,
                        "repetitions_for_file_count": case_repetitions,
                        "measurements": measurements, "warm_reused_results": warm_reused,
                        "equivalence": equivalence,
                    })

        part_curve = []
        for count in (1, 5, 20):
            for repetition in range(repetitions):
                data = _docx(count, seed)
                source = models.BytesInput(data, f"part-curve-{count}-{repetition}.docx")
                row, _normalized_findings, report = _measure(service, [source], use_cache=False)
                row["parts_requested"] = count
                coverage = _part_curve_coverage(report)
                row.update(coverage)
                row["covered_text_surfaces"] = row["backend_worker_launches"]
                row["covered_text_surfaces_complete"] = (
                    row["required_complete"] and row["expected_nontext_omission_only"]
                    and row["covered_text_surfaces"] == count
                )
                row["input_sha256"] = _sha(data)
                part_curve.append({"parts": count, "repetition": repetition, **row})
        hook_rows = _hook_latency_benchmark(
            root=input_root, config=config, backend=gitleaks,
            repetitions=repetitions, marker=marker,
        )
    finally:
        service.close()

    checks, identity_cases = _aggregate_checks(benchmarks, part_curve, hook_rows)
    version_result = subprocess.run([str(gitleaks), "version"], capture_output=True,
                                    timeout=10, check=False)
    version_text = version_result.stdout.decode("utf-8", "replace") if version_result.returncode == 0 else ""
    version_match = re.search(r"\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b", version_text)
    backend_version = version_match.group(0) if version_match else "unavailable"
    dependencies = {}
    for package in ("packaging", "pypdf", "olefile"):
        try:
            dependencies[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            dependencies[package] = "unavailable"
    return {
        "seed": seed, "repetitions": repetitions, "file_curve": benchmarks,
        "part_curve": part_curve, "hook_latency": hook_rows,
        "service_open_seconds": round(service_open_seconds, 6),
        "backend_sha256": backend_digest, "backend_version": backend_version,
        "rules_sha256": rules_digest, "installed_dependencies": dependencies,
        "scan_identity_cases": identity_cases,
        "scan_identities_consistent": checks["scan_identity_failures"] == 0,
        "metric_definitions": {
            "backend_worker_launches": "Calls to leakguard_core.backends.run_worker only; excludes Git, parser and other subprocesses.",
            "sqlite_statement_count": "SQLite trace callback count only; statement text and parameters are discarded.",
            "parent_lifetime_high_water_bytes": "Parent process lifetime RSS high-water, not per-operation peak.",
            "children_lifetime_high_water_bytes": "Cumulative child-process lifetime RSS high-water, not per-operation peak.",
            "service_open_seconds": "ScanService constructor time, recorded separately from scan calls.",
        },
        "checks": checks,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261025)
    args = parser.parse_args(argv)
    started = dt.datetime.now(dt.timezone.utc)
    monotonic = time.monotonic()
    output = Path(args.output).absolute()
    result = {"outcome": "setup-failed", "failed_stage": "preflight"}
    backend_digest = None
    try:
        if type(args.repetitions) is not int or not 3 <= args.repetitions <= 5:
            raise BenchmarkFailure("repetitions-invalid")
        config = _validate_config(Path(args.config))
        backend = Path(args.gitleaks)
        if backend.is_symlink():
            raise BenchmarkFailure("backend-invalid")
        backend = backend.resolve(strict=True)
        backend_digest = _sha(backend.read_bytes())
        state = Path(args.state).absolute()
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise BenchmarkFailure("receipt-path")
        state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        input_root = Path(tempfile.mkdtemp(prefix="leakguard-benchmark-inputs-", dir=state.parent))
        try:
            details = run_benchmark(config=config, state=state, gitleaks=backend,
                                    repetitions=args.repetitions, seed=args.seed,
                                    input_root=input_root)
        finally:
            shutil.rmtree(input_root)
        failures = sum(details["checks"].values())
        source_commit, source_digest = source_identity(ROOT)
        backend_digest_after = _sha(backend.read_bytes())
        backend_stable = backend_digest == backend_digest_after
        if not backend_stable and failures == 0:
            failures = 1
        result = {"outcome": "passed" if failures == 0 else "failed",
                  "failed_stage": None if failures == 0 else "benchmark-checks",
                  "source_commit": source_commit, "source_digest": source_digest,
                  "config_sha256": _sha(config.read_bytes()),
                  "backend_sha256_after": backend_digest_after,
                  "backend_stable": backend_stable,
                  "details": details}
    except BenchmarkFailure as error:
        result = {"outcome": "failed", "failed_stage": error.code}
    except Exception:
        result = {"outcome": "setup-failed", "failed_stage": "preflight"}
    try:
        source_commit_after, source_digest_after = source_identity(ROOT)
        source_stable = (result.get("source_commit"), result.get("source_digest")) == (
            source_commit_after, source_digest_after,
        )
    except Exception:
        source_commit_after, source_digest_after, source_stable = "unknown", "unknown", False
    if result.get("outcome") == "passed" and not source_stable:
        result = {"outcome": "failed", "failed_stage": "source-changed-during-benchmark",
                  "source_commit": result.get("source_commit"),
                  "source_digest": result.get("source_digest")}
    receipt = {
        "schema_version": 1, "run_id": uuid.uuid4().hex,
        "host_label": platform.system().lower(), "python": sys.version.split()[0],
        "started_utc": started.isoformat(),
        "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - monotonic, 3),
        "gitleaks_identity": backend_digest,
        "source_commit_after": source_commit_after,
        "source_digest_after": source_digest_after,
        "source_stable": source_stable,
        **result,
    }
    try:
        _exclusive_write(output, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except Exception:
        return 2
    return 0 if receipt["outcome"] == "passed" else (1 if receipt["outcome"] == "failed" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
