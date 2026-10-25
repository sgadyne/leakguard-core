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
import json
import os
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
BENCHMARK_DEADLINE_SECONDS = 180


class BenchmarkFailure(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _rss_bytes() -> int | None:
    if resource is None:
        return None
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (AttributeError, OSError, ValueError):
        return None
    return int(value if sys.platform == "darwin" else value * 1024)


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

    started = time.perf_counter()
    with patch.object(backends, "run_worker", side_effect=counted):
        report = service.scan(
            sources, policy=models.ScanPolicy.inventory(),
            limits=models.ScanLimits(BENCHMARK_DEADLINE_SECONDS, max(1, len(sources))),
            use_cache=use_cache,
        )
    elapsed = time.perf_counter() - started
    row = {
        "seconds": round(elapsed, 6), "worker_launches": launches,
        "deadline_seconds": BENCHMARK_DEADLINE_SECONDS,
        "findings": sum(len(result.findings) for result in report.results),
        "results": len(report.results),
        "coverage_complete": all(result.coverage.value == "complete" for result in report.results),
        "outcomes": dict(Counter(result.outcome.value for result in report.results)),
        "coverage_states": dict(Counter(result.coverage.value for result in report.results)),
        "issue_codes": dict(Counter(issue.code.value for result in report.results for issue in result.issues)),
        "policy_verdict": report.decision.verdict.value,
        "process_rss_high_water_bytes": _rss_bytes(),
        "policy_id": report.policy_id,
        "runtime_id": next((result.identity.runtime_id for result in report.results), None),
    }
    return row, _normalized(report), report


def _validate_config(path: Path) -> Path:
    if path.is_symlink():
        raise BenchmarkFailure("config-invalid")
    resolved = path.resolve(strict=True)
    if json.loads(resolved.read_text(encoding="utf-8")) != {}:
        raise BenchmarkFailure("config-invalid")
    return resolved


def run_benchmark(*, config: Path, state: Path, gitleaks: Path,
                  repetitions: int, seed: int, input_root: Path) -> dict:
    from leakguard_core import engine, models

    if state.is_symlink() or state.exists() and (not state.is_dir() or any(state.iterdir())):
        raise BenchmarkFailure("state-not-empty")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if gitleaks.is_symlink() or not gitleaks.is_file() or not os.access(gitleaks, os.X_OK):
        raise BenchmarkFailure("backend-invalid")
    rules = Path(engine.RULES).resolve(strict=True)
    service = engine.ScanService({
        "gitleaks_executable": str(gitleaks.resolve(strict=True)),
        "gitleaks_config": str(rules),
    }, state_dir=state)
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
                row["parts_detected"] = row["worker_launches"]
                row["input_sha256"] = _sha(data)
                row["coverage_complete"] = all(result.coverage.value == "complete" for result in report.results)
                part_curve.append({"parts": count, "repetition": repetition, **row})
    finally:
        service.close()

    equivalence_failures = sum(
        not all(item["equivalence"].values()) for item in benchmarks
    )
    cache_failures = sum(
        item["measurements"]["warm"]["worker_launches"] != 0
        or item["warm_reused_results"] != item["files"]
        for item in benchmarks
    )
    coverage_failures = sum(
        not all(item["measurements"][mode]["coverage_complete"]
                for mode in ("cold", "warm", "uncached"))
        for item in benchmarks
    ) + sum(not item["coverage_complete"] or item["parts_detected"] != item["parts_requested"]
            for item in part_curve)
    return {
        "seed": seed, "repetitions": repetitions, "file_curve": benchmarks,
        "part_curve": part_curve,
        "checks": {"equivalence_failures": equivalence_failures,
                   "cache_reuse_failures": cache_failures,
                   "coverage_failures": coverage_failures},
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
        result = {"outcome": "passed" if failures == 0 else "failed",
                  "failed_stage": None if failures == 0 else "benchmark-checks",
                  "source_commit": subprocess.run(
                      ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                      timeout=10, check=True).stdout.decode("ascii").strip(),
                  "details": details}
    except BenchmarkFailure as error:
        result = {"outcome": "failed", "failed_stage": error.code}
    except Exception:
        result = {"outcome": "setup-failed", "failed_stage": "preflight"}
    receipt = {
        "schema_version": 1, "run_id": uuid.uuid4().hex,
        "host_label": platform.system().lower(), "python": sys.version.split()[0],
        "started_utc": started.isoformat(),
        "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - monotonic, 3),
        "gitleaks_identity": backend_digest, **result,
    }
    try:
        _exclusive_write(output, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except Exception:
        return 2
    return 0 if receipt["outcome"] == "passed" else (1 if receipt["outcome"] == "failed" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
