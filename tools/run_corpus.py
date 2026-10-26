#!/usr/bin/env python3
"""Run the deterministic synthetic extraction/plugin corpus with a safe receipt."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "tests" / "fixtures" / "corpus_catalog.json"
sys.path.insert(0, str(ROOT / "src"))
from _safe_inputs import read_json_object, source_identity

WORKER_POLICIES = {"strict", "supervised-alpha"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


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


def _source_identity() -> tuple[str, str]:
    return source_identity(ROOT)


def _dependency_versions() -> dict[str, str]:
    rows = []
    for name in ("packaging", "pypdf", "olefile"):
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            version = "unavailable"
        rows.append((name, version))
    return dict(rows)


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _validate(args):
    config_input = Path(args.config)
    config_data = read_json_object(config_input)
    if (set(config_data) - {"worker_policy"}
            or ("worker_policy" in config_data
                and (type(config_data["worker_policy"]) is not str
                     or config_data["worker_policy"] not in WORKER_POLICIES))):
        raise ValueError
    config = config_input.resolve(strict=True)
    backend_input = Path(args.gitleaks)
    if backend_input.is_symlink():
        raise ValueError
    backend = backend_input.resolve(strict=True)
    if not backend.is_file() or not os.access(backend, os.X_OK):
        raise ValueError
    state = Path(args.state).absolute()
    if state.is_symlink():
        raise ValueError
    if state.exists():
        if not state.is_dir() or any(state.iterdir()):
            raise ValueError
    else:
        state.mkdir(mode=0o700, parents=True)
    output = Path(args.output).absolute()
    manifest_path = output.with_suffix(output.suffix + ".manifest.json")
    if output.is_symlink() or manifest_path.is_symlink() or output.exists() or manifest_path.exists():
        raise ValueError
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    catalog_data = json.loads(CATALOG.read_text(encoding="utf-8"))
    if (type(catalog_data) is not dict or set(catalog_data) != {"schema_version", "seed", "cases"}
            or catalog_data["schema_version"] != 3 or type(catalog_data["cases"]) is not list
            or len(catalog_data["cases"]) < 32):
        raise ValueError
    return config, backend, state, output, manifest_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=20261025)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--config", required=True,
                        help="owned bounded JSON object; optional worker_policy is strict or supervised-alpha")
    parser.add_argument("--state", required=True, help="new or empty private state directory")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)
    started = dt.datetime.now(dt.timezone.utc)
    monotonic_start = time.monotonic()
    output = Path(args.output).absolute()
    summary = None
    catalog_data = None
    manifest_bytes = b""
    revision, patch_digest = "unknown", "unknown"
    backend = None
    manifest_path = None
    labels = []
    try:
        if args.seed < 0 or not 1 <= args.timeout_seconds <= 900:
            raise ValueError
        config, backend, state, output, manifest_path = _validate(args)
        config_data = read_json_object(config)
        catalog_data = json.loads(CATALOG.read_text(encoding="utf-8"))
        labels = [{"case_id": row["case_id"], "category": row["category"],
                   "declared_state": row["state"]} for row in catalog_data["cases"]]
        revision, patch_digest = _source_identity()
        environment = dict(os.environ)
        environment.pop("PYTHONHOME", None)
        environment.update({
            "LEAKGUARD_CONFIG": str(config),
            "LEAKGUARD_STATE_DIR": str(state),
            "LEAKGUARD_GITLEAKS": str(backend),
            "LEAKGUARD_CORPUS_SEED": str(args.seed),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(state.parent / "gitconfig"),
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT / "tests"))),
        })
        command = [sys.executable, str(ROOT / "tools" / "_corpus_runner.py")]
        from leakguard_core._supervision import WorkerError, run_worker
        try:
            completed = run_worker(
                command, b"", cwd=ROOT, env=environment, timeout=args.timeout_seconds,
                max_output_bytes=8 * 1024 * 1024, max_input_bytes=1024, memory_bytes=None,
            )
            summary = json.loads(completed.stdout)
            if (type(summary) is not dict or set(summary) != {"seed", "worker_policy", "policy_id", "runtime_id", "counts", "detector_metrics", "by_category", "cases"}
                    or summary["seed"] != args.seed
                    or summary["worker_policy"] != config_data.get("worker_policy")
                    or summary["counts"].get("labeled_cases") != len(catalog_data["cases"])
                    or len(summary["cases"]) != len(catalog_data["cases"])):
                raise ValueError
            outcome = "passed" if completed.returncode == 0 and summary["counts"].get("failed") == 0 else "failed"
            exit_code = 0 if outcome == "passed" else 1
            del completed
        except WorkerError as error:
            outcome = "timeout" if error.code == "worker-timeout" else "failed"
            exit_code = 1
        except Exception:
            outcome = "failed"
            exit_code = 1
            summary = None
        case_artifacts = []
        if summary:
            for item in summary.get("cases", ()):
                case_artifacts.append({key: item.get(key) for key in
                                       ("case_id", "category", "status", "coverage", "artifact_sha256")})
        manifest_bytes = _json({"schema_version": 1, "seed": args.seed,
                                "cases": labels, "artifacts": case_artifacts})
        _exclusive_write(manifest_path, manifest_bytes)
    except Exception:
        outcome = "setup-failed"
        exit_code = 2
        backend = None
        revision, patch_digest = "unknown", "unknown"
        summary = None
        manifest_bytes = b""

    try:
        revision_after, patch_digest_after = _source_identity()
        source_stable = (revision, patch_digest) == (revision_after, patch_digest_after)
    except Exception:
        revision_after, patch_digest_after, source_stable = "unknown", "unknown", False
    if outcome == "passed" and not source_stable:
        outcome, exit_code = "failed", 1
    finished = dt.datetime.now(dt.timezone.utc)
    receipt = {
        "run_id": uuid.uuid4().hex,
        "lane": "evidence",
        "host_label": platform.system().lower(),
        "source_commit": revision,
        "patch_digest": patch_digest,
        "source_commit_after": revision_after,
        "patch_digest_after": patch_digest_after,
        "source_stable": source_stable,
        "input_manifest_digest": _sha(manifest_bytes),
        "python": sys.version.split()[0],
        "dependency_lock_digest": _sha(_json({"python": sys.version.split()[0], "packages": _dependency_versions()})),
        "installed_dependencies": _dependency_versions(),
        "gitleaks_identity": _file_sha(backend) if backend is not None else None,
        "policy_id": summary.get("policy_id") if summary else None,
        "runtime_id": summary.get("runtime_id") if summary else None,
        "command": ["python", "tools/_corpus_runner.py", "--seed", str(args.seed)],
        "seed": args.seed,
        "worker_policy": summary.get("worker_policy") if summary else None,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "elapsed_seconds": round(time.monotonic() - monotonic_start, 3),
        "cache_status": "uncached",
        "outcome": outcome,
        "counts": summary.get("counts", {"labeled_cases": 0, "failed": 0, "uncovered": 0}) if summary else {"labeled_cases": 0, "failed": 0, "uncovered": 0},
        "detector_metrics": summary.get("detector_metrics") if summary else None,
        "by_category": summary.get("by_category") if summary else None,
        "peak_rss_bytes": None,
        "subprocess_count": None,
        "artifact_sha256": _sha(manifest_bytes),
    }
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _exclusive_write(output, (json.dumps(receipt, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode("utf-8"))
    except Exception:
        return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
