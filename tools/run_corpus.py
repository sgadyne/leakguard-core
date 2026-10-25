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
import re
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
CASE_IDS = (
    "multiline-parts", "utf16-input", "unusual-extension", "duplicate-json",
    "verified-ast-proof", "wrong-source-proof", "plugin-rule-collision",
    "synthetic-pdf", "synthetic-msg", "unsupported-compound",
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _source_identity() -> tuple[str, str]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, check=True, timeout=5,
    ).stdout.decode("ascii").strip()
    patch = subprocess.run(
        ["git", "diff", "--binary", "HEAD"], cwd=ROOT, capture_output=True, check=True, timeout=10,
    ).stdout
    hasher = hashlib.sha256(patch)
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, capture_output=True, check=True, timeout=5,
    ).stdout
    for relative in untracked.split(b"\0"):
        if not relative:
            continue
        path = (ROOT / os.fsdecode(relative)).resolve()
        if not path.is_relative_to(ROOT) or not path.is_file() or path.is_symlink():
            continue
        hasher.update(relative + b"\0")
        hasher.update(path.read_bytes())
    return revision, hasher.hexdigest()


def _dependency_versions() -> dict[str, str]:
    rows = []
    for name in ("packaging", "pypdf", "olefile"):
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            version = "unavailable"
        rows.append((name, version))
    return dict(rows)


def _validate(args):
    config_input = Path(args.config)
    if config_input.is_symlink():
        raise ValueError
    config = config_input.resolve(strict=True)
    if json.loads(config.read_text(encoding="utf-8")) != {}:
        raise ValueError
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
    return config, backend, state, output, manifest_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--seed", type=int, default=20261025)
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--config", required=True, help="must be an owned empty JSON object")
    parser.add_argument("--state", required=True, help="new or empty private state directory")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args(argv)
    started = dt.datetime.now(dt.timezone.utc)
    monotonic_start = time.monotonic()
    output = Path(args.output).absolute()
    try:
        if args.seed < 0 or not 1 <= args.timeout_seconds <= 900:
            raise ValueError
        config, backend, state, output, manifest_path = _validate(args)
        labels = [{"case_id": value} for value in CASE_IDS]
        manifest = {"schema_version": 1, "seed": args.seed, "cases": labels}
        manifest_bytes = _json(manifest)
        manifest_path.write_bytes(manifest_bytes)
        revision, patch_digest = _source_identity()
        environment = dict(os.environ)
        environment.update({
            "LEAKGUARD_CONFIG": str(config),
            "LEAKGUARD_STATE_DIR": str(state),
            "LEAKGUARD_GITLEAKS": str(backend),
            "LEAKGUARD_CORPUS_SEED": str(args.seed),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(state.parent / "gitconfig"),
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONPATH": str(ROOT / "src"),
        })
        home = state.parent / "home"
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment["HOME"] = str(home)
        command = [sys.executable, str(ROOT / "tools" / "_corpus_runner.py")]
        sys.path.insert(0, str(ROOT / "src"))
        from leakguard_core._supervision import WorkerError, run_worker
        try:
            completed = run_worker(
                command, b"", cwd=ROOT, env=environment, timeout=args.timeout_seconds,
                max_output_bytes=4 * 1024 * 1024, max_input_bytes=1024, memory_bytes=None,
            )
            match = re.search(rb"Ran ([0-9]+) tests? in", completed.stdout)
            test_count = int(match.group(1)) if match else 0
            outcome = "passed" if completed.returncode == 0 and test_count > 0 else "failed"
            exit_code = 0 if outcome == "passed" else 1
            # Runner output is deliberately discarded; failures may include
            # synthetic fixture reprs, while this receipt contains no text.
            del completed
        except WorkerError as error:
            outcome = "timeout" if error.code == "worker-timeout" else "failed"
            exit_code = 1
            test_count = 0
    except Exception:
        outcome = "setup-failed"
        exit_code = 2
        test_count = 0
        backend = None
        revision, patch_digest = "unknown", "unknown"
        manifest_bytes = b""
        manifest_path = None

    finished = dt.datetime.now(dt.timezone.utc)
    receipt = {
        "run_id": uuid.uuid4().hex,
        "lane": "evidence",
        "host_label": platform.system().lower(),
        "source_commit": revision,
        "patch_digest": patch_digest,
        "input_manifest_digest": _sha(manifest_bytes),
        "python": sys.version.split()[0],
        "dependency_lock_digest": _sha(_json({"python": sys.version.split()[0], "packages": _dependency_versions()})),
        "installed_dependencies": _dependency_versions(),
        "gitleaks_identity": _sha(backend.read_bytes()) if backend is not None else None,
        "policy_id": None,
        "runtime_id": None,
        "command": ["python", "tools/_corpus_runner.py"],
        "seed": args.seed,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "elapsed_seconds": round(time.monotonic() - monotonic_start, 3),
        "cache_status": "uncached",
        "outcome": outcome,
        "counts": {"cases": len(CASE_IDS), "tests_run": test_count},
        "peak_rss_bytes": None,
        "subprocess_count": None,
        "artifact_sha256": _sha(manifest_bytes),
    }
    try:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, sort_keys=True, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    except Exception:
        return 2
    if manifest_path is not None and not manifest_path.exists():
        manifest_path.write_bytes(manifest_bytes)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
