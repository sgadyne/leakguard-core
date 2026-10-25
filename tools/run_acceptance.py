#!/usr/bin/env python3
"""Build and test LeakGuard from a source checkout or a clean installed wheel.

The wheel mode installs only built artifacts into a new virtual environment,
copies the test suite and fixtures to an unrelated scratch directory, and runs
with source-tree PYTHONPATH removed. Output is an allowlisted redacted receipt.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import venv
import zipfile

if __package__:
    from ._safe_inputs import read_empty_json_object, source_identity
else:
    from _safe_inputs import read_empty_json_object, source_identity


ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_INDEX = "https://pypi.org/simple"
MAX_STAGE_SECONDS = 900


class AcceptanceFailure(RuntimeError):
    def __init__(self, stage: str):
        self.stage = stage
        super().__init__(stage)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _source_identity() -> tuple[str, str]:
    return source_identity(ROOT)


def _command(argv, *, cwd: Path, env: dict[str, str], stage: str,
             timeout: int = MAX_STAGE_SECONDS) -> subprocess.CompletedProcess:
    try:
        process = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                                 timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise AcceptanceFailure(stage) from None
    if process.returncode:
        raise AcceptanceFailure(stage)
    return process


def _parse_unittest_summary(output: str) -> dict | None:
    """Extract aggregate counts and fixed skip IDs, discarding test output text."""
    lines = output.splitlines()
    ran = [re.fullmatch(r"Ran (\d+) tests? in [0-9.]+s", line.strip())
           for line in lines]
    ran = [match for match in ran if match]
    if not ran:
        return None
    total = int(ran[-1].group(1))
    status = next((line.strip() for line in reversed(lines)
                   if line.strip()), "")
    ok = re.fullmatch(r"OK(?: \(skipped=(\d+)\))?", status)
    failed = re.fullmatch(r"FAILED(?: \((.*)\))?", status)
    if ok:
        skipped = int(ok.group(1) or "0")
        failures = errors = 0
    elif failed:
        counts = dict(re.findall(r"(failures|errors)=(\d+)", failed.group(1) or ""))
        failures = int(counts.get("failures", "0"))
        errors = int(counts.get("errors", "0"))
        skipped_match = re.search(r"skipped=(\d+)", failed.group(1) or "")
        skipped = int(skipped_match.group(1)) if skipped_match else 0
    else:
        return None

    skip_ids = []
    skip_line = re.compile(
        r"^(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. skipped(?:\s|$)"
    )
    for line in lines:
        match = skip_line.match(line)
        if match:
            skip_ids.append(f"{match.group(2)}.{match.group(1)}")
    passed = total - skipped - failures - errors
    if min(total, skipped, failures, errors, passed) < 0:
        return None
    return {"total": total, "passed": passed, "skipped": skipped,
            "failures": failures, "errors": errors,
            "skip_test_ids": sorted(set(skip_ids))}


def _python(venv_root: Path) -> Path:
    return venv_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _site_packages(venv_root: Path) -> Path:
    if os.name == "nt":
        return venv_root / "Lib" / "site-packages"
    candidates = sorted((venv_root / "lib").glob("python*/site-packages"))
    if len(candidates) != 1:
        raise AcceptanceFailure("venv-site-packages-invalid")
    return candidates[0]


def _environment(*, config: Path, state: Path, gitleaks: Path,
                 global_gitconfig: Path, base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(base if base is not None else os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.update({
        "LEAKGUARD_CONFIG": str(config),
        "LEAKGUARD_STATE_DIR": str(state),
        "LEAKGUARD_GITLEAKS": str(gitleaks),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(global_gitconfig),
        "GIT_TERMINAL_PROMPT": "0",
        "PIP_INDEX_URL": OFFICIAL_INDEX,
        "PIP_CONFIG_FILE": os.devnull,
    })
    return env


def _artifact_members(artifact: Path, forbidden_paths: tuple[Path, ...]) -> tuple[list[dict], list[str]]:
    rows = []
    problems = []
    try:
        if artifact.suffix == ".whl":
            with zipfile.ZipFile(artifact) as archive:
                members = ((item.filename, archive.read(item)) for item in archive.infolist())
                for name, payload in members:
                    rows.append({"name": name, "size_bytes": len(payload), "sha256": _hash(payload)})
                    if _artifact_member_problem(name, payload, forbidden_paths):
                        problems.append("artifact-content-review")
        elif artifact.name.endswith(".tar.gz"):
            with tarfile.open(artifact, "r:gz") as archive:
                for item in archive.getmembers():
                    if not item.isfile():
                        continue
                    stream = archive.extractfile(item)
                    payload = stream.read() if stream else b""
                    rows.append({"name": item.name, "size_bytes": len(payload), "sha256": _hash(payload)})
                    if _artifact_member_problem(item.name, payload, forbidden_paths):
                        problems.append("artifact-content-review")
        else:
            problems.append("artifact-format-unknown")
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        problems.append("artifact-read-failed")
    return sorted(rows, key=lambda item: item["name"]), sorted(set(problems))


def _artifact_member_problem(name: str, payload: bytes, forbidden_paths: tuple[Path, ...]) -> bool:
    folded = name.lower()
    if any(part in folded for part in (
        ".git/", "/scratch/", "/state/", "/reports/", "/docs/handoff/",
        "handoff.md", "/receipts/", "/tools/gitleaks", "heavy.py",
    )):
        return True
    if folded.endswith((".sqlite", ".sqlite3", ".db-wal", ".db-shm")):
        return True
    encoded_name = name.encode("utf-8", errors="surrogateescape")
    if any(str(path).encode() in payload or str(path).encode() in encoded_name
           for path in forbidden_paths):
        return True
    return False


def _fixture_case_files(work: Path) -> tuple[Path, Path, Path]:
    detector_v1 = work / "detector-v1-cases.json"
    detector_v2 = work / "detector-v2-cases.json"
    extractor = work / "extractor-cases.json"
    detector_v1.write_text(json.dumps({"cases": [{
        "case_id": "installed-v1-marker", "text": "ordinary\nSYNTHETIC_REVIEW_MARKER\n",
        "logical_path": "sample.txt", "format_id": "text", "part_id": "text",
        "expected_findings": [{"rule": "example-review-marker", "start_line": 2,
                               "end_line": 2, "severity": "review"}],
    }]}, sort_keys=True), encoding="utf-8")
    detector_v2.write_text(json.dumps({"cases": [{
        "case_id": "installed-v2-marker", "text": "ordinary\nFIRM-DEMO-MARKER\n",
        "logical_path": "sample.txt", "format_id": "text", "part_id": "text",
        "expected_findings": [{"rule": "example-firm-marker", "start_line": 2,
                               "end_line": 2, "severity": "review"}],
    }]}, sort_keys=True), encoding="utf-8")
    text = "demo note\n"
    import base64
    extractor.write_text(json.dumps({"cases": [{
        "case_id": "installed-note", "data_base64": base64.b64encode(b"LGNOTE\n" + text.encode()).decode("ascii"),
        "logical_path": "sample.lgnote", "expected_format": "example-envelope",
        "expected_disposition": "extracted", "expected_parts": [{
            "part_id": "note-1", "text_sha256": _hash(text.encode()), "line_count": 1,
        }],
    }]}, sort_keys=True), encoding="utf-8")
    return detector_v1, detector_v2, extractor


def _run_conformance(python: Path, module: str, kind: str, cases: Path,
                     cwd: Path, env: dict[str, str], stage: str) -> dict:
    result = _command([str(python), "-m", "leakguard_core.conformance", "--kind", kind,
                       "--module", module, "--cases", str(cases)],
                      cwd=cwd, env=env, stage=stage, timeout=90)
    try:
        lines = result.stdout.decode("utf-8").splitlines()
        if len(lines) != 1:
            raise ValueError
        report = json.loads(lines[0])
        if (type(report) is not dict or report.get("passed") is not True
                or report.get("failed_cases") != 0 or report.get("issues") != []):
            raise ValueError
        return {"passed": True, "cases": report.get("passed_cases", 0),
                "component_id": report.get("component_id"), "kind": report.get("kind")}
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise AcceptanceFailure(stage) from None


def _wheel_acceptance(work: Path, args, config: Path, gitleaks: Path) -> dict:
    builder_site = work / "build-tools"
    builder_site.mkdir(mode=0o700)
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONUSERBASE", None)
    env.update({"PIP_INDEX_URL": OFFICIAL_INDEX, "PIP_CONFIG_FILE": os.devnull,
                "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_CACHE_DIR": str(work / "pip-cache"),
                "PYTHONDONTWRITEBYTECODE": "1"})
    _command([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
              "--target", str(builder_site), "build", "setuptools>=77"],
             cwd=work, env=env, stage="build-tool-install")
    build_env = dict(env, PYTHONPATH=str(builder_site))
    dist = work / "dist"
    dist.mkdir(mode=0o700)
    source = work / "build-source"
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.pyc", ".venv", "tmp", "dist", "build", "*.egg-info"))
    _command([sys.executable, "-m", "build", "--no-isolation", "--sdist", "--wheel", "--outdir", str(dist)],
             cwd=source, env=build_env, stage="core-build")
    examples = work / "example-wheels"
    examples.mkdir(mode=0o700)
    for name in ("v2_detector", "v2_extractor"):
        _command([sys.executable, "-m", "build", "--no-isolation", "--wheel", "--outdir", str(examples)],
                 cwd=source / "examples" / name, env=build_env, stage="example-build")
    wheels = sorted(dist.glob("leakguard_core-*.whl"))
    sdists = sorted(dist.glob("leakguard_core-*.tar.gz"))
    example_wheels = sorted(examples.glob("*.whl"))
    if len(wheels) != 1 or len(sdists) != 1 or len(example_wheels) != 2:
        raise AcceptanceFailure("artifact-set-invalid")
    members = {}
    forbidden_paths = tuple(path for path in (ROOT, Path(args.config).resolve(),
                                                Path(args.gitleaks).resolve(), work.resolve())
                            if path.is_absolute())
    for artifact in [*wheels, *sdists, *example_wheels]:
        rows, problems = _artifact_members(artifact, forbidden_paths)
        if problems:
            raise AcceptanceFailure(problems[0])
        members[artifact.name] = rows
    env_root = work / "installed-venv"
    target_python = Path(args.python).resolve(strict=True) if args.python else Path(sys.executable).resolve(strict=True)
    target_version_probe = subprocess.run(
        [str(target_python), "-c", "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"],
        cwd=work, env=env, capture_output=True, timeout=10, check=False,
    )
    if target_version_probe.returncode:
        raise AcceptanceFailure("target-python-probe")
    target_python_version = target_version_probe.stdout.decode("ascii").strip()
    _command([str(target_python), "-m", "venv", "--without-pip", str(env_root)], cwd=work, env=env,
             stage="target-venv-create")
    target = _python(env_root)
    use_venv = False
    try:
        probe = subprocess.run([str(target), "-c", "import sys;print(sys.prefix)"], cwd=work,
                               env=env, capture_output=True, timeout=10, check=False)
        use_venv = probe.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        use_venv = False
    if use_venv:
        target_site = _site_packages(env_root)
        target_environment = _environment(config=config, state=work / "state", gitleaks=gitleaks,
                                          global_gitconfig=work / "gitconfig", base=env)
        target_environment["PYTHONNOUSERSITE"] = "1"
        installation_mode = "venv"
    else:
        # Some relocatable developer Python builds have a compiled `/install`
        # prefix and cannot start copied/symlinked venv interpreters. Install to
        # an isolated user base for that exact interpreter, with PYTHONPATH unset.
        version = subprocess.run(
            [str(target_python), "-c", "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')"],
            cwd=work, env=env, capture_output=True, timeout=10, check=True,
        ).stdout.decode("ascii").strip()
        user_base = work / "python-userbase"
        target_site = user_base / "lib" / f"python{version}" / "site-packages"
        target_site.mkdir(mode=0o700, parents=True)
        target = target_python
        target_environment = _environment(config=config, state=work / "state", gitleaks=gitleaks,
                                          global_gitconfig=work / "gitconfig", base=env)
        target_environment["PYTHONUSERBASE"] = str(user_base)
        target_environment.pop("PYTHONNOUSERSITE", None)
        installation_mode = "private-pythonuserbase-fallback"
    install_env = _environment(config=config, state=work / "state", gitleaks=gitleaks,
                               global_gitconfig=work / "gitconfig", base=env)
    (work / "state").mkdir(mode=0o700)
    pip_install = [sys.executable, "-m", "pip", "--python", str(target_python),
                   "install", "--disable-pip-version-check", "--target", str(target_site)]
    _command([*pip_install, str(wheels[0])], cwd=work, env=install_env, stage="core-wheel-install")
    if args.documents_extra:
        _command([*pip_install[:-2], "--target", str(target_site), "--upgrade",
                  "pypdf>=6,<7", "olefile>=0.47,<1"], cwd=work, env=install_env,
                 stage="documents-extra-install")
    _command([*pip_install[:-2], "--target", str(target_site), "--no-deps",
              *map(str, example_wheels)], cwd=work, env=install_env,
             stage="example-wheel-install")
    # pip --python re-executes pip under target_python, so dependency markers
    # use the requested target runtime rather than the builder interpreter.
    check_env = dict(install_env, PYTHONPATH=str(target_site))
    _command([sys.executable, "-m", "pip", "--python", str(target_python), "check"], cwd=work, env=check_env,
             stage="dependency-check")

    installed_tests = work / "installed-tests"
    installed_tests.mkdir(mode=0o700)
    shutil.copytree(ROOT / "tests", installed_tests / "tests",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(ROOT / "tools" / "_safe_inputs.py",
                 installed_tests / "tests" / "_safe_inputs.py")
    installed_tools = installed_tests / "tools"
    installed_tools.mkdir(mode=0o700)
    shutil.copy2(ROOT / "tools" / "_safe_inputs.py",
                 installed_tools / "_safe_inputs.py")
    shutil.copy2(ROOT / "tools" / "benchmark_scan.py",
                 installed_tools / "benchmark_scan.py")
    shutil.copy2(ROOT / "tools" / "run_acceptance.py",
                 installed_tools / "run_acceptance.py")
    (installed_tests / "state").mkdir(mode=0o700)
    test_env = _environment(config=config, state=installed_tests / "state", gitleaks=gitleaks,
                             global_gitconfig=installed_tests / "gitconfig", base=target_environment)
    origin = _command([str(target), "-c",
                       "import pathlib,leakguard_core;print(pathlib.Path(leakguard_core.__file__).resolve())"],
                      cwd=installed_tests, env=test_env, stage="installed-origin-check", timeout=30)
    package_origin = Path(origin.stdout.decode("utf-8").strip()).resolve()
    site_roots = [target_site.resolve()]
    if not any(package_origin.is_relative_to(path) for path in site_roots):
        raise AcceptanceFailure("source-path-leak")

    shutil.copy2(installed_tests / "tests" / "fixtures" / "example_plugin.py",
                 installed_tests / "example_plugin.py")
    detector_v1_cases, detector_v2_cases, extractor_cases = _fixture_case_files(installed_tests)
    conformance = [
        _run_conformance(target, "example_plugin", "detector", detector_v1_cases,
                         installed_tests, test_env, "v1-conformance"),
        _run_conformance(target, "example_detector.plugin", "detector", detector_v2_cases,
                         installed_tests, test_env, "v2-detector-conformance"),
        _run_conformance(target, "example_extractor.plugin", "extractor", extractor_cases,
                         installed_tests, test_env, "v2-extractor-conformance"),
    ]
    # The script adapter fixture is exercised by the full installed test suite.
    suite = _command([str(target), "-m", "unittest", "discover", "-s", "tests", "-v"],
                     cwd=installed_tests, env=test_env, stage="installed-full-suite", timeout=MAX_STAGE_SECONDS)
    suite_text = suite.stderr.decode("utf-8", errors="replace") + suite.stdout.decode("utf-8", errors="replace")
    test_summary = _parse_unittest_summary(suite_text)
    if test_summary is None or test_summary["failures"] or test_summary["errors"]:
        raise AcceptanceFailure("installed-full-suite")
    test_count = test_summary["total"]
    if test_count < 100:
        raise AcceptanceFailure("installed-suite-count")
    return {"installed_origin": str(package_origin), "test_count": test_count,
            "test_summary": test_summary,
            "target_python_version": target_python_version,
            "installation_mode": installation_mode,
            "conformance": conformance,
            "documents_extra": bool(args.documents_extra), "artifacts": members,
            "installed_dependencies": _installed_dependencies(target, installed_tests, test_env)}


def _installed_dependencies(python: Path, cwd: Path, env: dict[str, str]) -> dict[str, str]:
    result = _command([str(python), "-c",
                       "import importlib.metadata as m,json;print(json.dumps({n:(m.version(n) if any(d.metadata['Name'].lower()==n.lower() for d in m.distributions()) else 'unavailable') for n in ('leakguard-core','packaging','pypdf','olefile','leakguard-example-detector','leakguard-example-extractor')}))"],
                      cwd=cwd, env=env, stage="installed-metadata-check", timeout=30)
    try:
        value = json.loads(result.stdout)
        if type(value) is not dict:
            raise ValueError
        return value
    except (json.JSONDecodeError, ValueError):
        raise AcceptanceFailure("installed-metadata-check") from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("source", "wheel"), default="wheel")
    parser.add_argument("--output", required=True, help="new redacted JSON receipt path")
    parser.add_argument("--gitleaks", required=True)
    parser.add_argument("--config", required=True, help="must be an owned empty JSON object")
    parser.add_argument("--python", help="target interpreter for the clean installed environment")
    parser.add_argument("--documents-extra", action="store_true")
    args = parser.parse_args(argv)
    started = dt.datetime.now(dt.timezone.utc)
    monotonic = time.monotonic()
    output = Path(args.output).absolute()
    result = {"outcome": "setup-failed", "failed_stage": "preflight"}
    work = None
    revision, patch_digest = "unknown", "unknown"
    try:
        config_input, backend_input = Path(args.config), Path(args.gitleaks)
        if config_input.is_symlink() or backend_input.is_symlink():
            raise AcceptanceFailure("preflight")
        read_empty_json_object(config_input)
        config = config_input.resolve(strict=True)
        backend = backend_input.resolve(strict=True)
        if not backend.is_file() or not os.access(backend, os.X_OK):
            raise AcceptanceFailure("preflight")
        if output.is_symlink() or output.exists():
            raise AcceptanceFailure("receipt-path")
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        revision, patch_digest = _source_identity()
        work = Path(tempfile.mkdtemp(prefix="leakguard-acceptance-", dir=output.parent))
        os.chmod(work, 0o700)
        if args.mode == "wheel":
            details = _wheel_acceptance(work, args, config, backend)
        else:
            env = _environment(config=config, state=work / "state", gitleaks=backend,
                               global_gitconfig=work / "gitconfig")
            (work / "state").mkdir(mode=0o700)
            completed = _command([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                                 cwd=ROOT, env={**env, "PYTHONPATH": str(ROOT / "src")},
                                 stage="source-full-suite")
            output_text = (completed.stderr.decode("utf-8", errors="replace")
                           + completed.stdout.decode("utf-8", errors="replace"))
            test_summary = _parse_unittest_summary(output_text)
            if (test_summary is None or test_summary["total"] < 100
                    or test_summary["failures"] or test_summary["errors"]):
                raise AcceptanceFailure("source-full-suite")
            details = {"test_count": test_summary["total"], "test_summary": test_summary,
                       "documents_extra": bool(args.documents_extra),
                       "installed_origin": str((ROOT / "src" / "leakguard_core" / "__init__.py").resolve())}
        result = {"outcome": "passed", "failed_stage": None, "mode": args.mode,
                  "source_commit": revision, "patch_digest": patch_digest, **details}
    except AcceptanceFailure as error:
        result = {"outcome": "failed", "failed_stage": error.stage, "mode": args.mode,
                  "source_commit": revision, "patch_digest": patch_digest}
    except Exception:
        result = {"outcome": "setup-failed", "failed_stage": "preflight", "mode": args.mode,
                  "source_commit": revision, "patch_digest": patch_digest}
    finally:
        if work is not None:
            # Preserve build/install artifacts for review; the receipt records
            # their location without copying any source or test input values.
            result["work_directory"] = str(work)
    try:
        revision_after, patch_digest_after = _source_identity()
        source_stable = (revision, patch_digest) == (revision_after, patch_digest_after)
    except Exception:
        revision_after, patch_digest_after, source_stable = "unknown", "unknown", False
    if result.get("outcome") == "passed" and not source_stable:
        result = {"outcome": "failed", "failed_stage": "source-changed-during-acceptance",
                  "mode": args.mode}
    result.update({"source_commit_after": revision_after,
                   "patch_digest_after": patch_digest_after,
                   "source_stable": source_stable})
    finished = dt.datetime.now(dt.timezone.utc)
    receipt = {
        "schema_version": 1, "run_id": uuid.uuid4().hex,
        "host_label": platform.system().lower(), "python": sys.version.split()[0],
        "started_utc": started.isoformat(), "finished_utc": finished.isoformat(),
        "elapsed_seconds": round(time.monotonic() - monotonic, 3),
        "gitleaks_identity": _hash(backend.read_bytes()) if "backend" in locals() else None,
        **result,
    }
    try:
        _write_exclusive(output, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except Exception:
        return 2
    return 0 if result.get("outcome") == "passed" else (1 if result.get("outcome") == "failed" else 2)


if __name__ == "__main__":
    raise SystemExit(main())
