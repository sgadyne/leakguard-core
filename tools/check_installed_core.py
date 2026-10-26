#!/usr/bin/env python3
"""Check installed release wheels against the current isolated core suite.

Run this script with the immutable release Python. It creates only a new,
test-only venv and work tree, installs the supplied release and fixture wheels
offline, then runs the current source tests from a staged unrelated directory.
"""
from __future__ import annotations

import argparse
import datetime as dt
from email.parser import Parser
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
import zipfile


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT / "tools"))
import run_acceptance as acceptance  # noqa: E402


MAX_WHEEL_BYTES = 256 * 1024 * 1024
MAX_WHEELHOUSE_BYTES = 1024 * 1024 * 1024
EXPECTED_FIXTURES = {
    "leakguard-example-detector": "examples/v2_detector",
    "leakguard-example-extractor": "examples/v2_extractor",
}
WORKER_POLICY = "supervised-alpha"


class DriverFailure(RuntimeError):
    def __init__(self, stage: str, details: dict | None = None):
        self.stage = stage
        self.details = details or {}
        super().__init__(stage)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _directory(raw: str, stage: str) -> Path:
    path = Path(raw)
    if path.is_symlink():
        raise DriverFailure(stage)
    try:
        path = path.resolve(strict=True)
    except OSError:
        raise DriverFailure(stage) from None
    if not path.is_dir():
        raise DriverFailure(stage)
    return path


def _regular_input(path: Path, stage: str) -> Path:
    try:
        info = path.lstat()
    except OSError:
        raise DriverFailure(stage) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise DriverFailure(stage)
    return path.resolve(strict=True)


def _wheel_tag(artifact: Path) -> str:
    try:
        with zipfile.ZipFile(artifact) as archive:
            names = [name for name in archive.namelist()
                     if name.endswith(".dist-info/WHEEL")]
            if len(names) != 1 or archive.getinfo(names[0]).file_size > 1_000_000:
                raise ValueError
            text = archive.read(names[0]).decode("utf-8")
            tags = [line.partition(":")[2].strip() for line in text.splitlines()
                    if line.startswith("Tag:")]
            if tags != ["py3-none-any"]:
                raise ValueError
            return tags[0]
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile):
        raise DriverFailure("fixture-wheel-tag") from None


def _wheel_rows(directory: Path, *, expected_count: int | None = None) -> list[dict]:
    candidates = sorted(directory.glob("*.whl"), key=lambda path: path.name)
    if not candidates or (expected_count is not None and len(candidates) != expected_count):
        raise DriverFailure("wheel-set-invalid")
    rows = []
    seen_names = set()
    total_size = 0
    for candidate in candidates:
        path = _regular_input(candidate, "wheel-file-invalid")
        size = path.stat().st_size
        total_size += size
        if size <= 0 or size > MAX_WHEEL_BYTES or total_size > MAX_WHEELHOUSE_BYTES:
            raise DriverFailure("wheel-size-limit")
        try:
            distribution, version = acceptance._wheel_distribution(path)
        except acceptance.AcceptanceFailure:
            raise DriverFailure("wheel-metadata-invalid") from None
        canonical = _canonical(distribution)
        if canonical in seen_names:
            raise DriverFailure("wheel-duplicate-distribution")
        seen_names.add(canonical)
        rows.append({
            "filename": path.name,
            "distribution": canonical,
            "version": version,
            "size_bytes": size,
            "sha256": _sha256_path(path),
            "path": str(path),
        })
    return rows


def _validate_fixture_wheels(directory: Path) -> tuple[list[Path], list[dict]]:
    rows = _wheel_rows(directory, expected_count=2)
    actual = {row["distribution"] for row in rows}
    if actual != set(EXPECTED_FIXTURES):
        raise DriverFailure("fixture-wheel-set-invalid")
    for row in rows:
        _wheel_tag(Path(row["path"]))
        row["source_project"] = EXPECTED_FIXTURES[row["distribution"]]
        row["wheel_tag"] = "py3-none-any"
    return [Path(row["path"]) for row in rows], rows


def _validate_release_wheels(wheelhouse: Path) -> tuple[list[Path], dict, list[dict]]:
    rows = _wheel_rows(wheelhouse)
    manifest_path = _regular_input(wheelhouse.parent / "release.json",
                                   "release-manifest-missing")
    try:
        manifest = acceptance.read_json_object(manifest_path)
    except (OSError, ValueError, TypeError):
        raise DriverFailure("release-manifest-invalid") from None
    packages = manifest.get("packages")
    source_commit = manifest.get("source_commit")
    release_version = manifest.get("release_version")
    target_python = manifest.get("target_python")
    if (type(packages) is not list
            or type(source_commit) is not str
            or not re.fullmatch(r"[0-9a-f]{40}", source_commit)
            or type(release_version) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!-]{0,99}", release_version)
            or type(target_python) is not str
            or not re.fullmatch(r"[0-9]+\.[0-9]+", target_python)):
        raise DriverFailure("release-manifest-invalid")
    expected = {}
    for entry in packages:
        if type(entry) is not dict:
            raise DriverFailure("release-manifest-invalid")
        filename = entry.get("filename")
        name = entry.get("name")
        version = entry.get("version")
        sha256 = entry.get("sha256")
        if (type(filename) is not str or Path(filename).name != filename
                or not filename.endswith(".whl") or type(name) is not str
                or type(version) is not str or type(sha256) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                or filename in expected):
            raise DriverFailure("release-manifest-invalid")
        expected[filename] = {
            "distribution": _canonical(name), "version": version, "sha256": sha256,
        }
    observed = {row["filename"]: row for row in rows}
    if set(observed) != set(expected):
        raise DriverFailure("release-wheel-manifest-mismatch")
    for filename, row in observed.items():
        binding = expected[filename]
        if (row["distribution"] != binding["distribution"]
                or row["version"] != binding["version"]
                or row["sha256"] != binding["sha256"]):
            raise DriverFailure("release-wheel-manifest-mismatch")
        row["source"] = "immutable-release-wheelhouse"
    if _canonical("leakguard-core") not in {row["distribution"] for row in rows}:
        raise DriverFailure("release-core-wheel-missing")
    return [Path(row["path"]) for row in rows], manifest, rows


def _tree_digest(root: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    for path in sorted(root.rglob("*"), key=lambda entry: entry.relative_to(root).as_posix()):
        info = path.lstat()
        relative = path.relative_to(root).as_posix().encode("utf-8")
        if stat.S_ISLNK(info.st_mode):
            raise DriverFailure("staged-input-symlink")
        if not stat.S_ISREG(info.st_mode):
            continue
        digest.update(relative + b"\0")
        digest.update(bytes.fromhex(_sha256_path(path)))
        count += 1
    return digest.hexdigest(), count


def _helper_hashes() -> dict[str, str]:
    result = {}
    for name in ("check_installed_core.py", "run_acceptance.py", "_safe_inputs.py"):
        path = SOURCE_ROOT / "tools" / name
        if path.is_symlink() or not path.is_file():
            raise DriverFailure("validation-helper-missing")
        result[name] = _sha256_path(path)
    return result


def _env(*, config: Path, state: Path, gitleaks: Path, global_gitconfig: Path,
         base: dict[str, str] | None = None) -> dict[str, str]:
    env = acceptance._environment(config=config, state=state, gitleaks=gitleaks,
                                  global_gitconfig=global_gitconfig, base=base)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONUSERBASE", None)
    env.pop("PIP_INDEX_URL", None)
    env["PIP_NO_INDEX"] = "1"
    env["PIP_CONFIG_FILE"] = os.devnull
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _pip_command(test_python: Path, target_site: Path,
                 wheel_paths: list[Path]) -> list[str]:
    # Keep sys.executable as supplied by the installed venv. Resolving a venv
    # symlink can select its base Python, which may not carry the installed pip.
    return [str(Path(sys.executable)), "-m", "pip", "--python", str(test_python),
            "install", "--disable-pip-version-check", "--no-index", "--no-deps",
            "--target", str(target_site), *map(str, wheel_paths)]


def _execute(args, evidence: dict) -> dict:
    config_input = _regular_input(Path(args.config), "config-invalid")
    gitleaks_input = _regular_input(Path(args.gitleaks), "backend-invalid")
    if not os.access(gitleaks_input, os.X_OK):
        raise DriverFailure("backend-invalid")
    config = acceptance._read_policy_config(config_input, require_policy=True)
    if config.get("worker_policy") != WORKER_POLICY:
        raise DriverFailure("worker-policy-invalid")
    wheelhouse = _directory(args.wheelhouse, "wheelhouse-invalid")
    fixture_directory = _directory(args.fixture_wheels, "fixture-directory-invalid")
    evidence["worker_policy"] = WORKER_POLICY

    work = Path(args.work).absolute()
    if work.is_symlink() or work.exists():
        raise DriverFailure("work-directory-not-new")
    protected = [SOURCE_ROOT, wheelhouse, fixture_directory,
                 config_input.parent, gitleaks_input.parent]
    if any(work == item or work.is_relative_to(item) or item.is_relative_to(work)
           for item in protected):
        raise DriverFailure("work-directory-overlap")
    work.mkdir(mode=0o700, parents=True)
    evidence["work_directory"] = str(work)

    release_paths, release_manifest, release_rows = _validate_release_wheels(wheelhouse)
    fixture_paths, fixture_rows = _validate_fixture_wheels(fixture_directory)
    all_distributions = [row["distribution"] for row in [*release_rows, *fixture_rows]]
    if len(all_distributions) != len(set(all_distributions)):
        raise DriverFailure("wheel-duplicate-distribution")

    release_manifest_path = wheelhouse.parent / "release.json"
    evidence.update({
        "release": {
            "release_version": release_manifest["release_version"],
            "source_commit": release_manifest["source_commit"],
            "target_python": release_manifest["target_python"],
            "target_platform": release_manifest.get("target_platform"),
            "manifest_sha256": _sha256_path(release_manifest_path),
            "wheelhouse": str(wheelhouse),
            "wheels": release_rows,
        },
        "fixtures": {"wheels": fixture_rows},
        "backend_sha256": _sha256_path(gitleaks_input),
        "release_runtime": {
            "executable": str(Path(sys.executable)),
            "version": sys.version.split()[0],
            "prefix": sys.prefix,
            "pip_version": metadata.version("pip"),
        },
    })

    python_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    if release_manifest["target_python"] != python_minor:
        raise DriverFailure("release-python-mismatch")
    source_commit, patch_digest = acceptance._source_identity()
    helper_hashes = _helper_hashes()
    evidence["validation_source"] = {
        "source_commit": source_commit,
        "patch_digest": patch_digest,
        "helper_sha256": helper_hashes,
    }

    state = work / "state"
    state.mkdir(mode=0o700)
    global_gitconfig = work / "gitconfig"
    test_env = _env(config=config_input.resolve(), state=state, gitleaks=gitleaks_input,
                    global_gitconfig=global_gitconfig)

    venv_root = work / "test-venv"
    acceptance._command([str(Path(sys.executable)), "-m", "venv", "--without-pip",
                         str(venv_root)], cwd=work, env=test_env,
                        stage="test-venv-create", timeout=120)
    test_python = acceptance._python(venv_root)
    target_site = acceptance._site_packages(venv_root)
    pip_argv = _pip_command(test_python, target_site, [*release_paths, *fixture_paths])
    acceptance._command(pip_argv, cwd=work, env=test_env,
                        stage="offline-wheel-install", timeout=180)
    check_argv = [str(Path(sys.executable)), "-m", "pip", "--python",
                  str(test_python), "check"]
    acceptance._command(check_argv, cwd=work, env={**test_env,
                                                   "PYTHONPATH": str(target_site)},
                        stage="offline-dependency-check", timeout=60)

    installed_tests = work / "installed-tests"
    installed_tests.mkdir(mode=0o700)
    shutil.copytree(SOURCE_ROOT / "tests", installed_tests / "tests",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    acceptance._stage_test_tools(SOURCE_ROOT, installed_tests)
    acceptance._stage_test_deploy_files(SOURCE_ROOT, installed_tests)
    staged_inputs_sha256, staged_input_files = _tree_digest(installed_tests)

    # Import only from the test site; the source checkout is never placed on
    # the test process's Python search path.
    probe_env = {**test_env, "PYTHONPATH": str(target_site)}
    origin = acceptance._command(
        [str(test_python), "-c",
         "import pathlib,leakguard_core;print(pathlib.Path(leakguard_core.__file__).resolve())"],
        cwd=installed_tests, env=probe_env, stage="installed-origin-check", timeout=30)
    try:
        package_origin = Path(origin.stdout.decode("utf-8").strip()).resolve(strict=True)
        site_root = target_site.resolve(strict=True)
    except (OSError, UnicodeError):
        raise DriverFailure("installed-origin-check") from None
    if not package_origin.is_relative_to(site_root):
        raise DriverFailure("source-path-leak")
    evidence["installed_core_origin"] = str(package_origin)
    evidence["release_runtime"]["test_python"] = str(test_python)

    shutil.copy2(installed_tests / "tests" / "fixtures" / "example_plugin.py",
                 installed_tests / "example_plugin.py")
    detector_v1, detector_v2, extractor = acceptance._fixture_case_files(installed_tests)
    conformance = [
        acceptance._run_conformance(test_python, "example_plugin", "detector",
                                    detector_v1, installed_tests, probe_env,
                                    "v1-conformance"),
        acceptance._run_conformance(test_python, "example_detector.plugin", "detector",
                                    detector_v2, installed_tests, probe_env,
                                    "v2-detector-conformance"),
        acceptance._run_conformance(test_python, "example_extractor.plugin", "extractor",
                                    extractor, installed_tests, probe_env,
                                    "v2-extractor-conformance"),
    ]
    suite = acceptance._command(
        [str(test_python), "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=installed_tests, env=probe_env, stage="installed-full-suite",
        timeout=acceptance.MAX_STAGE_SECONDS, allow_failure=True)
    summary = acceptance._parse_unittest_summary(
        suite.stderr.decode("utf-8", errors="replace"),
        suite.stdout.decode("utf-8", errors="replace"))
    if (summary is None or summary["failures"] or summary["errors"]
            or suite.returncode or summary["total"] < 100):
        raise DriverFailure("installed-full-suite", {"test_summary": summary})
    evidence["test_count"] = summary["total"]
    evidence["test_summary"] = summary
    evidence["conformance"] = conformance
    evidence["staged_inputs_sha256"] = staged_inputs_sha256
    evidence["staged_input_file_count"] = staged_input_files

    source_commit_after, patch_digest_after = acceptance._source_identity()
    source_stable = (source_commit, patch_digest) == (source_commit_after, patch_digest_after)
    if not source_stable:
        raise DriverFailure("source-changed-during-acceptance")
    evidence.update({
        "outcome": "passed",
        "failed_stage": None,
        "work_directory": str(work),
        "validation_source": {
            **evidence["validation_source"],
            "source_commit_after": source_commit_after,
            "patch_digest_after": patch_digest_after,
            "source_stable": source_stable,
        },
        "installed_dependencies": acceptance._installed_dependencies(
            test_python, installed_tests, probe_env),
    })
    return evidence


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, help="new, private test work directory")
    parser.add_argument("--wheelhouse", required=True,
                        help="immutable installed release wheelhouse with adjacent release.json")
    parser.add_argument("--fixture-wheels", required=True,
                        help="directory containing the two universal v2 example wheels")
    parser.add_argument("--config", required=True,
                        help="explicit worker-policy config; native runs require supervised-alpha")
    parser.add_argument("--gitleaks", required=True, help="pinned executable backend")
    parser.add_argument("--output", required=True, help="new redacted JSON receipt path")
    args = parser.parse_args(argv)

    started = dt.datetime.now(dt.timezone.utc)
    monotonic = time.monotonic()
    output = Path(args.output).absolute()
    result = {"outcome": "setup-failed", "failed_stage": "preflight"}
    evidence = {}
    try:
        source_commit_before, patch_digest_before = acceptance._source_identity()
        source_before = {"source_commit": source_commit_before,
                         "patch_digest": patch_digest_before,
                         "helper_sha256": _helper_hashes()}
    except Exception:
        source_before = {"source_commit": "unknown", "patch_digest": "unknown",
                         "helper_sha256": {}}
    try:
        if output.is_symlink() or output.exists():
            raise DriverFailure("receipt-path")
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        work_arg = Path(args.work).absolute()
        if output == work_arg or output.is_relative_to(work_arg):
            raise DriverFailure("receipt-path-inside-work")
        result = _execute(args, evidence)
    except DriverFailure as error:
        result = {"outcome": "failed", "failed_stage": error.stage,
                  **evidence, **error.details}
    except acceptance.AcceptanceFailure as error:
        result = {"outcome": "failed", "failed_stage": error.stage,
                  **evidence, **error.details}
    except Exception:
        # Do not copy exception messages, test output, or input values into the
        # public receipt. The private work directory remains available locally.
        result = {"outcome": "setup-failed", "failed_stage": "unexpected-error"}

    try:
        source_commit_after, patch_digest_after = acceptance._source_identity()
        source_stable_after = (
            source_commit_after == source_before["source_commit"]
            and patch_digest_after == source_before["patch_digest"]
        )
    except Exception:
        source_commit_after, patch_digest_after, source_stable_after = "unknown", "unknown", False
    if result.get("outcome") == "passed" and not source_stable_after:
        result = {"outcome": "failed", "failed_stage": "source-identity-after-run"}
    result.setdefault("validation_source", {})
    result["validation_source"].setdefault("source_commit", source_before["source_commit"])
    result["validation_source"].setdefault("patch_digest", source_before["patch_digest"])
    result["validation_source"].setdefault("helper_sha256", source_before["helper_sha256"])
    result["validation_source"].setdefault("source_commit_after", source_commit_after)
    result["validation_source"].setdefault("patch_digest_after", patch_digest_after)
    result["validation_source"]["source_stable"] = (
        bool(result["validation_source"].get("source_stable", True))
        and source_stable_after
    )
    finished = dt.datetime.now(dt.timezone.utc)
    receipt = {
        "schema_version": 1,
        "run_id": uuid.uuid4().hex,
        "host_label": platform.system().lower(),
        "runtime_python": sys.version.split()[0],
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "elapsed_seconds": round(time.monotonic() - monotonic, 3),
        "runtime_python_executable": str(Path(sys.executable)),
        "runtime_python_prefix": sys.prefix,
        "worker_policy": WORKER_POLICY,
        **result,
    }
    try:
        acceptance._write_exclusive(
            output, (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except Exception:
        return 2
    return 0 if result.get("outcome") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
