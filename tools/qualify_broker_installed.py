"""Run the new broker suite against installed wheels from outside the checkout.

Invoke through the run's heavy admission wrapper. This runner adds only test
packages to the specified isolated interpreter; it never installs editable code.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--wheels", required=True, type=Path)
    parser.add_argument("--uv", type=Path, default=Path(shutil.which("uv") or "uv"))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    artifacts = args.artifacts.resolve()
    if artifacts.is_relative_to(repo) or not args.python.is_absolute():
        raise SystemExit("qualification-path-invalid")
    artifacts.mkdir(parents=True, exist_ok=True)
    copied = artifacts / "suite"
    if copied.exists():
        raise SystemExit("qualification-artifacts-exist")
    copied.mkdir()
    tests = repo / "packages" / "leakguard_broker" / "tests"
    copied_tests = copied / "packages" / "leakguard_broker" / "tests"
    copied_tests.parent.mkdir(parents=True)
    shutil.copytree(tests, copied_tests, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (copied / "tools").mkdir()
    shutil.copy2(repo / "tools" / "installed_acceptance.py", copied / "tools" / "installed_acceptance.py")
    (copied / "pytest.ini").write_text("[pytest]\nasyncio_mode = auto\nasyncio_default_fixture_loop_scope = function\n")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env["HYPOTHESIS_STORAGE_DIRECTORY"] = str(artifacts / "hypothesis")
    env["UV_CACHE_DIR"] = str(artifacts / "uv-cache")
    receipt = {
        "schema": 1, "status": "running", "assignment_version": 1,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
        "source_dirty": subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True).splitlines(),
        "test_hashes": {str(p.relative_to(tests)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(tests.rglob("*.py"))},
        "commands": [],
    }

    def run(command, *, capture=False):
        receipt["commands"].append([str(c) for c in command])
        return subprocess.run([str(c) for c in command], cwd=copied, env=env, text=True,
                              check=True, capture_output=capture, timeout=600)

    try:
        if receipt["source_dirty"]:
            raise RuntimeError("qualification-source-dirty")
        run([args.uv, "pip", "install", "--python", args.python,
             "pytest==9.0.2", "pytest-asyncio==1.3.0", "hypothesis==6.151.9"])
        probe = run([args.python, "-I", "-c", '''
import importlib.metadata as m,json,platform,ssl
import leakguard_broker,leakguard_broker.server,leakguard_vault,leakguard_core
print(json.dumps({"python":platform.python_version(),"platform":platform.platform(),"openssl":ssl.OPENSSL_VERSION,
 "modules":{x.__name__:x.__file__ for x in (leakguard_broker,leakguard_vault,leakguard_core)},
 "distributions":{d.metadata["Name"]:d.version for d in m.distributions()}}))
'''], capture=True)
        receipt["environment"] = json.loads(probe.stdout)
        receipt["environment"]["openssl_cli"] = subprocess.check_output(["openssl", "version"], text=True).strip()
        lock = repo / "packages" / "leakguard_broker" / "requirements-py311.lock"
        receipt["runtime_lock_sha256"] = hashlib.sha256(lock.read_bytes()).hexdigest()
        installed = {k.lower().replace("_", "-"): v for k, v in receipt["environment"]["distributions"].items()}
        for line in lock.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            name, version = line.split("==")
            if installed.get(name) != version:
                raise RuntimeError("qualification-runtime-drift")
        receipt["project_file_integrity"] = {}
        for name, module in receipt["environment"]["modules"].items():
            path = Path(module).resolve()
            if path.is_relative_to(repo) or "site-packages" not in path.parts:
                raise RuntimeError("qualification-source-import")
            source = repo / "src" / name if name == "leakguard_core" else repo / "packages" / name / "src" / name
            matches = list(args.wheels.glob(name + "-*.whl"))
            if len(matches) != 1:
                raise RuntimeError("qualification-wheel-ambiguous")
            wheel = matches[0]
            with zipfile.ZipFile(wheel) as archive:
                expected = {n: hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist()
                            if n.startswith(name + "/") and n.endswith(".py")}
            source_files = {name + "/" + str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in source.rglob("*.py")}
            installed_files = {name + "/" + str(p.relative_to(path.parent)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in path.parent.rglob("*.py")}
            receipt["project_file_integrity"][name] = {
                "wheel": str(wheel.resolve()), "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "python_files": len(expected), "source_equals_wheel": source_files == expected,
                "installed_equals_wheel": installed_files == expected, "python_sha256": expected,
            }
            if source_files != expected or installed_files != expected:
                raise RuntimeError("qualification-project-bytes-mismatch")
        run([args.python, "-I", "-m", "pytest", str(copied_tests),
             "-c", str(copied / "pytest.ini"), "--basetemp", str(artifacts / "tmp"),
             "--junitxml", str(artifacts / "results.xml"), "-q"])
        receipt["status"] = "passed"
        receipt["assertions"] = {"outside_source_cwd": True, "isolated_python": True,
                                 "all_project_modules_from_site_packages": True,
                                 "source_wheel_installed_python_bytes_equal": True,
                                 "new_package_suite_passed": True}
    except Exception as error:
        receipt["status"] = "failed"
        receipt["error_type"] = type(error).__name__
    finally:
        receipt["completed_at"] = datetime.now(timezone.utc).isoformat()
        temporary = artifacts / "receipt.json.tmp"
        temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, artifacts / "receipt.json")
        print("installed broker suite: " + receipt["status"])
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
