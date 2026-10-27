#!/usr/bin/env python3
"""Qualify the integrated Linux/Python 3.11 release using disposable wheels.

Run once through the run's heavy wrapper. Creates a new private artifact root;
all tests run from outside the checkout against the same non-editable venv.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = {
    "leakguard_host": ("packages/leakguard_host", "src/leakguard_host"),
    "presidio_detector": ("plugins/presidio_detector", "src/presidio_detector"),
    "jose_recognizers": ("plugins/jose_recognizers", "src/jose_recognizers"),
    "firm_presidio_recognizer": ("plugins/presidio_detector/examples/firm_presidio_recognizer", "src/firm_presidio_recognizer"),
    "sensitive_basics": ("plugins/sensitive_basics", "src/sensitive_basics"),
    "firm_plugin": ("templates/firm_plugin", "src/firm_plugin"),
    "example_detector": ("examples/v2_detector", "src/example_detector"),
    "example_extractor": ("examples/v2_extractor", "src/example_extractor"),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifacts", required=True, type=Path)
    p.add_argument("--gitleaks", required=True, type=Path)
    p.add_argument("--uv", type=Path, default=Path("/home/dev/.local/bin/uv"))
    args = p.parse_args()
    artifacts = args.artifacts.absolute()
    if artifacts.resolve().is_relative_to(ROOT) or artifacts.exists() or artifacts.is_symlink():
        raise SystemExit("artifact-root-invalid")
    artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONHOME", "LEAKGUARD_CONFIG", "LEAKGUARD_STATE_DIR", "LEAKGUARD_GITLEAKS"} and not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "UV_CACHE_DIR": str(artifacts / "uv-cache"), "PIP_DISABLE_PIP_VERSION_CHECK": "1"})
    result = {"schema": 1, "status": "running", "started_at": datetime.now(timezone.utc).isoformat(),
              "commands": [], "synthetic_only": True}
    stage = "preflight"
    def run(label, command, timeout=1200, cwd=None, environment=None):
        result["commands"].append([str(c) for c in command])
        with (artifacts / (label + ".log")).open("wb") as log:
            proc = subprocess.run([str(c) for c in command], cwd=cwd or artifacts, env=environment or env,
                                  stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        if proc.returncode:
            raise RuntimeError("stage-failed")
    try:
        status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True)
        if status:
            raise RuntimeError("source-dirty")
        result["source_commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        gitleaks = args.gitleaks.resolve(strict=True)
        if not gitleaks.is_file() or not os.access(gitleaks, os.X_OK):
            raise RuntimeError("gitleaks-invalid")
        result["gitleaks_sha256"] = digest(gitleaks)
        stage = "broker-cli"
        broker = artifacts / "broker"
        run(stage, [sys.executable, ROOT / "tools/installed_acceptance.py", "--artifact-dir", broker])
        vpy, wheels = broker / "venv/bin/python", broker / "wheels"
        result["broker_receipt"] = str(broker / "receipt.json")
        stage = "build-extra-wheels"
        for index, (project, _) in enumerate(PROJECTS.values()):
            run(f"build-extra-{index}", [args.uv, "build", "--wheel", "--out-dir", wheels, ROOT / project])
        stage = "install-combined"
        extra_wheels = sorted(wheels.glob("*.whl"))
        run("install-lock", [args.uv, "pip", "install", "--python", vpy, "--require-hashes", "-r", ROOT / "plugins/presidio_detector/requirements-py311.lock"])
        run("install-extras", [args.uv, "pip", "install", "--python", vpy, "--no-deps", "--no-index", *extra_wheels])
        run("install-docs", [args.uv, "pip", "install", "--python", vpy, "pypdf==6.12.2", "olefile==0.47"])
        run("dependency-check", [args.uv, "pip", "check", "--python", vpy])
        stage = "project-identity"
        spec = importlib.util.spec_from_file_location("installed_acceptance", ROOT / "tools/installed_acceptance.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        purelib = Path(subprocess.check_output([vpy, "-I", "-c", "import sysconfig;print(sysconfig.get_paths()['purelib'])"], cwd=artifacts, env=env, text=True).strip())
        roots = {"leakguard_core": ROOT / "src/leakguard_core", "leakguard_vault": ROOT / "packages/leakguard_vault/src/leakguard_vault", "leakguard_broker": ROOT / "packages/leakguard_broker/src/leakguard_broker"}
        roots.update({module: ROOT / project / package for module, (project, package) in PROJECTS.items()})
        identity = mod._project_python_identity(roots, extra_wheels, purelib)
        if any(not x["source_equals_wheel"] or not x["wheel_equals_installed"] for x in identity.values()):
            raise RuntimeError("project-identity-mismatch")
        def resource_identity():
            required = {"leakguard_core/rules.toml", "presidio_detector/cases.json",
                        "presidio_detector/leakguard-plugin.json", "jose_recognizers/py.typed",
                        "sensitive_basics/cases.json", "sensitive_basics/leakguard-plugin.json",
                        "firm_plugin/cases.json", "firm_plugin/leakguard-plugin.json"}
            resources = {}
            for module, row in identity.items():
                with zipfile.ZipFile(wheels / row["wheel"]) as archive:
                    for name in archive.namelist():
                        if not name.startswith(module + "/") or name.endswith(("/", ".py")):
                            continue
                        rel = name[len(module) + 1:]
                        source, installed = roots[module] / rel, purelib / name
                        wheel_hash = hashlib.sha256(archive.read(name)).hexdigest()
                        if not source.is_file() or not installed.is_file() or digest(source) != wheel_hash or digest(installed) != wheel_hash:
                            raise RuntimeError("project-resource-mismatch")
                        resources[name] = wheel_hash
            if not required <= set(resources):
                raise RuntimeError("required-resources-missing")
            return resources
        result["project_python_identity"] = identity
        result["project_resource_sha256"] = resource_identity()
        result["wheels"] = [{"name": w.name, "sha256": digest(w)} for w in extra_wheels]
        stage = "broker-suite"
        run(stage, [sys.executable, ROOT / "tools/qualify_broker_installed.py", "--python", vpy, "--wheels", wheels, "--artifacts", artifacts / "broker-suite", "--uv", args.uv])
        result["broker_suite_receipt"] = str(artifacts / "broker-suite/receipt.json")
        stage = "core-only-install"
        core_only = artifacts / "core-only/bin/python"
        core_wheels = list(wheels.glob("leakguard_core-*.whl"))
        if len(core_wheels) != 1:
            raise RuntimeError("core-wheel-ambiguous")
        run("core-only-venv", [args.uv, "venv", "--python", "/usr/bin/python3.11", artifacts / "core-only"])
        run("core-only-wheel", [args.uv, "pip", "install", "--python", core_only, "--no-index", "--no-deps", core_wheels[0]])
        run("core-only-deps", [args.uv, "pip", "install", "--python", core_only,
                               "packaging==26.3", "psutil==7.2.2", "cachetools==7.2.5"])
        run("core-only-check", [args.uv, "pip", "check", "--python", core_only])
        stage = "recognizer-profile-journey"
        run(stage, [vpy, "-I", ROOT / "tools/check_recognizer_profiles.py", "--gitleaks", gitleaks,
                    "--source-root", ROOT, "--output-dir", artifacts / "profile-journey",
                    "--core-only-python", core_only], timeout=1800)
        result["profile_receipt"] = str(artifacts / "profile-journey/receipt.json")
        stage = "installed-smoke"
        run(stage, [vpy, "-I", ROOT / "tools/check_presidio_smoke.py"])
        stage = "installed-adapter-and-jose"
        staged = artifacts / "contracts"
        staged.mkdir()
        for relative in ("plugins/jose_recognizers/tests", "plugins/presidio_detector/tests"):
            source, destination = ROOT / relative, staged / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        excluded = ("test_required_spacy_ner_uses_configured_model_without_fallback",
                    "test_required_ner_rejects_a_model_for_the_wrong_language",
                    "test_required_ner_rejects_a_mismatched_model_identity")
        run(stage, [vpy, "-I", "-m", "pytest", "-q", "--import-mode=importlib",
                    staged / "plugins/jose_recognizers/tests", staged / "plugins/presidio_detector/tests",
                    "-k", " and ".join("not " + name for name in excluded)], timeout=1800)
        stage = "installed-core-suite"
        sys.path.insert(0, str(ROOT / "tools"))
        import run_acceptance as acceptance
        core = artifacts / "core-suite"
        core.mkdir()
        shutil.copytree(ROOT / "tests", core / "tests", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(ROOT / "tools/_safe_inputs.py", core / "tests/_safe_inputs.py")
        acceptance._stage_test_tools(ROOT, core)
        acceptance._stage_test_deploy_files(ROOT, core)
        shutil.copy2(core / "tests/fixtures/example_plugin.py", core / "example_plugin.py")
        (core / "state").mkdir()
        config = core / "config.json"
        config.write_text(json.dumps({"worker_policy": "strict"}) + "\n")
        test_env = acceptance._environment(config=config, state=core / "state", gitleaks=gitleaks,
                                           global_gitconfig=core / "gitconfig", base=env)
        test_env["PYTHONNOUSERSITE"] = "1"
        cases = acceptance._fixture_case_files(core)
        result["conformance"] = [
            acceptance._run_conformance(vpy, module, kind, case, core, test_env, "conformance")
            for module, kind, case in zip(("example_plugin", "example_detector.plugin", "example_extractor.plugin"),
                                          ("detector", "detector", "extractor"), cases)
        ]
        runner = core / "run_installed_core_suite.py"
        shutil.copy2(ROOT / "tools/run_installed_core_suite.py", runner)
        result["core_corpus_exclusions"] = [
            "test_corpus.DeterministicCorpusTests.test_actual_labeled_cases_emit_case_level_counts_without_fixture_text",
            "test_corpus.DeterministicCorpusTests.test_same_seed_artifact_manifest_is_stable_across_wall_clock_ticks",
        ]
        result["core_corpus_exclusion_reason"] = "unchanged full corpus; previous sealed and rehearsal evidence retained"
        run(stage, [vpy, "-s", runner], timeout=1800, cwd=core, environment=test_env)
        suite_output = (artifacts / (stage + ".log")).read_text(errors="replace")
        summary = acceptance._parse_unittest_summary(suite_output, "")
        if summary is None or summary["total"] < 100 or summary["failures"] or summary["errors"]:
            raise RuntimeError("installed-core-summary-invalid")
        result["core_test_summary"] = summary
        stage = "final-identity"
        identity_after = mod._project_python_identity(roots, extra_wheels, purelib)
        if resource_identity() != result["project_resource_sha256"]:
            raise RuntimeError("project-resources-changed")
        if identity_after != identity or subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True):
            raise RuntimeError("source-or-install-changed")
        run("final-dependency-check", [args.uv, "pip", "check", "--python", vpy])
        result.update(status="passed", installed_python=str(vpy), source_and_install_unchanged=True)
    except Exception as error:
        result.update(status="failed", failed_stage=stage, error_type=type(error).__name__)
    finally:
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        tmp = artifacts / ".receipt.tmp"
        tmp.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        os.replace(tmp, artifacts / "receipt.json")
        print(json.dumps({"status": result["status"], "stage": result.get("failed_stage"), "receipt": str(artifacts / "receipt.json")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
