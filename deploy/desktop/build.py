#!/usr/bin/env python3
"""Build a standalone Password Buddy payload and Electron app without publishing."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import zipfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[1]
DESKTOP_VERSION = "0.1.0-alpha.1"
BACKEND_RELEASE = "desktop-0.1.0-alpha.1"
TARGETS = {"macos-arm64": ("darwin", "arm64", "3.11.16", "bin/python3"),
           "windows-x86_64": ("win32", "x64", "3.11.16", "python.exe"),
           "linux-x86_64": ("linux", "x64", "3.11.16", "bin/python3")}


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = load_module("desktop_bootstrap", HERE / "bootstrap.py")


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def run(command, cwd=SOURCE):
    subprocess.run(list(map(str, command)), cwd=cwd, check=True)


def clean_copy(source, destination):
    # Enumeration validates links before copytree follows no symlink at all.
    bootstrap.records(source)
    shutil.copytree(source, destination, symlinks=True)


def make_buddy_wheel(source, destination):
    """Construct a fresh PEP 427 pure wheel and RECORD from the declared package.

    No old wheel is modified. This project's only package data are static/*;
    reject layout/metadata changes rather than silently dropping new build rules.
    """
    project_root = source / "apps/buddy"
    project = tomllib.loads((project_root / "pyproject.toml").read_text())["project"]
    if project["name"] != "leakguard-buddy" or project["version"] != "0.1.0a2":
        raise ValueError("Integrated Buddy must declare version 0.1.0a2")
    package = project_root / "src/leakguard_buddy"
    if not (package / "desktop.py").is_file():
        raise ValueError("Integrated Buddy desktop entry point is absent")
    assets = package / "static"
    if {path.name for path in assets.iterdir() if path.is_file()} != {"index.html", "app.js", "app.css"}:
        raise ValueError("Production UI must contain exactly index.html/app.js/app.css")
    generated = source / "apps/buddy-ui/dist"
    if {path.name for path in generated.iterdir()} != {"index.html", "app.js", "app.css"}:
        raise ValueError("UI dist must contain exactly index.html/app.js/app.css")
    if any((generated / name).read_bytes() != (assets / name).read_bytes()
           for name in ("index.html", "app.js", "app.css")):
        raise ValueError("Packaged static files differ from the built UI; regenerate before packaging")
    html = (assets / "index.html").read_text()
    if html.count("__BUDDY_STYLE_NONCE__") != 1:
        raise ValueError("Production UI nonce sentinel is absent or repeated")
    files = {}
    for path in sorted(package.rglob("*")):
        if path.is_symlink():
            raise ValueError("Buddy package may not contain symlinks")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            files[path.relative_to(project_root / "src").as_posix()] = path.read_bytes()
    info = "leakguard_buddy-0.1.0a2.dist-info"
    metadata = ["Metadata-Version: 2.4", "Name: leakguard-buddy", "Version: 0.1.0a2",
                "Summary: " + project["description"], "Requires-Python: " + project["requires-python"]]
    metadata += ["Requires-Dist: " + value for value in project["dependencies"]]
    files[info + "/METADATA"] = ("\n".join(metadata) + "\n\n").encode()
    files[info + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: password-buddy-desktop-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files[info + "/entry_points.txt"] = ("[console_scripts]\n" + "\n".join(
        f"{name} = {value}" for name, value in sorted(project["scripts"].items())) + "\n").encode()
    files[info + "/top_level.txt"] = b"leakguard_buddy\n"
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, content in sorted(files.items()):
        hashed = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        writer.writerow([name, "sha256=" + hashed, len(content)])
    writer.writerow([info + "/RECORD", "", ""])
    files[info + "/RECORD"] = record.getvalue().encode()
    wheel = destination / "leakguard_buddy-0.1.0a2-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in sorted(files.items()):
            member = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, content)
    return wheel


def assemble(args):
    output = args.output.absolute()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory must be absent or empty; previous receipts are preserved")
    output.mkdir(parents=True, exist_ok=True)
    if subprocess.check_output(["node", "--version"], text=True).strip() != "v22.23.2":
        raise ValueError("Release tooling requires Node 22.23.2")
    if not args.skip_js_build:
        for project in (SOURCE / "apps/buddy-ui", SOURCE / "apps/desktop"):
            run(["npm", "ci", "--no-audit", "--no-fund"], project)
            run(["npm", "run", "build"], project)
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip()
    source_time = subprocess.check_output(["git", "show", "-s", "--format=%cI", "HEAD"], cwd=SOURCE, text=True).strip()
    # Generated output may be ignored by Git. Input file hashes below identify every byte.
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=SOURCE, text=True).strip():
        raise ValueError("Commit integrated inputs before packaging (working tree is dirty)")
    resources = output / "resources/buddy"
    resources.mkdir(parents=True)
    runtime_input = args.runtime_input.resolve(strict=True)
    backend_input = args.backend_input.resolve(strict=True)
    original_manifest = json.loads((backend_input / "release.json").read_text())
    installer = load_module("desktop_source_installer", backend_input / "deploy/installer.py")
    installer.validate_wheelhouse(backend_input, installer.read_manifest(backend_input / "release.json"))
    if original_manifest["target_platform"] != args.target:
        raise ValueError("Backend input targets a different platform")
    input_runtime_files = bootstrap.records(runtime_input)
    input_backend_files = bootstrap.records(backend_input)
    clean_copy(runtime_input, resources / "python")
    bundle = resources / "backend/LeakGuard"
    bundle.parent.mkdir()
    clean_copy(backend_input, bundle)
    shutil.copy2(HERE / "bootstrap.py", resources / "bootstrap.py")
    # The backend builder must rebuild every local product wheel from this
    # revision. Replacing only Buddy mislabels stale vault/host/scanner bytes.
    if original_manifest.get("source_commit") != source_commit:
        raise ValueError("Backend input must be built from the exact integrated commit")
    required = {"leakguard-core", "leakguard-buddy", "leakguard-host", "leakguard-vault",
                "leakguard-credential-detector", "leakguard-presidio-detector", "leakguard-jose-recognizers"}
    present = {item["name"].lower().replace("_", "-") for item in original_manifest["packages"]}
    if not required.issubset(present):
        raise ValueError("Backend input is missing required full-product packages")
    if original_manifest.get("target_python") != ".".join(TARGETS[args.target][2].split(".")[:2]):
        raise ValueError("Backend wheelhouse does not match bundled Python minor")
    # Retain the UI source-to-built-byte check for the freshly built Buddy wheel.
    with tempfile.TemporaryDirectory() as temp:
        expected_wheel = make_buddy_wheel(SOURCE, Path(temp))
        buddy = next(item for item in original_manifest["packages"] if item["name"] == "leakguard-buddy")
        with zipfile.ZipFile(expected_wheel) as expected, zipfile.ZipFile(bundle / "wheelhouse" / buddy["filename"]) as actual:
            for name in expected.namelist():
                if name.startswith("leakguard_buddy/") and actual.read(name) != expected.read(name):
                    raise ValueError("Buddy wheel differs from reviewed source/UI: " + name)
    release = original_manifest
    # ZIP extraction discarded alpha backend execute modes. Restore owned immutable payload.
    if args.target != "windows-x86_64":
        for item in release["backend_artifacts"]:
            (bundle / item["bundle_path"]).chmod(0o755)
        (bundle / "deploy/install.sh").chmod(0o755)
        executable = resources / "python" / TARGETS[args.target][3]
        executable.chmod(executable.stat().st_mode | 0o111)
    installer.validate_wheelhouse(bundle, installer.read_manifest(bundle / "release.json"))
    unchanged = release["packages"]
    for item in unchanged:
        if bootstrap.digest(bundle / "wheelhouse" / item["filename"]) != item["sha256"]:
            raise ValueError("An original backend wheel changed")
    provenance = {"schemaVersion": 1, "sourceCommit": source_commit,
                  "runtimeInput": {"directory": str(runtime_input), "files": input_runtime_files},
                  "backendInput": {"directory": str(backend_input), "files": input_backend_files,
                                   "releaseManifest": original_manifest},
                  "wheelBuild": {"method": "integrated-backend-build", "version": "0.1.0a2",
                                 "sha256": buddy["sha256"],
                                 "sourceFiles": [{"path": path.relative_to(SOURCE).as_posix(), "sha256": bootstrap.digest(path)}
                                                 for path in sorted((SOURCE / "apps/buddy").rglob("*"))
                                                 if path.is_file() and path.suffix in {".py", ".toml", ".html", ".js", ".css"}
                                                 and not any(part in {"build", "dist", "__pycache__", ".egg-info"} for part in path.parts)]},
                  "upstreamArchiveProvenance": None}
    if args.provenance:
        provenance["upstreamArchiveProvenance"] = json.loads(args.provenance.read_text())
    write_json(resources / "provenance.json", provenance)
    manifest = {"schemaVersion": 1, "desktopVersion": DESKTOP_VERSION, "protocolVersion": 1,
                "target": args.target, "pythonVersion": TARGETS[args.target][2],
                "pythonExecutable": "python/" + TARGETS[args.target][3], "backendBundle": "backend/LeakGuard",
                "backendRelease": BACKEND_RELEASE, "sourceCommit": source_commit, "files": bootstrap.records(resources)}
    manifest["runtimeId"] = bootstrap.runtime_identity(manifest)
    write_json(resources / "desktop-manifest.json", manifest)
    receipt = {"schemaVersion": 1, "target": args.target, "sourceCommit": source_commit,
               "runtimeId": manifest["runtimeId"], "resources": str(resources),
               "manifestSha256": bootstrap.digest(resources / "desktop-manifest.json"),
               "stageOnly": args.stage_only, "nativeAcceptance": "not-run", "signed": False}
    if not args.stage_only:
        run(["npm", "ci", "--no-audit", "--no-fund"], HERE)
        run(["node", HERE / "package.mjs", "--target", args.target, "--source", SOURCE / "apps/desktop",
             "--resources", resources, "--output", output / "apps"])
        app_paths = list((output / "apps").iterdir())
        if len(app_paths) != 1:
            raise ValueError("Packager returned an unexpected app directory set")
        app = app_paths[0]
        artifact = output / f"Password-Buddy-{DESKTOP_VERSION}-{args.target}.zip"
        app_bundle = app / "Password Buddy.app" if args.target == "macos-arm64" else app
        packaged_resources = (app_bundle / "Contents/Resources/buddy" if args.target == "macos-arm64"
                              else app_bundle / "resources/buddy")
        if bootstrap.records(packaged_resources) != manifest["files"]:
            raise ValueError("Packaged resource bytes or symlink targets differ from the sealed payload")
        zip_tree(app_bundle, artifact)
        app_files = {"sourceCommit": source_commit, "runtimeId": manifest["runtimeId"], "files": bootstrap.records(app_bundle)}
        write_json(output / "artifact-files.json", app_files)
        receipt.update(appDirectory=str(app_bundle), artifact=str(artifact), artifactSha256=bootstrap.digest(artifact),
                       appFilesSha256=bootstrap.digest(output / "artifact-files.json"),
                       artifactBytes=artifact.stat().st_size)
        if args.target == "windows-x86_64":
            receipt["nativeAcceptance"] = "native Windows unverified"
    write_json(output / "artifact-receipt.json", receipt)
    print(json.dumps(receipt, sort_keys=True))


def zip_tree(root, destination):
    """Unix ZIP attributes retain execute permissions and relative in-tree symlinks."""
    bootstrap.records(root)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root.parent).as_posix()
            if path.is_dir() and not path.is_symlink():
                continue
            info = zipfile.ZipInfo(relative, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = path.lstat().st_mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--runtime-input", type=Path, required=True)
    parser.add_argument("--backend-input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage-only", action="store_true")
    parser.add_argument("--skip-js-build", action="store_true", help="consume already built integrated shell/UI")
    parser.add_argument("--provenance", type=Path, help="JSON with original runtime/archive URL and hashes")
    args = parser.parse_args()
    try:
        assemble(args)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, bootstrap.PreparationError) as error:
        parser.exit(1, f"desktop-build: {error}\n")


if __name__ == "__main__":
    main()
