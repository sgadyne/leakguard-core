#!/usr/bin/env python3
"""Build a self-contained, hash-indexed offline LeakGuard release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zipfile import BadZipFile


ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wheel_identity(path: Path) -> tuple[str, str]:
    if path.suffix.lower() != ".whl":
        raise ValueError(f"not a wheel file: {path.name}")
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_files = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
            if len(metadata_files) != 1:
                raise ValueError(f"wheel must contain one METADATA file: {path.name}")
            metadata = archive.read(metadata_files[0]).decode("utf-8", "strict")
    except (BadZipFile, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid wheel archive: {path.name}") from exc
    fields: dict[str, str] = {}
    for line in metadata.splitlines():
        if not line or line[0].isspace():
            continue
        key, separator, value = line.partition(":")
        if separator and key in {"Name", "Version"}:
            if key in fields:
                raise ValueError(f"duplicate {key} in wheel metadata: {path.name}")
            fields[key] = value.strip()
    name, version = fields.get("Name"), fields.get("Version")
    if not name or not version or not PACKAGE_RE.fullmatch(name) or not VERSION_RE.fullmatch(version):
        raise ValueError(f"wheel has missing or invalid identity: {path.name}")
    return name, version


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def validate_commit(value: str) -> None:
    if value != "unknown" and not re.fullmatch(r"[0-9a-fA-F]{7,64}", value):
        raise ValueError("source commit must be a hexadecimal Git commit ID or 'unknown'")


def make_bundle(args: argparse.Namespace) -> Path:
    release_spec_path = args.release_manifest.resolve(strict=True)
    release_spec = json.loads(release_spec_path.read_text(encoding="utf-8"))
    if not isinstance(release_spec, dict) or release_spec.get("schema_version") != 1:
        raise ValueError("release manifest must use schema version 1")
    if release_spec.get("wheelhouse", "wheelhouse") != "wheelhouse":
        raise ValueError("offline bundles use the fixed wheelhouse/ directory")
    version = args.version or release_spec.get("release_version")
    if not isinstance(version, str):
        raise ValueError("release version is required in the release manifest or on the command line")
    if not VERSION_RE.fullmatch(version) or version in {".", ".."}:
        raise ValueError("invalid release version")
    validate_commit(args.source_commit)
    target_platform = args.target_platform
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", target_platform) or target_platform in {".", ".."}:
        raise ValueError("target platform must be a short OS-architecture label")
    target_python = args.target_python
    if not re.fullmatch(r"3\.[0-9]{1,2}", target_python):
        raise ValueError("target Python must be a major.minor version such as 3.11")
    if tuple(int(part) for part in target_python.split(".")) < (3, 11):
        raise ValueError("target Python must satisfy the release minimum of Python 3.11")
    current_python = f"{sys.version_info.major}.{sys.version_info.minor}"
    if target_python != current_python:
        raise ValueError(f"bundle builder is running Python {current_python}; run it under target Python {target_python}")
    backend_version = args.backend_version or release_spec.get("backend_version")
    if not isinstance(backend_version, str) or not VERSION_RE.fullmatch(backend_version):
        raise ValueError("release manifest must declare an exact backend_version")
    wheelhouse = args.wheelhouse.resolve(strict=True)
    if not wheelhouse.is_dir():
        raise ValueError("wheelhouse must be a directory")
    wheel_paths = sorted(wheelhouse.glob("*.whl"), key=lambda path: path.name.lower())
    if not wheel_paths:
        raise ValueError("wheelhouse contains no wheel artifacts")

    wheels: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in wheel_paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"wheelhouse entries must be regular files: {path.name}")
        name, wheel_version = wheel_identity(path)
        normalized = normalized_name(name)
        if normalized in seen:
            raise ValueError(f"wheelhouse contains more than one wheel for {name}")
        seen.add(normalized)
        wheels.append({
            "name": name,
            "version": wheel_version,
            "filename": path.name,
            "sha256": sha256_file(path),
        })

    pins = release_spec.get("pinned_distributions")
    if not isinstance(pins, dict) or not pins:
        raise ValueError("release manifest must list exact pinned_distributions")
    wheel_versions = {normalized_name(item["name"]): item["version"] for item in wheels}
    for name, pinned_version in pins.items():
        if not isinstance(name, str) or not PACKAGE_RE.fullmatch(name) or not isinstance(pinned_version, str):
            raise ValueError("invalid exact pin in release manifest")
        actual = wheel_versions.get(normalized_name(name))
        if actual is None:
            raise ValueError(f"wheelhouse is missing required distribution: {name}")
        if actual != pinned_version:
            raise ValueError(f"{name} must be exactly {pinned_version}; wheelhouse contains {actual}")
    for value in args.require_package:
        if normalized_name(value) not in seen:
            raise ValueError(f"wheelhouse is missing required distribution: {value}")
    service_command = args.service_command or release_spec.get("service_command") or ["leakguard-buddy"]
    if not all(isinstance(item, str) and item and "\x00" not in item for item in service_command):
        raise ValueError("service command must contain non-empty text arguments")

    backend_artifacts: list[dict[str, str]] = []
    backend_destinations: set[tuple[str, str]] = set()
    for spec in args.backend_artifact:
        target, separator, raw_path = spec.partition("=")
        platform_name, slash, artifact_name = target.partition("/")
        if (not separator or not slash or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", platform_name)
                or platform_name in {".", ".."}
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", artifact_name)
                or artifact_name in {".", ".."}):
            raise ValueError("backend artifacts use PLATFORM/NAME=PATH")
        source_arg = Path(raw_path).expanduser()
        if source_arg.is_symlink() or not source_arg.is_file():
            raise ValueError(f"backend artifact must be a regular file: {source_arg}")
        source = source_arg.resolve(strict=True)
        if source.stat().st_size > 256 * 1024 * 1024:
            raise ValueError("backend artifact exceeds the 256 MiB archive member limit")
        key = (platform_name, artifact_name)
        if key in backend_destinations:
            raise ValueError(f"duplicate backend artifact target: {target}")
        backend_destinations.add(key)
        backend_artifacts.append({"platform": platform_name, "filename": artifact_name,
                                  "bundle_path": f"backends/{platform_name}/{artifact_name}",
                                  "sha256": sha256_file(source), "source_path": str(source)})

    target_backends = [item for item in backend_artifacts if item["platform"] == target_platform]
    if any(item["platform"] != target_platform for item in backend_artifacts):
        raise ValueError("a target-platform bundle may contain backend artifacts only for that platform")
    expected_backend_name = "gitleaks.exe" if target_platform.lower().startswith("windows-") else "gitleaks"
    if target_backends:
        if len(target_backends) != 1 or target_backends[0]["filename"] != expected_backend_name:
            raise ValueError(f"target bundle backend must be exactly {expected_backend_name}")
    elif not args.partial:
        raise ValueError("a complete release requires the target platform's pinned Gitleaks executable; use --partial only for an explicitly incomplete target")

    if len(wheels) + len(backend_artifacts) + 6 > 1000:
        raise ValueError("bundle would exceed the installer 1,000-member limit")
    uncompressed_bytes = sum(path.stat().st_size for path in wheel_paths)
    uncompressed_bytes += sum(Path(item["source_path"]).stat().st_size for item in backend_artifacts)
    uncompressed_bytes += sum((ROOT / "deploy" / filename).stat().st_size
                              for filename in ("installer.py", "install.sh", "install.ps1", "default-config.json"))
    uncompressed_bytes += release_spec_path.stat().st_size
    if any(path.stat().st_size > 256 * 1024 * 1024 for path in wheel_paths):
        raise ValueError("a wheel exceeds the 256 MiB archive member limit")
    if uncompressed_bytes > 1024 * 1024 * 1024:
        raise ValueError("bundle would exceed the installer 1 GiB uncompressed size limit")

    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing bundle: {output}")
    with tempfile.TemporaryDirectory(prefix="leakguard-bundle-", dir=output.parent) as temp:
        stage = Path(temp) / "LeakGuard"
        stage.mkdir(mode=0o700)
        (stage / "wheelhouse").mkdir(mode=0o700)
        (stage / "deploy").mkdir(mode=0o700)
        if backend_artifacts:
            (stage / "backends").mkdir(mode=0o700)
        for record in wheels:
            shutil.copyfile(wheelhouse / record["filename"], stage / "wheelhouse" / record["filename"])
        for filename in ("installer.py", "install.sh", "install.ps1", "default-config.json"):
            shutil.copyfile(ROOT / "deploy" / filename, stage / "deploy" / filename)
        shutil.copyfile(release_spec_path, stage / "deploy" / "release-manifest.json")
        for artifact in backend_artifacts:
            destination = stage / artifact["bundle_path"]
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(artifact["source_path"], destination)
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "release_version": version,
            "source_commit": args.source_commit.lower(),
            "target_platform": target_platform,
            "target_python": target_python,
            "release_quality": "partial" if not target_backends else "complete",
            "backend_version": backend_version,
            "source_manifest_sha256": sha256_file(release_spec_path),
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "python_requires": release_spec.get("python_requires", ">=3.11"),
            "wheelhouse": release_spec.get("wheelhouse", "wheelhouse"),
            "default_config_sha256": sha256_file(ROOT / "deploy" / "default-config.json"),
            "pinned_distributions": pins,
            "packages": wheels,
            "backend_artifacts": [{key: value for key, value in artifact.items() if key != "source_path"}
                                  for artifact in backend_artifacts],
            "buddy_command": args.buddy_command or release_spec.get("buddy_command", "leakguard-buddy"),
            "service_command": service_command,
        }
        (stage / "release.json").write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        temp_output = output.with_name(output.name + ".tmp")
        try:
            with zipfile.ZipFile(temp_output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for path in sorted(stage.rglob("*")):
                    if path.is_file():
                        archive.write(path, Path("LeakGuard") / path.relative_to(stage))
            os.replace(temp_output, output)
        finally:
            temp_output.unlink(missing_ok=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True, help="directory containing the exact release wheels")
    parser.add_argument("--output", type=Path, required=True, help="new .zip file to create")
    parser.add_argument("--release-manifest", type=Path, default=ROOT / "deploy" / "release-manifest.json")
    parser.add_argument("--version", help="release version label (defaults to the checked-in manifest)")
    parser.add_argument("--source-commit", required=True, help="integrated source commit ID")
    parser.add_argument("--target-platform", required=True, help="target OS-architecture label, e.g. linux-x86_64 or macos-arm64")
    parser.add_argument("--target-python", required=True, help="exact Python major.minor used for this wheelhouse, e.g. 3.11")
    parser.add_argument("--backend-version", help="exact Gitleaks version (defaults to checked-in manifest)")
    parser.add_argument("--partial", action="store_true", help="allow an explicitly incomplete release without a native Gitleaks backend")
    parser.add_argument("--require-package", action="append", default=[], metavar="NAME", help="require a distribution in the wheelhouse; repeat as needed")
    parser.add_argument("--buddy-command", help="installed UI console command (defaults to the checked-in manifest)")
    parser.add_argument("--service-command", action="append", default=[], metavar="ARG", help="service argv element; repeat in order")
    parser.add_argument("--backend-artifact", action="append", default=[], metavar="PLATFORM/NAME=PATH",
                        help="include a backend binary with its platform and SHA-256 recorded; repeat as needed")
    args = parser.parse_args()
    try:
        bundle = make_bundle(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"bundle failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"bundle": str(bundle), "sha256": sha256_file(bundle)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
