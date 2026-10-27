#!/usr/bin/env python3
"""Install and manage a private LeakGuard release from an offline bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import PurePosixPath, PureWindowsPath
from pathlib import Path
from typing import Any, Sequence


VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
MANIFEST_NAME = "release.json"
ACTIVE_NAME = "active.json"
MANAGED_FILES = ("installer.py", "install.sh", "install.ps1", "default-config.json")
MAX_BUNDLE_MEMBERS = 1000
MAX_BUNDLE_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_BUNDLE_MEMBER_BYTES = 256 * 1024 * 1024
MAX_SUPPORT_FILES = 128
MAX_SUPPORT_FILE_BYTES = 8 * 1024 * 1024


class DeployError(RuntimeError):
    pass


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)


def _atomic_json(path: Path, value: Any) -> None:
    _private_mkdir(path.parent)
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temp.chmod(0o600)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def data_root() -> Path:
    override = os.environ.get("LEAKGUARD_INSTALL_ROOT")
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise DeployError("LEAKGUARD_INSTALL_ROOT must be an absolute path")
        return path
    return default_data_root()


def default_data_root() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise DeployError("LOCALAPPDATA is unavailable; install requires a per-user Windows profile")
        return Path(base) / "LeakGuard"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "LeakGuard"
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    if not base.is_absolute():
        raise DeployError("XDG_DATA_HOME must be an absolute path")
    return base / "leakguard"


def state_root() -> Path:
    override = os.environ.get("LEAKGUARD_STATE_DIR")
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise DeployError("LEAKGUARD_STATE_DIR must be an absolute path")
        return path
    configured = _active_state_dir(data_root())
    if configured:
        return configured
    if os.environ.get("LEAKGUARD_INSTALL_ROOT"):
        return data_root() / "state"
    if os.name == "nt":
        return data_root() / "state"
    if sys.platform == "darwin":
        return data_root() / "state"
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "state"
    if not base.is_absolute():
        raise DeployError("XDG_STATE_HOME must be an absolute path")
    return base / "leakguard"


def bin_root() -> Path:
    override = os.environ.get("LEAKGUARD_BIN_DIR")
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise DeployError("LEAKGUARD_BIN_DIR must be an absolute path")
        return path
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise DeployError("LOCALAPPDATA is unavailable")
        return Path(base) / "LeakGuard" / "bin"
    if sys.platform == "darwin":
        return Path.home() / ".local" / "bin"
    xdg = os.environ.get("XDG_BIN_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "bin"
    if not base.is_absolute():
        raise DeployError("XDG_BIN_HOME must be an absolute path")
    return base


def read_manifest(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            raise DeployError("release manifest is a symlink or exceeds the 4 MiB limit")
        data = json.loads(path.read_text(encoding="utf-8"))
    except DeployError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError(f"cannot read release manifest: {path}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise DeployError("unsupported release manifest")
    version = data.get("release_version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version) or version in {".", ".."}:
        raise DeployError("invalid release version in manifest")
    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        raise DeployError("release manifest has no package wheel list")
    seen: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise DeployError("invalid package item in release manifest")
        name, package_version = package.get("name"), package.get("version")
        filename, digest = package.get("filename"), package.get("sha256")
        if not isinstance(name, str) or not PACKAGE_RE.fullmatch(name):
            raise DeployError("invalid package name in release manifest")
        if not isinstance(package_version, str) or not VERSION_RE.fullmatch(package_version):
            raise DeployError(f"invalid version for package {name}")
        if normalized_name(name) in seen:
            raise DeployError(f"duplicate package in release manifest: {name}")
        seen.add(normalized_name(name))
        if (not isinstance(filename, str) or Path(filename).name != filename
                or PureWindowsPath(filename).name != filename or "\\" in filename or not filename.endswith(".whl")):
            raise DeployError(f"invalid wheel filename for {name}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise DeployError(f"invalid wheel hash for {name}")
    source_commit = data.get("source_commit", "unknown")
    if not isinstance(source_commit, str) or (source_commit != "unknown" and not re.fullmatch(r"[0-9a-fA-F]{7,64}", source_commit)):
        raise DeployError("invalid source commit in release manifest")
    if not isinstance(data.get("buddy_command", "leakguard-buddy"), str):
        raise DeployError("invalid Buddy command in manifest")
    support_files = data.get("support_files", [])
    if not isinstance(support_files, list) or len(support_files) > MAX_SUPPORT_FILES:
        raise DeployError("release manifest has an invalid support file list")
    support_paths: set[str] = set()
    for item in support_files:
        if not isinstance(item, dict):
            raise DeployError("release manifest has an invalid support file record")
        relative, digest = item.get("path"), item.get("sha256")
        if not isinstance(relative, str):
            raise DeployError("release manifest has an invalid support path")
        posix = PurePosixPath(relative)
        windows = PureWindowsPath(relative)
        if (posix.is_absolute() or windows.is_absolute() or windows.drive or "\\" in relative
                or "\x00" in relative or not posix.parts or posix.parts[0] != "support"
                or any(part in {"", ".", ".."} for part in posix.parts)
                or posix.as_posix() != relative):
            raise DeployError("release manifest has an unsafe support file path")
        key = relative.casefold()
        if key in support_paths:
            raise DeployError("release manifest has duplicate support file paths")
        support_paths.add(key)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise DeployError("release manifest has an invalid support file hash")
    service_command = data.get("service_command", [])
    if not isinstance(service_command, list) or not all(isinstance(item, str) and item and "\x00" not in item for item in service_command):
        raise DeployError("invalid service command in manifest")
    if data.get("wheelhouse", "wheelhouse") != "wheelhouse":
        raise DeployError("unsupported wheelhouse directory in release manifest")
    target_platform = data.get("target_platform")
    target_python = data.get("target_python")
    quality = data.get("release_quality")
    backend_version = data.get("backend_version")
    if (not isinstance(target_platform, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", target_platform)
            or target_platform in {".", ".."}):
        raise DeployError("release manifest has no valid target platform")
    if not isinstance(target_python, str) or not re.fullmatch(r"3\.[0-9]{1,2}", target_python):
        raise DeployError("release manifest has no valid target Python version")
    if quality not in {"complete", "partial"}:
        raise DeployError("release manifest has invalid release quality")
    if not isinstance(backend_version, str) or not VERSION_RE.fullmatch(backend_version):
        raise DeployError("release manifest has no exact backend version")
    return data


def find_bundle_root(path: Path) -> Path:
    path = path.expanduser().resolve(strict=True)
    if path.is_file():
        if path.suffix.lower() != ".zip":
            raise DeployError("bundle must be an extracted directory or .zip archive")
        temp = Path(tempfile.mkdtemp(prefix="leakguard-bundle-"))
        try:
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > MAX_BUNDLE_MEMBERS:
                    raise DeployError("bundle archive has too many members")
                total_size = 0
                seen: set[str] = set()
                root = temp.resolve()
                for item in members:
                    name = item.filename
                    posix_name = PurePosixPath(name)
                    windows_name = PureWindowsPath(name)
                    if (not name or not posix_name.parts or "\x00" in name or "\\" in name or posix_name.is_absolute()
                            or windows_name.is_absolute() or windows_name.drive or ".." in posix_name.parts):
                        raise DeployError("bundle archive contains an unsafe path")
                    key = "/".join(posix_name.parts).casefold()
                    if key in {"", ".", ".."} or key in seen:
                        raise DeployError("bundle archive contains duplicate or empty member paths")
                    seen.add(key)
                    mode = item.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise DeployError("bundle archive may not contain symbolic links")
                    if mode and stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                        raise DeployError("bundle archive may contain only regular files and directories")
                    if item.flag_bits & 0x1:
                        raise DeployError("encrypted bundle members are not supported")
                    if item.file_size > MAX_BUNDLE_MEMBER_BYTES:
                        raise DeployError("bundle archive contains a member larger than 256 MiB")
                    target = (temp / Path(*posix_name.parts)).resolve()
                    if root not in target.parents and target != root:
                        raise DeployError("bundle archive contains an unsafe path")
                    total_size += item.file_size
                    if total_size > MAX_BUNDLE_UNCOMPRESSED_BYTES:
                        raise DeployError("bundle archive exceeds the 1 GiB uncompressed size limit")
                archive.extractall(temp)
        except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
            shutil.rmtree(temp, ignore_errors=True)
            raise DeployError("cannot extract release bundle") from exc
        except BaseException:
            shutil.rmtree(temp, ignore_errors=True)
            raise
        children = list(temp.iterdir())
        if len(children) == 1 and children[0].is_dir():
            return children[0]
        return temp
    return path


def _bundle_child(bundle: Path, relative: Path) -> Path:
    root = bundle.resolve()
    path = root / relative
    current = path
    while current != root and root in current.parents:
        if current.is_symlink():
            raise DeployError("release bundle may not contain symbolic links")
        current = current.parent
    if current != root:
        raise DeployError("release artifact path escapes the bundle directory")
    return bundle / relative


def validate_wheelhouse(bundle: Path, manifest: dict[str, Any]) -> list[Path]:
    source_manifest_hash = manifest.get("source_manifest_sha256")
    source_manifest = _bundle_child(bundle, Path("deploy/release-manifest.json"))
    if not isinstance(source_manifest_hash, str) or not SHA256_RE.fullmatch(source_manifest_hash):
        raise DeployError("release manifest has no valid source manifest hash")
    if not source_manifest.is_file() or sha256_file(source_manifest) != source_manifest_hash:
        raise DeployError("source release manifest is missing or its SHA-256 does not match")
    default_config = _bundle_child(bundle, Path("deploy/default-config.json"))
    config_hash = manifest.get("default_config_sha256")
    if not isinstance(config_hash, str) or not SHA256_RE.fullmatch(config_hash):
        raise DeployError("release manifest has no valid default configuration hash")
    if not default_config.is_file() or sha256_file(default_config) != config_hash:
        raise DeployError("default runtime config is missing or its SHA-256 does not match")
    folder = manifest.get("wheelhouse", "wheelhouse")
    if (not isinstance(folder, str) or Path(folder).is_absolute() or PureWindowsPath(folder).is_absolute()
            or PureWindowsPath(folder).drive or "\\" in folder or Path(folder).name != folder
            or folder in {".", ".."}):
        raise DeployError("unsafe wheelhouse path")
    wheelhouse = _bundle_child(bundle, Path(folder))
    if not wheelhouse.is_dir():
        raise DeployError("release bundle is missing its wheelhouse")
    for filename in MANAGED_FILES + ("release-manifest.json",):
        managed = _bundle_child(bundle, Path("deploy") / filename)
        if not managed.is_file():
            raise DeployError(f"release bundle is missing deploy/{filename}")
    verified: list[Path] = []
    for item in manifest["packages"]:
        path = _bundle_child(bundle, Path(folder) / item["filename"])
        if not path.is_file() or path.is_symlink():
            raise DeployError(f"release wheel is missing: {item['filename']}")
        if sha256_file(path) != item["sha256"]:
            raise DeployError(f"release wheel hash mismatch: {item['filename']}")
        try:
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if len(members) > 100_000:
                    raise DeployError(f"wheel has too many members: {item['filename']}")
                metadata_files = [info for info in members if info.filename.endswith(".dist-info/METADATA")]
                if len(metadata_files) != 1 or metadata_files[0].file_size > 1024 * 1024:
                    raise DeployError(f"wheel metadata is ambiguous: {item['filename']}")
                metadata = archive.read(metadata_files[0]).decode("utf-8", "strict")
        except (OSError, zipfile.BadZipFile, UnicodeDecodeError) as exc:
            raise DeployError(f"wheel metadata is invalid: {item['filename']}") from exc
        fields: dict[str, str] = {}
        for line in metadata.splitlines():
            if line and not line[0].isspace():
                key, separator, value = line.partition(":")
                if separator and key in {"Name", "Version"}:
                    if key in fields:
                        raise DeployError(f"wheel metadata repeats {key}: {item['filename']}")
                    fields[key] = value.strip()
        if normalized_name(fields.get("Name", "")) != normalized_name(item["name"]) or fields.get("Version") != item["version"]:
            raise DeployError(f"wheel identity does not match the release manifest: {item['filename']}")
        verified.append(path)
    validate_support_files(bundle, manifest)
    pins = manifest.get("pinned_distributions", {})
    if not isinstance(pins, dict):
        raise DeployError("release manifest has invalid exact pins")
    versions = {normalized_name(item["name"]): item["version"] for item in manifest["packages"]}
    for name, version in pins.items():
        if not isinstance(name, str) or not isinstance(version, str) or versions.get(normalized_name(name)) != version:
            raise DeployError(f"release package closure violates exact pin: {name}")
    backend_artifacts = manifest.get("backend_artifacts", [])
    if not isinstance(backend_artifacts, list):
        raise DeployError("release manifest has invalid backend artifacts")
    backend_destinations: set[str] = set()
    target_backend_count = 0
    for artifact in backend_artifacts:
        if not isinstance(artifact, dict):
            raise DeployError("release manifest has invalid backend artifact")
        platform_name = artifact.get("platform")
        filename = artifact.get("filename")
        relative = artifact.get("bundle_path")
        digest = artifact.get("sha256")
        if (not isinstance(platform_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", platform_name)
                or platform_name in {".", ".."}
                or not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", filename)
                or filename in {".", ".."}):
            raise DeployError("release manifest has invalid backend artifact identity")
        expected_relative = f"backends/{platform_name}/{filename}"
        if (not isinstance(relative, str) or relative != expected_relative
                or Path(relative).parts != ("backends", platform_name, filename)):
            raise DeployError("release manifest has unsafe backend artifact path")
        if relative.casefold() in backend_destinations:
            raise DeployError("release manifest has duplicate backend artifact paths")
        backend_destinations.add(relative.casefold())
        if platform_name == manifest["target_platform"]:
            expected_name = "gitleaks.exe" if platform_name.startswith("windows-") else "gitleaks"
            if filename != expected_name:
                raise DeployError("target release includes an unexpected backend executable name")
            target_backend_count += 1
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise DeployError("release manifest has invalid backend artifact hash")
        path = _bundle_child(bundle, Path(relative))
        if path.is_symlink() or not path.is_file() or sha256_file(path) != digest:
            raise DeployError("backend artifact is missing or its SHA-256 does not match")
    if any(item.get("platform") != manifest["target_platform"] for item in backend_artifacts):
        raise DeployError("release bundle contains a backend for a different target platform")
    if target_backend_count > 1 or (manifest["release_quality"] == "complete") != (target_backend_count == 1):
        raise DeployError("release quality does not match its target Gitleaks backend artifacts")
    return verified


def validate_support_files(bundle: Path, manifest: dict[str, Any]) -> list[tuple[Path, Path]]:
    verified: list[tuple[Path, Path]] = []
    records = manifest.get("support_files", [])
    total_size = 0
    for item in records:
        relative = Path(*PurePosixPath(item["path"]).parts)
        source = _bundle_child(bundle, relative)
        if source.is_symlink() or not source.is_file():
            raise DeployError("release support file is missing or is a symbolic link")
        size = source.stat().st_size
        if size > MAX_SUPPORT_FILE_BYTES:
            raise DeployError("release support file exceeds the 8 MiB limit")
        total_size += size
        if total_size > MAX_SUPPORT_FILE_BYTES * MAX_SUPPORT_FILES:
            raise DeployError("release support files exceed the aggregate size limit")
        if sha256_file(source) != item["sha256"]:
            raise DeployError("release support file hash mismatch")
        verified.append((source, relative))
    return verified


def python_for_release(release: Path) -> Path:
    if os.name == "nt":
        return release / "venv" / "Scripts" / "python.exe"
    return release / "venv" / "bin" / "python"


def _platform_label(system: str | None = None, machine: str | None = None) -> str:
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    os_name = {"darwin": "macos", "macos": "macos", "windows": "windows", "linux": "linux"}.get(system)
    arch = {"amd64": "x86_64", "x64": "x86_64", "x86_64": "x86_64",
            "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if not os_name or not arch:
        raise DeployError("this release does not identify the current operating system and CPU architecture")
    return f"{os_name}-{arch}"


def _release_complete(release: Path, version: str | None = None) -> bool:
    marker = release / ".leakguard-release.json"
    try:
        if release.is_symlink() or marker.is_symlink() or not marker.is_file():
            return False
        value = json.loads(marker.read_text(encoding="utf-8"))
        if (not isinstance(value, dict) or value.get("schema_version") != 1
                or value.get("complete") is not True):
            return False
        manifest = read_manifest(release / MANIFEST_NAME)
        return manifest["release_version"] == value.get("release_version") and (version is None or version == value.get("release_version"))
    except (OSError, json.JSONDecodeError, DeployError):
        return False


def active_version(root: Path) -> str | None:
    marker = root / ACTIVE_NAME
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError("active release record is unreadable") from exc
    version = value.get("active_version") if isinstance(value, dict) else None
    if version is not None and (not isinstance(version, str) or not VERSION_RE.fullmatch(version)):
        raise DeployError("active release record is invalid")
    return version


def _active_record(root: Path) -> dict[str, Any]:
    try:
        value = json.loads((root / ACTIVE_NAME).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise DeployError("active release record is unreadable") from exc
    if not isinstance(value, dict):
        raise DeployError("active release record is invalid")
    return value


def _active_state_dir(root: Path) -> Path | None:
    value = _active_record(root)
    raw = value.get("state_dir") if isinstance(value, dict) else None
    if raw is None:
        return None
    if not isinstance(raw, str) or not Path(raw).is_absolute():
        raise DeployError("active release has an invalid state directory")
    return Path(raw)


def _script_path(release: Path, command: str) -> Path:
    if os.name == "nt":
        return release / "venv" / "Scripts" / (command + ".exe")
    return release / "venv" / "bin" / command


def _quote_sh(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def write_launchers(root: Path, version: str, manifest: dict[str, Any], state: Path, *, external: bool) -> None:
    release = root / "releases" / version
    launcher_root = bin_root() if external else root / "bin"
    launcher_root.mkdir(parents=True, exist_ok=True)
    command = manifest.get("buddy_command", "leakguard-buddy")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", command):
        raise DeployError("unsafe Buddy command name")
    buddy = _script_path(release, command)
    installer_python = python_for_release(release)
    deploy_script = release / "deploy" / "installer.py"
    config_path = state / "config.json"
    if not buddy.is_file() or not installer_python.is_file() or not deploy_script.is_file():
        raise DeployError("installed release is missing a launcher or management runtime")
    if os.name == "nt":
        launcher = launcher_root / "LeakGuard Buddy.cmd"
        launcher.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{buddy}" %*\r\n', encoding="utf-8")
        manager = launcher_root / "leakguard-install.cmd"
        manager.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{installer_python}" "{deploy_script}" %*\r\n', encoding="utf-8")
        doctor = launcher_root / "leakguard-doctor.cmd"
        doctor.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{installer_python}" "{deploy_script}" doctor %*\r\n', encoding="utf-8")
        open_shortcut = launcher_root / "LeakGuard Buddy Open.cmd"
        open_shortcut.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{buddy}" open --state-dir "{state}" %*\r\n', encoding="utf-8")
        cli = _script_path(release, "leakguard")
        if cli.is_file():
            cli_wrapper = launcher_root / "leakguard.cmd"
            cli_wrapper.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{cli}" %*\r\n', encoding="utf-8")
        if external:
            start = Path(os.environ.get("APPDATA", str(Path.home()))) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "LeakGuard Buddy.cmd"
            start.parent.mkdir(parents=True, exist_ok=True)
            start.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{buddy}" %*\r\n', encoding="utf-8")
            start_open = start.with_name("LeakGuard Buddy Open.cmd")
            start_open.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{buddy}" open --state-dir "{state}" %*\r\n', encoding="utf-8")
            start_doctor = start.with_name("LeakGuard Doctor.cmd")
            start_doctor.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{installer_python}" "{deploy_script}" doctor %*\r\n', encoding="utf-8")
            start_manage = start.with_name("LeakGuard Manage.cmd")
            start_manage.write_text(f'@echo off\r\nset "LEAKGUARD_INSTALL_ROOT={root}"\r\nset "LEAKGUARD_STATE_DIR={state}"\r\nset "LEAKGUARD_CONFIG={config_path}"\r\n"{installer_python}" "{deploy_script}" %*\r\n', encoding="utf-8")
    else:
        launcher = launcher_root / "leakguard-buddy"
        launcher.write_text(
            "#!/bin/sh\nexport LEAKGUARD_INSTALL_ROOT=" + _quote_sh(str(root)) + "\n"
            "export LEAKGUARD_STATE_DIR=" + _quote_sh(str(state)) + "\nexport LEAKGUARD_CONFIG=" + _quote_sh(str(config_path)) + "\nexec " + _quote_sh(str(buddy)) + ' "$@"\n', encoding="utf-8"
        )
        os.chmod(launcher, 0o700)
        cli = _script_path(release, "leakguard")
        if cli.is_file():
            cli_wrapper = launcher_root / "leakguard"
            cli_wrapper.write_text(
                "#!/bin/sh\nexport LEAKGUARD_INSTALL_ROOT=" + _quote_sh(str(root)) + "\n"
                "export LEAKGUARD_STATE_DIR=" + _quote_sh(str(state)) + "\nexport LEAKGUARD_CONFIG=" + _quote_sh(str(config_path)) + "\nexec " + _quote_sh(str(cli)) + ' "$@"\n',
                encoding="utf-8",
            )
            os.chmod(cli_wrapper, 0o700)
        manager = launcher_root / "leakguard-install"
        manager.write_text(
            "#!/bin/sh\nexport LEAKGUARD_INSTALL_ROOT=" + _quote_sh(str(root)) + "\n"
            "export LEAKGUARD_STATE_DIR=" + _quote_sh(str(state)) + "\nexport LEAKGUARD_CONFIG=" + _quote_sh(str(config_path)) + "\nexec " + _quote_sh(str(installer_python)) + " " + _quote_sh(str(deploy_script)) + ' "$@"\n',
            encoding="utf-8",
        )
        os.chmod(manager, 0o700)
        doctor = launcher_root / "leakguard-doctor"
        doctor.write_text(
            "#!/bin/sh\nexport LEAKGUARD_INSTALL_ROOT=" + _quote_sh(str(root)) + "\n"
            "export LEAKGUARD_STATE_DIR=" + _quote_sh(str(state)) + "\nexport LEAKGUARD_CONFIG=" + _quote_sh(str(config_path)) + "\nexec " + _quote_sh(str(installer_python)) + " " + _quote_sh(str(deploy_script)) + " doctor \"$@\"\n",
            encoding="utf-8",
        )
        os.chmod(doctor, 0o700)
        open_shortcut = launcher_root / "leakguard-buddy-open"
        open_shortcut.write_text(
            "#!/bin/sh\nexport LEAKGUARD_INSTALL_ROOT=" + _quote_sh(str(root)) + "\n"
            "export LEAKGUARD_STATE_DIR=" + _quote_sh(str(state)) + "\nexport LEAKGUARD_CONFIG=" + _quote_sh(str(config_path)) + "\nexec " + _quote_sh(str(buddy)) + " open --state-dir " + _quote_sh(str(state)) + " --config " + _quote_sh(str(config_path)) + ' "$@"\n',
            encoding="utf-8",
        )
        os.chmod(open_shortcut, 0o700)
        if external:
            applications = Path.home() / ".local" / "share" / "applications"
            applications.mkdir(parents=True, exist_ok=True)
            desktop = applications / "leakguard-buddy.desktop"
            desktop.write_text(
                "[Desktop Entry]\nType=Application\nName=LeakGuard Buddy\nComment=Local secret scanning and review\n"
                f'Exec="{launcher}"\nTerminal=false\nCategories=Utility;Security;\n',
                encoding="utf-8",
            )
            os.chmod(desktop, 0o600)
            open_desktop = applications / "leakguard-buddy-open.desktop"
            open_desktop.write_text(
                "[Desktop Entry]\nType=Application\nName=LeakGuard Buddy Open\nComment=Open the running LeakGuard Buddy session\n"
                f'Exec="{open_shortcut}"\nTerminal=false\nCategories=Utility;Security;\n',
                encoding="utf-8",
            )
            os.chmod(open_desktop, 0o600)
    if os.name != "nt":
        launcher.chmod(0o700)
        manager.chmod(0o700)
        doctor.chmod(0o700)
        open_shortcut.chmod(0o700)


def _run(argv: Sequence[str], *, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    if not argv or not all(isinstance(item, str) and "\x00" not in item for item in argv):
        raise DeployError("invalid command returned by the service adapter")
    try:
        result = subprocess.run(list(argv), text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeployError(f"could not execute platform command: {argv[0]}") from exc
    if check and result.returncode:
        message = (result.stderr or result.stdout).strip()
        raise DeployError(f"platform command failed ({result.returncode}): {message[:400]}")
    return result


def _expected_backend_path(release: Path, manifest: dict[str, Any]) -> Path:
    filename = "gitleaks.exe" if manifest["target_platform"].startswith("windows-") else "gitleaks"
    return release / "backends" / manifest["target_platform"] / filename


def _check_backend_runtime(release: Path, manifest: dict[str, Any], *, required: bool) -> tuple[bool, str]:
    backend = _expected_backend_path(release, manifest)
    records = manifest.get("backend_artifacts", [])
    record = next((item for item in records if item.get("platform") == manifest["target_platform"]), None)
    if record is None or not backend.is_file():
        if required:
            raise DeployError("complete release is missing its selected Gitleaks backend")
        return False, "backend not included in partial release"
    if sha256_file(backend) != record.get("sha256"):
        raise DeployError("installed Gitleaks backend hash does not match the release manifest")
    if os.name != "nt" and not os.access(backend, os.X_OK):
        raise DeployError("installed Gitleaks backend is not executable")
    try:
        result = subprocess.run([str(backend), "version"], text=True, capture_output=True,
                                timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeployError("installed Gitleaks backend could not report its version") from exc
    output = (result.stdout or "") + "\n" + (result.stderr or "")
    if result.returncode != 0 or not re.search(r"(?<![0-9.])" + re.escape(manifest["backend_version"]) + r"(?![0-9.])", output):
        raise DeployError("installed Gitleaks backend version does not match the release manifest")
    return True, "selected backend hash and version verified"


def _buddy_start_smoke(release: Path, manifest: dict[str, Any]) -> None:
    buddy = _script_path(release, manifest.get("buddy_command", "leakguard-buddy"))
    if not buddy.is_file():
        raise DeployError("installed Buddy console entrypoint is missing")
    _run([str(buddy), "--help"], timeout=30)
    core_cli = _script_path(release, "leakguard")
    if core_cli.is_file():
        _run([str(core_cli), "--help"], timeout=30)
    with tempfile.TemporaryDirectory(prefix="leakguard-start-smoke-") as temporary:
        scratch = Path(temporary)
        state = scratch / "state"
        _private_mkdir(state)
        config = json.loads((release / "deploy" / "default-config.json").read_text(encoding="utf-8"))
        config["observation_backend"] = "encrypted"
        config["observation_path"] = str(state / "observations.lgo")
        config["gitleaks_executable"] = str(release / "backends" / manifest["target_platform"] /
                                                ("gitleaks.exe" if manifest["target_platform"].startswith("windows-") else "gitleaks"))
        config_path = scratch / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        argv = [str(buddy), "--no-browser", "--state-dir", str(state), "--config", str(config_path)]
        try:
            child = subprocess.Popen(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            timed_out = False
            try:
                stdout, _stderr = child.communicate(timeout=7)
            except subprocess.TimeoutExpired:
                timed_out = True
                child.kill()
                stdout, _stderr = child.communicate(timeout=3)
        except OSError as exc:
            raise DeployError("installed Buddy could not start in its loopback smoke check") from exc
        marker = re.compile(r"Password Buddy listening at http://127\.0\.0\.1:\d+")
        if not marker.search(stdout or "") or (not timed_out and child.returncode not in (0, None)):
            # Do not surface captured process output: it can contain bootstrap
            # material if a future UI accidentally changes its startup logging.
            raise DeployError("installed Buddy did not report its loopback startup marker")


def _build_release(bundle: Path, release: Path, manifest: dict[str, Any], wheels: list[Path]) -> None:
    if release.is_symlink():
        raise DeployError("versioned release path may not be a symbolic link")
    _private_mkdir(release)
    try:
        _private_mkdir(release / "deploy")
        shutil.copy2(_bundle_child(bundle, Path(MANIFEST_NAME)), release / MANIFEST_NAME)
        for filename in MANAGED_FILES:
            shutil.copy2(_bundle_child(bundle, Path("deploy") / filename), release / "deploy" / filename)
        source_manifest = _bundle_child(bundle, Path("deploy/release-manifest.json"))
        shutil.copy2(source_manifest, release / "deploy" / source_manifest.name)
        for source, relative in validate_support_files(bundle, manifest):
            destination = release / relative
            _private_mkdir(destination.parent)
            shutil.copyfile(source, destination)
        wheel_dir = release / "wheelhouse"
        _private_mkdir(wheel_dir)
        for source in wheels:
            shutil.copyfile(source, wheel_dir / source.name)

        import venv
        uv = shutil.which("uv")
        venv_dir = release / "venv"
        if uv:
            _run([uv, "venv", "--python", sys.executable, str(venv_dir)], timeout=120)
        else:
            try:
                venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
            except (OSError, subprocess.SubprocessError) as exc:
                raise DeployError("Python could not create a private venv. Install uv for this user or use Python with ensurepip.") from exc
        interpreter = python_for_release(release)
        if uv:
            install_args = [uv, "pip", "install", "--python", str(interpreter), "--offline", "--no-deps"]
            install_args.extend(str(wheel_dir / item["filename"]) for item in manifest["packages"])
            _run(install_args, timeout=900)
            _run([uv, "pip", "check", "--python", str(interpreter)], timeout=120)
        else:
            install_args = [str(interpreter), "-m", "pip", "install", "--disable-pip-version-check", "--no-index", "--no-deps"]
            install_args.extend(str(wheel_dir / item["filename"]) for item in manifest["packages"])
            _run(install_args, timeout=900)
            _run([str(interpreter), "-m", "pip", "check"], timeout=120)
        pip_record = next((item for item in manifest["packages"] if normalized_name(item["name"]) == "pip"), None)
        if pip_record is None:
            raise DeployError("release closure must include an exact pip wheel for private extension installs")
        pip_result = _run([str(interpreter), "-m", "pip", "--version"], timeout=30)
        if pip_record["version"] not in pip_result.stdout:
            raise DeployError("installed private runtime pip version does not match the release manifest")
        versions_code = "import importlib.metadata as m,json,sys; print(json.dumps({n:m.version(n) for n in json.loads(sys.argv[1])},sort_keys=True))"
        versions = _runtime_json(interpreter, versions_code, json.dumps([item["name"] for item in manifest["packages"]]))
        if versions is None or any(versions.get(item["name"]) != item["version"] for item in manifest["packages"]):
            raise DeployError("private runtime package versions do not match the release manifest")

        for artifact in manifest.get("backend_artifacts", []):
            source = _bundle_child(bundle, Path(artifact["bundle_path"]))
            destination = release / artifact["bundle_path"]
            _private_mkdir(destination.parent)
            shutil.copyfile(source, destination)
            if os.name != "nt":
                destination.chmod(0o700)
        _check_backend_runtime(release, manifest, required=manifest["release_quality"] == "complete")
        _buddy_start_smoke(release, manifest)

        if os.name != "nt":
            for current, dirs, files in os.walk(release):
                Path(current).chmod(0o700)
                for filename in files:
                    file_path = Path(current) / filename
                    if not file_path.is_symlink():
                        # Keep executable bits on installed entrypoints and the native backend.
                        mode = stat.S_IMODE(file_path.stat().st_mode)
                        file_path.chmod((mode & 0o700) | 0o600)
        _atomic_json(release / ".leakguard-release.json", {
            "schema_version": 1, "release_version": manifest["release_version"], "complete": True,
        })
    except BaseException:
        shutil.rmtree(release, ignore_errors=True)
        raise


def install_bundle(bundle_arg: Path, *, root: Path | None = None, state: Path | None = None, activate: bool = True) -> Path:
    bundle = find_bundle_root(bundle_arg)
    owns_temp = bundle_arg.is_file()
    explicit_root = root is not None
    root = root or data_root()
    root = root.expanduser()
    if not root.is_absolute():
        raise DeployError("install prefix must be an absolute path")
    state = state or (root / "state" if explicit_root else state_root())
    state = state.expanduser()
    if not state.is_absolute():
        raise DeployError("state directory must be an absolute path")
    if root.is_symlink() or state.is_symlink():
        raise DeployError("install prefix and state directory may not be symbolic links")
    try:
        manifest = read_manifest(_bundle_child(bundle, Path(MANIFEST_NAME)))
        actual_platform = _platform_label()
        if manifest["target_platform"] != actual_platform:
            raise DeployError(f"bundle targets {manifest['target_platform']}; this host is {actual_platform}")
        actual_python = f"{sys.version_info.major}.{sys.version_info.minor}"
        if actual_python != manifest["target_python"]:
            raise DeployError(
                f"bundle wheels target Python {manifest['target_python']}; "
                f"selected Python is {actual_python}; select a matching interpreter and rebuild the private runtime"
            )
        wheels = validate_wheelhouse(bundle, manifest)
        if sys.version_info < (3, 11):
            raise DeployError("LeakGuard requires Python 3.11 or newer")
        base = root.resolve()
        _private_mkdir(base)
        if (base / "releases").is_symlink():
            raise DeployError("refusing to install through a symlinked releases directory")
        _private_mkdir(base / "releases")
        release = base / "releases" / manifest["release_version"]
        if release.exists():
            if release.is_symlink():
                raise DeployError("versioned release path may not be a symbolic link")
            if not _release_complete(release, manifest["release_version"]):
                if active_version(base) == manifest["release_version"]:
                    raise DeployError("active release is incomplete and will not be replaced")
                shutil.rmtree(release)
            else:
                old_manifest = read_manifest(release / MANIFEST_NAME)
                if old_manifest != manifest:
                    raise DeployError("this release version is already installed from a different artifact")
        if not _release_complete(release, manifest["release_version"]):
            _build_release(bundle, release, manifest, wheels)

        _ensure_default_config(state, release / "deploy" / "default-config.json", release, manifest)
        if activate:
            previous = active_version(base)
            previous_state = _active_state_dir(base)
            _atomic_json(base / ACTIVE_NAME, {"schema_version": 1, "active_version": manifest["release_version"], "previous_version": previous, "state_dir": str(state)})
            try:
                write_launchers(base, manifest["release_version"], manifest, state,
                                external=base.resolve() == default_data_root().resolve())
            except BaseException:
                if previous:
                    old_state = previous_state or state
                    _atomic_json(base / ACTIVE_NAME, {"schema_version": 1, "active_version": previous, "state_dir": str(old_state)})
                    old_manifest = read_manifest(base / "releases" / previous / MANIFEST_NAME)
                    _ensure_default_config(state, base / "releases" / previous / "deploy" / "default-config.json",
                                           base / "releases" / previous, old_manifest)
                    write_launchers(base, previous, old_manifest, old_state,
                                    external=base.resolve() == default_data_root().resolve())
                else:
                    (base / ACTIVE_NAME).unlink(missing_ok=True)
                raise
        return release
    finally:
        if owns_temp:
            shutil.rmtree(bundle.parent if bundle.parent.name.startswith("leakguard-bundle-") else bundle, ignore_errors=True)


def _ensure_default_config(state: Path, template: Path, release: Path, manifest: dict[str, Any]) -> None:
    _private_mkdir(state)
    config = state / "config.json"
    if config.is_symlink():
        raise DeployError("runtime config may not be a symbolic link; preserved it without modification")
    is_new_config = not config.exists()
    if not is_new_config:
        try:
            value = json.loads(config.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DeployError("existing runtime config is unreadable; preserved it without modification") from exc
        if not isinstance(value, dict):
            raise DeployError("existing runtime config must be a JSON object; preserved it without modification")
    else:
        try:
            value = json.loads(template.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DeployError("release bundle has no valid default runtime config") from exc
        if not isinstance(value, dict):
            raise DeployError("release default config must be a JSON object")
    # Installed runs use only the encrypted observation store. An unavailable key
    # leaves enforcement explicitly ephemeral; legacy plaintext SQLite is never
    # selected by an installed configuration.
    value["observation_backend"] = "encrypted"
    value["observation_path"] = str(state / "observations.lgo")
    backend_name = "gitleaks.exe" if manifest["target_platform"].startswith("windows-") else "gitleaks"
    value["gitleaks_executable"] = str((release / "backends" / manifest["target_platform"] / backend_name).resolve())
    if "worker_policy" in value:
        worker_policy = value["worker_policy"]
        if not isinstance(worker_policy, str) or worker_policy not in {"strict", "supervised-alpha"}:
            raise DeployError("runtime config has an invalid worker_policy; preserved it without modification")
    if sys.platform == "darwin" and (is_new_config or "worker_policy" not in value):
        value["worker_policy"] = "supervised-alpha"
    _atomic_json(config, value)


def _current_release(root: Path) -> tuple[str, Path, dict[str, Any]]:
    version = active_version(root)
    if not version:
        raise DeployError("no active LeakGuard release")
    release = root / "releases" / version
    if not release.is_dir():
        raise DeployError("active LeakGuard release directory is missing")
    if not _release_complete(release, version):
        raise DeployError("active LeakGuard release is incomplete")
    return version, release, read_manifest(release / MANIFEST_NAME)


def rollback(root: Path | None = None) -> str:
    root = root or data_root()
    root = root.expanduser().resolve()
    current, _, _ = _current_release(root)
    candidates = sorted(
        (path for path in (root / "releases").iterdir() if path.is_dir() and not path.name.startswith(".")),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    prior = next((path for path in candidates if path.name != current and _release_complete(path, path.name)), None)
    if prior is None:
        raise DeployError("no earlier installed version is available for rollback")
    manifest = read_manifest(prior / MANIFEST_NAME)
    state = _active_state_dir(root) or state_root()
    _ensure_default_config(state, prior / "deploy" / "default-config.json", prior, manifest)
    _atomic_json(root / ACTIVE_NAME, {"schema_version": 1, "active_version": prior.name, "previous_version": current,
                                      "state_dir": str(state)})
    write_launchers(root, prior.name, manifest, state, external=root == default_data_root().resolve())
    return prior.name


def _load_service_spec(release: Path, manifest: dict[str, Any], state: Path) -> dict[str, Any]:
    interpreter = python_for_release(release)
    command = _script_path(release, manifest.get("buddy_command", "leakguard-buddy"))
    service_argv = manifest.get("service_command") or [manifest.get("buddy_command", "leakguard-buddy")]
    buddy_name = manifest.get("buddy_command", "leakguard-buddy")
    replacements = {"{state_dir}": str(state), "{config_path}": str(state / "config.json")}
    resolved_argv: list[str] = []
    for item in service_argv:
        if item == buddy_name:
            resolved_argv.append(str(command))
        else:
            for token, replacement in replacements.items():
                item = item.replace(token, replacement)
            resolved_argv.append(item)
    code = (
        "import json,sys; from pathlib import Path; from leakguard_host import service_spec; "
        "print(json.dumps(service_spec(command=json.loads(sys.argv[1]), state_dir=Path(sys.argv[2]))))"
    )
    try:
        result = subprocess.run([str(interpreter), "-c", code, json.dumps(resolved_argv), str(state)],
                                text=True, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeployError("host service adapter could not be started") from exc
    if result.returncode:
        raise DeployError("host service adapter is unavailable: " + (result.stderr.strip()[:300] or "unknown error"))
    try:
        spec = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DeployError("host service adapter returned invalid data") from exc
    if not isinstance(spec, dict) or not isinstance(spec.get("supported"), bool):
        raise DeployError("host service adapter returned an incomplete capability result")
    return spec


def _substitute_argv(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise DeployError("host service adapter returned an invalid action")
    output: list[str] = []
    for argument in value:
        if not isinstance(argument, str):
            raise DeployError("host service adapter returned an invalid action argument")
        output.append(argument)
    return output


def _check_no_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise DeployError("refusing to access a service path with a symbolic-link component")


def manage_service(action: str, root: Path | None = None) -> dict[str, Any]:
    explicit_root = root is not None
    root = (root or data_root()).expanduser().resolve()
    version, release, manifest = _current_release(root)
    state = _active_state_dir(root) or (root / "state" if explicit_root else state_root())
    _private_mkdir(state)
    spec = _load_service_spec(release, manifest, state)
    if not spec["supported"]:
        label = spec.get("platform", platform.system())
        raise DeployError(f"per-user service is unavailable on {label}: {spec.get('reason', 'unsupported')}")
    filename = spec.get("filename")
    raw_path = spec.get("path")
    content = spec.get("content")
    if not isinstance(filename, str) or Path(filename).name != filename or not isinstance(raw_path, str):
        raise DeployError("host service adapter returned an unsafe service file path")
    service_file = Path(raw_path)
    if not service_file.is_absolute() or service_file.name != filename:
        raise DeployError("host service adapter returned a non-absolute or inconsistent service file path")
    expected_paths = {
        "linux": Path.home() / ".config" / "systemd" / "user" / "leakguard-buddy.service",
        "darwin": Path.home() / "Library" / "LaunchAgents" / "io.leakguard.buddy.plist",
        "windows": state / "leakguard-buddy-task.xml",
    }
    expected_path = expected_paths.get(str(spec.get("platform", "")).lower())
    if expected_path is None or os.path.normcase(os.path.abspath(service_file)) != os.path.normcase(os.path.abspath(expected_path)):
        raise DeployError("host service adapter returned an unexpected per-user service path")
    _check_no_symlink_components(service_file)
    if not isinstance(content, (str, bytes)):
        raise DeployError("host service adapter returned invalid service contents")
    system = spec.get("platform")
    if action == "enable":
        _private_mkdir(service_file.parent)
        temp = service_file.with_name(service_file.name + f".{os.getpid()}.tmp")
        if isinstance(content, bytes):
            temp.write_bytes(content)
        else:
            temp.write_text(content, encoding=spec.get("encoding", "utf-8"))
        if os.name != "nt":
            temp.chmod(0o600)
        os.replace(temp, service_file)
    if action == "disable":
        _run(_substitute_argv(spec.get("disable_argv")), check=True, timeout=60)
        service_file.unlink(missing_ok=True)
        reload_command = _substitute_argv(spec.get("reload_argv", []))
        if reload_command:
            _run(reload_command, check=True, timeout=60)
        return {"action": action, "platform": system, "service_file": str(service_file), "returncode": 0, "status": "disabled"}
    if action == "enable":
        reload_command = _substitute_argv(spec.get("reload_argv", []))
        if reload_command:
            _run(reload_command, check=True, timeout=60)
    argv = spec.get({"enable": "enable_argv", "status": "status_argv"}[action])
    command = _substitute_argv(argv)
    result = _run(command, check=action != "status", timeout=60)
    _, observation_path, encrypted_config, _ = _observation_config(state, state / "config.json")
    _, _, keyring_available, keyring_code = _observation_keyring(observation_path, python_for_release(release))
    unattended_available = encrypted_config and keyring_available
    return {"action": action, "platform": system, "service_file": str(service_file), "returncode": result.returncode,
            "status": (result.stdout or result.stderr).strip()[:300],
            "unattended_requires": spec.get("unattended_requires"),
            "native_verified": bool(spec.get("native_verified", False)),
            "unattended_available": unattended_available,
            "observation_keyring_error": keyring_code}


def _runtime_json(interpreter: Path, code: str, argument: str) -> dict[str, Any] | None:
    if not interpreter.is_file():
        return None
    try:
        result = subprocess.run([str(interpreter), "-c", code, argument], text=True,
                                capture_output=True, timeout=25, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _observation_config(state: Path, config_path: Path | None = None) -> tuple[dict[str, Any] | None, Path, bool, str]:
    path = config_path or Path(os.environ.get("LEAKGUARD_CONFIG", str(state / "config.json"))).expanduser()
    fallback = state / "observations.lgo"
    if not path.is_absolute() or path.is_symlink():
        return None, fallback, False, "runtime config path is invalid"
    try:
        if path.stat().st_size > 1024 * 1024:
            return None, fallback, False, "runtime config exceeds the 1 MiB limit"
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, fallback, False, "runtime config is missing or invalid"
    if not isinstance(config, dict):
        return None, fallback, False, "runtime config must be a JSON object"
    raw_observation_path = config.get("observation_path")
    if raw_observation_path is None:
        observation_path = fallback
        path_valid = True
    elif isinstance(raw_observation_path, str) and Path(raw_observation_path).is_absolute():
        observation_path = Path(raw_observation_path)
        path_valid = (os.path.normcase(os.path.abspath(observation_path)) ==
                      os.path.normcase(os.path.abspath(fallback))) and not observation_path.is_symlink()
        if not path_valid:
            observation_path = fallback
    else:
        observation_path = fallback
        path_valid = False
    encrypted = config.get("observation_backend") == "encrypted" and path_valid
    detail = "encrypted backend selected" if encrypted else "installed config does not select a valid encrypted observation store"
    return config, observation_path, encrypted, detail


def _sqlite_serialization_probe(interpreter: Path | None) -> tuple[bool, str]:
    if interpreter is None:
        return False, "installed LeakGuard runtime is unavailable"
    code = """
import json
from leakguard_core.scan_store import SQLiteScanStore

store = SQLiteScanStore.from_memory()
payload = store.serialize()
reopened = SQLiteScanStore.from_memory(payload)
reopened.close()
store.close()
print(json.dumps({"ok": isinstance(payload, bytes) and len(payload) > 0, "bytes": len(payload)}))
"""
    result = _runtime_json(interpreter, code, "")
    if result is None or result.get("ok") is not True:
        return False, "in-memory SQLiteScanStore serialize/deserialize failed"
    size = result.get("bytes")
    return True, f"in-memory SQLiteScanStore serialized {size} bytes"


def _observation_keyring(observation_path: Path, interpreter: Path | None) -> tuple[str, str, bool, str]:
    if interpreter is None:
        return "unavailable", "installed runtime is unavailable", False, "runtime-unavailable"
    code = """
import json, sys
from pathlib import Path
from leakguard_vault import EncryptedScanStore, NativeKeyring

backend = None
error_code = ""
available = False
detail = ""
try:
    status = NativeKeyring().status()
    backend = status.get("native_backend") if isinstance(status, dict) else None
except Exception as exc:
    error_code = getattr(exc, "code", "native-keyring-check-failed")
path = Path(sys.argv[1])
if not path.is_file():
    error_code = "observation-store-missing"
    detail = "encrypted observation store is not configured"
else:
    try:
        status = EncryptedScanStore.keyring_status(path)
        if isinstance(status, dict):
            available = bool(status.get("unattended_available"))
            error_code = status.get("error_code") or ""
        else:
            error_code = "invalid-status"
    except Exception as exc:
        error_code = getattr(exc, "code", "observation-keyring-check-failed")
if not detail:
    detail = "encrypted observation key is available from the native keyring" if available else str(error_code or "native observation key is unavailable")[:100]
print(json.dumps({"backend": backend, "detail": detail, "available": available, "error_code": str(error_code)[:80]}))
"""
    value = _runtime_json(interpreter, code, str(observation_path))
    if value is None:
        return "unavailable", "vault native-keyring probe is unavailable", False, "vault-probe-unavailable"
    backend = value.get("backend")
    label = str(backend)[:80] if isinstance(backend, str) and backend else "unavailable"
    detail = value.get("detail")
    detail = str(detail)[:120] if isinstance(detail, str) else "native observation-key status is unavailable"
    available = value.get("available") is True
    error = value.get("error_code")
    error_code = str(error)[:80] if isinstance(error, str) else "invalid-status"
    return label, detail, available, error_code


def doctor(root: Path | None = None) -> tuple[dict[str, Any], int]:
    explicit_root = root is not None
    root = root or data_root()
    checks: list[dict[str, Any]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    add("platform", "info", platform.platform())
    add("python", "pass" if sys.version_info >= (3, 11) else "fail", platform.python_version())
    version, release, manifest = (None, None, None)
    try:
        version, release, manifest = _current_release(root)
        add("active_release", "pass", version)
        runtime_python = python_for_release(release)
        runtime_python_info = _runtime_json(
            runtime_python,
            "import json, sys; print(json.dumps({'minor': f'{sys.version_info.major}.{sys.version_info.minor}'}))",
            "{}",
        ) if runtime_python else None
        runtime_minor = runtime_python_info.get("minor") if runtime_python_info else None
        python_ok = runtime_minor == manifest["target_python"]
        add("target_python", "pass" if python_ok else "fail",
            f"bundle targets Python {manifest['target_python']}; installed runtime is "
            f"{runtime_minor if isinstance(runtime_minor, str) else 'unavailable'}")
        _ = validate_wheelhouse(release, manifest)
        add("release_hashes", "pass", "all installed wheel artifacts match the release manifest")
    except (DeployError, OSError) as exc:
        add("active_release", "fail", str(exc))
    state = _active_state_dir(root) or (root / "state" if explicit_root else state_root())
    runtime_python = python_for_release(release) if release is not None else None
    sqlite_ok, sqlite_detail = _sqlite_serialization_probe(runtime_python)
    add("sqlite_serialization", "pass" if sqlite_ok else "fail", sqlite_detail)
    config_path = Path(os.environ.get("LEAKGUARD_CONFIG", str(state / "config.json"))).expanduser()
    config, observation_path, encrypted_config, config_detail = _observation_config(state, config_path)
    config_status = "pass" if encrypted_config else "fail"
    add("observation_backend", config_status, config_detail)
    keyring_label, keyring_detail, keyring_available, keyring_code = _observation_keyring(observation_path, runtime_python)
    unattended_available = encrypted_config and keyring_available
    key_status = "pass" if keyring_available else "warning"
    add("native_keyring", key_status, f"{keyring_label}: {keyring_detail}")
    if config is not None:
        try:
            worker_policy = config.get("worker_policy", "strict")
            add("runtime_config", "pass", "configuration is readable")
        except Exception:
            worker_policy = "invalid"
            add("runtime_config", "warning", "configuration fields are invalid")
        add("worker_policy", "info", str(worker_policy))
    else:
        add("runtime_config", "warning", "configuration file is missing or invalid")
    backend_ok = False
    backend_path: Path | None = None
    if release is not None and manifest is not None:
        backend_path = _expected_backend_path(release, manifest)
        configured_backend = config.get("gitleaks_executable") if isinstance(config, dict) else None
        config_matches = isinstance(configured_backend, str) and Path(configured_backend).is_absolute() \
            and os.path.normcase(os.path.abspath(configured_backend)) == os.path.normcase(os.path.abspath(backend_path))
        try:
            backend_ok, backend_detail = _check_backend_runtime(
                release, manifest, required=manifest["release_quality"] == "complete")
            if not config_matches:
                backend_ok = False
                backend_detail = "installed config does not select the release-pinned Gitleaks path"
            backend_status = "pass" if backend_ok else ("warning" if manifest["release_quality"] == "partial" and not backend_path.is_file() else "fail")
        except (DeployError, OSError) as exc:
            backend_detail = str(exc)
            backend_status = "warning" if manifest["release_quality"] == "partial" and not backend_path.exists() else "fail"
        add("gitleaks_backend", backend_status, backend_detail)
    else:
        add("gitleaks_backend", "fail", "no validated active release backend")
    package_results = []
    if manifest is not None:
        version_code = """
import importlib.metadata as metadata
import json, sys

versions = {}
for name in json.loads(sys.argv[1]):
    try:
        versions[name] = metadata.version(name)
    except metadata.PackageNotFoundError:
        versions[name] = None
print(json.dumps(versions, sort_keys=True))
"""
        installed_versions = _runtime_json(runtime_python, version_code,
                                           json.dumps([item["name"] for item in manifest["packages"]])) if runtime_python else None
        if installed_versions is None:
            add("packages", "fail", "installed runtime package metadata is unavailable")
        for package in manifest["packages"]:
            installed_value = installed_versions.get(package["name"]) if installed_versions is not None else None
            installed = installed_value if isinstance(installed_value, str) else "missing"
            ok = installed == package["version"]
            package_results.append(ok)
            if not ok:
                add("package:" + package["name"], "fail", f"expected {package['version']}, found {installed}")
        if package_results and all(package_results):
            add("packages", "pass", f"{len(package_results)} pinned distributions are installed")
    native_execution: dict[str, Any] | None = None
    if release is not None:
        core_cli = _script_path(release, "leakguard")
        if core_cli.is_file():
            try:
                core_result = subprocess.run([str(core_cli), "doctor", "--config", str(config_path), "--format", "json"],
                                              text=True, capture_output=True, timeout=30, check=False,
                                              env={**os.environ, "LEAKGUARD_STATE_DIR": str(state), "LEAKGUARD_CONFIG": str(config_path)})
                if core_result.returncode == 0:
                    parsed = json.loads(core_result.stdout)
                    if isinstance(parsed, dict):
                        native_execution = parsed.get("native_execution", parsed.get("capabilities", parsed))
                if native_execution is None:
                    add("native_execution", "warning", "core doctor did not return a capability report")
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                add("native_execution", "warning", "core doctor capability report is unavailable")
    report = {"schema_version": 1, "platform": platform.system().lower(), "checks": checks,
              "capabilities": {"sqlite_serialization": sqlite_ok, "native_keyring": keyring_label,
                               "observation_keyring_error": keyring_code,
                               "gitleaks": {"available": backend_ok,
                                            "path": str(backend_path) if backend_path else None,
                                            "version": manifest.get("backend_version") if manifest else None,
                                            "release_quality": manifest.get("release_quality") if manifest else None},
                               "unattended_observation_store": unattended_available,
                               "native_execution": native_execution}}
    failed = any(item["status"] == "fail" for item in checks)
    print(json.dumps(report, sort_keys=True, indent=2))
    return report, 1 if failed else 0


def uninstall(root: Path | None = None, *, purge_data: bool = False) -> int:
    explicit_root = root is not None
    root = (root or data_root()).expanduser().resolve()
    active = active_version(root)
    state = _active_state_dir(root)
    if active:
        _, release, manifest = _current_release(root)
        state = state or (root / "state" if explicit_root else state_root())
        spec = _load_service_spec(release, manifest, state)
        service_path = spec.get("path") if isinstance(spec, dict) else None
        if spec.get("supported") and isinstance(service_path, str) and Path(service_path).is_file():
            manage_service("disable", root)
    external = root == default_data_root().resolve()
    launcher_root = bin_root() if external else root / "bin"
    for name in ("leakguard-buddy", "LeakGuard Buddy.cmd", "leakguard", "leakguard.cmd", "leakguard-install", "leakguard-install.cmd",
                 "leakguard-doctor", "leakguard-doctor.cmd", "leakguard-buddy-open", "LeakGuard Buddy Open.cmd"):
        (launcher_root / name).unlink(missing_ok=True)
    if external:
        (Path.home() / ".local" / "share" / "applications" / "leakguard-buddy.desktop").unlink(missing_ok=True)
        (Path.home() / ".local" / "share" / "applications" / "leakguard-buddy-open.desktop").unlink(missing_ok=True)
        start_shortcut = Path(os.environ.get("APPDATA", str(Path.home()))) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "LeakGuard Buddy.cmd"
        start_shortcut.unlink(missing_ok=True)
        start_shortcut.with_name("LeakGuard Buddy Open.cmd").unlink(missing_ok=True)
        start_shortcut.with_name("LeakGuard Doctor.cmd").unlink(missing_ok=True)
        start_shortcut.with_name("LeakGuard Manage.cmd").unlink(missing_ok=True)
    releases = root / "releases"
    if releases.is_symlink():
        raise DeployError("refusing to remove a symlinked release directory")
    if releases.exists():
        shutil.rmtree(releases)
    (root / ACTIVE_NAME).unlink(missing_ok=True)
    if launcher_root.exists():
        try:
            launcher_root.rmdir()
        except OSError:
            pass
    if state is None:
        state = root / "state" if explicit_root or os.name == "nt" or sys.platform == "darwin" else Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "leakguard"
    if purge_data and state.exists():
        if state.is_symlink() or state == Path(state.anchor) or state == Path.home() or root == state or state in root.parents:
            raise DeployError("refusing to recursively remove an unsafe state path")
        shutil.rmtree(state)
    try:
        root.rmdir()
    except OSError:
        pass
    print(json.dumps({"uninstalled": True, "state_retained": not purge_data, "state_dir": str(state)}, sort_keys=True))
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    prefix = args.root or data_root()
    effective_state = args.state_dir or (prefix / "state" if args.root is not None else state_root())
    release = install_bundle(args.bundle, root=args.root, state=args.state_dir, activate=not args.no_activate)
    manifest = read_manifest(release / MANIFEST_NAME)
    print(json.dumps({"installed": str(release), "active": not args.no_activate,
                      "release_version": manifest["release_version"], "source_commit": manifest.get("source_commit"),
                      "runtime_python": str(python_for_release(release)),
                      "buddy_command": str(_script_path(release, manifest.get("buddy_command", "leakguard-buddy"))),
                      "state_dir": str(effective_state)}, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    install = sub.add_parser("install", help="install an offline release bundle")
    install.add_argument("bundle", type=Path)
    install.add_argument("--root", "--prefix", dest="root", type=Path, help="absolute private install prefix")
    install.add_argument("--state-dir", type=Path, help="absolute private state directory; defaults to a per-user state root")
    install.add_argument("--no-activate", action="store_true")
    rollback_parser = sub.add_parser("rollback", help="activate the previous installed release")
    rollback_parser.add_argument("--root", type=Path)
    doctor_parser = sub.add_parser("doctor", help="check runtime and native capabilities")
    doctor_parser.add_argument("--root", type=Path)
    uninstall_parser = sub.add_parser("uninstall", help="remove the application while retaining local state by default")
    uninstall_parser.add_argument("--root", type=Path)
    uninstall_parser.add_argument("--purge-data", action="store_true", help="also permanently delete this user's LeakGuard state")
    service_parser = sub.add_parser("service", help="opt in to a per-user background service")
    service_parser.add_argument("action", choices=("enable", "disable", "status"))
    service_parser.add_argument("--root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            return cmd_install(args)
        if args.command == "rollback":
            version = rollback(args.root)
            print(json.dumps({"active_version": version}, sort_keys=True))
            return 0
        if args.command == "doctor":
            return doctor(args.root)[1]
        if args.command == "uninstall":
            return uninstall(args.root, purge_data=args.purge_data)
        result = manage_service(args.action, args.root)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["returncode"] == 0 else 1
    except (DeployError, OSError, ValueError) as exc:
        print(f"leakguard-install: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
