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
import sqlite3
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
    service_command = data.get("service_command", [])
    if not isinstance(service_command, list) or not all(isinstance(item, str) and item and "\x00" not in item for item in service_command):
        raise DeployError("invalid service command in manifest")
    if data.get("wheelhouse", "wheelhouse") != "wheelhouse":
        raise DeployError("unsupported wheelhouse directory in release manifest")
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
    path = bundle / relative
    current = path
    while current != root and root in current.parents:
        if current.is_symlink():
            raise DeployError("release bundle may not contain symbolic links")
        current = current.parent
    if current != root:
        raise DeployError("release artifact path escapes the bundle directory")
    return path


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
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise DeployError("release manifest has invalid backend artifact hash")
        path = _bundle_child(bundle, Path(relative))
        if path.is_symlink() or not path.is_file() or sha256_file(path) != digest:
            raise DeployError("backend artifact is missing or its SHA-256 does not match")
    return verified


def python_for_release(release: Path) -> Path:
    if os.name == "nt":
        return release / "venv" / "Scripts" / "python.exe"
    return release / "venv" / "bin" / "python"


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
            raise DeployError(f"release {manifest['release_version']} already exists; install a new version or use rollback")
        stage = base / "releases" / (".staging-" + manifest["release_version"] + f"-{os.getpid()}")
        if stage.exists():
            shutil.rmtree(stage)
        _private_mkdir(stage)
        try:
            shutil.copy2(bundle / MANIFEST_NAME, stage / MANIFEST_NAME)
            for filename in MANAGED_FILES:
                source = bundle / "deploy" / filename
                if source.is_file():
                    _private_mkdir(stage / "deploy")
                    shutil.copy2(source, stage / "deploy" / filename)
            source_manifest = bundle / "deploy" / "release-manifest.json"
            if source_manifest.is_file():
                _private_mkdir(stage / "deploy")
                shutil.copy2(source_manifest, stage / "deploy" / source_manifest.name)
            wheel_dir = stage / "wheelhouse"
            _private_mkdir(wheel_dir)
            for source in wheels:
                shutil.copyfile(source, wheel_dir / source.name)
            venv_dir = stage / "venv"
            import venv
            uv = shutil.which("uv")
            if uv:
                _run([uv, "venv", "--python", sys.executable, str(venv_dir)], timeout=120)
            else:
                try:
                    venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
                except (OSError, subprocess.SubprocessError) as exc:
                    raise DeployError("Python could not create a private venv. Install uv for this user or use Python with ensurepip.") from exc
            interpreter = python_for_release(stage)
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
            backend_artifacts = manifest.get("backend_artifacts", [])
            for artifact in backend_artifacts:
                relative = Path(artifact["bundle_path"])
                source = bundle / relative
                destination = stage / relative
                _private_mkdir(destination.parent)
                shutil.copyfile(source, destination)
                if os.name != "nt":
                    destination.chmod(0o700)
            (stage / ".leakguard-release.json").write_text(
                json.dumps({"schema_version": 1, "release_version": manifest["release_version"]}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if os.name != "nt":
                for current, dirs, files in os.walk(stage):
                    Path(current).chmod(0o700)
                    for filename in files:
                        file_path = Path(current) / filename
                        if not file_path.is_symlink():
                            file_path.chmod(stat.S_IMODE(file_path.stat().st_mode) & 0o700 | 0o600)
            os.replace(stage, release)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise

        _ensure_default_config(state, bundle / "deploy" / "default-config.json")
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
                    write_launchers(base, previous, old_manifest, old_state,
                                    external=base.resolve() == default_data_root().resolve())
                else:
                    (base / ACTIVE_NAME).unlink(missing_ok=True)
                raise
        return release
    finally:
        if owns_temp:
            shutil.rmtree(bundle.parent if bundle.parent.name.startswith("leakguard-bundle-") else bundle, ignore_errors=True)


def _ensure_default_config(state: Path, template: Path) -> None:
    _private_mkdir(state)
    config = state / "config.json"
    if config.is_symlink():
        raise DeployError("runtime config may not be a symbolic link; preserved it without modification")
    if config.exists():
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
    if sys.platform == "darwin":
        value["worker_policy"] = "supervised-alpha"
    _atomic_json(config, value)


def _current_release(root: Path) -> tuple[str, Path, dict[str, Any]]:
    version = active_version(root)
    if not version:
        raise DeployError("no active LeakGuard release")
    release = root / "releases" / version
    if not release.is_dir():
        raise DeployError("active LeakGuard release directory is missing")
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
    prior = next((path for path in candidates if path.name != current and (path / MANIFEST_NAME).is_file()), None)
    if prior is None:
        raise DeployError("no earlier installed version is available for rollback")
    manifest = read_manifest(prior / MANIFEST_NAME)
    state = _active_state_dir(root) or state_root()
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
    _, _, unattended_available, keyring_code = _observation_keyring(state, python_for_release(release))
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


def _observation_keyring(state: Path, interpreter: Path | None) -> tuple[str, str, bool, str]:
    observation_path = state / "observations.lgo"
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
        _ = validate_wheelhouse(release, manifest)
        add("release_hashes", "pass", "all installed wheel artifacts match the release manifest")
    except (DeployError, OSError) as exc:
        add("active_release", "fail", str(exc))
    sqlite_ok = hasattr(sqlite3.Connection, "serialize") and hasattr(sqlite3.Connection, "deserialize")
    if sqlite_ok:
        try:
            connection = sqlite3.connect(":memory:")
            connection.execute("create table doctor_check (value integer)")
            blob = connection.serialize()
            check = sqlite3.connect(":memory:")
            check.deserialize(blob)
            sqlite_ok = check.execute("select count(*) from doctor_check").fetchone() == (0,)
            connection.close()
            check.close()
        except Exception:
            sqlite_ok = False
    add("sqlite_serialization", "pass" if sqlite_ok else "fail", "serialize/deserialize " + ("available" if sqlite_ok else "unavailable or failed"))
    state = _active_state_dir(root) or (root / "state" if explicit_root else state_root())
    runtime_python = python_for_release(release) if release is not None else None
    keyring_label, keyring_detail, unattended_available, keyring_code = _observation_keyring(state, runtime_python)
    key_status = "pass" if unattended_available else "warning"
    add("native_keyring", key_status, f"{keyring_label}: {keyring_detail}")
    config_path = Path(os.environ.get("LEAKGUARD_CONFIG", str(state / "config.json")))
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        worker_policy = config.get("worker_policy", "strict") if isinstance(config, dict) else "invalid"
        add("worker_policy", "info", str(worker_policy))
    except (OSError, json.JSONDecodeError):
        add("runtime_config", "warning", "configuration file is missing or invalid")
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
