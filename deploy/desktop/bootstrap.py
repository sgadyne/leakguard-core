#!/usr/bin/env python3
"""Prepare only Password Buddy's explicit private desktop runtime (stdlib only)."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import time


class PreparationError(Exception):
    pass


def fail(code):
    raise PreparationError(code)


def emit(kind, **fields):
    print(json.dumps({"type": kind, **fields}, separators=(",", ":")), flush=True)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        fail("manifest-path-invalid")
    posix, windows = PurePosixPath(value), PureWindowsPath(value)
    if (posix.is_absolute() or windows.drive or windows.is_absolute()
            or any(part in {".", ".."} for part in posix.parts) or posix.as_posix() != value):
        fail("manifest-path-invalid")
    return Path(*posix.parts)


def records(root):
    """Do not follow directory symlinks; every link must resolve inside the tree."""
    result = []
    root = root.resolve(strict=True)
    for current, directories, filenames in os.walk(root, followlinks=False):
        for name in sorted(directories + filenames):
            path = Path(current) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                continue
            if relative == "desktop-manifest.json":
                continue
            item = {"path": relative, "mode": stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                item["mode"] = 0o777  # Symlink access bits are ignored; macOS ditto normalizes them.
                target = os.readlink(path)
                if Path(target).is_absolute() or not path.resolve(strict=True).is_relative_to(root):
                    fail("payload-symlink-escape")
                item.update(linkTarget=target, sha256=hashlib.sha256(os.fsencode(target)).hexdigest())
            elif stat.S_ISREG(info.st_mode):
                item["sha256"] = digest(path)
            else:
                fail("payload-file-type-invalid")
            result.append(item)
    return sorted(result, key=lambda item: item["path"])


def runtime_identity(manifest):
    value = {key: manifest[key] for key in (
        "schemaVersion", "desktopVersion", "protocolVersion", "target", "pythonVersion",
        "pythonExecutable", "backendBundle", "backendRelease", "files")}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_resources(root):
    manifest_path = root / "desktop-manifest.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > 16 * 1024 * 1024:
        fail("manifest-invalid")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (manifest.get("schemaVersion") != 1 or manifest.get("protocolVersion") != 1
            or manifest.get("target") not in {"macos-arm64", "windows-x86_64", "linux-x86_64"}
            or not re.fullmatch(r"[a-f0-9]{64}", manifest.get("runtimeId", ""))):
        fail("manifest-invalid")
    for key in ("pythonExecutable", "backendBundle"):
        relative_path(manifest.get(key))
    if manifest["backendBundle"] != "backend/LeakGuard":
        fail("manifest-invalid")
    expected = manifest.get("files")
    if not isinstance(expected, list) or not expected or len(expected) > 100000:
        fail("manifest-invalid")
    seen = set()
    for item in expected:
        relative_path(item.get("path"))
        key = item["path"] if manifest["target"] == "linux-x86_64" else item["path"].casefold()
        if key in seen or not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")):
            fail("manifest-invalid")
        seen.add(key)
    actual = records(root)
    # Windows does not preserve POSIX permission bits. Native modes are checked on POSIX.
    compared = actual if os.name != "nt" else [{k: v for k, v in x.items() if k != "mode"} for x in actual]
    wanted = expected if os.name != "nt" else [{k: v for k, v in x.items() if k != "mode"} for x in expected]
    if compared != wanted or runtime_identity(manifest) != manifest["runtimeId"]:
        fail("resource-integrity-failed")
    actual_target = {"darwin": "macos", "win32": "windows", "linux": "linux"}.get(sys.platform)
    machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64"}.get(platform.machine().lower())
    if manifest["target"] != f"{actual_target}-{machine}":
        fail("runtime-target-mismatch")
    if platform.python_version() != manifest["pythonVersion"]:
        fail("runtime-python-mismatch")
    return manifest


def private_directory(path, root):
    if not path.is_relative_to(root):
        fail("profile-path-invalid")
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            fail("profile-symlink-refused")
        current.mkdir(mode=0o700, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


def owned_path(value, root):
    if not isinstance(value, str) or not Path(value).is_absolute():
        fail("runtime-receipt-invalid")
    path = Path(value)
    if not path.is_relative_to(root) or not path.resolve(strict=True).is_relative_to(root):
        fail("runtime-receipt-invalid")
    return path


def atomic_json(path, value):
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class PreparationLock:
    def __init__(self, path, code="runtime-preparation-in-use"):
        self.descriptor = None
        descriptor = None
        try:
            if path.is_symlink():
                fail("profile-symlink-refused")
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
                fail("profile-path-invalid")
            if os.name == "nt":
                import msvcrt
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.descriptor, descriptor = descriptor, None
        except OSError:
            fail(code)
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


def clean_environment(base_python, state):
    allowed = {"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "SystemRoot",
               "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    # Existing installer discovers uv through PATH. This path contains only copied CPython.
    # State/config are explicit installer arguments. Do not select its not-yet-created
    # config in the environment: the installed core --help smoke reads that setting.
    environment.update(PATH=str(base_python.parent), PYTHONNOUSERSITE="1", PIP_NO_INDEX="1",
                       PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_CONFIG_FILE=os.devnull)
    return environment


def run_json(command, environment, deadline, code):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        fail("runtime-preparation-timeout")
    # Installer output is captured, bounded and never forwarded to the shell or a log.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                    env=environment, timeout=remaining, check=False)
        except subprocess.TimeoutExpired:
            fail("runtime-preparation-timeout")
        if result.returncode:
            fail(code)
        output.seek(0)
        raw = output.read(65537)
        if len(raw) > 65536:
            fail(code)
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        fail(code)


def check_runtime(receipt, manifest, root, state, environment, deadline):
    interpreter = owned_path(receipt.get("python"), root)
    if receipt.get("stateDir") != str(state) or receipt.get("config") != str(state / "config.json"):
        fail("runtime-receipt-invalid")
    owned_path(receipt["config"], root)
    code = (
        "import importlib.metadata as m,json,pip,sqlite3,sys;"
        "print(json.dumps({'private':sys.prefix!=sys.base_prefix,'prefix':sys.prefix,"
        "'base':sys.base_prefix,'buddy':m.version('leakguard-buddy'),"
        "'pip':m.version('pip'),'sqlite':hasattr(sqlite3.Connection,'serialize')}))"
    )
    checked = run_json([str(interpreter), "-I", "-B", "-X", "utf8", "-c", code], environment, deadline, "private-runtime-check-failed")
    if (checked.get("private") is not True or checked.get("buddy") != "0.1.0a2"
            or not checked.get("pip") or checked.get("sqlite") is not True):
        fail("private-runtime-check-failed")
    owned_path(checked["prefix"], root)
    base = owned_path(checked["base"], root)
    if base != root / "runtimes" / manifest["runtimeId"] / "python":
        fail("private-runtime-check-failed")


def prepare(resources, data):
    manifest = verify_resources(resources)
    if not data.is_absolute() or data.is_symlink() or data.resolve() != data:
        fail("profile-path-invalid")
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        data.chmod(0o700)
    lock = PreparationLock(data / ".desktop-prepare.lock")
    ownership = None
    try:
        profile = data / "profile"
        private_directory(profile, data)
        marker = profile / "desktop-runtime.json"
        if marker.is_symlink():
            fail("profile-symlink-refused")
        previous = json.loads(marker.read_text()) if marker.exists() else None
        if previous is not None and previous.get("runtimeId") != manifest["runtimeId"]:
            fail("runtime-migration-required")
        if (profile / "state").is_symlink():
            fail("profile-symlink-refused")
        if previous is None and (profile / "state").exists() and any((profile / "state").iterdir()):
            fail("unclaimed-profile-state")
        state = profile / "state"
        private_directory(state, data)
        # Same flock/msvcrt byte-zero lock as BuddyBackend, even with both stores locked.
        ownership = PreparationLock(state / ".buddy-owner.lock", "profile-in-use")
        identity = {"schemaVersion": 1, "runtimeId": manifest["runtimeId"], "target": manifest["target"],
                    "sourceCommit": manifest["sourceCommit"], "status": "preparing"}
        if previous is None:
            atomic_json(marker, identity)
        runtime = data / "runtimes" / manifest["runtimeId"]
        private_directory(runtime, data)
        base = runtime / "python"
        if base.is_symlink():
            fail("profile-symlink-refused")
        copied_marker = runtime / ".python-complete.json"
        if not copied_marker.exists():
            if base.exists():
                # Only an incomplete base owned by this profile/identity can be repaired.
                if previous is not None and previous.get("status") == "ready":
                    fail("private-runtime-check-failed")
                shutil.rmtree(base)
            emit("progress", stage="copying-runtime")
            staging = runtime / ".python-staging"
            if staging.is_symlink():
                fail("profile-symlink-refused")
            if staging.exists():
                shutil.rmtree(staging)
            shutil.copytree(resources / "python", staging, symlinks=True)
            os.replace(staging, base)
            atomic_json(copied_marker, {"runtimeId": manifest["runtimeId"]})
        base_python = base / Path(*PurePosixPath(manifest["pythonExecutable"]).parts[1:])
        owned_path(str(base_python), data)
        environment = clean_environment(base_python, state)
        deadline = time.monotonic() + 590
        saved = runtime / ".installer-receipt.json"
        if saved.is_symlink():
            fail("profile-symlink-refused")
        if saved.exists():
            receipt = json.loads(saved.read_text())
        else:
            if previous is not None and previous.get("status") == "ready":
                fail("private-runtime-check-failed")
            emit("progress", stage="installing-backend")
            private_directory(runtime / "engine", data)
            bundle = resources / manifest["backendBundle"]
            installed = run_json([str(base_python), "-I", "-B", "-X", "utf8", str(bundle / "deploy" / "installer.py"),
                                  "install", str(bundle), "--root", str(runtime / "engine"),
                                  "--state-dir", str(state)], environment, deadline, "backend-install-failed")
            if installed.get("release_version") != manifest["backendRelease"] or installed.get("state_dir") != str(state):
                fail("runtime-receipt-invalid")
            receipt = {"type": "runtime-ready", "protocol": 1, "runtimeId": manifest["runtimeId"],
                       "python": installed.get("runtime_python"), "stateDir": str(state), "config": str(state / "config.json")}
            check_runtime(receipt, manifest, data, state, environment, deadline)
            atomic_json(saved, receipt)
        emit("progress", stage="checking-runtime")
        check_runtime(receipt, manifest, data, state, environment, deadline)
        atomic_json(marker, {**identity, "status": "ready"})
        emit("runtime-ready", **{key: receipt[key] for key in ("protocol", "runtimeId", "python", "stateDir", "config")})
    finally:
        if ownership is not None:
            ownership.close()
        lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.resources.resolve(strict=True), args.data_dir)
        return 0
    except PreparationError as error:
        emit("error", code=str(error))
    except (OSError, ValueError, KeyError, TypeError, shutil.Error):
        emit("error", code="runtime-preparation-failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
