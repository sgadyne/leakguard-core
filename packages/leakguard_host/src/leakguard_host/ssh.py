"""Explicit current-user SSH deployment and bounded, value-free remote scans.

SSH uses the user's existing keys/agent and known_hosts. This adapter never asks
for, saves, or forwards credential-vault values or share passwords.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time

from .errors import HostError


def _remote_path(value, *, allow_root=False) -> str:
    if type(value) is not str or len(value) > 4096 or not value.startswith("/") or any(char in value for char in "\x00\r\n"):
        raise HostError("remote-path-invalid")
    path = PurePosixPath(value)
    if ".." in path.parts or not allow_root and str(path) == "/":
        raise HostError("remote-path-invalid")
    return str(path)


def _target(value: str) -> str:
    # No ssh options, shell operators, URL syntax, password, or ProxyCommand.
    if type(value) is not str or len(value) > 320 or not re.fullmatch(r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\[[0-9A-Fa-f:]+\])", value):
        raise HostError("ssh-target-invalid")
    return value


def _terminate(process):
    try:
        if os.name == "posix":
            # Descendants can outlive the process leader and retain pipe FDs.
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except (ProcessLookupError, OSError):
        pass


def _exchange(argv: list[str], payload: bytes, *, timeout: float, maximum: int, cancel=None) -> bytes:
    """Bound stdout AND stderr while writing input; never expose stderr."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=os.name == "posix")
    except OSError:
        raise HostError("ssh-unavailable") from None
    output = bytearray()
    exceeded = threading.Event()
    def read(stream, keep):
        count = 0
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    break
                count += len(chunk)
                if count > (maximum if keep else 65_536):
                    exceeded.set()
                    _terminate(process)
                    break
                if keep:
                    output.extend(chunk)
        except OSError:
            pass
        finally:
            stream.close()
    def write():
        try:
            process.stdin.write(payload)
        except (OSError, BrokenPipeError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass
    readers = [threading.Thread(target=read, args=(process.stdout, True), daemon=True),
               threading.Thread(target=read, args=(process.stderr, False), daemon=True)]
    writer = threading.Thread(target=write, daemon=True)
    for thread in readers + [writer]:
        thread.start()
    deadline = time.monotonic() + timeout
    failure = None
    try:
        while process.poll() is None:
            if exceeded.is_set():
                failure = "ssh-output-limit"
                break
            if cancel is not None and cancel():
                failure = "cancelled"
                break
            if time.monotonic() >= deadline:
                failure = "ssh-timeout"
                break
            try:
                process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass
    finally:
        _terminate(process)
        process.wait()
        for thread in readers + [writer]:
            thread.join(timeout=2)
    if exceeded.is_set():
        raise HostError("ssh-output-limit")
    if failure:
        raise HostError(failure)
    if process.returncode != 0:
        raise HostError("ssh-execution-failed")
    return bytes(output)


# The remote supervisor enforces a wall bound even after client disconnection.
_SCAN_SUPERVISOR = r'''
import json,os,signal,subprocess,sys
request=json.loads(sys.stdin.buffer.read(65537))
seconds=request["max_seconds"]
if type(seconds) is not int or not 1 <= seconds <= 120: sys.exit(2)
p=subprocess.Popen([sys.executable,"-m","leakguard_host.remote_worker"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
try:
    out,_=p.communicate(json.dumps(request).encode(),timeout=seconds+30)
    if p.returncode or len(out)>4500000: sys.exit(2)
    sys.stdout.buffer.write(out)
except subprocess.TimeoutExpired:
    os.killpg(p.pid,signal.SIGKILL)
    p.communicate()
    sys.exit(2)
'''

_UPLOAD = r'''
import hashlib,json,os,pathlib,sys
root=pathlib.Path(sys.argv[1]); expected=sys.argv[2]; maximum=int(sys.argv[3])
if not root.is_absolute() or root.exists(): sys.exit(2)
root.mkdir(mode=0o700,parents=False)
os.chmod(root,0o700)
path=root/"release.zip"; h=hashlib.sha256(); total=0
try:
    with path.open("xb") as stream:
        os.chmod(path,0o600)
        while True:
            chunk=sys.stdin.buffer.read(1048576)
            if not chunk: break
            total+=len(chunk)
            if total>maximum: raise ValueError()
            h.update(chunk); stream.write(chunk)
        stream.flush();os.fsync(stream.fileno())
    if h.hexdigest()!=expected: raise ValueError()
    print(json.dumps({"version":1,"uploaded":True,"sha256":expected,"bytes":total}))
except BaseException:
    path.unlink(missing_ok=True)
    try: root.rmdir()
    except OSError: pass
    raise
'''

_INSTALL = r'''
import hashlib,json,os,pathlib,signal,stat,subprocess,sys,zipfile
root=pathlib.Path(sys.argv[1]); expected=sys.argv[2]
if sys.version_info<(3,11) or not root.is_absolute() or root.is_symlink(): sys.exit(2)
info=root.stat()
if info.st_uid!=os.getuid() or info.st_mode&0o077: sys.exit(2)
archive=root/"release.zip"
if archive.is_symlink() or not archive.is_file() or archive.stat().st_size>536870912: sys.exit(2)
h=hashlib.sha256()
with archive.open("rb") as stream:
    for chunk in iter(lambda:stream.read(1048576),b""): h.update(chunk)
if h.hexdigest()!=expected: sys.exit(2)
destination=root/"content"
destination.mkdir(mode=0o700,exist_ok=False)
with zipfile.ZipFile(archive) as bundle:
    members=bundle.infolist()
    if not 1<=len(members)<=5000 or sum(x.file_size for x in members)>1073741824: sys.exit(2)
    seen=set()
    for member in members:
        name=member.filename
        parts=name.rstrip("/").split("/")
        path=pathlib.PurePosixPath(name)
        mode=member.external_attr>>16
        if not parts or parts[0]!="LeakGuard" or any(x in ("",".","..") for x in parts) or "\\" in name or ":" in name or "\x00" in name: sys.exit(2)
        if path.is_absolute() or path.as_posix() in seen or member.flag_bits&1 or member.file_size>268435456: sys.exit(2)
        if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR): sys.exit(2)
        seen.add(path.as_posix())
    for member in members:
        target=destination.joinpath(*pathlib.PurePosixPath(member.filename).parts)
        if member.is_dir(): target.mkdir(mode=0o700,parents=True,exist_ok=True);continue
        target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with bundle.open(member) as source,target.open("xb") as out:
            os.chmod(target,0o600)
            remaining=member.file_size
            while remaining:
                chunk=source.read(min(1048576,remaining))
                if not chunk: raise ValueError()
                out.write(chunk);remaining-=len(chunk)
            if source.read(1): raise ValueError()
bundle_root=destination/"LeakGuard"
installer=bundle_root/"deploy/installer.py"
if not installer.is_file() or not (bundle_root/"release.json").is_file(): sys.exit(2)
command=[sys.executable,str(installer),"install",str(bundle_root),"--prefix",str(root/"runtime"),"--state-dir",str(root/"state")]
p=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
try:
    output,_=p.communicate(timeout=300)
    if p.returncode or len(output)>65536: sys.exit(2)
    receipt=json.loads(output)
    fields={"installed","active","release_version","source_commit","runtime_python","buddy_command","state_dir"}
    if type(receipt) is not dict or set(receipt)!=fields or receipt["active"] is not True: sys.exit(2)
    for key in ("installed","buddy_command"):
        value=pathlib.Path(receipt[key]).resolve()
        if not value.is_relative_to((root/"runtime").resolve()): sys.exit(2)
    runtime=pathlib.Path(receipt["runtime_python"])
    if not runtime.is_absolute() or ".." in runtime.parts or not runtime.parent.resolve().is_relative_to((root/"runtime").resolve()): sys.exit(2)
    if not runtime.is_file(): sys.exit(2)
    if not runtime.resolve().is_relative_to((root/"runtime").resolve()) and not runtime.samefile(sys.executable): sys.exit(2)
    if pathlib.Path(receipt["state_dir"]).resolve()!=(root/"state").resolve(): sys.exit(2)
    print(json.dumps(receipt))
except subprocess.TimeoutExpired:
    os.killpg(p.pid,signal.SIGKILL);p.communicate();sys.exit(2)
'''


class SSHRunner:
    def __init__(self, *, executable: str | None = None, port: int = 22,
                 identity_file: Path | None = None, known_hosts_file: Path | None = None):
        self.executable = executable or shutil.which("ssh") or "ssh"
        if type(port) is not int or not 1 <= port <= 65535:
            raise HostError("ssh-port-invalid")
        self.port = port
        for path in (identity_file, known_hosts_file):
            if path is not None and (not isinstance(path, Path) or not path.is_absolute() or not path.is_file() or any(char in str(path) for char in "\x00\r\n")):
                raise HostError("ssh-file-invalid")
        self.identity_file = identity_file
        self.known_hosts_file = known_hosts_file

    def _command(self, target: str, python: str, script: str, args=()) -> list[str]:
        target = _target(target)
        if python != "python3":
            python = _remote_path(python)
        # OpenSSH's remote command uses a POSIX shell; quote each fixed argument.
        command = shlex.join([python, "-c", script, *args])
        argv = [self.executable, "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
                "-p", str(self.port)]
        if self.identity_file is not None:
            argv += ["-i", str(self.identity_file), "-o", "IdentitiesOnly=yes"]
        if self.known_hosts_file is not None:
            value = str(self.known_hosts_file).replace("\\", "\\\\").replace('"', '\\"')
            argv += ["-o", 'UserKnownHostsFile="' + value + '"']
        return [*argv, "--", target, command]

    def run(self, target: str, root: str, *, python: str, config_path: str | None = None,
            max_seconds: int = 30, max_files: int = 100, cancel=None) -> dict:
        root = _remote_path(root, allow_root=True)
        if type(max_seconds) is not int or not 1 <= max_seconds <= 120 or type(max_files) is not int or not 1 <= max_files <= 1000:
            raise HostError("remote-limit-invalid")
        if config_path is not None:
            config_path = _remote_path(config_path)
        request = {"version": 1, "root": root, "config_path": config_path, "max_seconds": max_seconds, "max_files": max_files}
        output = _exchange(self._command(target, python, _SCAN_SUPERVISOR), json.dumps(request).encode(),
                           timeout=max_seconds + 45, maximum=4_500_000, cancel=cancel)
        try:
            try:
                from leakguard_core.api import parse_report
            except ImportError:
                # Compatibility during the alpha's coordinated core rollout.
                from leakguard_core.scan_store import _report_from
                def unique(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value:
                            raise ValueError()
                        value[key] = item
                    return value
                report = _report_from(json.loads(output, object_pairs_hook=unique))
            else:
                report = parse_report(output, max_bytes=4_500_000)
            return {"target": _target(target), "root": root, "report": report.to_dict(),
                    "persistence": "memory-only",
                    "coverage": "complete" if report.coverage.required_complete and report.coverage.enumeration_complete else "incomplete"}
        except Exception:
            raise HostError("remote-report-invalid") from None

    def upload(self, target: str, artifact: Path, remote_directory: str, *, sha256: str, python: str = "python3", cancel=None) -> dict:
        """Transfer exactly one chosen ZIP into a NEW, private remote directory."""
        remote_directory = _remote_path(remote_directory)
        if not isinstance(artifact, Path) or artifact.is_symlink() or not artifact.is_file() or artifact.suffix.lower() != ".zip" or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise HostError("artifact-invalid")
        try:
            with artifact.open("rb") as stream:
                data = stream.read(536_870_913)
        except OSError:
            raise HostError("artifact-unreadable") from None
        if len(data) > 536_870_912 or hashlib.sha256(data).hexdigest() != sha256:
            raise HostError("artifact-hash-invalid")
        output = _exchange(self._command(target, python, _UPLOAD, (remote_directory, sha256, str(len(data)))), data,
                           timeout=300, maximum=4096, cancel=cancel)
        try:
            receipt = json.loads(output)
            if receipt != {"version": 1, "uploaded": True, "sha256": sha256, "bytes": len(data)}:
                raise ValueError()
        except (ValueError, TypeError, UnicodeError):
            raise HostError("remote-receipt-invalid") from None
        return {**receipt, "target": _target(target), "remote_directory": remote_directory,
                "artifact": remote_directory + "/release.zip", "installed": False}

    def install(self, target: str, remote_directory: str, *, sha256: str, python: str = "python3", cancel=None) -> dict:
        """Explicitly install an uploaded offline bundle within its private root."""
        remote_directory = _remote_path(remote_directory)
        if type(sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise HostError("artifact-hash-invalid")
        output = _exchange(self._command(target, python, _INSTALL, (remote_directory, sha256)), b"",
                           timeout=330, maximum=65_536, cancel=cancel)
        try:
            value = json.loads(output)
            fields = {"installed", "active", "release_version", "source_commit", "runtime_python", "buddy_command", "state_dir"}
            if type(value) is not dict or set(value) != fields or value["active"] is not True:
                raise ValueError()
            for key in fields - {"active", "source_commit"}:
                if type(value[key]) is not str or len(value[key]) > 4096:
                    raise ValueError()
            if value["source_commit"] is not None and (type(value["source_commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", value["source_commit"])):
                raise ValueError()
            for key in ("installed", "runtime_python", "buddy_command"):
                if not PurePosixPath(_remote_path(value[key])).is_relative_to(PurePosixPath(remote_directory) / "runtime"):
                    raise ValueError()
            if _remote_path(value["state_dir"]) != remote_directory + "/state":
                raise ValueError()
        except (ValueError, TypeError, UnicodeError, HostError):
            raise HostError("remote-receipt-invalid") from None
        return {"target": _target(target), "remote_directory": remote_directory, "installed": True,
                "sha256": sha256, "receipt": value}

    def deploy(self, target: str, artifact: Path, remote_directory: str, *, sha256: str, python: str = "python3",
               scan_root: str | None = None, max_seconds: int = 30, max_files: int = 100, cancel=None) -> dict:
        """Upload AND install only after this explicit deploy action."""
        if scan_root is not None:
            scan_root = _remote_path(scan_root, allow_root=True)
            if type(max_seconds) is not int or not 1 <= max_seconds <= 120 or type(max_files) is not int or not 1 <= max_files <= 1000:
                raise HostError("remote-limit-invalid")
        self.upload(target, artifact, remote_directory, sha256=sha256, python=python, cancel=cancel)
        result = self.install(target, remote_directory, sha256=sha256, python=python, cancel=cancel)
        if scan_root is not None:
            receipt = result["receipt"]
            try:
                result["scan"] = self.run(target, scan_root, python=receipt["runtime_python"],
                    config_path=receipt["state_dir"] + "/config.json", max_seconds=max_seconds, max_files=max_files, cancel=cancel)
            except HostError as error:
                # Installation has already succeeded; retain its reviewable
                # receipt even if the subsequent bounded scan cannot run.
                result["scan"] = {"coverage": "incomplete", "error": error.code, "persistence": "memory-only"}
        return result
