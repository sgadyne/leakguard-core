"""Owned loopback SSH transport receipt; never a claim about external hosts.

Run from a private runtime with core/host installed. All keys are synthetic and
the exact temporary daemon is always stopped. No global ssh configuration changes.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import zipfile

from leakguard_host import HostError, SSHRunner


def main():
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    root = Path(sys.argv[1]).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("host", "client"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)], check=True)
    (root / "authorized_keys").write_bytes((root / "client.pub").read_bytes())
    (root / "authorized_keys").chmod(0o600)
    with socket.socket() as socket_for_port:
        socket_for_port.bind(("127.0.0.1", 0))
        port = socket_for_port.getsockname()[1]
    public = " ".join((root / "host.pub").read_text().split()[:2])
    known = root / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {public}\n")
    known.chmod(0o600)
    config = root / "sshd_config"
    config.write_text(f'''Port {port}
ListenAddress 127.0.0.1
HostKey {root / 'host'}
PidFile {root / 'sshd.pid'}
AuthorizedKeysFile {root / 'authorized_keys'}
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
AllowUsers {getpass.getuser()}
StrictModes yes
LogLevel ERROR
''')
    source = root / "source"
    source.mkdir()
    value = "SYNTHETIC_SSH_TRANSPORT_55980c28c60e456a"
    (source / "example.txt").write_text(f'password = "{value}"\n')
    original = hashlib.sha256((source / "example.txt").read_bytes()).hexdigest()
    scan_config = root / "scan-config.json"
    scan_config.write_text(json.dumps({"gitleaks_executable": str(Path(sys.argv[2]).resolve())}))
    bundle = root / "synthetic-release.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("LeakGuard/release.json", "{}")
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    target = getpass.getuser() + "@127.0.0.1"
    runner = SSHRunner(port=port, identity_file=root / "client", known_hosts_file=known)
    with (root / "sshd.log").open("wb") as log:
        process = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], stdout=subprocess.DEVNULL,
                                   stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError("owned-sshd-unavailable")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned-sshd-timeout")
                    time.sleep(0.05)
            result = runner.run(target, str(source), python=str(Path(sys.executable).absolute()),
                                config_path=str(scan_config), max_seconds=10, max_files=10)
            assert result["coverage"] == "complete", result["coverage"]
            assert result["report"]["counts"]["findings"] == 1
            assert value not in json.dumps(result)
            upload = runner.upload(target, bundle, str(root / "uploaded"), sha256=digest)
            assert upload["uploaded"] and not upload["installed"]
            assert hashlib.sha256((root / "uploaded/release.zip").read_bytes()).hexdigest() == digest
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    assert hashlib.sha256((source / "example.txt").read_bytes()).hexdigest() == original
    # Secret test keys have no continued purpose after this bounded receipt.
    (root / "client").unlink()
    (root / "host").unlink()
    print(json.dumps({"ssh_loopback": "passed", "external_ssh": "unverified", "redacted_findings": 1,
                      "upload_hash": "verified", "source_unchanged": True, "daemon_stopped": process.poll() is not None,
                      "platform": sys.platform}, sort_keys=True))


if __name__ == "__main__":
    main()
