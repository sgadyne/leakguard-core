"""Build and exercise the broker's public wheel-installed CLI.

Run with the approved heavy admission wrapper, for example:
  python3 /path/to/run-heavy.py testing -- python3.11 tools/installed_acceptance.py

The child mode intentionally imports the installed wheel only. Synthetic TLS
fixture code stays in the parent runner and never imports broker internals.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import pty
import select
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import sysconfig
import tempfile
import time
import zipfile


_MASTER = "lg-test-only-master-passphrase-4b2f"
_MARKER = "lg-test-only-credential-7f3c6a9e-do-not-use"


def _run(command: list[str], *, cwd: Path | None = None, env=None, capture=False, timeout=600, check=True, input_text=None):
    return subprocess.run(
        command, cwd=cwd, env=env, check=check, text=True, timeout=timeout,
        capture_output=capture, input=input_text,
    )


def _run_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "control" / "dispatch.json").is_file():
            return parent
    raise RuntimeError("run root not found")


def _fingerprint(cert_path: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    return hashlib.sha256(der).hexdigest()


def _project_python_identity(source_roots: dict[str, Path], wheels: list[Path], installed_root: Path) -> dict:
    """Compare each shipped project module byte-for-byte across source, wheel, and venv."""
    wheel_by_module = {}
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            modules = [
                name[:-len("/__init__.py")]
                for name in archive.namelist()
                if name.endswith("/__init__.py") and name.count("/") == 1
            ]
            for module in modules:
                if module in source_roots:
                    if module in wheel_by_module:
                        raise RuntimeError("duplicate local project wheel")
                    wheel_by_module[module] = wheel

    if set(wheel_by_module) != set(source_roots):
        raise RuntimeError("local project wheel selection mismatch")

    report = {}
    for module, source_root in source_roots.items():
        source_files = {
            f"{module}/{path.relative_to(source_root).as_posix()}": path.read_bytes()
            for path in source_root.rglob("*.py")
        }
        if not source_files:
            raise RuntimeError("empty project source tree")
        wheel = wheel_by_module[module]
        with zipfile.ZipFile(wheel) as archive:
            wheel_files = {
                name: archive.read(name)
                for name in archive.namelist()
                if name.startswith(module + "/") and name.endswith(".py")
            }
        installed_package = installed_root / module
        installed_files = {
            f"{module}/{path.relative_to(installed_package).as_posix()}": path.read_bytes()
            for path in installed_package.rglob("*.py")
        } if installed_package.is_dir() else {}

        source_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in source_files.items()}
        wheel_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in wheel_files.items()}
        installed_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in installed_files.items()}
        report[module] = {
            "wheel": wheel.name,
            "python_file_count": len(source_files),
            "source_sha256": source_hashes,
            "wheel_sha256": wheel_hashes,
            "installed_sha256": installed_hashes,
            "source_equals_wheel": source_hashes == wheel_hashes,
            "wheel_equals_installed": wheel_hashes == installed_hashes,
        }
    return report


def _pty_until(master_fd: int, marker: bytes, timeout: float = 10) -> bytes:
    output = bytearray()
    deadline = time.monotonic() + timeout
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("admin terminal prompt timeout")
        ready, _, _ = select.select([master_fd], [], [], remaining)
        if not ready:
            raise TimeoutError("admin terminal prompt timeout")
        try:
            chunk = os.read(master_fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    if marker not in output:
        raise RuntimeError("admin terminal closed before expected prompt")
    return bytes(output)


def _spawn_admin_tty(
    vpy: Path, admin_executable: Path, socket_path: str, env: dict[str, str],
    cwd: Path,
) -> tuple[int, int]:
    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(cwd)
            os.execve(
                str(vpy), [str(vpy), "-I", str(admin_executable), "shell", "--socket", socket_path], env,
            )
        except BaseException:
            os._exit(127)
    return pid, master_fd


class _AdminSocketSession:
    """One synthetic operator stream, kept open until daemon shutdown."""

    def __init__(self, socket_path: Path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect(str(socket_path))
        self.reader = self.sock.makefile("rb")

    def call(self, request: dict) -> dict:
        self.sock.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        line = self.reader.readline(131073)
        if not line or not line.endswith(b"\n"):
            raise RuntimeError("installed daemon admin response missing")
        result = json.loads(line)
        if type(result) is not dict:
            raise RuntimeError("installed daemon admin response invalid")
        return result

    def close(self) -> None:
        try:
            self.reader.close()
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def _finish_admin_tty(
    pid: int, master_fd: int, timeout: float = 10, *, send_eof: bool = False,
    output: bytearray | None = None,
) -> int:
    if send_eof:
        try:
            os.write(master_fd, b"\x04")
        except OSError:
            pass
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master_fd], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master_fd, 4096)
                if output is not None:
                    output.extend(chunk)
            except OSError:
                pass
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            os.close(master_fd)
            return 0
        if waited:
            os.close(master_fd)
            return os.waitstatus_to_exitcode(status)
    os.close(master_fd)
    os.kill(pid, signal.SIGTERM)
    _, status = os.waitpid(pid, 0)
    raise TimeoutError(f"admin terminal child timed out (exit {os.waitstatus_to_exitcode(status)})")


def _json_lines(output: bytes) -> list[dict]:
    values = []
    decoder = json.JSONDecoder()
    for line in output.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        # input(prompt) writes its prompt to stdout even when stdin is piped,
        # so a status JSON row can begin with ``leakguard-admin> ``. Parse the
        # first object on each line without accepting arbitrary exception text.
        start = line.find("{")
        if start >= 0:
            try:
                value, _ = decoder.raw_decode(line[start:])
            except json.JSONDecodeError:
                continue
            if type(value) is dict:
                values.append(value)
    return values


def _child(config_path: Path) -> int:
    import leakguard_broker
    import leakguard_core
    import leakguard_vault
    from leakguard_broker.provider import VaultProvider
    from leakguard_broker.server import Broker, server_tls

    config = json.loads(config_path.read_text())

    async def run_child() -> None:
        vault_path = Path(config["vault_path"])
        provider = VaultProvider(vault_path)
        provider.create(_MASTER)
        entry = provider.put(title="synthetic installed acceptance", secret=_MARKER)
        provider.lock()
        client_fingerprint = _fingerprint(Path(config["client_cert"]))
        policy = {
            "schema": 1,
            "principals": {client_fingerprint: "wheel-agent"},
            "max_unlock_seconds": 120,
            "bindings": [{
                "id": "synthetic-binding",
                "label": "Synthetic test service",
                "tags": ["test", "synthetic"],
                "environment": "test",
                "credential_ref": entry["id"],
                "origin": config["upstream_origin"],
                "auth": {"kind": "bearer"},
                "rules": [{"method": "GET", "prefix": "/"}],
                "allowed_cidrs": ["127.0.0.0/8"],
                "max_body_bytes": 1048576,
                "max_response_bytes": 8388608,
                "timeout_seconds": 5,
                "ca_file": config["upstream_ca"],
            }],
        }
        broker = Broker(policy, vault_path)
        await broker.start(
            admin_socket=Path(config["admin_socket"]),
            host="127.0.0.1", port=0,
            tls=server_tls(config["broker_cert"], config["broker_key"], config["inbound_ca"]),
        )
        admin_reader, admin_writer = await asyncio.open_unix_connection(config["admin_socket"])

        async def admin(request: dict) -> dict:
            admin_writer.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
            await admin_writer.drain()
            line = await asyncio.wait_for(admin_reader.readline(), 5)
            return json.loads(line)

        unlocked = await admin({"op": "unlock", "passphrase": _MASTER, "ttl": 60})
        if unlocked.get("ok") is not True:
            raise RuntimeError("synthetic admin unlock failed")
        grant = await admin({
            "op": "grant.create", "principal": "wheel-agent",
            "bindings": ["synthetic-binding"], "ttl": 45, "max_requests": 10,
        })
        if grant.get("ok") is not True:
            raise RuntimeError("synthetic grant creation failed")
        print(json.dumps({
            "ready": True, "port": broker.port,
            "grant_id": grant["result"]["grant_id"],
            "entry_id": entry["id"],
            "installed_module": str(Path(leakguard_broker.__file__).resolve()),
            "installed_module_paths": {
                "leakguard_broker": str(Path(leakguard_broker.__file__).resolve()),
                "leakguard_vault": str(Path(leakguard_vault.__file__).resolve()),
                "leakguard_core": str(Path(leakguard_core.__file__).resolve()),
            },
            "site_packages": str(Path(sysconfig.get_paths()["purelib"]).resolve()),
            "package_version": importlib.metadata.version("leakguard-broker"),
            "installed_versions": {
                name: importlib.metadata.version(name)
                for name in ("leakguard-core", "leakguard-vault", "leakguard-broker", "aiohttp", "cryptography")
            },
            "python": platform.python_version(),
        }), flush=True)

        # Keep the sole admin connection open for the public CLI round trip.
        await asyncio.to_thread(sys.stdin.readline)
        admin_writer.close()
        await admin_writer.wait_closed()
        await asyncio.sleep(0.1)
        print(json.dumps({"revoked_by_admin_eof": True}), flush=True)
        await asyncio.to_thread(sys.stdin.readline)
        await broker.close()
        print(json.dumps({"stopped": True}), flush=True)

    try:
        asyncio.run(run_child())
        return 0
    except BaseException:
        # Never write exception text from the broker/vault into acceptance logs.
        sys.stderr.write("installed acceptance child failed\n")
        return 2


def _main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        return _child(Path(sys.argv[2]))

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, help="new private directory outside the source checkout")
    args = parser.parse_args()
    root = _run_root()
    repo = Path(os.environ.get("LEAKGUARD_BROKER_SOURCE_ROOT", Path(__file__).resolve().parents[1])).resolve()
    fixture_root = Path(__file__).resolve().parents[1]
    artifact_root = (args.artifact_dir.absolute() if args.artifact_dir else
                     root / "control" / "artifacts" / "testing-installed")
    if artifact_root.resolve().is_relative_to(repo):
        raise SystemExit("artifact-dir-inside-source")
    artifact_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    wheel_dir = artifact_root / "wheels"
    wheel_dir.mkdir()
    venv = artifact_root / "venv"
    uv = Path(os.environ.get("LEAKGUARD_BROKER_UV", shutil.which("uv") or "uv"))
    lock_path = repo / "packages" / "leakguard_broker" / "requirements-py311.lock"
    receipt_path = artifact_root / "receipt.json"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt = {
        "schema": 1,
        "status": "running",
        "assignment_version": 4,
        "source_commit": None,
        "source_dirty": None,
        "source_status": [],
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "commands": [],
        "execution_context": [],
        "wheels": [],
        "dependency_lock": None,
        "installed_versions": {},
        "installed_module_paths": {},
        "assertions": {},
        "untested_limits": [
            "This synthetic installed run does not exercise real upstreams, real credentials, or non-loopback routing.",
            "It is one Linux/Python 3.11 run and does not establish cross-platform wheel behavior.",
        ],
    }

    def record_execution_context(command: list[str], *, cwd: Path, environment: dict[str, str]):
        receipt["execution_context"].append({
            "cwd": str(cwd.resolve()),
            "python_isolated": "-I" in command,
            "pythonpath_present": "PYTHONPATH" in environment,
            "cwd_outside_source": not cwd.resolve().is_relative_to(repo),
        })

    def record(command: list[str], **kwargs):
        receipt["commands"].append(command)
        cwd = Path(kwargs["cwd"]) if kwargs.get("cwd") else artifact_root
        environment = kwargs.get("env", os.environ)
        if isinstance(environment, dict):
            record_execution_context(command, cwd=cwd, environment=environment)
        return _run(command, **kwargs)

    temp = None
    socket_temp = None
    child = None
    daemon_processes = []
    daemon_operator = None
    stage = "start"
    return_code = 1
    cleanup_issues = []
    try:
        receipt["source_commit"] = _run(["git", "rev-parse", "HEAD"], cwd=repo, capture=True).stdout.strip()
        source_status = _run(
            ["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo, capture=True,
        ).stdout.splitlines()
        receipt["source_status"] = source_status
        receipt["source_dirty"] = bool(source_status)
        lock_lines = [line.strip() for line in lock_path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
        lock_versions = {line.split("==", 1)[0].lower().replace("_", "-"): line.split("==", 1)[1] for line in lock_lines}
        receipt["dependency_lock"] = {
            "file": str(lock_path),
            "sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            "packages": lock_versions,
        }
        receipt["runtime_lock_sha256"] = receipt["dependency_lock"]["sha256"]
        stage = "build-wheels"
        for package in (repo, repo / "packages" / "leakguard_vault", repo / "packages" / "leakguard_broker"):
            record([str(uv), "build", "--wheel", "--out-dir", str(wheel_dir), str(package)], cwd=artifact_root)
        receipt["wheels"] = [
            {"file": path.name, "path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(wheel_dir.glob("*.whl"))
        ]
        if len(receipt["wheels"]) != 3:
            raise RuntimeError("expected three project wheels")
        stage = "install-clean-venv"
        record([str(uv), "venv", "--clear", str(venv), "--python", "/usr/bin/python3.11"], cwd=artifact_root)
        vpy = venv / "bin" / "python"
        uv_cache = Path(tempfile.mkdtemp(prefix="uv-cache-", dir=artifact_root))
        install_env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
        install_env["UV_CACHE_DIR"] = str(uv_cache.resolve())
        receipt["uv_cache_dir"] = str(uv_cache.resolve())
        local_wheels = [Path(item["path"]) for item in receipt["wheels"]]
        record([
            str(uv), "pip", "install", "--python", str(vpy),
            "--no-index", "--no-deps", "--no-cache", *map(str, local_wheels),
        ], cwd=artifact_root, env=install_env)
        record([
            str(uv), "pip", "install", "--python", str(vpy), "--no-cache",
            "--requirements", str(lock_path),
        ], cwd=artifact_root, env=install_env)
        record([str(uv), "pip", "check", "--python", str(vpy)], cwd=artifact_root)
        versions = record([
            str(vpy), "-I", "-c",
            "import importlib.metadata as m,json; "
            "print(json.dumps({d.metadata.get('Name','').lower().replace('_','-'):d.version "
            "for d in m.distributions()}, sort_keys=True))",
        ], cwd=artifact_root, capture=True)
        installed_lock = json.loads(versions.stdout)
        if type(installed_lock) is not dict or any(type(value) is not str for value in installed_lock.values()):
            raise RuntimeError("installed distribution metadata probe was invalid")
        receipt["installed_lock_packages"] = installed_lock
        receipt["installed_versions"] = installed_lock
        if installed_lock != lock_versions:
            raise RuntimeError("clean venv package set differs from the pinned runtime lock")
        receipt["assertions"]["installed_runtime_lock_exact"] = True

        stage = "installed-wheel-source-identity"
        purelib_result = record([
            str(vpy), "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])",
        ], cwd=artifact_root, capture=True)
        purelib = Path(purelib_result.stdout.strip()).resolve()
        source_roots = {
            "leakguard_core": repo / "src" / "leakguard_core",
            "leakguard_vault": repo / "packages" / "leakguard_vault" / "src" / "leakguard_vault",
            "leakguard_broker": repo / "packages" / "leakguard_broker" / "src" / "leakguard_broker",
        }
        receipt["project_python_identity"] = _project_python_identity(source_roots, local_wheels, purelib)
        if any(
            not item["source_equals_wheel"] or not item["wheel_equals_installed"]
            for item in receipt["project_python_identity"].values()
        ):
            raise RuntimeError("installed project Python files differ from source-built wheels")
        receipt["assertions"]["all_project_python_source_wheel_installed_bytes_equal"] = True

        runtime_env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}
        receipt["isolated_runtime"] = {
            "python": str(vpy),
            "flags": ["-I"],
            "pythonpath_cleared": "PYTHONPATH" not in runtime_env,
            "working_directory": str(artifact_root.resolve()),
            "working_directory_outside_source": not artifact_root.resolve().is_relative_to(repo),
        }

        # Keep only disposable PKI and config in a temporary run-local directory.
        temp = tempfile.TemporaryDirectory(prefix="installed-pki-", dir=artifact_root)
        pki_dir = Path(temp.name)
        test_dir = fixture_root / "packages" / "leakguard_broker" / "tests"
        sys.path.insert(0, str(test_dir))
        from tls_fixtures import SyntheticHttpsWitness, SyntheticPKI

        stage = "synthetic-tls-fixtures"
        pki = SyntheticPKI(pki_dir / "pki")
        with SyntheticHttpsWitness(pki.upstream_server) as upstream:
            run_dir = pki_dir / "run"
            run_dir.mkdir(mode=0o700)
            socket_temp = tempfile.TemporaryDirectory(prefix="lgbr-", dir="/tmp")
            socket_dir = Path(socket_temp.name)
            config_path = run_dir / "child-config.json"
            config = {
                "vault_path": str(run_dir / "vault.lgv"),
                "admin_socket": str(socket_dir / "admin.sock"),
                "broker_cert": str(pki.broker_server.cert),
                "broker_key": str(pki.broker_server.key),
                "inbound_ca": str(pki.inbound_ca.ca_cert),
                "client_cert": str(pki.client.cert),
                "upstream_ca": str(pki.upstream_ca.ca_cert),
                "upstream_origin": upstream.origin,
            }
            config_path.write_text(json.dumps(config))
            child_env = dict(runtime_env)
            child_command = [str(vpy), "-I", str(Path(__file__).resolve()), "--child", str(config_path)]
            receipt["commands"].append(child_command)
            receipt["execution_context"].append({
                "cwd": str(run_dir.resolve()), "python_isolated": True,
                "pythonpath_present": False, "cwd_outside_source": not run_dir.resolve().is_relative_to(repo),
            })
            child = subprocess.Popen(
                child_command,
                cwd=run_dir, env=child_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1,
            )
            stage = "installed-broker-readiness"
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                if not selector.select(30):
                    raise TimeoutError("installed broker readiness timeout")
                ready_line = child.stdout.readline()
            ready = json.loads(ready_line) if ready_line else {}
            if ready.get("ready") is not True:
                raise RuntimeError("installed broker did not become ready")
            site_packages = Path(ready["site_packages"]).resolve()
            if not site_packages.is_relative_to(venv):
                raise RuntimeError("isolated interpreter site-packages escaped the clean venv")
            module_paths = {name: Path(path).resolve() for name, path in ready["installed_module_paths"].items()}
            if set(module_paths) != {"leakguard_broker", "leakguard_vault", "leakguard_core"}:
                raise RuntimeError("installed module path probe was incomplete")
            if any(not path.is_relative_to(site_packages) for path in module_paths.values()):
                raise RuntimeError("child imported a project module outside installed site-packages")
            module_path = module_paths["leakguard_broker"]
            receipt["installed_module_paths"] = {name: str(path) for name, path in module_paths.items()}
            receipt["installed_site_packages"] = str(site_packages)
            grant_id = ready["grant_id"]
            client_env = dict(runtime_env)
            client_env.update({
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "HTTP_PROXY": "http://127.0.0.1:1",
                "http_proxy": "http://127.0.0.1:1",
                "ALL_PROXY": "http://127.0.0.1:1",
                "all_proxy": "http://127.0.0.1:1",
                "NO_PROXY": "",
                "no_proxy": "",
            })
            agent = str(venv / "bin" / "leakguard-agent")
            common = [
                str(vpy), "-I", agent, "--url", f"https://127.0.0.1:{ready['port']}",
                "--ca", str(pki.inbound_ca.ca_cert),
                "--cert", str(pki.client.cert), "--key", str(pki.client.key),
            ]
            good_command = common + [
                "request", "--grant", grant_id, "--binding", "synthetic-binding",
                "--method", "GET", "--path", "/wheel-roundtrip",
            ]
            stage = "installed-public-cli-roundtrip"
            result = record(good_command, cwd=run_dir, env=client_env, capture=True, timeout=30)
            if result.returncode != 0 or b"wheel-roundtrip" not in result.stdout.encode():
                raise RuntimeError("installed public CLI roundtrip failed")
            if _MARKER in result.stdout or _MARKER in result.stderr:
                raise RuntimeError("synthetic auth marker reached CLI output")
            witness = upstream.snapshot()
            if len(witness) != 1 or witness[0]["headers"].get("authorization") != f"Bearer {_MARKER}":
                raise RuntimeError("upstream witness did not observe exactly one brokered credential request")
            receipt["assertions"]["installed_public_cli_broker_upstream_roundtrip"] = True
            receipt["assertions"]["upstream_received_synthetic_auth"] = True
            receipt["assertions"]["client_proxy_environment_ignored"] = True
            receipt["installed_module"] = str(module_path)

            child.stdin.write("release\n")
            child.stdin.flush()
            revoked_line = child.stdout.readline()
            revoked = json.loads(revoked_line) if revoked_line else {}
            if revoked.get("revoked_by_admin_eof") is not True:
                raise RuntimeError("admin EOF was not acknowledged by installed broker child")
            denied = record(good_command, cwd=run_dir, env=client_env, capture=True, timeout=30, check=False)
            if denied.returncode == 0 or _MARKER in denied.stdout or _MARKER in denied.stderr:
                raise RuntimeError("grant remained usable after admin EOF")
            if len(upstream.snapshot()) != 1:
                raise RuntimeError("revoked CLI call reached synthetic upstream")
            receipt["assertions"]["admin_eof_invalidated_installed_cli_grant"] = True

            stage = "installed-admin-shell-pty"
            admin_executable = venv / "bin" / "leakguard-admin"

            def spawn_installed_admin_tty():
                command = [
                    str(vpy), "-I", str(admin_executable), "shell", "--socket", config["admin_socket"],
                ]
                receipt["commands"].append(command)
                record_execution_context(command, cwd=run_dir, environment=client_env)
                return _spawn_admin_tty(
                    vpy, admin_executable, config["admin_socket"], client_env, run_dir,
                )

            def installed_admin_status():
                status_command = [
                    str(vpy), "-I", str(admin_executable), "shell", "--socket", config["admin_socket"],
                ]
                result = record(
                    status_command, cwd=run_dir, env=runtime_env, capture=True,
                    timeout=15, input_text="status\nquit\n",
                )
                rows = [row for row in _json_lines(result.stdout.encode()) if "unlocked" in row]
                if result.returncode != 0 or not rows:
                    raise RuntimeError("installed admin status command failed")
                return rows[-1]

            admin_pid, admin_fd = spawn_installed_admin_tty()
            terminal_output = bytearray(_pty_until(admin_fd, b"leakguard-admin> "))
            stage = "installed-admin-getpass-unlock"
            os.write(admin_fd, b"unlock 60\n")
            terminal_output.extend(_pty_until(admin_fd, b"Vault passphrase: "))
            os.write(admin_fd, _MASTER.encode() + b"\n")
            terminal_output.extend(_pty_until(admin_fd, b"leakguard-admin> "))
            stage = "installed-admin-create-grant"
            os.write(admin_fd, b"grant create wheel-agent 30 10 synthetic-binding\n")
            terminal_output.extend(_pty_until(admin_fd, b"leakguard-admin> "))
            grant_rows = [row for row in _json_lines(bytes(terminal_output)) if "grant_id" in row]
            if not grant_rows:
                raise RuntimeError("installed admin shell did not return a grant id")
            shell_grant = grant_rows[-1]["grant_id"]
            if _MASTER.encode() in terminal_output or _MARKER.encode() in terminal_output:
                raise RuntimeError("getpass output contained a synthetic secret")
            if b"Warning: Password input may be echoed" in terminal_output:
                raise RuntimeError("getpass warned that entered text may be echoed")
            process_root = Path(f"/proc/{admin_pid}")
            process_args = (process_root / "cmdline").read_bytes()
            process_env = (process_root / "environ").read_bytes()
            if _MASTER.encode() in process_args or _MARKER.encode() in process_args:
                raise RuntimeError("a synthetic secret appeared in admin argv")
            if _MASTER.encode() in process_env or _MARKER.encode() in process_env:
                raise RuntimeError("a synthetic secret appeared in admin environment")
            for item in run_dir.rglob("*"):
                if item.is_file():
                    contents = item.read_bytes()
                    if _MASTER.encode() in contents or _MARKER.encode() in contents:
                        raise RuntimeError("a synthetic secret appeared in a regular artifact file")

            shell_cli = common + [
                "request", "--grant", shell_grant, "--binding", "synthetic-binding",
                "--method", "GET", "--path", "/wheel-admin-roundtrip",
            ]
            stage = "installed-admin-issued-cli-roundtrip"
            shell_roundtrip = record(shell_cli, cwd=run_dir, env=client_env, capture=True, timeout=30)
            if (shell_roundtrip.returncode != 0 or "/wheel-admin-roundtrip" not in shell_roundtrip.stdout or
                    _MARKER in shell_roundtrip.stdout or _MARKER in shell_roundtrip.stderr):
                raise RuntimeError("agent CLI could not use the installed admin shell grant")
            if len(upstream.snapshot()) != 2:
                raise RuntimeError("expected exactly two installed CLI upstream requests")
            receipt["assertions"]["installed_admin_getpass_not_argv_env_disk_or_output"] = True
            receipt["assertions"]["installed_admin_created_usable_grant"] = True

            stage = "installed-admin-shell-eof"
            admin_exit = _finish_admin_tty(admin_pid, admin_fd, send_eof=True)
            admin_pid = admin_fd = None
            if admin_exit != 0:
                raise RuntimeError("installed admin shell did not exit cleanly on terminal EOF")
            receipt["assertions"]["installed_admin_shell_eof"] = True
            denied = record(shell_cli, cwd=run_dir, env=client_env, capture=True, timeout=30, check=False)
            if denied.returncode == 0 or _MARKER in denied.stdout or _MARKER in denied.stderr:
                raise RuntimeError("installed admin shell EOF left its grant usable")
            if len(upstream.snapshot()) != 2:
                raise RuntimeError("post-EOF installed CLI call reached synthetic upstream")
            receipt["assertions"]["admin_eof_invalidated_installed_cli_grant"] = True

            # Start from a fresh active admin session so the credential prompt
            # test proves that EOF revokes real, previously usable authority.
            stage = "installed-credential-prompt-eof-setup"
            active_pid, active_fd = spawn_installed_admin_tty()
            active_output = bytearray(_pty_until(active_fd, b"leakguard-admin> "))
            os.write(active_fd, b"unlock 60\n")
            active_output.extend(_pty_until(active_fd, b"Vault passphrase: "))
            os.write(active_fd, _MASTER.encode() + b"\n")
            active_output.extend(_pty_until(active_fd, b"leakguard-admin> "))
            os.write(active_fd, b"grant create wheel-agent 30 10 synthetic-binding\n")
            active_output.extend(_pty_until(active_fd, b"leakguard-admin> "))
            active_grant_rows = [row for row in _json_lines(bytes(active_output)) if "grant_id" in row]
            if not active_grant_rows:
                raise RuntimeError("active-authority EOF setup did not return a grant id")
            active_grant = active_grant_rows[-1]["grant_id"]
            active_cli = common + [
                "request", "--grant", active_grant, "--binding", "synthetic-binding",
                "--method", "GET", "--path", "/wheel-before-credential-prompt-eof",
            ]
            active_before = record(active_cli, cwd=run_dir, env=client_env, capture=True, timeout=30)
            if (active_before.returncode != 0 or
                    "/wheel-before-credential-prompt-eof" not in active_before.stdout or
                    _MARKER in active_before.stdout or _MARKER in active_before.stderr):
                raise RuntimeError("active-authority EOF grant was not usable before secret prompt")
            if len(upstream.snapshot()) != 3:
                raise RuntimeError("active-authority setup did not produce one witnessed upstream request")
            receipt["assertions"]["credential_prompt_eof_grant_usable_before_eof"] = True
            receipt["credential_prompt_eof_evidence"] = {
                "upstream_request_count_before_prompt": len(upstream.snapshot()),
                "active_grant_cli_returncode_before_prompt": active_before.returncode,
            }

            stage = "installed-credential-prompt-eof"
            os.write(active_fd, b"credential put Synthetic\n")
            active_output.extend(_pty_until(active_fd, b"Credential secret: "))
            os.write(active_fd, b"\x04")
            active_exit = _finish_admin_tty(active_pid, active_fd, output=active_output)
            active_pid = active_fd = None
            if active_exit != 0:
                raise RuntimeError("credential-prompt EOF did not exit the installed admin shell cleanly")
            if b"secret-input-cancelled" not in active_output:
                raise RuntimeError("credential-prompt EOF did not report safe cancellation")
            if _MASTER.encode() in active_output or _MARKER.encode() in active_output:
                raise RuntimeError("credential-prompt EOF output exposed a synthetic secret")
            receipt["assertions"]["installed_credential_prompt_eof_exits_admin"] = True
            receipt["credential_prompt_eof_evidence"].update({
                "secret_prompt_observed": b"Credential secret: " in active_output,
                "cancellation_code_observed": b"secret-input-cancelled" in active_output,
                "admin_exit_code": active_exit,
            })

            stage = "installed-credential-prompt-eof-revocation"
            after_eof = record(active_cli, cwd=run_dir, env=client_env, capture=True, timeout=30, check=False)
            if after_eof.returncode == 0 or _MARKER in after_eof.stdout or _MARKER in after_eof.stderr:
                raise RuntimeError("credential-prompt EOF left the existing grant usable")
            if len(upstream.snapshot()) != 3:
                raise RuntimeError("credential-prompt EOF revoked too late; old grant reached upstream")
            locked_status = installed_admin_status()
            if locked_status.get("unlocked") is not False or locked_status.get("grants") != 0:
                raise RuntimeError("credential-prompt EOF left broker vault unlocked or grants active")
            receipt["assertions"]["credential_prompt_eof_revoked_existing_grant"] = True
            receipt["assertions"]["credential_prompt_eof_no_extra_upstream_request"] = True
            receipt["assertions"]["credential_prompt_eof_broker_locked_no_grants"] = True
            receipt["credential_prompt_eof_evidence"].update({
                "old_grant_cli_returncode_after_eof": after_eof.returncode,
                "upstream_request_count_after_denied_attempt": len(upstream.snapshot()),
                "broker_locked_after_eof": locked_status["unlocked"] is False,
                "active_grants_after_eof": locked_status["grants"],
            })

            # EOF during the initial unlock prompt also terminates the shell
            # and leaves the locked broker available to a fresh admin session.
            stage = "installed-unlock-prompt-eof"
            eof_pid, eof_fd = spawn_installed_admin_tty()
            eof_output = bytearray(_pty_until(eof_fd, b"leakguard-admin> "))
            os.write(eof_fd, b"unlock 60\n")
            eof_output.extend(_pty_until(eof_fd, b"Vault passphrase: "))
            os.write(eof_fd, b"\x04")
            eof_exit = _finish_admin_tty(eof_pid, eof_fd, output=eof_output)
            eof_pid = eof_fd = None
            if eof_exit != 0:
                raise RuntimeError("unlock-prompt EOF did not exit the installed admin shell cleanly")
            if b"secret-input-cancelled" not in eof_output:
                raise RuntimeError("unlock-prompt EOF did not report safe cancellation")
            if _MASTER.encode() in eof_output or _MARKER.encode() in eof_output:
                raise RuntimeError("unlock-prompt EOF output exposed a synthetic secret")
            locked_after_unlock_eof = installed_admin_status()
            if locked_after_unlock_eof.get("unlocked") is not False or locked_after_unlock_eof.get("grants") != 0:
                raise RuntimeError("unlock-prompt EOF changed broker lock or grant state")
            receipt["assertions"]["installed_unlock_prompt_eof_exits_admin_locked"] = True
            receipt["unlock_prompt_eof_evidence"] = {
                "passphrase_prompt_observed": b"Vault passphrase: " in eof_output,
                "cancellation_code_observed": b"secret-input-cancelled" in eof_output,
                "admin_exit_code": eof_exit,
                "broker_locked_after_eof": locked_after_unlock_eof["unlocked"] is False,
                "active_grants_after_eof": locked_after_unlock_eof["grants"],
            }
            stage = "installed-broker-shutdown"
            child.stdin.write("stop\n")
            child.stdin.flush()
            child.wait(timeout=15)
            if child.returncode != 0:
                raise RuntimeError("installed broker child did not stop cleanly")
            child = None

            # Exercise the installed foreground daemon entrypoint as a real
            # process. It reuses only the synthetic vault, certificate chain,
            # and policy created above.
            stage = "installed-daemon-configure"
            daemon_request_baseline = len(upstream.snapshot())
            daemon_port_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            daemon_port_probe.bind(("127.0.0.1", 0))
            daemon_port = daemon_port_probe.getsockname()[1]
            daemon_port_probe.close()
            daemon_config_path = run_dir / "daemon-config.json"
            daemon_policy = {
                "schema": 1,
                "principals": {_fingerprint(pki.client.cert): "wheel-agent"},
                "max_unlock_seconds": 120,
                "bindings": [{
                    "id": "synthetic-binding",
                    "label": "Synthetic test service",
                    "tags": ["test", "synthetic"],
                    "environment": "test",
                    "credential_ref": ready["entry_id"],
                    "origin": upstream.origin,
                    "auth": {"kind": "bearer"},
                    "rules": [{"method": "GET", "prefix": "/"}],
                    "allowed_cidrs": ["127.0.0.0/8"],
                    "max_body_bytes": 1048576,
                    "max_response_bytes": 8388608,
                    "timeout_seconds": 5,
                    "ca_file": str(pki.upstream_ca.ca_cert),
                }],
            }
            daemon_config = {
                "policy": daemon_policy,
                "vault_path": config["vault_path"],
                "admin_socket": config["admin_socket"],
                "listen_host": "127.0.0.1",
                "listen_port": daemon_port,
                "server_cert": str(pki.broker_server.cert),
                "server_key": str(pki.broker_server.key),
                "client_ca": str(pki.inbound_ca.ca_cert),
            }
            daemon_config_path.write_text(json.dumps(daemon_config))
            daemon_executable = venv / "bin" / "leakguard-broker"
            daemon_command = [str(vpy), "-I", str(daemon_executable), "--config", str(daemon_config_path)]

            def start_installed_daemon():
                receipt["commands"].append(daemon_command)
                receipt["execution_context"].append({
                    "cwd": str(run_dir.resolve()), "python_isolated": True,
                    "pythonpath_present": False, "cwd_outside_source": not run_dir.resolve().is_relative_to(repo),
                })
                process = subprocess.Popen(
                    daemon_command, cwd=run_dir, env=runtime_env,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, bufsize=1,
                )
                daemon_processes.append(process)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    if not selector.select(20):
                        raise TimeoutError("installed daemon startup readiness timeout")
                    line = process.stdout.readline()
                if line.strip() != "broker-ready":
                    raise RuntimeError("installed daemon did not report readiness")
                return process

            stage = "installed-daemon-first-start"
            daemon_process = start_installed_daemon()
            first_status = installed_admin_status()
            if first_status.get("unlocked") is not False or first_status.get("grants") != 0:
                raise RuntimeError("installed daemon did not start locked")
            receipt["assertions"]["installed_daemon_startup"] = True
            receipt["assertions"]["installed_daemon_admin_status_locked"] = True

            stage = "installed-daemon-grant-and-roundtrip"
            daemon_operator = _AdminSocketSession(Path(config["admin_socket"]))
            unlock_response = daemon_operator.call({"op": "unlock", "passphrase": _MASTER, "ttl": 60})
            grant_response = daemon_operator.call({
                "op": "grant.create", "principal": "wheel-agent",
                "bindings": ["synthetic-binding"], "ttl": 45, "max_requests": 10,
            })
            if unlock_response.get("ok") is not True or grant_response.get("ok") is not True:
                raise RuntimeError("installed daemon synthetic grant setup failed")
            daemon_grant = grant_response["result"]["grant_id"]
            daemon_common = [
                str(vpy), "-I", agent,
                "--url", f"https://127.0.0.1:{daemon_port}",
                "--ca", str(pki.inbound_ca.ca_cert),
                "--cert", str(pki.client.cert), "--key", str(pki.client.key),
            ]
            daemon_cli = daemon_common + [
                "request", "--grant", daemon_grant, "--binding", "synthetic-binding",
                "--method", "GET", "--path", "/daemon-before-restart",
            ]
            daemon_roundtrip = record(
                daemon_cli, cwd=run_dir, env=client_env, capture=True, timeout=30,
            )
            if (daemon_roundtrip.returncode != 0 or "/daemon-before-restart" not in daemon_roundtrip.stdout or
                    _MARKER in daemon_roundtrip.stdout or _MARKER in daemon_roundtrip.stderr):
                raise RuntimeError("installed daemon-issued grant did not reach synthetic upstream")
            if len(upstream.snapshot()) != daemon_request_baseline + 1:
                raise RuntimeError("installed daemon did not produce exactly one witnessed request")
            receipt["assertions"]["installed_daemon_grant_usable_before_sigterm"] = True

            stage = "installed-daemon-sigterm"
            daemon_process.send_signal(signal.SIGTERM)
            daemon_process.wait(timeout=20)
            if daemon_process.returncode != 0:
                raise RuntimeError("installed daemon did not exit cleanly on SIGTERM")
            daemon_processes.remove(daemon_process)
            daemon_process = None
            receipt["assertions"]["installed_daemon_sigterm_clean_exit"] = True

            stage = "installed-daemon-restart-locked"
            daemon_process = start_installed_daemon()
            restart_status = installed_admin_status()
            if restart_status.get("unlocked") is not False or restart_status.get("grants") != 0:
                raise RuntimeError("installed daemon restart restored unlock or grant state")
            denied_restart = record(
                daemon_cli, cwd=run_dir, env=client_env, capture=True, timeout=30, check=False,
            )
            if (denied_restart.returncode == 0 or _MARKER in denied_restart.stdout or
                    _MARKER in denied_restart.stderr or len(upstream.snapshot()) != daemon_request_baseline + 1):
                raise RuntimeError("pre-restart installed grant was usable after daemon restart")
            receipt["assertions"]["installed_daemon_restarted"] = True
            receipt["assertions"]["installed_daemon_restart_status_locked"] = True
            receipt["assertions"]["installed_daemon_grant_not_resurrected"] = True
            daemon_operator.close()
            daemon_operator = None
            daemon_process.send_signal(signal.SIGTERM)
            daemon_process.wait(timeout=20)
            if daemon_process.returncode != 0:
                raise RuntimeError("restarted installed daemon did not exit cleanly")
            daemon_processes.remove(daemon_process)
            daemon_process = None
            receipt["assertions"]["installed_daemon_restart_sigterm_clean_exit"] = True

        receipt["status"] = "passed"
        receipt["completed_at_epoch"] = time.time()
    except BaseException as error:
        receipt["status"] = "failed"
        receipt["error_type"] = type(error).__name__
        receipt["failed_stage"] = stage
        receipt["completed_at_epoch"] = time.time()
        if "installed_public_cli_broker_upstream_roundtrip" not in receipt["assertions"]:
            receipt["untested_limits"].append("Installed wheel CLI to broker to upstream roundtrip did not complete.")
        if "installed_admin_shell_eof" not in receipt["assertions"]:
            receipt["untested_limits"].append("Wheel-installed admin shell EOF behavior did not complete.")
        if "credential_prompt_eof_revoked_existing_grant" not in receipt["assertions"]:
            receipt["untested_limits"].append(
                "Credential-prompt EOF while a grant was usable did not complete the existing-grant revocation proof."
            )
        if "installed_unlock_prompt_eof_exits_admin_locked" not in receipt["assertions"]:
            receipt["untested_limits"].append("Unlock-prompt EOF shell-exit and locked-state proof did not complete.")
        if "installed_daemon_grant_not_resurrected" not in receipt["assertions"]:
            receipt["untested_limits"].append("Installed daemon restart and grant non-resurrection smoke did not complete.")
        return_code = 1
    else:
        return_code = 0
    finally:
        if "admin_pid" in locals() and admin_pid is not None and admin_fd is not None:
            try:
                _finish_admin_tty(admin_pid, admin_fd, timeout=5, send_eof=True)
            except Exception:
                cleanup_issues.append("admin-pty")
        if "eof_pid" in locals() and eof_pid is not None and eof_fd is not None:
            try:
                _finish_admin_tty(eof_pid, eof_fd, timeout=5, send_eof=True)
            except Exception:
                cleanup_issues.append("getpass-pty")
        if "active_pid" in locals() and active_pid is not None and active_fd is not None:
            try:
                _finish_admin_tty(active_pid, active_fd, timeout=5, send_eof=True)
            except Exception:
                cleanup_issues.append("credential-prompt-eof-pty")
        if daemon_operator is not None:
            try:
                daemon_operator.close()
            except Exception:
                cleanup_issues.append("daemon-admin-socket")
        for process in list(daemon_processes):
            try:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=10)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except Exception:
                    cleanup_issues.append("daemon-process")
        if child is not None and child.poll() is None:
            try:
                child.stdin.write("stop\n")
                child.stdin.flush()
                child.wait(timeout=5)
            except Exception:
                try:
                    child.terminate()
                    child.wait(timeout=5)
                except Exception:
                    cleanup_issues.append("installed-child")
        if temp is not None:
            try:
                temp.cleanup()
            except Exception:
                cleanup_issues.append("synthetic-pki-artifacts")
        if socket_temp is not None:
            try:
                socket_temp.cleanup()
            except Exception:
                cleanup_issues.append("synthetic-admin-socket")
        if cleanup_issues:
            receipt["cleanup_issues"] = cleanup_issues
            receipt["status"] = "failed"
            receipt["error_type"] = "CleanupFailed"
            receipt["failed_stage"] = "cleanup"
            return_code = 1
        receipt["completed_at_epoch"] = time.time()
        receipt_temp = receipt_path.with_suffix(".json.tmp")
        receipt_temp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        os.replace(receipt_temp, receipt_path)
        print(f"installed acceptance: {receipt['status']} ({receipt_path})")
    return return_code


if __name__ == "__main__":
    raise SystemExit(_main())
