"""Independent, local-only TLS fixtures for the broker acceptance tests.

All keys and credentials created here are disposable test material.  The
fixtures use OpenSSL's command line so they do not depend on broker crypto
helpers or accidentally share its certificate-generation code.
"""

from __future__ import annotations

import http.server
import json
import pathlib
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any


SYNTHETIC_MARKER = "lg-test-only-credential-7f3c6a9e-do-not-use"


@dataclass(frozen=True)
class Certificate:
    cert: pathlib.Path
    key: pathlib.Path


class SyntheticCA:
    """Tiny independent CA that issues broker/client/upstream test leaves."""

    def __init__(self, directory: pathlib.Path, name: str) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ca_cert = directory / "ca.pem"
        self.ca_key = directory / "ca-key.pem"
        self._run(
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", str(self.ca_key), "-out", str(self.ca_cert),
            "-days", "2", "-sha256", "-subj", f"/CN={name}",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
        )
        self._init_ca_database()

    @staticmethod
    def _run(*args: str) -> None:
        executable = shutil.which("openssl")
        if not executable:
            raise RuntimeError("openssl is required for independent synthetic TLS fixtures")
        subprocess.run(
            [executable, *args], check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )

    def _init_ca_database(self) -> None:
        (self.directory / "newcerts").mkdir()
        (self.directory / "index.txt").write_text("")
        (self.directory / "serial").write_text("1000\n")
        self.ca_config = self.directory / "ca.cnf"
        self.ca_config.write_text(
            "\n".join(
                (
                    "[ ca ]",
                    "default_ca = local_ca",
                    "[ local_ca ]",
                    f"dir = {self.directory}",
                    "database = $dir/index.txt",
                    "new_certs_dir = $dir/newcerts",
                    "certificate = $dir/ca.pem",
                    "private_key = $dir/ca-key.pem",
                    "serial = $dir/serial",
                    "default_md = sha256",
                    "default_days = 2",
                    "policy = policy_any",
                    "x509_extensions = leaf_ext",
                    "unique_subject = no",
                    "[ policy_any ]",
                    "commonName = supplied",
                )
            ) + "\n"
        )

    def issue(
        self,
        name: str,
        *,
        common_name: str,
        usage: str,
        dns_names: tuple[str, ...] = (),
        ip_names: tuple[str, ...] = (),
        expired: bool = False,
    ) -> Certificate:
        key = self.directory / f"{name}-key.pem"
        csr = self.directory / f"{name}.csr"
        cert = self.directory / f"{name}.pem"
        ext = self.directory / f"{name}.ext"
        self._run(
            "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", str(key),
        )
        self._run(
            "req", "-new", "-key", str(key), "-out", str(csr),
            "-subj", f"/CN={common_name}",
        )
        ext_lines = [
            "[ leaf_ext ]",
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature,keyAgreement",
            f"extendedKeyUsage={usage}",
        ]
        names = [*(f"DNS.{i + 1} = {value}" for i, value in enumerate(dns_names)),
                 *(f"IP.{i + 1} = {value}" for i, value in enumerate(ip_names))]
        if names:
            ext_lines.extend(("subjectAltName=@subject_alt_names", "[ subject_alt_names ]", *names))
        ext.write_text("\n".join(ext_lines) + "\n")
        cmd = [
            "ca", "-batch", "-notext", "-config", str(self.ca_config), "-in", str(csr),
            "-out", str(cert), "-extfile", str(ext), "-extensions", "leaf_ext",
        ]
        # Keep tests deterministic: expired identities have long since expired.
        if expired:
            cmd.extend(("-startdate", "20200101000000Z", "-enddate", "20200102000000Z"))
        self._run(*cmd)
        return Certificate(cert=cert, key=key)


class _WitnessHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self._record_and_reply()

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._record_and_reply()

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._record_and_reply()

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._record_and_reply()

    def _record_and_reply(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        record = {
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": body,
            "peer": self.client_address,
        }
        witness = self.server.witness  # type: ignore[attr-defined]
        with witness._lock:
            witness.requests.append(record)
        if witness.response_delay:
            time.sleep(witness.response_delay)
        payload: dict[str, Any] = {"received": True, "path": self.path}
        if witness.echo_authorization:
            payload["authorization"] = self.headers.get("Authorization")
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(witness.status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        for key, value in witness.response_headers.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            # Expected when an end-to-end test proves an expiring grant cancels
            # an already transmitted, slow upstream request.
            pass

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep synthetic auth headers out of pytest's captured logs.
        return


class SyntheticHttpsWitness:
    """A TLS upstream that records every request and credential it receives."""

    def __init__(
        self,
        certificate: Certificate,
        *,
        echo_authorization: bool = False,
        status_code: int = 200,
        response_headers: dict[str, str] | None = None,
        response_delay: float = 0,
    ) -> None:
        self._lock = threading.Lock()
        self.requests: list[dict[str, Any]] = []
        self.echo_authorization = echo_authorization
        self.status_code = status_code
        self.response_headers = dict(response_headers or {})
        self.response_delay = response_delay
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _WitnessHandler)
        self._server.daemon_threads = True
        self._server.witness = self  # type: ignore[attr-defined]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(certificate.cert), str(certificate.key))
        self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def origin(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.requests)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def __enter__(self) -> "SyntheticHttpsWitness":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class SyntheticPKI:
    """Separate roots for inbound broker mTLS and outbound test HTTPS."""

    def __init__(self, directory: pathlib.Path) -> None:
        self.directory = directory
        self.inbound_ca = SyntheticCA(directory / "inbound-ca", "LeakGuard test inbound CA")
        self.upstream_ca = SyntheticCA(directory / "upstream-ca", "LeakGuard test upstream CA")
        self.untrusted_ca = SyntheticCA(directory / "untrusted-ca", "LeakGuard untrusted test CA")
        self.broker_server = self.inbound_ca.issue(
            "broker-server", common_name="broker.test", usage="serverAuth",
            dns_names=("broker.test", "localhost"), ip_names=("127.0.0.1",),
        )
        self.client = self.inbound_ca.issue(
            "agent-client", common_name="agent-test", usage="clientAuth",
        )
        self.second_client = self.inbound_ca.issue(
            "agent-client-2", common_name="agent-test-2", usage="clientAuth",
        )
        self.expired_client = self.inbound_ca.issue(
            "agent-expired", common_name="agent-expired", usage="clientAuth", expired=True,
        )
        self.untrusted_client = self.untrusted_ca.issue(
            "agent-untrusted", common_name="agent-untrusted", usage="clientAuth",
        )
        self.upstream_server = self.upstream_ca.issue(
            "upstream-server", common_name="127.0.0.1", usage="serverAuth",
            dns_names=("localhost",), ip_names=("127.0.0.1",),
        )
        self.wrong_name_upstream = self.upstream_ca.issue(
            "wrong-name-upstream", common_name="wrong.test", usage="serverAuth",
            dns_names=("wrong.test",),
        )


def make_synthetic_pki(directory: pathlib.Path) -> SyntheticPKI:
    return SyntheticPKI(directory)


def pki_tmp_path() -> pathlib.Path:
    """Return an owned temporary root for callers that need lifetime control."""
    return pathlib.Path(tempfile.mkdtemp(prefix="leakguard-broker-test-pki-"))
