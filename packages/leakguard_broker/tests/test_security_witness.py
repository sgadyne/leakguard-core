"""Synthetic TLS witness independent of aiohttp's server and harness fixtures."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import ssl
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MARKER = "review-only-SYNTHETIC-secret-6b1c9d4e"
HOST = "upstream.review.test"


@dataclass(frozen=True)
class Identity:
    cert: Path
    key: Path
    der: bytes


class PKI:
    """One ephemeral CA; all identity material remains beneath pytest tmp_path."""

    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic review CA")])
        now = datetime.now(timezone.utc)
        self.ca = (
            x509.CertificateBuilder()
            .subject_name(self.name)
            .issuer_name(self.name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        self.ca_file = self.path / "ca.pem"
        self.ca_file.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))

    def issue(self, name: str, *, client: bool = False, lifetime: timedelta = timedelta(hours=1)) -> Identity:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        san = [x509.DNSName(name)]
        if not client:
            san += [x509.DNSName("localhost"), *[x509.IPAddress(ipaddress.ip_address(ip)) for ip in ("127.0.0.1", "127.0.0.2", "::1")]]
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(self.name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + lifetime)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        cert_path = self.path / f"{name}.pem"
        key_path = self.path / f"{name}.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        return Identity(cert_path, key_path, cert.public_bytes(serialization.Encoding.DER))

    def server_context(self, identity: Identity, *, mtls: bool = False) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(identity.cert, identity.key)
        if mtls:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(self.ca_file)
        return context

    def client_context(self, identity: Identity | None = None) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.ca_file))
        context.keylog_filename = None
        if identity is not None:
            context.load_cert_chain(identity.cert, identity.key)
        return context


@dataclass(frozen=True)
class Received:
    method: str
    target: str
    headers: dict[str, str]
    body: bytes
    peer: object
    sni: str | None


def response(body: bytes = b"ok", *, status: str = "200 OK", headers: tuple[tuple[str, str], ...] = ()) -> bytes:
    fields = [("Content-Length", str(len(body))), ("Connection", "close"), *headers]
    return f"HTTP/1.1 {status}\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k, v in fields) + b"\r\n" + body


class TLSWitness:
    """Records requests before responding; TLS hostname and Host stay observable."""

    def __init__(self, context: ssl.SSLContext, reply: bytes | Callable[[Received], bytes] | None = None):
        self.context = context
        self.reply = response() if reply is None else reply
        self.received: list[Received] = []
        self.connected = 0
        self.closed = 0
        self.arrived = asyncio.Event()
        self.release = asyncio.Event()
        self.release.set()
        self.server: asyncio.Server | None = None
        self.tasks: set[asyncio.Task] = set()
        self.sni: dict[int, str | None] = {}
        self.context.set_servername_callback(self._sni)

    def _sni(self, sock: ssl.SSLObject, name: str | None, context: ssl.SSLContext) -> None:
        self.sni[id(sock)] = name

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> TLSWitness:
        self.server = await asyncio.start_server(self._handle, host, port, ssl=self.context, limit=65536)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self.tasks.add(task)
        self.connected += 1
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            lines = header.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ", 2)
            headers = {}
            for line in lines[1:]:
                if line:
                    key, value = line.split(":", 1)
                    headers[key.lower()] = value.strip()
            size = int(headers.get("content-length", "0"))
            if not 0 <= size <= 1024 * 1024:
                raise ValueError("synthetic witness inbound limit")
            body = await asyncio.wait_for(reader.readexactly(size), 5)
            request = Received(method, target, headers, body, writer.get_extra_info("peername"), self.sni.get(id(writer.get_extra_info("ssl_object"))))
            self.received.append(request)
            self.arrived.set()
            await asyncio.wait_for(self.release.wait(), 10)
            writer.write(self.reply(request) if callable(self.reply) else self.reply)
            await writer.drain()
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass
            self.closed += 1
            self.tasks.discard(task)

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
