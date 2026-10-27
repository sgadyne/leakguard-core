from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shutil
import ssl
from pathlib import Path
import tempfile

import aiohttp
import pytest

from leakguard_broker.provider import VaultProvider
from leakguard_broker.server import Broker, server_tls
from .tls_fixtures import SYNTHETIC_MARKER, SyntheticHttpsWitness


_MASTER = "lg-test-only-master-passphrase-4b2f"
_SYNTHETIC_USER = "lg-test-only-user-9a21"


def _fingerprint(certificate: Path) -> str:
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
    return hashlib.sha256(der).hexdigest()


def _client_context(pki, certificate=None, *, ca_file=None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(ca_file or pki.inbound_ca.ca_cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if certificate is not None:
        context.load_cert_chain(str(certificate.cert), str(certificate.key))
    return context


def _policy(
    pki, witness, vault_path: Path, *, extra_principals=(), auth=None,
    rules=None, allowed_headers=None, timeout_seconds=3, upstream_ca=None,
) -> dict:
    provider = VaultProvider(vault_path)
    provider.create(_MASTER)
    credential = provider.put(
        title="synthetic test entry", secret=SYNTHETIC_MARKER, username=_SYNTHETIC_USER,
    )
    provider.lock()
    principals = {_fingerprint(pki.client.cert): "agent-one"}
    for certificate, principal in extra_principals:
        principals[_fingerprint(certificate.cert)] = principal
    return {
        "schema": 1,
        "principals": principals,
        "max_unlock_seconds": 120,
        "bindings": [
            {
                "id": "synthetic-binding",
                "label": "Synthetic test service",
                "tags": ["test", "synthetic"],
                "environment": "test",
                "credential_ref": credential["id"],
                "origin": witness.origin,
                "auth": auth or {"kind": "bearer"},
                "rules": rules or [{"method": "GET", "prefix": "/"}],
                "allowed_headers": allowed_headers or ["x-probe"],
                "allowed_cidrs": ["127.0.0.0/8"],
                "max_body_bytes": 1024 * 1024,
                "max_response_bytes": 8 * 1024 * 1024,
                "timeout_seconds": timeout_seconds,
                "ca_file": str(upstream_ca or pki.upstream_ca.ca_cert),
            }
        ],
    }


async def _running_broker(
    pki, witness, tmp_path: Path, *, extra_principals=(), auth=None, rules=None,
    allowed_headers=None, timeout_seconds=3, upstream_ca=None, broker_certificate=None,
):
    vault_path = tmp_path / "broker-vault.lgv"
    policy = _policy(
        pki, witness, vault_path, extra_principals=extra_principals, auth=auth,
        rules=rules, allowed_headers=allowed_headers, timeout_seconds=timeout_seconds,
        upstream_ca=upstream_ca,
    )
    # AF_UNIX paths are limited to 108 bytes; pytest's ILMR tmp_path is longer.
    socket_dir = Path(tempfile.mkdtemp(prefix="lgbr-", dir="/tmp"))
    admin_socket = socket_dir / "admin.sock"
    broker = Broker(policy, vault_path)
    # Kept only as synthetic test fixture state for policy replacement and a
    # same-vault broker restart; this is not part of the production API.
    broker._test_policy = policy
    broker._test_vault_path = vault_path
    await broker.start(
        admin_socket=admin_socket,
        host="127.0.0.1",
        port=0,
        tls=server_tls(
            (broker_certificate or pki.broker_server).cert,
            (broker_certificate or pki.broker_server).key,
            pki.inbound_ca.ca_cert,
        ),
    )
    return broker, admin_socket, socket_dir


class AdminConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer

    @classmethod
    async def open(cls, path: Path) -> "AdminConnection":
        reader, writer = await asyncio.open_unix_connection(str(path), limit=131073)
        return cls(reader, writer)

    async def call(self, request: dict) -> dict:
        self.writer.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        await self.writer.drain()
        line = await asyncio.wait_for(self.reader.readline(), timeout=5)
        assert line.endswith(b"\n")
        response = json.loads(line)
        assert type(response) is dict
        return response

    async def unlock_and_grant(self, *, unlock_ttl=60, grant_ttl=45, max_requests=20) -> str:
        unlocked = await self.call({"op": "unlock", "passphrase": _MASTER, "ttl": unlock_ttl})
        assert unlocked["ok"] is True
        grant = await self.call({
            "op": "grant.create", "principal": "agent-one",
            "bindings": ["synthetic-binding"], "ttl": grant_ttl, "max_requests": max_requests,
        })
        assert grant["ok"] is True
        return grant["result"]["grant_id"]

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()


async def _call_request(
    session, broker, grant_id, *, path="/roundtrip", headers=None, method="GET",
    binding_id="synthetic-binding",
):
    payload = {
        "grant_id": grant_id,
        "binding_id": binding_id,
        "method": method,
        "path": path,
        "query": [["team", "red team"]],
        "headers": headers or {},
        "body_b64": "",
    }
    async with session.post(
        f"https://127.0.0.1:{broker.port}/v1/request", json=payload, allow_redirects=False,
    ) as response:
        return response.status, await response.read()


@pytest.mark.asyncio
async def test_forbidden_alternate_destination_gets_no_credential(synthetic_pki, upstream_witness, tmp_path):
    hostile = SyntheticHttpsWitness(synthetic_pki.upstream_server)
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client), force_close=False)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=False, cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
        ) as session:
            status, body = await _call_request(session, broker, grant, path="/roundtrip", headers={"x-probe": "synthetic"})
            assert status == 200
            result = json.loads(body)
            upstream_body = base64.b64decode(result["body_b64"], validate=True)
            assert json.loads(upstream_body)["received"] is True
            request = upstream_witness.snapshot()[0]
            assert request["headers"]["authorization"] == f"Bearer {SYNTHETIC_MARKER}"
            assert request["headers"]["x-probe"] == "synthetic"
            assert request["headers"]["host"] == f"127.0.0.1:{upstream_witness.port}"

            # An attacker-controlled authority in the relative path must fail
            # before a socket is opened to this independently observed sink.
            attack = f"//127.0.0.1:{hostile.port}/collect"
            status, body = await _call_request(session, broker, grant, path=attack)
            assert status >= 400
            assert SYNTHETIC_MARKER.encode() not in body
            assert hostile.snapshot() == []
            assert not any("authorization" in request["headers"] for request in hostile.snapshot())
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
        hostile.close()


@pytest.mark.asyncio
async def test_upstream_redirect_never_reaches_hostile_destination(synthetic_pki, tmp_path):
    hostile = SyntheticHttpsWitness(synthetic_pki.upstream_server)
    redirect_target = hostile.origin + "/collect"
    redirecting = SyntheticHttpsWitness(
        synthetic_pki.upstream_server,
        status_code=302,
        response_headers={"Location": redirect_target},
    )
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, redirecting, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(
            connector=connector, trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            status, body = await _call_request(session, broker, grant)
            assert status == 502
            assert SYNTHETIC_MARKER.encode() not in body
            assert redirecting.snapshot()[0]["headers"]["authorization"] == f"Bearer {SYNTHETIC_MARKER}"
            assert hostile.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
        redirecting.close()
        hostile.close()


@pytest.mark.asyncio
async def test_upstream_cookies_are_not_returned_or_reused(synthetic_pki, tmp_path):
    target = SyntheticHttpsWitness(
        synthetic_pki.upstream_server,
        response_headers={"Set-Cookie": "synthetic-session=do-not-forward; Secure"},
    )
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, target, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(
            connector=connector, trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            first_status, first_body = await _call_request(session, broker, grant, path="/first")
            second_status, second_body = await _call_request(session, broker, grant, path="/second")
            assert first_status == second_status == 200
            for body in (first_body, second_body):
                headers = json.loads(body)["headers"]
                assert "set-cookie" not in headers
                assert "cookie" not in headers
            requests = target.snapshot()
            assert len(requests) == 2
            assert all("cookie" not in item["headers"] for item in requests)
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
        target.close()


@pytest.mark.asyncio
async def test_lock_and_new_unlock_do_not_resurrect_old_grant(synthetic_pki, upstream_witness, tmp_path):
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        old_grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            status, _ = await _call_request(session, broker, old_grant, path="/before-lock")
            assert status == 200
            assert (await admin.call({"op": "lock"}))["ok"] is True
            assert (await admin.call({"op": "unlock", "passphrase": _MASTER, "ttl": 60}))["ok"] is True
            status, body = await _call_request(session, broker, old_grant, path="/after-unlock")
            assert status in (401, 403, 423)
            assert SYNTHETIC_MARKER.encode() not in body
            assert len(upstream_witness.snapshot()) == 1
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_admin_deadline_expires_grant(synthetic_pki, upstream_witness, tmp_path):
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant(unlock_ttl=1, grant_ttl=0.8)
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            first_status, _ = await _call_request(session, broker, grant, path="/before-deadline")
            assert first_status == 200
            await asyncio.sleep(1.15)
            second_status, body = await _call_request(session, broker, grant, path="/after-deadline")
            assert second_status in (401, 403, 423)
            assert SYNTHETIC_MARKER.encode() not in body
            assert len(upstream_witness.snapshot()) == 1
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_wrong_upstream_hostname_fails_before_credential_dispatch(synthetic_pki, tmp_path):
    wrong_name = SyntheticHttpsWitness(synthetic_pki.wrong_name_upstream)
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, wrong_name, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            status, body = await _call_request(session, broker, grant)
            assert status == 502
            assert SYNTHETIC_MARKER.encode() not in body
            assert wrong_name.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
        wrong_name.close()


@pytest.mark.asyncio
async def test_admin_eof_revokes_grant_on_reused_tls_connection(synthetic_pki, upstream_witness, tmp_path):
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    reused = []

    async def reused_connection(_session, _context, _params):
        reused.append(True)

    trace = aiohttp.TraceConfig()
    trace.on_connection_reuseconn.append(reused_connection)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client), force_close=False)
        async with aiohttp.ClientSession(
            connector=connector, trust_env=False, cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False, trace_configs=[trace],
        ) as session:
            first_status, first_body = await _call_request(session, broker, grant)
            assert first_status == 200
            assert SYNTHETIC_MARKER.encode() not in first_body
            assert len(upstream_witness.snapshot()) == 1

            # EOF on the one active admin connection must invalidate authority
            # before this next POST, while aiohttp confirms the TLS socket was reused.
            await admin.close()
            await asyncio.sleep(0.05)
            second_status, second_body = await _call_request(session, broker, grant)
            assert reused, "the second agent request did not use the existing TLS connection"
            assert second_status in (401, 403, 423)
            assert SYNTHETIC_MARKER.encode() not in second_body
            assert len(upstream_witness.snapshot()) == 1
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_missing_untrusted_expired_and_unenrolled_mtls_identities_fail_closed(
    synthetic_pki, upstream_witness, tmp_path,
):
    broker, socket_path, socket_dir = await _running_broker(
        synthetic_pki, upstream_witness, tmp_path,
        extra_principals=((synthetic_pki.second_client, "agent-two"),),
    )
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        identities = (
            ("missing", None),
            ("untrusted", synthetic_pki.untrusted_client),
            ("expired", synthetic_pki.expired_client),
        )
        for _name, identity in identities:
            context = _client_context(synthetic_pki, identity)
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=context), trust_env=False,
            ) as session:
                try:
                    async with session.post(
                        f"https://127.0.0.1:{broker.port}/v1/request",
                        json={"grant_id": grant, "binding_id": "synthetic-binding", "method": "GET", "path": "/roundtrip"},
                    ) as response:
                        await response.read()
                        assert response.status >= 400
                except (aiohttp.ClientError, ssl.SSLError, OSError):
                    pass

        # This certificate chains to the right CA but is not enrolled, so it
        # reaches HTTP authentication and is denied before upstream dispatch.
        context = _client_context(synthetic_pki, synthetic_pki.second_client)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=context), trust_env=False) as session:
            status, body = await _call_request(session, broker, grant)
            assert status in (401, 403)
            assert SYNTHETIC_MARKER.encode() not in body
        assert upstream_witness.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_literal_auth_reflection_is_suppressed(synthetic_pki, tmp_path):
    with SyntheticHttpsWitness(synthetic_pki.upstream_server, echo_authorization=True) as echo:
        broker, socket_path, socket_dir = await _running_broker(synthetic_pki, echo, tmp_path)
        admin = await AdminConnection.open(socket_path)
        try:
            grant = await admin.unlock_and_grant()
            connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
            async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
                status, body = await _call_request(session, broker, grant)
                assert SYNTHETIC_MARKER.encode() not in body
                assert status >= 400
                assert echo.snapshot()[0]["headers"]["authorization"] == f"Bearer {SYNTHETIC_MARKER}"
        finally:
            await admin.close()
            await broker.close()
            shutil.rmtree(socket_dir, ignore_errors=True)
