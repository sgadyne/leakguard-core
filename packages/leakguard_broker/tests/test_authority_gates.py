from __future__ import annotations

import asyncio
import base64
import copy
import shutil
import ssl
import tempfile
from types import SimpleNamespace

import aiohttp
import pytest

from leakguard_broker.server import Broker, server_tls
from .test_broker_e2e import (
    AdminConnection,
    _SYNTHETIC_USER,
    _call_request,
    _client_context,
    _fingerprint,
    _running_broker,
)
from .tls_fixtures import SYNTHETIC_MARKER, SyntheticHttpsWitness


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("auth", "header_name", "expected"),
    [
        ({"kind": "bearer"}, "authorization", f"Bearer {SYNTHETIC_MARKER}"),
        (
            {"kind": "basic"},
            "authorization",
            "Basic " + base64.b64encode(f"{_SYNTHETIC_USER}:{SYNTHETIC_MARKER}".encode()).decode(),
        ),
        (
            {"kind": "header", "header": "x-synthetic-auth", "prefix": "Token "},
            "x-synthetic-auth",
            f"Token {SYNTHETIC_MARKER}",
        ),
    ],
)
async def test_each_configured_auth_mode_reaches_the_real_upstream_witness(
    synthetic_pki, upstream_witness, tmp_path, auth, header_name, expected,
):
    broker, socket_path, socket_dir = await _running_broker(
        synthetic_pki, upstream_witness, tmp_path, auth=auth,
    )
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            status, body = await _call_request(session, broker, grant)
        assert status == 200
        assert SYNTHETIC_MARKER.encode() not in body
        seen = upstream_witness.snapshot()
        assert len(seen) == 1
        assert seen[0]["headers"].get(header_name) == expected
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("x-synthetic-auth", f"Token attacker-{SYNTHETIC_MARKER}"),
        ("authorization", f"Bearer attacker-{SYNTHETIC_MARKER}"),
    ],
)
async def test_caller_cannot_override_custom_auth_header(
    synthetic_pki, upstream_witness, tmp_path, name, value,
):
    broker, socket_path, socket_dir = await _running_broker(
        synthetic_pki, upstream_witness, tmp_path,
        auth={"kind": "header", "header": "x-synthetic-auth", "prefix": "Token "},
    )
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            status, body = await _call_request(session, broker, grant, headers={name: value})
        assert status >= 400
        assert SYNTHETIC_MARKER.encode() not in body
        assert upstream_witness.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_unauthorized_binding_method_and_path_never_reach_upstream(
    synthetic_pki, upstream_witness, tmp_path,
):
    broker, socket_path, socket_dir = await _running_broker(
        synthetic_pki, upstream_witness, tmp_path,
        rules=[{"method": "GET", "path": "/only"}],
    )
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            cases = (
                {"binding_id": "other-binding", "method": "GET", "path": "/only"},
                {"binding_id": "synthetic-binding", "method": "POST", "path": "/only"},
                {"binding_id": "synthetic-binding", "method": "GET", "path": "/other"},
            )
            for case in cases:
                status, body = await _call_request(
                    session, broker, grant, binding_id=case["binding_id"],
                    method=case["method"], path=case["path"],
                )
                assert status >= 400
                assert SYNTHETIC_MARKER.encode() not in body
                assert upstream_witness.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_request_budget_is_enforced_against_real_witness(
    synthetic_pki, upstream_witness, tmp_path,
):
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant(max_requests=1)
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            first_status, _ = await _call_request(session, broker, grant, path="/budget-1")
            second_status, body = await _call_request(session, broker, grant, path="/budget-2")
        assert first_status == 200
        assert second_status == 429
        assert SYNTHETIC_MARKER.encode() not in body
        requests = upstream_witness.snapshot()
        assert len(requests) == 1
        assert requests[0]["path"].startswith("/budget-1")
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_grants_are_bound_to_the_enrolled_principal(
    synthetic_pki, upstream_witness, tmp_path,
):
    broker, socket_path, socket_dir = await _running_broker(
        synthetic_pki, upstream_witness, tmp_path,
        extra_principals=((synthetic_pki.second_client, "agent-two"),),
    )
    admin = await AdminConnection.open(socket_path)
    try:
        grant_one = await admin.unlock_and_grant()
        grant_two_result = await admin.call({
            "op": "grant.create", "principal": "agent-two",
            "bindings": ["synthetic-binding"], "ttl": 45, "max_requests": 20,
        })
        assert grant_two_result["ok"] is True
        grant_two = grant_two_result["result"]["grant_id"]
        clients = {}
        for identity in (synthetic_pki.client, synthetic_pki.second_client):
            context = _client_context(synthetic_pki, identity)
            clients[identity] = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=context), trust_env=False,
            )
        try:
            status, body = await _call_request(clients[synthetic_pki.client], broker, grant_two)
            assert status in (401, 403, 423)
            assert SYNTHETIC_MARKER.encode() not in body
            status, body = await _call_request(clients[synthetic_pki.second_client], broker, grant_one)
            assert status in (401, 403, 423)
            assert SYNTHETIC_MARKER.encode() not in body
            assert upstream_witness.snapshot() == []

            assert (await _call_request(clients[synthetic_pki.client], broker, grant_one))[0] == 200
            assert (await _call_request(clients[synthetic_pki.second_client], broker, grant_two))[0] == 200
            assert len(upstream_witness.snapshot()) == 2
        finally:
            await asyncio.gather(*(client.close() for client in clients.values()))
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["policy.replace", "principal.revoke"])
async def test_policy_and_principal_mutations_revoke_existing_tls_authority(
    synthetic_pki, upstream_witness, tmp_path, mutation,
):
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    reused = []

    async def mark_reuse(_session, _context, _params):
        reused.append(True)

    trace = aiohttp.TraceConfig()
    trace.on_connection_reuseconn.append(mark_reuse)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(
            ssl=_client_context(synthetic_pki, synthetic_pki.client), force_close=False,
        )
        async with aiohttp.ClientSession(
            connector=connector, trust_env=False, trace_configs=[trace],
        ) as session:
            assert (await _call_request(session, broker, grant, path="/before-mutation"))[0] == 200
            if mutation == "policy.replace":
                replacement = copy.deepcopy(broker._test_policy)
                replacement["bindings"][0]["label"] = "replacement-policy"
                changed = await admin.call({"op": "policy.replace", "policy": replacement})
            else:
                changed = await admin.call({
                    "op": "principal.revoke", "fingerprint": _fingerprint(synthetic_pki.client.cert),
                })
            assert changed["ok"] is True
            status, body = await _call_request(session, broker, grant, path="/after-mutation")
            assert reused, "the post-mutation request did not use the existing TLS connection"
            assert status in (401, 403, 423)
            assert SYNTHETIC_MARKER.encode() not in body
            assert len(upstream_witness.snapshot()) == 1
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_short_individual_grant_expiry_cancels_slow_upstream_response(
    synthetic_pki, tmp_path,
):
    slow = SyntheticHttpsWitness(synthetic_pki.upstream_server, response_delay=0.8)
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, slow, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant(unlock_ttl=30, grant_ttl=0.25)
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            status, body = await _call_request(session, broker, grant, path="/slow-grant-expiry")
        assert status in (401, 403, 423)
        assert SYNTHETIC_MARKER.encode() not in body
        # The broker had already transmitted one authenticated request. The
        # expired grant must prevent its late upstream response from reaching
        # the agent; it cannot retract bytes already sent upstream.
        requests = slow.snapshot()
        assert len(requests) == 1
        assert requests[0]["headers"]["authorization"] == f"Bearer {SYNTHETIC_MARKER}"
        await asyncio.sleep(0.7)
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
        slow.close()


@pytest.mark.asyncio
async def test_broker_restart_does_not_resurrect_grant_or_unlock_vault(
    synthetic_pki, upstream_witness, tmp_path,
):
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    grant = await admin.unlock_and_grant()
    connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
    session = aiohttp.ClientSession(connector=connector, trust_env=False)
    restarted = None
    restart_dir = None
    restarted_admin = None
    try:
        # Keep this local import so the follow-up patch also applies cleanly
        # after the original v2 harness commit has been integrated separately.
        from pathlib import Path as RestartPath

        assert (await _call_request(session, broker, grant, path="/before-restart"))[0] == 200
        await admin.close()
        await broker.close()

        restart_dir = RestartPath(tempfile.mkdtemp(prefix="lgbr-restart-", dir="/tmp"))
        restarted = Broker(broker._test_policy, broker._test_vault_path)
        restarted._test_policy = broker._test_policy
        restarted._test_vault_path = broker._test_vault_path
        await restarted.start(
            admin_socket=restart_dir / "admin.sock", host="127.0.0.1", port=0,
            tls=server_tls(
                synthetic_pki.broker_server.cert, synthetic_pki.broker_server.key,
                synthetic_pki.inbound_ca.ca_cert,
            ),
        )
        restarted_admin = await AdminConnection.open(restart_dir / "admin.sock")
        status = await restarted_admin.call({"op": "status"})
        assert status["ok"] is True
        assert status["result"]["unlocked"] is False
        assert status["result"]["grants"] == 0
        denied, body = await _call_request(
            session, SimpleNamespace(port=restarted.port), grant, path="/after-restart",
        )
        assert denied in (401, 403, 423)
        assert SYNTHETIC_MARKER.encode() not in body
        assert len(upstream_witness.snapshot()) == 1
    finally:
        await session.close()
        await admin.close()
        if restarted_admin is not None:
            await restarted_admin.close()
        await broker.close()
        if restarted is not None:
            await restarted.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
        if restart_dir is not None:
            shutil.rmtree(restart_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_connect_and_http_upgrade_are_rejected_before_outbound_dispatch(
    synthetic_pki, upstream_witness, tmp_path,
):
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, upstream_witness, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            payload = {
                "grant_id": grant, "binding_id": "synthetic-binding",
                "method": "GET", "path": "/roundtrip", "body_b64": "",
            }
            async with session.request(
                "CONNECT", f"https://127.0.0.1:{broker.port}/v1/request", json=payload,
            ) as response:
                connect_status, connect_body = response.status, await response.read()
            async with session.post(
                f"https://127.0.0.1:{broker.port}/v1/request", json=payload,
                headers={"Connection": "Upgrade", "Upgrade": "websocket"},
            ) as response:
                upgrade_status, upgrade_body = response.status, await response.read()
        assert connect_status >= 400
        assert upgrade_status >= 400
        assert SYNTHETIC_MARKER.encode() not in connect_body + upgrade_body
        assert upstream_witness.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)


@pytest.mark.asyncio
async def test_upstream_certificate_from_wrong_ca_gets_no_credential(
    synthetic_pki, tmp_path,
):
    wrong_ca_cert = synthetic_pki.untrusted_ca.issue(
        "wrong-ca-upstream", common_name="127.0.0.1", usage="serverAuth",
        ip_names=("127.0.0.1",),
    )
    wrong_ca = SyntheticHttpsWitness(wrong_ca_cert)
    broker, socket_path, socket_dir = await _running_broker(synthetic_pki, wrong_ca, tmp_path)
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(ssl=_client_context(synthetic_pki, synthetic_pki.client))
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            status, body = await _call_request(session, broker, grant)
        assert status == 502
        assert SYNTHETIC_MARKER.encode() not in body
        assert wrong_ca.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
        wrong_ca.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong", ["hostname", "ca"])
async def test_wrong_broker_hostname_or_ca_is_rejected_by_agent_tls(
    synthetic_pki, upstream_witness, tmp_path, wrong,
):
    if wrong == "hostname":
        broker_certificate = synthetic_pki.inbound_ca.issue(
            "wrong-name-broker", common_name="wrong.test", usage="serverAuth",
            dns_names=("wrong.test",),
        )
        client_ca = synthetic_pki.inbound_ca.ca_cert
    else:
        broker_certificate = synthetic_pki.untrusted_ca.issue(
            "wrong-ca-broker", common_name="127.0.0.1", usage="serverAuth",
            ip_names=("127.0.0.1",),
        )
        client_ca = synthetic_pki.inbound_ca.ca_cert
    broker, socket_path, socket_dir = await _running_broker(
        synthetic_pki, upstream_witness, tmp_path, broker_certificate=broker_certificate,
    )
    admin = await AdminConnection.open(socket_path)
    try:
        grant = await admin.unlock_and_grant()
        connector = aiohttp.TCPConnector(
            ssl=_client_context(synthetic_pki, synthetic_pki.client, ca_file=client_ca),
        )
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            try:
                await _call_request(session, broker, grant)
            except (aiohttp.ClientError, ssl.SSLError, OSError):
                pass
            else:
                pytest.fail(f"agent accepted wrong broker {wrong}")
        assert upstream_witness.snapshot() == []
    finally:
        await admin.close()
        await broker.close()
        shutil.rmtree(socket_dir, ignore_errors=True)
