"""Review selected encoded/decoded, queue and timeout bounds at their boundaries."""
from __future__ import annotations

import asyncio
import base64
import gzip
import json
import socket

import aiohttp
import pytest

from leakguard_broker.errors import BrokerError
from leakguard_broker.transport import Transport, prepare_request

if __package__:
    from .test_security_outbound import policy_for, use_resolver
    from .test_security_server import Admin, agent_post, client_for, grant, running
    from .test_security_witness import HOST, MARKER, PKI, TLSWitness, response
else:
    from test_security_outbound import policy_for, use_resolver
    from test_security_server import Admin, agent_post, client_for, grant, running
    from test_security_witness import HOST, MARKER, PKI, TLSWitness, response



def test_security_outbound_slots_and_queued_deadlines_are_bounded(tmp_path, monkeypatch):
    async def scenario():
        pki = PKI(tmp_path)
        witness = await TLSWitness(pki.server_context(pki.issue(HOST))).start()
        witness.release.clear()
        use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)]])
        binding = policy_for(pki, witness.port, timeout_seconds=.4)
        transport = Transport()
        retrieved = 0

        async def get_entry():
            nonlocal retrieved
            retrieved += 1
            return {"secret": MARKER, "username": "synthetic"}

        prepared = prepare_request(binding, {"method": "GET", "path": "/safe/slow"})
        pending = [asyncio.create_task(transport.execute(binding, prepared, get_entry, lambda: None)) for _ in range(8)]
        try:
            async with asyncio.timeout(.3):
                while len(witness.received) < 4:
                    await asyncio.sleep(.005)
            await asyncio.sleep(.03)
            assert len(witness.received) == 4
            assert retrieved == 4, "queued work must not retrieve credentials before acquiring a slot"
            results = await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), 1)
            assert all(isinstance(result, BrokerError) and result.code == "upstream-timeout" for result in results)
            assert len(witness.received) == 4
            assert transport._semaphore._value == 4
        finally:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            await witness.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("body", [base64.b64encode(b"x" * 17).decode(), "A" * 25])
def test_security_body_limit_applies_before_and_after_base64_decode(tmp_path, body):
    pki = PKI(tmp_path)
    binding = policy_for(pki, 8443, max_body_bytes=16)
    with pytest.raises(BrokerError) as error:
        prepare_request(binding, {"method": "POST", "path": "/safe/mutate", "body_b64": body})
    assert error.value.code == "body-too-large"


def test_security_inbound_encoded_and_chunked_body_caps_and_compression_denial(tmp_path):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            gid = await grant(admin)
            url = f"https://localhost:{broker.port}/v1/request"
            async with client_for(pki, alice) as client:
                async with client.post(url, data=b"A" * (1024 * 1024 + 1), headers={"Content-Type": "application/json"}) as response:
                    assert response.status == 413
                    assert (await response.json())["error"] == "body-too-large"

                async def chunks():
                    yield b"A" * 600000
                    yield b"A" * 600000

                async with client.post(url, data=chunks(), headers={"Content-Type": "application/json"}) as response:
                    assert response.status == 413
                    assert (await response.json())["error"] == "body-too-large"
                async with client.post(url, data=gzip.compress(b"A" * (2 * 1024 * 1024)), headers={"Content-Type": "application/json", "Content-Encoding": "gzip"}) as response:
                    assert response.status == 400
                    assert (await response.json())["error"] == "encoding-denied"
                assert not broker.state.inflight
                assert (await agent_post(client, broker, "inventory.find", {"grant_id": gid}))[0] == 200
            await admin.close()

    asyncio.run(scenario())


def test_security_slow_input_deadline_denies_before_dispatch(tmp_path):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            reader, writer = await asyncio.open_connection("127.0.0.1", broker.port, ssl=pki.client_context(alice), server_hostname="localhost")
            try:
                writer.write(b"POST /v1/request HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")
                await writer.drain()
                headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 6)
                assert headers.startswith(b"HTTP/1.1 408 ")
                length = next(int(line.split(b":", 1)[1].strip()) for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length:"))
                body = await asyncio.wait_for(reader.readexactly(length), 1)
                assert b'"input-timeout"' in body
                assert MARKER.encode() not in body
                assert not broker.state.inflight
            finally:
                writer.close()
                await writer.wait_closed()
                await admin.close()

    asyncio.run(scenario())


def test_security_nonreading_receiver_slot_expires_after_idle_and_tls_shutdown(tmp_path, monkeypatch):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            witness = await TLSWitness(pki.server_context(pki.issue(HOST)), response(b"x" * (8 * 1024 * 1024))).start()
            use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)]])
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            await admin.good("policy.replace", policy={"schema": 1, "principals": dict(broker.state.policy.principals), "bindings": [{
                "id": "review", "label": "Review", "tags": [], "environment": "test", "credential_ref": "synthetic",
                "origin": f"https://{HOST}:{witness.port}", "auth": {"kind": "bearer"},
                "rules": [{"method": "GET", "prefix": "/safe/"}], "allowed_cidrs": ["127.0.0.1/32"],
                "ca_file": str(pki.ca_file), "timeout_seconds": 2,
            }]})
            gid = await grant(admin)
            receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            receive_socket.setblocking(False)
            await asyncio.get_running_loop().sock_connect(receive_socket, ("127.0.0.1", broker.port))
            reader, writer = await asyncio.open_connection(sock=receive_socket, ssl=pki.client_context(alice), server_hostname="localhost", limit=1024)
            try:
                body = json.dumps({"grant_id": gid, "binding_id": "review", "method": "GET", "path": "/safe/large"}).encode()
                writer.write(b"POST /v1/request HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
                await writer.drain()
                await asyncio.wait_for(witness.arrived.wait(), 2)
                async with asyncio.timeout(2):
                    while b"\r\n\r\n" not in reader._buffer:
                        await asyncio.sleep(.005)
                assert reader._buffer.startswith(b"HTTP/1.1 200 ")
                await admin.close()
                # Do not consume response bytes. Idle + TLS shutdown must still release its slot.
                async with asyncio.timeout(18):
                    while broker._site._tasks:
                        await asyncio.sleep(.05)
                assert len(reader._buffer) < 1024 * 1024
                assert not broker.state.active
                assert not broker.state.inflight
                assert not broker._runner.server.connections
            finally:
                writer.transport.abort()
                await asyncio.gather(asyncio.wait_for(writer.wait_closed(), 1), return_exceptions=True)
                await admin.close()
                await witness.close()

    asyncio.run(scenario())
