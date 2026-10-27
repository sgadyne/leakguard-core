"""mTLS and admin-connection interactions against real Broker HTTP/TLS code.

The provider is a synthetic in-memory witness, so these cases isolate protocol
ownership and cancellation from cryptographic KDF duration. The integration
harness separately exercises the existing encrypted CredentialVault.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import time

from cryptography import x509

import aiohttp

from leakguard_broker.errors import BrokerError
from leakguard_broker.server import Broker, server_tls

if __package__:
    from .test_security_outbound import use_resolver
    from .test_security_witness import HOST, MARKER, PKI, TLSWitness
else:
    from test_security_outbound import use_resolver
    from test_security_witness import HOST, MARKER, PKI, TLSWitness


class SyntheticProvider:
    def __init__(self):
        self.unlocked = False

    def unlock(self, passphrase):
        self.unlocked = True

    create = unlock

    def lock(self):
        self.unlocked = False

    def get(self, entry_id):
        if not self.unlocked:
            raise BrokerError("locked", 423)
        return {"id": "synthetic", "title": "Review only", "username": "synthetic-user", "secret": MARKER}


class Admin:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    @classmethod
    async def connect(cls, path):
        return cls(*await asyncio.open_unix_connection(path))

    async def op(self, op, **fields):
        self.writer.write(json.dumps({"op": op, **fields}).encode() + b"\n")
        await self.writer.drain()
        raw = await asyncio.wait_for(self.reader.readline(), 3)
        assert raw
        return json.loads(raw)

    async def good(self, op, **fields):
        result = await self.op(op, **fields)
        assert result["ok"], result
        return result["result"]

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except ConnectionError:
            pass


@asynccontextmanager
async def running(tmp_path, *, upstream_port=None, alice_lifetime=timedelta(hours=1)):
    pki = PKI(tmp_path / "pki")
    broker_id = pki.issue("broker.review.test")
    alice = pki.issue("alice", client=True, lifetime=alice_lifetime)
    bob = pki.issue("bob", client=True)
    fingerprints = {hashlib.sha256(alice.der).hexdigest(): "alice", hashlib.sha256(bob.der).hexdigest(): "bob"}
    binding = {
        "id": "review", "label": "Review", "tags": [], "environment": "test",
        "credential_ref": "synthetic", "origin": f"https://{HOST}" + (f":{upstream_port}" if upstream_port else ""),
        "auth": {"kind": "bearer"}, "rules": [{"method": "GET", "prefix": "/safe/"}],
        "allowed_cidrs": ["127.0.0.1/32"], "ca_file": str(pki.ca_file), "timeout_seconds": 2,
    }
    broker = Broker({"schema": 1, "principals": fingerprints, "bindings": [binding], "max_unlock_seconds": 30}, tmp_path / "unused.lgv")
    broker.state.provider = SyntheticProvider()
    # A short POSIX path avoids AF_UNIX sun_path limits in deep checkout/temp trees.
    with tempfile.TemporaryDirectory(prefix="lg-sec-", dir="/tmp") as directory:
        admin_path = Path(directory) / "s"
        await broker.start(admin_path, "127.0.0.1", 0, server_tls(broker_id.cert, broker_id.key, pki.ca_file))
        try:
            yield broker, admin_path, pki, alice, bob
        finally:
            await broker.close()


def client_for(pki, identity):
    return aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=pki.client_context(identity), limit=1), timeout=aiohttp.ClientTimeout(total=4))


async def agent_post(client, broker, route, data):
    async with client.post(f"https://localhost:{broker.port}/v1/{route}", json=data) as response:
        return response.status, await response.json()


async def grant(admin, principal="alice"):
    result = await admin.good("grant.create", principal=principal, bindings=["review"], ttl=20, max_requests=50)
    return result["grant_id"]


async def wait_locked(broker):
    async with asyncio.timeout(2):
        while broker.state.active or broker.state.provider.unlocked:
            await asyncio.sleep(.005)


def test_security_kept_tls_connection_rechecks_grant_and_principal(tmp_path):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            gid = await grant(admin)
            async with client_for(pki, alice) as client, client_for(pki, bob) as other:
                status, body = await agent_post(client, broker, "inventory.find", {"grant_id": gid})
                assert status == 200
                connections = set(broker._runner.server.connections)
                assert len(connections) == 1
                status, body = await agent_post(other, broker, "inventory.find", {"grant_id": gid})
                assert status == 403
                await admin.good("grant.revoke", grant_id=gid)
                status, body = await agent_post(client, broker, "inventory.find", {"grant_id": gid})
                assert status == 403
                assert connections <= set(broker._runner.server.connections), "revocation probe must reuse its live TLS connection"
                new_gid = await grant(admin)
                assert new_gid != gid
                assert (await agent_post(client, broker, "inventory.find", {"grant_id": new_gid}))[0] == 200
                assert (await agent_post(client, broker, "inventory.find", {"grant_id": gid}))[0] == 403
            await admin.close()
            await wait_locked(broker)

    asyncio.run(scenario())


def test_security_admin_second_connection_cannot_reveal_and_eof_ends_authority(tmp_path):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            assert (await admin.good("credential.get", entry_id="synthetic"))["secret"] == MARKER
            second = await Admin.connect(path)
            denial = json.loads(await asyncio.wait_for(second.reader.readline(), 2))
            assert denial == {"ok": False, "error": "admin-busy"}
            assert MARKER not in str(denial)
            await second.close()
            assert broker.state.active
            gid = await grant(admin)
            await admin.close()
            await wait_locked(broker)
            next_admin = await Admin.connect(path)
            assert not (await next_admin.good("status"))["unlocked"]
            await next_admin.good("unlock", passphrase="synthetic review password")
            async with client_for(pki, alice) as client:
                assert (await agent_post(client, broker, "inventory.find", {"grant_id": gid}))[0] == 403
            await next_admin.close()
            await wait_locked(broker)

    asyncio.run(scenario())


def test_security_admin_eof_cancels_inflight_and_does_not_revive_old_grant(tmp_path, monkeypatch):
    async def scenario():
        # Use the broker's CA to certify the upstream so the entire request is live TLS.
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            witness = await TLSWitness(pki.server_context(pki.issue(HOST))).start()
            witness.release.clear()
            use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)]])
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            replacement = {"schema": 1, "principals": dict(broker.state.policy.principals), "bindings": [{
                "id": "review", "label": "Review", "tags": [], "environment": "test", "credential_ref": "synthetic",
                "origin": f"https://{HOST}:{witness.port}", "auth": {"kind": "bearer"},
                "rules": [{"method": "GET", "prefix": "/safe/"}], "allowed_cidrs": ["127.0.0.1/32"],
                "ca_file": str(pki.ca_file), "timeout_seconds": 2,
            }]}
            await admin.good("policy.replace", policy=replacement)
            gid = await grant(admin)
            try:
                async with client_for(pki, alice) as client:
                    payload = {"grant_id": gid, "binding_id": "review", "method": "GET", "path": "/safe/slow"}
                    pending = asyncio.create_task(agent_post(client, broker, "request", payload))
                    await asyncio.wait_for(witness.arrived.wait(), 2)
                    assert witness.received[0].headers["authorization"] == "Bearer " + MARKER
                    await admin.close()
                    status, result = await asyncio.wait_for(pending, 2)
                    assert status == 403
                    assert result == {"error": "request-revoked"}
                    await wait_locked(broker)
                    assert not broker.state.inflight
                    assert (await agent_post(client, broker, "request", payload))[0] == 423
                    next_admin = await Admin.connect(path)
                    await next_admin.good("unlock", passphrase="synthetic review password")
                    assert (await agent_post(client, broker, "request", payload))[0] == 403
                    assert len(witness.received) == 1
                    await next_admin.close()
            finally:
                await witness.close()

    asyncio.run(scenario())


def test_security_partial_tls_connections_have_aggregate_cap(tmp_path):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            writers = []
            try:
                # Finite review sample, not a stress test. All handshakes use one synthetic cert.
                context = pki.client_context(alice)
                for _ in range(80):
                    try:
                        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", broker.port, ssl=context, server_hostname="localhost"), 1)
                        writers.append(writer)
                        writer.write(b"POST /v1/request HTTP/1.1\r\n")
                        await writer.drain()
                    except (ConnectionError, TimeoutError):
                        pass
                await asyncio.sleep(.05)
                count = len(broker._runner.server.connections)
                assert broker._http_count == 0, "sample must remain before middleware admission"
                assert count <= 64, f"accepted {count} partial-header TLS connections outside the request cap"
            finally:
                for writer in writers:
                    writer.close()
                await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)

    asyncio.run(scenario())


def test_security_admin_claim_remains_reserved_during_old_session_cleanup(tmp_path):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            await broker.state._vault_mutex.acquire()
            held = True
            try:
                await admin.close()
                async with asyncio.timeout(2):
                    while broker.state.owner is not None:
                        await asyncio.sleep(.005)
                assert not broker.state.active
                second = await Admin.connect(path)
                denial = json.loads(await asyncio.wait_for(second.reader.readline(), 2))
                assert denial == {"ok": False, "error": "admin-busy"}
                await second.close()
                broker.state._vault_mutex.release()
                held = False
                async with asyncio.timeout(2):
                    while broker._admin_claimed:
                        await asyncio.sleep(.005)
                assert not broker.state.provider.unlocked
                third = await Admin.connect(path)
                assert not (await third.good("status"))["unlocked"]
                await third.good("unlock", passphrase="synthetic review password")
                await third.close()
                await wait_locked(broker)
            finally:
                if held:
                    broker.state._vault_mutex.release()

    asyncio.run(scenario())


def test_security_pre_tls_connections_count_and_slots_recover(tmp_path):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, bob):
            writers = []
            try:
                for _ in range(72):
                    try:
                        _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", broker.port), .5)
                        writers.append(writer)
                    except (ConnectionError, TimeoutError):
                        pass
                await asyncio.sleep(.05)
                assert len(broker._site._tasks) <= 64
                assert len(broker._runner.server.connections) == 0
                assert broker._http_count == 0
            finally:
                for writer in writers:
                    writer.close()
                await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)
            async with asyncio.timeout(2):
                while broker._site._tasks:
                    await asyncio.sleep(.005)
            async with client_for(pki, alice) as client:
                status, result = await agent_post(client, broker, "inventory.find", {"grant_id": "revoked"})
                assert status == 423, "all slots must recover after incomplete handshakes close"

    asyncio.run(scenario())


def test_security_expired_certificate_is_rejected_on_existing_tls_connection(tmp_path):
    async def scenario():
        async with running(tmp_path, alice_lifetime=timedelta(seconds=2)) as (broker, path, pki, alice, bob):
            admin = await Admin.connect(path)
            await admin.good("init", passphrase="synthetic review password")
            gid = await grant(admin)
            async with client_for(pki, alice) as client:
                assert (await agent_post(client, broker, "inventory.find", {"grant_id": gid}))[0] == 200
                connections = set(broker._runner.server.connections)
                assert len(connections) == 1
                expiry = x509.load_der_x509_certificate(alice.der).not_valid_after_utc.timestamp()
                await asyncio.sleep(max(0, expiry - time.time()) + .03)
                status, result = await agent_post(client, broker, "inventory.find", {"grant_id": gid})
                assert status == 403
                assert result == {"error": "identity-expired"}
                assert connections == set(broker._runner.server.connections)
            await admin.close()

    asyncio.run(scenario())


def test_security_eof_during_secret_prompt_closes_existing_admin_authority(tmp_path, monkeypatch):
    async def scenario():
        import io
        from leakguard_broker import admin_cli

        class Tty(io.StringIO):
            def isatty(self):
                return True

        async with running(tmp_path) as (broker, path, pki, alice, bob):
            commands = iter(["unlock 30", "grant create alice 20 10 review", "credential put Synthetic"])
            continued_after_eof = []
            prompts = 0

            def terminal_input(_prompt):
                try:
                    return next(commands)
                except StopIteration:
                    continued_after_eof.append(broker.state.active)
                    raise EOFError

            def secret_input(_prompt):
                nonlocal prompts
                prompts += 1
                if prompts == 1:
                    return "synthetic review password"
                assert broker.state.active and len(broker.state.grants) == 1
                raise EOFError

            monkeypatch.setattr(admin_cli.sys, "stdin", Tty())
            monkeypatch.setattr(admin_cli.sys, "stderr", Tty())
            monkeypatch.setattr(admin_cli.getpass, "getpass", secret_input)
            result = await admin_cli._shell(path, input_fn=terminal_input, out=Tty())
            assert result in (0, 2)
            await wait_locked(broker)
            assert prompts == 2
            assert continued_after_eof == [], "secret-prompt EOF returned to an unlocked admin shell"
            assert not broker.state.grants

    asyncio.run(scenario())
