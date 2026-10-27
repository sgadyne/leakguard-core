"""Release regressions for live revocation and durable operator configuration.

All identities, vaults and upstreams are disposable synthetic test state. The
daemon case intentionally uses the current installed interpreter with -I.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
from pathlib import Path
import signal
import socket
import sys
import tempfile
from types import SimpleNamespace

import pytest

from leakguard_vault import CredentialVault

from .test_security_outbound import use_resolver
from .test_security_server import Admin, agent_post, client_for, grant, running
from .test_security_witness import HOST, MARKER, PKI, TLSWitness


def _policy(pki, port, principals, credential_ref="synthetic", *, host=HOST):
    return {"schema": 1, "principals": principals, "max_unlock_seconds": 30,
            "bindings": [{
                "id": "review", "label": "Synthetic release review", "tags": [],
                "environment": "test", "credential_ref": credential_ref,
                "origin": f"https://{host}:{port}", "auth": {"kind": "bearer"},
                "rules": [{"method": "GET", "prefix": "/safe/"}],
                "allowed_cidrs": ["127.0.0.1/32"], "ca_file": str(pki.ca_file),
                "timeout_seconds": 2,
            }]}


@pytest.mark.parametrize("mutation", ["policy.replace", "principal.revoke", "grant.revoke"])
def test_security_live_mutation_cancels_inflight_on_existing_tls(tmp_path, monkeypatch, mutation):
    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, _bob):
            witness = await TLSWitness(pki.server_context(pki.issue(HOST))).start()
            witness.release.clear()
            use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)]])
            admin = await Admin.connect(path)
            pending = None
            try:
                await admin.good("init", passphrase="synthetic release password")
                await admin.good("policy.replace", policy=_policy(pki, witness.port, dict(broker.state.principals)))
                gid = await grant(admin)
                async with client_for(pki, alice) as client:
                    payload = {"grant_id": gid, "binding_id": "review", "method": "GET", "path": "/safe/slow"}
                    pending = asyncio.create_task(agent_post(client, broker, "request", payload))
                    await asyncio.wait_for(witness.arrived.wait(), 2)
                    assert witness.received[0].headers["authorization"] == "Bearer " + MARKER
                    connections = set(broker._runner.server.connections)
                    if mutation == "policy.replace":
                        await admin.good(mutation, policy=_policy(pki, witness.port, dict(broker.state.principals)))
                    elif mutation == "principal.revoke":
                        await admin.good(mutation, fingerprint=hashlib.sha256(alice.der).hexdigest())
                    else:
                        await admin.good(mutation, grant_id=gid)
                    status, result = await asyncio.wait_for(pending, 2)
                    assert (status, result) == (403, {"error": "request-revoked"})
                    witness.release.set()
                    assert (await agent_post(client, broker, "request", payload))[0] == 403
                    assert connections <= set(broker._runner.server.connections), "probe must retain its existing TLS connection"
                    assert not broker.state.inflight
                    assert len(witness.received) == 1, "revoked request dispatched another credential"
            finally:
                if pending is not None and not pending.done():
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
                await admin.close()
                await witness.close()

    asyncio.run(scenario())


def test_security_private_provider_exception_is_absent_from_errors_and_logs(tmp_path, monkeypatch, caplog, capsys):
    caplog.set_level(logging.DEBUG)

    async def scenario():
        async with running(tmp_path) as (broker, path, pki, alice, _bob):
            admin = await Admin.connect(path)
            try:
                await admin.good("init", passphrase="synthetic release password")
                gid = await grant(admin)

                def broken_provider(_entry_id):
                    raise RuntimeError("synthetic private provider failure: " + MARKER)

                monkeypatch.setattr(broker.state.provider, "get", broken_provider)
                async with client_for(pki, alice) as client:
                    status, result = await agent_post(client, broker, "request", {
                        "grant_id": gid, "binding_id": "review", "method": "GET", "path": "/safe/error",
                    })
                assert (status, result) == (500, {"error": "broker-failed"})
            finally:
                await admin.close()

    asyncio.run(scenario())
    captured = capsys.readouterr()
    assert MARKER not in caplog.text + captured.out + captured.err


def _protected_config(path, config):
    temporary = path.with_suffix(".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(config, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def test_security_protected_config_removal_survives_real_daemon_restart(tmp_path):
    async def scenario():
        passphrase = "synthetic release master password"
        pki = PKI(tmp_path / "pki")
        broker_id = pki.issue("broker.release.test")
        alice, bob = pki.issue("alice", client=True), pki.issue("bob", client=True)
        alice_fp, bob_fp = [hashlib.sha256(identity.der).hexdigest() for identity in (alice, bob)]
        vault_path = tmp_path / "state" / "credentials.lgv"
        vault = CredentialVault(vault_path)
        try:
            entry = vault.create(passphrase).save_entry(title="Synthetic release", secret=MARKER)
        finally:
            vault.lock()
        assert MARKER.encode() not in vault_path.read_bytes()
        witness = await TLSWitness(pki.server_context(pki.issue("localhost"))).start()
        processes = []
        admin = None
        with tempfile.TemporaryDirectory(prefix="lg-release-", dir="/tmp") as directory:
            config_path = Path(directory) / "config.json"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            broker = SimpleNamespace(port=port)
            config = {
                "policy": _policy(pki, witness.port, {alice_fp: "alice", bob_fp: "bob"}, entry["id"], host="localhost"),
                "vault_path": str(vault_path), "admin_socket": str(Path(directory) / "admin.sock"),
                "server_cert": str(broker_id.cert), "server_key": str(broker_id.key),
                "client_ca": str(pki.ca_file), "listen_host": "127.0.0.1", "listen_port": port,
            }
            _protected_config(config_path, config)
            original_config = config_path.read_bytes()
            env = {key: value for key, value in os.environ.items() if key not in {"PYTHONPATH", "PYTHONHOME"}}

            async def start():
                process = await asyncio.create_subprocess_exec(
                    sys.executable, "-I", "-m", "leakguard_broker.daemon", "--config", str(config_path),
                    cwd=directory, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                processes.append(process)
                assert await asyncio.wait_for(process.stdout.readline(), 10) == b"broker-ready\n"
                return process

            async def stop(process):
                if process.returncode is None:
                    process.send_signal(signal.SIGTERM)
                stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
                assert process.returncode == 0
                for private in (MARKER.encode(), passphrase.encode()):
                    assert private not in stdout + stderr, "daemon output exposed synthetic private data"

            async def request(client, gid, path):
                return await agent_post(client, broker, "request", {
                    "grant_id": gid, "binding_id": "review", "method": "GET", "path": path,
                })

            try:
                process = await start()
                admin = await Admin.connect(config["admin_socket"])
                await admin.good("unlock", passphrase=passphrase)
                alice_grant, bob_grant = await grant(admin), await grant(admin, "bob")
                async with client_for(pki, alice) as alice_client:
                    assert (await request(alice_client, alice_grant, "/safe/before"))[0] == 200
                    await admin.good("principal.revoke", fingerprint=alice_fp)
                    assert (await request(alice_client, alice_grant, "/safe/revoked"))[0] == 403
                assert config_path.read_bytes() == original_config, "live edits are documented as ephemeral"

                # The operator durably removes the principal in protected config,
                # then restarts. Do not implement a second policy persistence DB.
                durable = copy.deepcopy(config)
                del durable["policy"]["principals"][alice_fp]
                _protected_config(config_path, durable)
                assert config_path.stat().st_mode & 0o777 == 0o600
                await stop(process)
                await admin.close()
                admin = None
                process = await start()
                admin = await Admin.connect(config["admin_socket"])
                status = await admin.good("status")
                assert status["unlocked"] is False and status["grants"] == 0
                async with client_for(pki, alice) as alice_client, client_for(pki, bob) as bob_client:
                    assert (await request(alice_client, alice_grant, "/safe/locked"))[0] == 423
                    assert (await request(bob_client, bob_grant, "/safe/locked"))[0] == 423
                    await admin.good("unlock", passphrase=passphrase)
                    assert (await request(alice_client, alice_grant, "/safe/old"))[0] == 403
                    assert (await request(bob_client, bob_grant, "/safe/old"))[0] == 403
                    denial = await admin.op("grant.create", principal="alice", bindings=["review"], ttl=20, max_requests=50)
                    assert denial == {"ok": False, "error": "grant-invalid"}
                    fresh = await grant(admin, "bob")
                    assert (await request(alice_client, fresh, "/safe/wrong-principal"))[0] == 403
                    assert (await request(bob_client, fresh, "/safe/retained-principal"))[0] == 200
                assert len(witness.received) == 2, "denied restart probes reached the credential sink"
                assert all(item.headers["authorization"] == "Bearer " + MARKER for item in witness.received)
                assert MARKER.encode() not in vault_path.read_bytes()
                await stop(process)
            finally:
                if admin is not None:
                    await admin.close()
                for process in processes:
                    if process.returncode is None:
                        process.terminate()
                        try:
                            await asyncio.wait_for(process.communicate(), 10)
                        except TimeoutError:
                            process.kill()
                            await process.communicate()
                await witness.close()

    asyncio.run(scenario())
