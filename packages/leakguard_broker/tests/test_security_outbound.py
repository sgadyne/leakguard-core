"""Observe the real connector against independent synthetic TLS sinks."""
from __future__ import annotations

import asyncio
import base64
import gzip
import socket

import aiohttp
import pytest

from leakguard_broker.errors import BrokerError
from leakguard_broker.policy import Policy
from leakguard_broker.transport import Transport, prepare_request

if __package__:
    from .test_security_witness import HOST, MARKER, PKI, TLSWitness, response
else:
    from test_security_witness import HOST, MARKER, PKI, TLSWitness, response



def policy_for(pki, port, **changes):
    data = {
        "id": "review", "label": "Synthetic review", "tags": [], "environment": "test",
        "credential_ref": "synthetic", "origin": f"https://{HOST}:{port}",
        "auth": {"kind": "bearer"}, "rules": [{"method": "GET", "prefix": "/safe/"}, *[{"method": method, "path": "/safe/mutate"} for method in ("POST", "PUT", "DELETE")]],
        "allowed_cidrs": ["127.0.0.1/32"], "ca_file": str(pki.ca_file),
        "max_response_bytes": 1024, "timeout_seconds": 2,
    }
    data.update(changes)
    return Policy.parse({"schema": 1, "bindings": [data]}).bindings["review"]


def candidate(host, port, family=socket.AF_INET):
    return {"hostname": HOST, "host": host, "port": port, "family": family,
            "proto": socket.IPPROTO_TCP, "flags": socket.AI_NUMERICHOST}


def use_resolver(monkeypatch, answers):
    calls = []
    original = aiohttp.resolver.ThreadedResolver.resolve

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host != HOST:
            return await original(self, host, port, family)
        calls.append((host, port))
        selected = answers[min(len(calls) - 1, len(answers) - 1)]
        return [candidate(address, port, af) for address, af in selected]

    monkeypatch.setattr(aiohttp.resolver.ThreadedResolver, "resolve", resolve)
    return calls


async def execute(binding, *, method="GET", path="/safe/item", query=None, headers=None):
    payload = {"method": method, "path": path}
    if query is not None:
        payload["query"] = query
    if headers is not None:
        payload["headers"] = headers
    async def get_entry():
        return {"secret": MARKER, "username": "synthetic-user"}

    return await Transport().execute(binding, prepare_request(binding, payload), get_entry, lambda: None)


def test_security_actual_connector_rechecks_changed_dns_and_preserves_hostname(tmp_path, monkeypatch):
    async def scenario():
        pki = PKI(tmp_path)
        identity = pki.issue(HOST)
        allowed = await TLSWitness(pki.server_context(identity)).start()
        forbidden = await TLSWitness(pki.server_context(identity)).start("127.0.0.2", allowed.port)
        calls = use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)], [("127.0.0.2", socket.AF_INET)]])
        binding = policy_for(pki, allowed.port)
        try:
            result = await execute(binding, path="/safe/a_b-1~", query=[["next", "//evil.invalid/?a=b#c"], ["at", "user@evil.invalid"]])
            assert base64.b64decode(result["body_b64"]) == b"ok"
            with pytest.raises(BrokerError):
                await execute(binding)
            assert len(calls) == 2, "DNS cache or outbound connection was reused"
            assert len(allowed.received) == 1
            observed = allowed.received[0]
            assert observed.headers["authorization"] == "Bearer " + MARKER
            assert observed.headers["host"] == f"{HOST}:{allowed.port}"
            assert observed.sni == HOST
            assert observed.target.startswith("/safe/a_b-1~?")
            assert "#" not in observed.target
            assert forbidden.received == [], "credential reached a forbidden concrete address"
            assert forbidden.connected == 0
        finally:
            await allowed.close()
            await forbidden.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("bad_address,family", [("127.0.0.2", socket.AF_INET), ("::ffff:127.0.0.2", socket.AF_INET6)])
def test_security_actual_mixed_candidates_never_connect_forbidden_sink(tmp_path, monkeypatch, bad_address, family):
    async def scenario():
        pki = PKI(tmp_path)
        identity = pki.issue(HOST)
        allowed = await TLSWitness(pki.server_context(identity)).start()
        forbidden = await TLSWitness(pki.server_context(identity)).start("127.0.0.2", allowed.port)
        calls = use_resolver(monkeypatch, [[(bad_address, family), ("127.0.0.1", socket.AF_INET)]])
        try:
            result = await execute(policy_for(pki, allowed.port))
            assert result["status"] == 200
            assert len(calls) == 1
            assert len(allowed.received) == 1
            assert forbidden.connected == 0
            assert forbidden.received == []
        finally:
            await allowed.close()
            await forbidden.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("reply,expected", [
    (response(MARKER.encode()), "response-blocked"),
    (response(b"ok", headers=(("Content-Type", "text/plain; " + MARKER),)), "response-blocked"),
    (response(gzip.compress(b"A" * (1024 * 1024)), headers=(("Content-Encoding", "gzip"),)), "upstream-encoding"),
    (response(b"A" * 1025), "response-too-large"),
    (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n401\r\n" + b"A" * 1025 + b"\r\n0\r\n\r\n", "response-too-large"),
    (response(b"redirect", status="307 Temporary Redirect", headers=(("Location", "https://127.0.0.2/steal"),)), "upstream-redirect"),
], ids=["literal-body", "literal-header", "gzip-bomb", "declared-overflow", "chunked-overflow", "redirect"])
def test_security_malicious_upstream_is_buffered_and_blocked(tmp_path, monkeypatch, reply, expected):
    async def scenario():
        pki = PKI(tmp_path)
        witness = await TLSWitness(pki.server_context(pki.issue(HOST)), reply).start()
        use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)]])
        try:
            with pytest.raises(BrokerError) as caught:
                await execute(policy_for(pki, witness.port))
            assert caught.value.code == expected
            assert MARKER not in str(caught.value)
            assert len(witness.received) == 1
        finally:
            await witness.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_security_no_automatic_retry_after_upstream_observes_mutation(tmp_path, monkeypatch, method):
    async def scenario():
        pki = PKI(tmp_path)
        # No response bytes: the sink observes the mutation, then drops its TLS connection.
        witness = await TLSWitness(pki.server_context(pki.issue(HOST)), b"").start()
        calls = use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)]])
        try:
            with pytest.raises(BrokerError) as caught:
                await execute(policy_for(pki, witness.port), method=method, path="/safe/mutate")
            assert caught.value.code == "upstream-failed"
            assert len(witness.received) == 1
            assert len(calls) == 1
        finally:
            await witness.close()

    asyncio.run(scenario())


def test_security_upstream_cookies_and_auth_headers_are_not_delivered_or_replayed(tmp_path, monkeypatch):
    async def scenario():
        pki = PKI(tmp_path)
        witness = await TLSWitness(pki.server_context(pki.issue(HOST)), response(b"ok", headers=(("Set-Cookie", "session=" + MARKER), ("Authorization", "Bearer " + MARKER), ("X-Secret", MARKER)))).start()
        use_resolver(monkeypatch, [[("127.0.0.1", socket.AF_INET)]])
        binding = policy_for(pki, witness.port)
        try:
            for _ in range(2):
                result = await execute(binding)
                assert result["headers"] == {}
                assert MARKER not in str(result)
            assert len(witness.received) == 2
            assert all("cookie" not in req.headers for req in witness.received)
        finally:
            await witness.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("cert_host,authorized", [("fass.review.test", False), ("xn--fa-hia.review.test", True)], ids=["wrong-idna-name", "correct-a-label"])
def test_security_idna_tls_identity_matches_canonical_origin(tmp_path, monkeypatch, cert_host, authorized):
    async def scenario():
        pki = PKI(tmp_path)
        # UTS46/IDNA2008 faß differs from Python ssl's IDNA2003 fass mapping.
        canonical_host = "xn--fa-hia.review.test"
        witness = await TLSWitness(pki.server_context(pki.issue(cert_host))).start()

        async def resolve(self, host, port=0, family=socket.AF_INET):
            assert host == canonical_host
            return [candidate("127.0.0.1", port)]

        monkeypatch.setattr(aiohttp.resolver.ThreadedResolver, "resolve", resolve)
        binding = policy_for(pki, witness.port, origin=f"https://{canonical_host}:{witness.port}")
        try:
            denied = False
            try:
                await execute(binding)
            except BrokerError:
                denied = True
            count = len(witness.received)
            detail = "no HTTP request observed" if not count else f"SNI={witness.received[0].sni}; Host={witness.received[0].headers.get('host')}"
            if authorized:
                assert not denied, "canonical A-label certificate was rejected"
                assert count == 1
                assert witness.received[0].sni == canonical_host
                assert witness.received[0].headers["host"] == f"{canonical_host}:{witness.port}"
            else:
                assert count == 0, "credential sent to a different canonical TLS hostname: " + detail
                assert denied
        finally:
            await witness.close()

    asyncio.run(scenario())


@pytest.mark.parametrize("address,network,authorized", [("127.0.0.1", "127.0.0.1/32", True), ("127.0.0.2", "127.0.0.1/32", False), ("::1", "::1/128", True), ("::1", "127.0.0.1/32", False)])
def test_security_ip_literal_connections_use_same_network_guard(tmp_path, address, network, authorized):
    async def scenario():
        pki = PKI(tmp_path)
        witness = await TLSWitness(pki.server_context(pki.issue(HOST))).start(address)
        host = f"[{address}]" if ":" in address else address
        binding = policy_for(pki, witness.port, origin=f"https://{host}:{witness.port}", allowed_cidrs=[network])
        try:
            if authorized:
                assert (await execute(binding))["status"] == 200
                assert len(witness.received) == 1
            else:
                with pytest.raises(BrokerError):
                    await execute(binding)
                assert len(witness.received) == 0
                assert witness.connected == 0
        finally:
            await witness.close()

    asyncio.run(scenario())
