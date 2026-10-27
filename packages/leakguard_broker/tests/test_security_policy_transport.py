"""Independent probes of target canonicalization and concrete socket admission."""
from __future__ import annotations

import socket

import pytest
from yarl import URL

from leakguard_broker.errors import BrokerError
from leakguard_broker.policy import Policy, canonical_path
from leakguard_broker.transport import guarded_socket_factory, network_allowed


def binding_policy(**changes):
    binding = {
        "id": "review", "label": "Synthetic review only", "tags": ["synthetic"],
        "environment": "test", "credential_ref": "synthetic-entry",
        "origin": "https://upstream.review.test", "auth": {"kind": "bearer"},
        "rules": [{"method": "GET", "prefix": "/safe/"}],
        "allowed_headers": ["accept", "x-review"],
    }
    binding.update(changes)
    return {"schema": 1, "bindings": [binding]}


@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.255.255.254", "10.0.0.1", "172.16.1.1", "192.168.0.1",
    "169.254.169.254", "100.64.0.1", "0.0.0.0", "::", "::1", "fe80::1", "fc00::1",
    "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254",
    "fec0::1", "2002:7f00:0001::1", "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
])
def test_security_nonpublic_candidates_deny_by_default(address):
    assert not network_allowed(address, [])


@pytest.mark.parametrize("address,networks,expected", [
    ("127.0.0.1", ["127.0.0.1/32"], True),
    ("127.0.0.2", ["127.0.0.1/32"], False),
    ("8.8.8.8", ["127.0.0.1/32"], False),
    ("::ffff:127.0.0.1", ["127.0.0.1/32"], True),
    ("::ffff:127.0.0.2", ["127.0.0.1/32"], False),
    ("::1", ["::1/128"], True),
    ("2606:4700:4700::1111", ["::1/128"], False),
    ("8.8.8.8", [], True),
    ("2606:4700:4700::1111", [], True),
])
def test_security_cidr_scope_and_mapped_ipv4(address, networks, expected):
    assert network_allowed(address, networks) is expected


@pytest.mark.parametrize("family,sockaddr", [
    (socket.AF_INET, ("127.0.0.2", 443)),
    (socket.AF_INET6, ("::ffff:127.0.0.2", 443, 0, 0)),
    (socket.AF_INET6, ("::1", 443, 0, 0)),
])
def test_security_denied_candidate_never_creates_socket(monkeypatch, family, sockaddr):
    created = []

    def forbidden_creation(*args, **kwargs):
        created.append((args, kwargs))
        raise AssertionError("forbidden address reached socket creation")

    monkeypatch.setattr(socket, "socket", forbidden_creation)
    factory = guarded_socket_factory(["127.0.0.1/32"])
    with pytest.raises((BrokerError, OSError, ValueError)):
        factory((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
    assert created == []


@pytest.mark.parametrize("path", [
    "https://evil.invalid/safe/", "//evil.invalid/safe/", "\\\\evil.invalid\\safe",
    "/safe/../admin", "/safe/./item", "/safe/%2e%2e/admin", "/safe/%252e%252e/admin",
    "/safe/%2fadmin", "/safe/%5cadmin", "/safe/%00", "/safe/%0d%0aHost:evil",
    "/safe//item", "/safe/item?x=1", "/safe/item#frag", "/safe/\\item",
    " /safe/item", "\t/safe/item", "\r\n/safe/item", "/safe/item\r\nHost:evil",
    "/safe/\x00item", "/safe/\x7fitem", "/safe/..;", "/safe/user@example", "/safe/a:b", "/safe/a;b=1", "/safe/é", "/safe/／admin", "*", "",
])
def test_security_ambiguous_paths_rejected_before_policy(path):
    with pytest.raises(BrokerError):
        canonical_path(path)


@pytest.mark.parametrize("suffix", ["item", "a-b_c~d", "file.json", "safe./item"])
def test_security_accepted_path_is_the_url_library_raw_path(suffix):
    path = f"/safe/{suffix}"
    result = canonical_path(path)
    assert result == path
    # The wire target cannot silently acquire a different path while query is added.
    assert URL("https://upstream.review.test").with_path(result).with_query([("next", "//evil.invalid/a?b=#c"), ("x", "\r\n")]).raw_path == result
    policy = Policy.parse(binding_policy())
    assert policy.bindings["review"].permits("GET", result)
    assert not policy.bindings["review"].permits("GET", "/safeish/item")
    assert not policy.bindings["review"].permits("POST", result)


@pytest.mark.parametrize("origin", [
    "http://upstream.review.test", "https://user:pass@upstream.review.test",
    "https://upstream.review.test@evil.invalid", "https://upstream.review.test/safe",
    "https://upstream.review.test?", "https://upstream.review.test#",
    "https://upstream.review.test\\@evil.invalid", "https://upstream.review.test/%2f",
    "https://upstream.review.test:0", "https://upstream.review.test:65536",
    "https://upstream.review.test\r\nHost: evil.invalid",
])
def test_security_policy_rejects_ambiguous_origin(origin):
    with pytest.raises(BrokerError):
        Policy.parse(binding_policy(origin=origin))


@pytest.mark.parametrize("header", [
    "host", "authorization", "cookie", "proxy-authorization", "connection", "upgrade",
    "transfer-encoding", "content-length", "expect", "accept-encoding", "content-encoding",
    "forwarded", "x-forwarded-host", "x-forwarded-for", "te", "trailer", "proxy-connection",
])
def test_security_operator_cannot_allow_protocol_or_credential_override(header):
    with pytest.raises(BrokerError):
        Policy.parse(binding_policy(allowed_headers=[header]))
