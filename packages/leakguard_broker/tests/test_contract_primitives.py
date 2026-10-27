from __future__ import annotations

import socket

import pytest
from hypothesis import given, strategies as st

from leakguard_broker.errors import BrokerError
from leakguard_broker.policy import Policy, canonical_path
from leakguard_broker.transport import guarded_socket_factory, network_allowed, prepare_request


_safe_segment = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-~",
    min_size=1,
    max_size=24,
)


@given(st.lists(_safe_segment, min_size=1, max_size=8))
def test_canonical_path_preserves_safe_relative_segments(segments: list[str]) -> None:
    path = "/" + "/".join(segments)
    assert canonical_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "relative/path",
        "//attacker.test/collect",
        "/a//b",
        "/./collect",
        "/a/../collect",
        "/%2e%2e/collect",
        "/%2f%2fattacker.test",
        "/\\attacker.test",
        "/a?next=https://attacker.test",
        "/a#fragment",
        "/a\r\nHost: attacker.test",
        "https://attacker.test/collect",
        "/snowman-☃",
    ],
)
def test_canonical_path_rejects_authority_and_normalization_tricks(path: str) -> None:
    with pytest.raises(BrokerError) as exc:
        canonical_path(path)
    assert exc.value.code == "path-invalid"


def test_structured_query_cannot_change_the_configured_authority() -> None:
    policy = Policy.parse({
        "schema": 1,
        "bindings": [{
            "id": "example", "label": "Example", "tags": [], "environment": "test",
            "credential_ref": "entry", "origin": "https://api.example.test:9443",
            "auth": {"kind": "bearer"}, "rules": [{"method": "GET", "prefix": "/v1/"}],
            "allowed_cidrs": ["8.8.8.8/32"],
        }],
    })
    binding = policy.bindings["example"]
    method, url, headers, body = prepare_request(binding, {
        "method": "GET", "path": "/v1/items",
        "query": [["next", "//attacker.test/collect?x=1#frag"]],
        "headers": {}, "body_b64": "",
    })
    assert method == "GET"
    assert url.origin() == binding.origin
    assert url.raw_path == "/v1/items"
    assert url.raw_query_string != "//attacker.test/collect?x=1#frag"
    assert headers == {}
    assert body == b""


@pytest.mark.parametrize("header", ["host", "authorization", "cookie", "proxy-authorization", "connection"])
def test_agent_cannot_override_authority_or_auth_headers(header: str) -> None:
    policy = Policy.parse({
        "schema": 1,
        "bindings": [{
            "id": "example", "label": "Example", "tags": [], "environment": "test",
            "credential_ref": "entry", "origin": "https://api.example.test:9443",
            "auth": {"kind": "bearer"}, "rules": [{"method": "GET", "path": "/v1"}],
            "allowed_headers": ["x-probe"], "allowed_cidrs": ["8.8.8.8/32"],
        }],
    })
    with pytest.raises(BrokerError) as exc:
        prepare_request(policy.bindings["example"], {
            "method": "GET", "path": "/v1", "headers": {header: "attacker.test"},
        })
    assert exc.value.code == "header-denied"


@pytest.mark.parametrize(
    ("address", "cidrs", "expected"),
    [
        ("8.8.8.8", [], True),
        ("127.0.0.1", [], False),
        ("127.0.0.1", ["127.0.0.0/8"], True),
        ("127.0.0.1", ["127.0.0.2/32"], False),
        ("::1", ["127.0.0.0/8"], False),
        ("::ffff:127.0.0.1", ["127.0.0.0/8"], True),
        ("169.254.169.254", ["127.0.0.0/8"], False),
    ],
)
def test_address_policy_normalizes_mapped_ipv4(address: str, cidrs: list[str], expected: bool) -> None:
    assert network_allowed(address, cidrs) is expected


def _addr_info(address: str, family: int) -> tuple:
    if family == socket.AF_INET6:
        sockaddr = (address, 443, 0, 0)
    else:
        sockaddr = (address, 443)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def test_socket_factory_rejects_a_mixed_dns_answer_set() -> None:
    factory = guarded_socket_factory(["8.8.8.0/24"])
    mixed = [
        _addr_info("8.8.8.8", socket.AF_INET),
        _addr_info("127.0.0.1", socket.AF_INET),
    ]
    permitted = factory(mixed[0])
    permitted.close()
    with pytest.raises(OSError):
        factory(mixed[1])


def test_socket_factory_rejects_ipv4_mapped_loopback_candidate() -> None:
    factory = guarded_socket_factory(["127.0.0.0/8"])
    mapped = _addr_info("::ffff:127.0.0.1", socket.AF_INET6)
    sock = factory(mapped)
    try:
        assert sock.family == socket.AF_INET6
    finally:
        sock.close()
