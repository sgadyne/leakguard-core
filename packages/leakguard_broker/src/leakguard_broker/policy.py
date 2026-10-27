"""Small, strictly validated operator policy and canonical request targets."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import re
from types import MappingProxyType

from yarl import URL

from .errors import BrokerError

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9a-z-]+\Z")
PATH = re.compile(r"/[A-Za-z0-9._~/-]*\Z")
FINGERPRINT = re.compile(r"[0-9a-f]{64}\Z")
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
FORBIDDEN_HEADERS = frozenset({
    "host", "authorization", "cookie", "cookie2", "proxy-authorization", "proxy-authenticate",
    "connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade",
    "content-length", "expect", "accept-encoding", "content-encoding", "forwarded",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "via",
})


def fail():
    raise BrokerError("policy-invalid", 400)


def text(value, maximum=256, *, empty=False):
    if type(value) is not str or len(value) > maximum or (not empty and not value) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        fail()
    try:
        value.encode("utf-8")
    except UnicodeError:
        fail()
    return value


def identity(value):
    if type(value) is not str or not ID.fullmatch(value):
        fail()
    return value


def number(value, low, high, *, integer=True):
    if (type(value) is not int if integer else type(value) not in (int, float)) or not math.isfinite(value) or not low <= value <= high:
        fail()
    return value


def fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        fail()


def canonical_path(value):
    # Conservative subset: percent escapes, duplicate slashes and dot segments are
    # deliberately unavailable, avoiding upstream/framework decoding differences.
    if type(value) is not str or len(value) > 4096 or not PATH.fullmatch(value) or "//" in value or any(p in {".", ".."} for p in value.split("/")):
        raise BrokerError("path-invalid", 400)
    url = URL("https://canonical.invalid").with_path(value)
    if url.raw_path != value:
        raise BrokerError("path-invalid", 400)
    return url.raw_path


def header_name(value):
    if type(value) is not str or value != value.lower() or not TOKEN.fullmatch(value) or len(value) > 128:
        fail()
    return value


@dataclass(frozen=True)
class Binding:
    id: str
    label: str
    tags: tuple[str, ...]
    environment: str
    credential_ref: str
    origin: URL
    auth_kind: str
    auth_header: str
    auth_prefix: str
    rules: tuple[tuple[str, str, bool], ...]
    allowed_headers: frozenset[str]
    allowed_cidrs: tuple[str, ...]
    max_body_bytes: int
    max_response_bytes: int
    timeout_seconds: float
    ca_file: str | None

    def permits(self, method, path):
        return any(method == m and (path.startswith(p) if prefix else path == p) for m, p, prefix in self.rules)

    def metadata(self):
        return {"id": self.id, "label": self.label, "tags": list(self.tags), "environment": self.environment}

    @classmethod
    def parse(cls, data):
        try:
            return cls._parse(data)
        except BrokerError:
            raise
        except (ValueError, TypeError, KeyError, OverflowError, UnicodeError, RecursionError):
            fail()

    @classmethod
    def _parse(cls, data):
        fields(data, {"id", "label", "tags", "environment", "credential_ref", "origin", "auth", "rules"}, {"allowed_headers", "allowed_cidrs", "max_body_bytes", "max_response_bytes", "timeout_seconds", "ca_file"})
        bid = identity(data["id"])
        label = text(data["label"])
        environment = text(data["environment"], 128)
        tags = data["tags"]
        if type(tags) is not list or len(tags) > 32:
            fail()
        tags = tuple(sorted(set(text(t, 128) for t in tags)))
        ref = text(data["credential_ref"], 128)
        origin_text = text(data["origin"], 512)
        try:
            origin = URL(origin_text)
            if origin.scheme != "https" or not origin.host or origin.user is not None or origin.password is not None or origin.raw_path != "/" or origin.query_string or origin.fragment or "?" in origin_text or "#" in origin_text or "\\" in origin_text or "%" in origin_text:
                fail()
            if not 1 <= origin.port <= 65535 or origin_text.rstrip("/") != str(origin.origin()):
                fail()
            # Validate IP literals now; the socket guard always validates actual addresses.
            if ":" in origin.host:
                ipaddress.ip_address(origin.host)
        except (ValueError, TypeError, UnicodeError):
            fail()
        auth = data["auth"]
        fields(auth, {"kind"}, {"header", "prefix"})
        kind = auth["kind"]
        if kind not in {"bearer", "basic", "header"}:
            fail()
        if kind == "header":
            name = header_name(auth.get("header"))
            if name in FORBIDDEN_HEADERS:
                fail()
            prefix = text(auth.get("prefix", ""), 256, empty=True)
            if not prefix.isascii():
                fail()
        else:
            if set(auth) != {"kind"}:
                fail()
            name, prefix = "authorization", "Bearer " if kind == "bearer" else "Basic "
        rules = data["rules"]
        if type(rules) is not list or not 1 <= len(rules) <= 128:
            fail()
        parsed_rules = []
        for rule in rules:
            if type(rule) is not dict or set(rule) not in ({"method", "path"}, {"method", "prefix"}) or rule["method"] not in METHODS:
                fail()
            is_prefix = "prefix" in rule
            try:
                path = canonical_path(rule["prefix" if is_prefix else "path"])
            except BrokerError:
                fail()
            if is_prefix and not path.endswith("/"):
                fail()
            parsed_rules.append((rule["method"], path, is_prefix))
        headers = data.get("allowed_headers", [])
        if type(headers) is not list or len(headers) > 32:
            fail()
        headers = frozenset(header_name(h) for h in headers)
        if headers & FORBIDDEN_HEADERS or name in headers:
            fail()
        cidrs = data.get("allowed_cidrs", [])
        if type(cidrs) is not list or len(cidrs) > 64:
            fail()
        try:
            cidrs = tuple(str(ipaddress.ip_network(c, strict=True)) for c in cidrs)
        except (ValueError, TypeError):
            fail()
        ca_file = data.get("ca_file")
        if ca_file is not None:
            text(ca_file, 4096)
        return cls(bid, label, tags, environment, ref, origin.origin(), kind, name, prefix,
                   tuple(parsed_rules), headers, cidrs,
                   number(data.get("max_body_bytes", 1048576), 0, 1048576),
                   number(data.get("max_response_bytes", 8388608), 1, 8388608),
                   number(data.get("timeout_seconds", 30), .05, 30, integer=False), ca_file)


@dataclass(frozen=True)
class Policy:
    version: str
    bindings: MappingProxyType
    principals: MappingProxyType
    max_unlock_seconds: int

    @classmethod
    def parse(cls, data):
        try:
            return cls._parse(data)
        except BrokerError:
            raise
        except (ValueError, TypeError, KeyError, OverflowError, UnicodeError, RecursionError):
            fail()

    @classmethod
    def _parse(cls, data):
        fields(data, {"schema", "bindings"}, {"principals", "max_unlock_seconds"})
        if type(data["schema"]) is not int or data["schema"] != 1 or type(data["bindings"]) is not list or len(data["bindings"]) > 256:
            fail()
        bindings = {}
        for raw in data["bindings"]:
            binding = Binding.parse(raw)
            if binding.id in bindings:
                fail()
            bindings[binding.id] = binding
        principals = data.get("principals", {})
        if type(principals) is not dict or len(principals) > 1024:
            fail()
        for fingerprint, principal in principals.items():
            if type(fingerprint) is not str or not FINGERPRINT.fullmatch(fingerprint):
                fail()
            identity(principal)
        maximum = number(data.get("max_unlock_seconds", 900), 1, 3600)
        try:
            encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        except (TypeError, ValueError, UnicodeError):
            fail()
        if len(encoded) > 1048576:
            fail()
        return cls(hashlib.sha256(encoded).hexdigest(), MappingProxyType(bindings), MappingProxyType(dict(principals)), maximum)
