"""Bounded HTTPS requests with a guard at every concrete socket address."""
from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import socket
import ssl

import aiohttp
from yarl import URL

from .errors import BrokerError
from .policy import Binding, FORBIDDEN_HEADERS, METHODS, TOKEN, canonical_path


def network_allowed(address, allowed_cidrs):
    try:
        if type(address) is not str or "%" in address:
            return False
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_unspecified or ip.is_multicast:
            return False
        if allowed_cidrs:
            return any(ip in ipaddress.ip_network(c, strict=True) for c in allowed_cidrs)
        if isinstance(ip, ipaddress.IPv6Address) and (ip.is_site_local or ip.sixtofour is not None or ip.teredo is not None):
            return False
        return ip.is_global and not ip.is_reserved and not ip.is_loopback and not ip.is_link_local
    except (ValueError, TypeError):
        return False


def guarded_socket_factory(allowed_cidrs):
    cidrs = tuple(allowed_cidrs)
    # Validate configuration once too. The concrete candidate is checked below,
    # including IP literals and all happy-eyeballs candidates after DNS resolution.
    for cidr in cidrs:
        ipaddress.ip_network(cidr, strict=True)

    def factory(addr_info):
        family, type_, proto, _, sockaddr = addr_info
        if family not in {socket.AF_INET, socket.AF_INET6} or not network_allowed(sockaddr[0], cidrs):
            raise OSError("network-denied")
        return socket.socket(family=family, type=type_, proto=proto)
    return factory


def client_tls(ca_file=None):
    # Construct explicitly: create_default_context reads SSLKEYLOGFILE from env.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    if ca_file is None:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    else:
        context.load_verify_locations(cafile=str(ca_file))
    context.set_alpn_protocols(["http/1.1"])
    return context


def input_error(code="request-invalid"):
    raise BrokerError(code, 400)


def prepare_request(binding: Binding, data):
    method = data.get("method")
    if type(method) is not str or method not in METHODS:
        input_error("method-denied")
    path = canonical_path(data.get("path"))
    url = binding.origin.with_path(path)
    if url.raw_path != path or url.origin() != binding.origin or not binding.permits(method, url.raw_path):
        raise BrokerError("path-denied", 403)
    query = data.get("query", [])
    if type(query) is not list or len(query) > 128:
        input_error()
    total = 0
    pairs = []
    for pair in query:
        if type(pair) is not list or len(pair) != 2:
            input_error()
        for part in pair:
            if type(part) is not str or len(part) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in part):
                input_error()
            try:
                total += len(part.encode("utf-8"))
            except UnicodeError:
                input_error()
        pairs.append(tuple(pair))
    if total > 32768:
        input_error()
    url = url.with_query(pairs)
    if url.raw_path != path or url.origin() != binding.origin:
        input_error("path-invalid")
    raw_headers = data.get("headers", {})
    if type(raw_headers) is not dict or len(raw_headers) > 32:
        input_error("header-denied")
    headers = {}
    header_bytes = 0
    for name, value in raw_headers.items():
        if type(name) is not str or not name.isascii():
            input_error("header-denied")
        lower = name.lower()
        if (not TOKEN.fullmatch(lower) or lower not in binding.allowed_headers or
                lower in FORBIDDEN_HEADERS or lower == binding.auth_header or lower in headers or
                type(value) is not str or len(value) > 8192 or not value.isascii() or
                any(ord(c) < 32 or ord(c) == 127 for c in value)):
            input_error("header-denied")
        headers[lower] = value
        header_bytes += len(name) + len(value)
    if header_bytes > 32768:
        input_error("header-denied")
    body = data.get("body_b64", "")
    if type(body) is not str or len(body) > 4 * ((binding.max_body_bytes + 2) // 3):
        input_error("body-too-large")
    try:
        body = base64.b64decode(body, validate=True)
    except (ValueError, binascii.Error):
        input_error()
    if len(body) > binding.max_body_bytes:
        input_error("body-too-large")
    return method, url, headers, body


def authentication(binding, entry):
    secret, username = entry["secret"], entry["username"]
    if binding.auth_kind == "basic":
        if ":" in username or any(ord(c) < 32 or ord(c) == 127 for c in username):
            raise BrokerError("credential-unusable", 403)
        encoded = base64.b64encode((username + ":" + secret).encode("utf-8")).decode("ascii")
        value = "Basic " + encoded
    else:
        if not secret.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in secret):
            raise BrokerError("credential-unusable", 403)
        value = binding.auth_prefix + secret
    if len(value) > 16384:
        raise BrokerError("credential-unusable", 403)
    # Literal reflection detection is defense in depth, not semantic non-disclosure.
    markers = tuple(x for x in (secret.encode("utf-8"), value.encode("utf-8"),
                                value.removeprefix("Basic ").encode("utf-8") if binding.auth_kind == "basic" else b"") if x)
    return value, markers


class Transport:
    def __init__(self):
        self._semaphore = asyncio.Semaphore(4)

    async def execute(self, binding, prepared, get_entry, check_live):
        # The total deadline includes time waiting for the global outbound slot.
        try:
            async with asyncio.timeout(binding.timeout_seconds):
                async with self._semaphore:
                    check_live()
                    method, url, headers, body = prepared
                    headers = dict(headers)
                    auth_value, markers = authentication(binding, await get_entry())
                    headers[binding.auth_header] = auth_value
                    headers["Accept-Encoding"] = "identity"
                    ssl_context = client_tls(binding.ca_file)
                    connector = aiohttp.TCPConnector(
                        ssl=ssl_context, use_dns_cache=False, force_close=True,
                        limit=1, limit_per_host=1, socket_factory=guarded_socket_factory(binding.allowed_cidrs),
                    )
                    async with aiohttp.ClientSession(
                        connector=connector, cookie_jar=aiohttp.DummyCookieJar(),
                        trust_env=False, auto_decompress=False,
                        timeout=aiohttp.ClientTimeout(total=binding.timeout_seconds),
                        max_line_size=8192, max_field_size=8192, max_headers=64,
                        read_bufsize=65536,
                    ) as session:
                        # aiohttp 3.14.5 has no public retry switch. Pin this tested
                        # version and disable its internal persistent retry loop.
                        session._retry_connection = False
                        check_live()
                        async with session.request(method, url, headers=headers, data=body,
                                                   allow_redirects=False, proxy=None,
                                                   server_hostname=binding.origin.raw_host) as response:
                            if 300 <= response.status < 400:
                                raise BrokerError("upstream-redirect", 502)
                            if response.status == 101 or response.headers.get("Upgrade"):
                                raise BrokerError("upstream-upgrade", 502)
                            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                                raise BrokerError("upstream-encoding", 502)
                            if response.content_length is not None and response.content_length > binding.max_response_bytes:
                                raise BrokerError("response-too-large", 502)
                            chunks, size = [], 0
                            async for chunk in response.content.iter_chunked(65536):
                                size += len(chunk)
                                if size > binding.max_response_bytes:
                                    raise BrokerError("response-too-large", 502)
                                chunks.append(chunk)
                            result_body = b"".join(chunks)
                            safe_headers = {}
                            for name in ("Content-Type",):
                                values = response.headers.getall(name, [])
                                if len(values) == 1 and len(values[0]) <= 256:
                                    value = values[0]
                                    if value.isascii() and not any(ord(c) < 32 or ord(c) == 127 for c in value):
                                        safe_headers[name.lower()] = value
                            reflected = result_body + b"\n" + b"\n".join(v.encode("ascii") for v in safe_headers.values())
                            if any(marker in reflected for marker in markers):
                                raise BrokerError("response-blocked", 502)
                            check_live()
                            return {"status": response.status, "headers": safe_headers,
                                    "body_b64": base64.b64encode(result_body).decode("ascii")}
        except BrokerError:
            raise
        except TimeoutError:
            raise BrokerError("upstream-timeout", 504) from None
        except (aiohttp.ClientError, OSError, ValueError, UnicodeError):
            raise BrokerError("upstream-failed", 502) from None
