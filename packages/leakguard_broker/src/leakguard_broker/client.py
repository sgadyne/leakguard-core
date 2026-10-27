"""Small asynchronous mTLS client for the LeakGuard broker API.

The client carries an agent certificate and an explicit grant id. It has no
credential vault API and never reads or returns the agent's private key.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
import ssl
from pathlib import Path
from typing import Any, Mapping, Sequence

import aiohttp
from yarl import URL


_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_RESPONSE_WIRE_BYTES = 12 * 1024 * 1024
_ERROR_CODE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/-]*$")
_FORBIDDEN_REQUEST_HEADERS = {
    "authorization", "cookie", "cookie2", "host", "proxy-authorization",
    "proxy-authenticate", "connection", "keep-alive", "te", "trailer",
    "transfer-encoding", "upgrade", "content-length", "expect", "accept-encoding",
    "content-encoding", "forwarded", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "via",
}
_SAFE_RESPONSE_HEADERS = {
    "cache-control", "content-length", "content-type", "date", "etag", "last-modified",
}


class BrokerClientError(Exception):
    """An API error with a stable, payload-free code."""

    def __init__(self, code: str):
        self.code = code if type(code) is str and _ERROR_CODE.fullmatch(code) else "request-failed"
        super().__init__(self.code)


def _secure_base_url(value: str) -> URL:
    if type(value) is not str:
        raise BrokerClientError("configuration-invalid")
    try:
        url = URL(value)
        if (url.scheme != "https" or not url.host or url.user is not None or
                url.password is not None or url.query_string or url.fragment or
                url.path not in ("", "/")):
            raise ValueError
        # Keep only the canonical origin. aiohttp will use it for both Host and
        # TLS SNI / hostname verification.
        return url.with_path("").with_query(None).with_fragment(None)
    except (TypeError, ValueError):
        raise BrokerClientError("configuration-invalid") from None


def _validate_path(path: str) -> str:
    if type(path) is not str or len(path) > 4096 or not _PATH.fullmatch(path) or path.startswith("//"):
        raise BrokerClientError("request-invalid")
    if any(ch in path for ch in ("%", "?", "#", "\\")):
        raise BrokerClientError("request-invalid")
    if any(segment in (".", "..") for segment in path.split("/")):
        raise BrokerClientError("request-invalid")
    return path


def _validate_query(query: Sequence[Sequence[str]] | None) -> list[list[str]]:
    if query is None:
        return []
    if type(query) not in (list, tuple) or len(query) > 128:
        raise BrokerClientError("request-invalid")
    result: list[list[str]] = []
    total = 0
    for pair in query:
        if type(pair) not in (list, tuple) or len(pair) != 2 or any(type(item) is not str for item in pair):
            raise BrokerClientError("request-invalid")
        if any(len(item) > 8192 or any(ord(ch) < 32 or ord(ch) == 127 for ch in item) for item in pair):
            raise BrokerClientError("request-invalid")
        try:
            total += len(pair[0].encode("utf-8")) + len(pair[1].encode("utf-8"))
        except UnicodeError:
            raise BrokerClientError("request-invalid") from None
        if total > 32768:
            raise BrokerClientError("request-invalid")
        result.append([pair[0], pair[1]])
    return result


def _validate_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping) or len(headers) > 32:
        raise BrokerClientError("request-invalid")
    result: dict[str, str] = {}
    total = 0
    for name, value in headers.items():
        if (type(name) is not str or type(value) is not str or not name or
                len(name) > 128 or len(value) > 8192 or
                not name.isascii() or not _TOKEN.fullmatch(name.lower()) or
                any(ord(c) < 32 or ord(c) > 126 for c in value)):
            raise BrokerClientError("request-invalid")
        if name.lower() in _FORBIDDEN_REQUEST_HEADERS:
            raise BrokerClientError("request-invalid")
        normalized_name = name.lower()
        if normalized_name in result:
            raise BrokerClientError("request-invalid")
        total += len(name) + len(value)
        if total > 32768:
            raise BrokerClientError("request-invalid")
        result[normalized_name] = value
    return result


class BrokerClient:
    """Use a broker with a client certificate and a normal verified TLS peer.

    Call methods inside ``async with`` or explicitly call ``close``. No
    automatic redirects, retries, environment proxies, cookies, or compression
    are enabled.
    """

    def __init__(self, base_url: str, *, ca_file: str | Path,
                 cert_file: str | Path, key_file: str | Path,
                 timeout_seconds: float = 35.0):
        self._base_url = _secure_base_url(base_url)
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 60:
            raise BrokerClientError("configuration-invalid")
        try:
            # Build explicitly rather than create_default_context(): Python
            # reads SSLKEYLOGFILE there and opens the path before callers can
            # disable key logging. TLS client defaults still require a verified
            # peer and hostname, and this client trusts only its configured CA.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.options |= ssl.OP_NO_COMPRESSION
            context.load_verify_locations(cafile=str(ca_file))
            context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        except (OSError, ssl.SSLError, ValueError):
            raise BrokerClientError("client-identity-invalid") from None
        self._ssl_context = context
        self._timeout = aiohttp.ClientTimeout(total=float(timeout_seconds))
        self._session: aiohttp.ClientSession | None = None

    def __repr__(self) -> str:
        return "BrokerClient(<mTLS identity configured>)"

    async def __aenter__(self) -> "BrokerClient":
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                ssl=self._ssl_context, use_dns_cache=False,
                enable_cleanup_closed=True,
            )
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=self._timeout, trust_env=False,
                cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
                headers={"Accept": "application/json", "Accept-Encoding": "identity"},
            )
            # aiohttp 3.14.5 has no public setting for its stale-connection
            # retry. These broker operations can dispatch upstream mutations,
            # so pin the dependency and turn that retry off explicitly.
            self._session._retry_connection = False
        return self._session

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def _post(self, route: str, payload: dict[str, Any]) -> dict[str, Any]:
        session = await self._ensure_session()
        try:
            async with session.post(
                self._base_url / route.lstrip("/"), json=payload,
                allow_redirects=False,
            ) as response:
                body = bytearray()
                async for chunk in response.content.iter_chunked(64 * 1024):
                    if len(body) + len(chunk) > _MAX_RESPONSE_WIRE_BYTES:
                        raise BrokerClientError("response-too-large")
                    body.extend(chunk)
                try:
                    document = json.loads(body)
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                    raise BrokerClientError("response-invalid") from None
        except BrokerClientError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ssl.SSLError):
            raise BrokerClientError("transport-failed") from None
        if type(document) is not dict:
            raise BrokerClientError("response-invalid")
        if response.status >= 400:
            code = document.get("error")
            raise BrokerClientError(code if type(code) is str else "request-failed")
        return document

    async def inventory_find(self, grant_id: str, *, label: str | None = None,
                             tags: Sequence[str] | None = None,
                             environment: str | None = None,
                             cursor: str | None = None, limit: int = 20) -> dict[str, Any]:
        if type(grant_id) is not str or not grant_id or len(grant_id) > 128:
            raise BrokerClientError("request-invalid")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise BrokerClientError("request-invalid")
        payload: dict[str, Any] = {"grant_id": grant_id, "limit": limit}
        if len(grant_id) > 256:
            raise BrokerClientError("request-invalid")
        for name, value in (("label", label), ("environment", environment)):
            if value is not None:
                if type(value) is not str or len(value) > 256:
                    raise BrokerClientError("request-invalid")
                payload[name] = value
        if tags is not None:
            if (type(tags) not in (list, tuple) or len(tags) > 32 or
                    any(type(tag) is not str or len(tag) > 128 for tag in tags)):
                raise BrokerClientError("request-invalid")
            payload["tags"] = list(tags)
        if cursor is not None:
            if type(cursor) is not str or not cursor.isascii() or not cursor.isdecimal() or len(cursor) > 6:
                raise BrokerClientError("request-invalid")
            payload["cursor"] = cursor
        result = await self._post("/v1/inventory.find", payload)
        items = result.get("items")
        policy_version = result.get("policy_version")
        next_cursor = result.get("next_cursor")
        if (type(policy_version) is not str or not re.fullmatch(r"[0-9a-f]{64}", policy_version) or
                type(items) is not list or len(items) > limit or
                (next_cursor is not None and (type(next_cursor) is not str or not next_cursor.isascii() or
                                             not next_cursor.isdecimal() or len(next_cursor) > 6))):
            raise BrokerClientError("response-invalid")
        safe_items = []
        for item in items:
            if (type(item) is not dict or
                    any(type(item.get(key)) is not str for key in ("id", "label", "environment")) or
                    type(item.get("tags")) is not list or
                    len(item.get("id", "")) > 128 or len(item.get("label", "")) > 256 or
                    len(item.get("environment", "")) > 256 or len(item["tags"]) > 32 or
                    any(type(tag) is not str or len(tag) > 128 for tag in item["tags"])):
                raise BrokerClientError("response-invalid")
            safe_items.append({key: item[key] for key in ("id", "label", "tags", "environment")})
        # Rebuild the frozen DTO instead of forwarding unexpected response keys.
        return {"policy_version": policy_version, "items": safe_items, "next_cursor": next_cursor}

    async def request(self, grant_id: str, binding_id: str, method: str, path: str,
                      *, query: Sequence[Sequence[str]] | None = None,
                      headers: Mapping[str, str] | None = None,
                      body: bytes = b"") -> dict[str, Any]:
        if (type(grant_id) is not str or not grant_id or len(grant_id) > 128 or
                type(binding_id) is not str or not binding_id or len(binding_id) > 128):
            raise BrokerClientError("request-invalid")
        if type(method) is not str or method != method.upper() or method not in _METHODS:
            raise BrokerClientError("request-invalid")
        if type(body) is not bytes or len(body) > 1024 * 1024:
            raise BrokerClientError("request-invalid")
        payload: dict[str, Any] = {
            "grant_id": grant_id,
            "binding_id": binding_id,
            "method": method,
            "path": _validate_path(path),
            "query": _validate_query(query),
            "headers": _validate_headers(headers),
            "body_b64": base64.b64encode(body).decode("ascii"),
        }
        result = await self._post("/v1/request", payload)
        status = result.get("status")
        response_headers = result.get("headers")
        encoded = result.get("body_b64")
        if (type(status) is not int or not 100 <= status <= 599 or
                type(response_headers) is not dict or
                len(response_headers) > 64 or
                any(type(name) is not str or type(value) is not str for name, value in response_headers.items()) or
                type(encoded) is not str):
            raise BrokerClientError("response-invalid")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise BrokerClientError("response-invalid") from None
        if len(decoded) > _MAX_RESPONSE_BYTES:
            raise BrokerClientError("response-too-large")
        safe_headers = {
            name.lower(): value for name, value in response_headers.items()
            if name.lower() in _SAFE_RESPONSE_HEADERS
        }
        return {"status": status, "headers": safe_headers, "body_b64": encoded}
