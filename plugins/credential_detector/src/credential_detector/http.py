"""Recognize bounded, literal HTTP Authorization header lines.

Spans identify only the original wire token; decoded Basic credentials never
leave this module. The input is not interpreted as a request or sent anywhere.
Only complete, unindented header lines and the Basic and Bearer schemes are
recognized. CRLF, LF and a final line at EOF are supported.
"""

from __future__ import annotations

import base64
import binascii
import re

from .types import CredentialSpan

# Bounds are in input Unicode codepoints. Decoding is limited to 3 KiB.
_MAX_LINE = 8192
_MAX_TOKEN = 4096
_HEADER = re.compile(
    r"(?i:authorization):[ \t]*(?P<scheme>(?i:basic|bearer))[ \t]+"
    r"(?P<token>[^ \t\r\n]+)[ \t]*\Z",
    re.ASCII,
)
_BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*\Z", re.ASCII)
_REFERENCE = re.compile(
    r"\$\{[^}]*\}|\$\([^)]+\)|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^}]*\}\}|<[^<>]+>"
)


def _basic(token: str) -> bool:
    """Validate one canonical Base64 encoding of a printable user:password."""
    try:
        wire = token.encode("ascii")
        decoded = base64.b64decode(wire, validate=True)
        if base64.b64encode(decoded) != wire:
            return False
        value = decoded.decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error, ValueError):
        return False
    if not value.isprintable() or ":" not in value or _REFERENCE.search(value):
        return False
    user, password = value.split(":", 1)
    return bool(user.strip() and password.strip())


def scan_http(text: str) -> tuple[CredentialSpan, ...]:
    """Find literal Basic/Bearer credentials in complete header lines.

    Header names and schemes are ASCII case-insensitive; whitespace is only
    HTTP SP/HTAB. Bare environment/template references and malformed or
    oversized lines are excluded. No continuation/folding is performed.
    """
    found: list[CredentialSpan] = []
    offset = 0
    lines = text.split("\n")
    for index, line in enumerate(lines):
        length = len(line)
        # A CR is allowed only as the line terminator in CRLF.
        content = line[:-1] if line.endswith("\r") and index < len(lines) - 1 else line
        continuation = index + 1 < len(lines) and lines[index + 1].startswith((" ", "\t"))
        if len(content) <= _MAX_LINE and not continuation:
            match = _HEADER.fullmatch(content)
            if match:
                token = match.group("token")
                scheme = match.group("scheme").lower()
                if len(token) <= _MAX_TOKEN and (
                    (scheme == "basic" and _basic(token))
                    or (scheme == "bearer" and _BEARER.fullmatch(token))
                ):
                    found.append(CredentialSpan(
                        rule=f"credential-http-{scheme}",
                        start=offset + match.start("token"),
                        end=offset + match.end("token"),
                    ))
        offset += length + 1
    return tuple(found)
