"""Recognize bounded, literal HTTP Authorization header lines.

Spans identify only the original wire token; decoded Basic credentials never
leave this module. The input is not interpreted as a request or sent anywhere.
Only complete header lines and the Basic and Bearer schemes are
recognized. CRLF, LF and a final line at EOF are supported.
"""

from __future__ import annotations

import base64
import binascii
import re

from .types import CredentialSpan

# Bounds are in input Unicode codepoints. Decoding is limited to 3 KiB.
_MAX_TEXT = 10_000_000
_MAX_SPANS = 10_000
_MAX_LINE = 8192
_MAX_TOKEN = 4096
_HEADER = re.compile(
    r"[ \t]*(?i:authorization):[ \t]*(?P<scheme>(?i:basic|bearer))[ \t]+"
    r"(?P<token>[^ \t\r\n]+)[ \t]*\Z",
    re.ASCII,
)
_NEXT_HEADER = re.compile(r"[ \t]+[!#$%&'*+.^_`|~0-9A-Za-z-]+:", re.ASCII)
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
    if not value.isprintable() or ":" not in value:
        return False
    _, password = value.split(":", 1)
    if not password:
        return False
    if _REFERENCE.fullmatch(password):
        return False
    # Quoted pure placeholders are references; quoted $NAME and embedded
    # markers are literals, not expressions to expand.
    if (len(password) >= 2 and password[0] == password[-1]
            and password[0] in "\"'"
            and re.fullmatch(r"\$\{[^}]*\}|\{\{[^}]*\}\}|<[^<>]+>", password[1:-1])):
        return False
    return True


def scan_http(text: str) -> tuple[CredentialSpan, ...]:
    """Find literal Basic/Bearer credentials in complete header lines.

    Header names and schemes are ASCII case-insensitive; whitespace is only
    HTTP SP/HTAB. Bare environment/template references and malformed headers
    are excluded; oversized inputs raise ValueError. No folding is performed.
    """
    if len(text) > _MAX_TEXT:
        raise ValueError("HTTP text exceeds scan bound")
    found: list[CredentialSpan] = []
    offset = 0
    while True:
        newline = text.find("\n", offset)
        end = len(text) if newline < 0 else newline
        # A CR is allowed only as the line terminator in CRLF.
        content_end = end - 1 if newline >= 0 and end > offset and text[end - 1] == "\r" else end
        if content_end - offset > _MAX_LINE:
            raise ValueError("HTTP header line exceeds scan bound")
        content = text[offset:content_end]
        next_offset = end + 1
        continuation = (newline >= 0 and next_offset < len(text)
                        and text[next_offset] in " \t"
                        and not _NEXT_HEADER.match(text, next_offset))
        if not continuation:
            match = _HEADER.fullmatch(content)
            if match:
                token = match.group("token")
                scheme = match.group("scheme").lower()
                if len(token) > _MAX_TOKEN:
                    raise ValueError("HTTP authorization token exceeds scan bound")
                if (
                    (scheme == "basic" and _basic(token))
                    or (scheme == "bearer" and _BEARER.fullmatch(token))
                ):
                    if len(found) >= _MAX_SPANS:
                        raise ValueError("HTTP findings exceed scan bound")
                    found.append(CredentialSpan(
                        rule=f"credential-http-{scheme}",
                        start=offset + match.start("token"),
                        end=offset + match.end("token"),
                    ))
        if newline < 0:
            break
        offset = next_offset
    return tuple(found)
