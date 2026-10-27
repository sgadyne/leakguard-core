"""Bounded compact JOSE shape checks without value retention or crypto work."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import re
import string
from typing import Any


JWE_ENTITY = "JOSE_COMPACT_JWE"
JWS_ENTITY = "JOSE_COMPACT_JWS_CANDIDATE"
UNVERIFIED_ENTITY = "JOSE_COMPACT_UNVERIFIED"

MAX_SOURCE_CHARS = 16 * 1024 * 1024
MAX_TOKEN_CHARS = 16 * 1024
MAX_HEADER_BYTES = 4096
MAX_HEADER_DEPTH = 32
MAX_HEADER_SEGMENT_CHARS = (MAX_HEADER_BYTES * 4 + 2) // 3
MAX_CANDIDATES = 2048
MAX_CANDIDATE_CHARS = 1024 * 1024
MAX_EDGE_DOTS = 3
MAX_PBES2_ITERATIONS = 10_000_000
MIN_RSA_BYTES = 256
MAX_RSA_BYTES = 1024
_INVALID_BASE64_PREFIXES = frozenset("+*")
_INVALID_BASE64_SUFFIXES = frozenset("=+*")

_B64URL_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
_B64URL = frozenset(_B64URL_ALPHABET)
_TOKEN_CHARS = _B64URL | {"."}

_CONTENT_ENCRYPTION = {
    "A128GCM": (12, 16, 16),
    "A192GCM": (12, 16, 24),
    "A256GCM": (12, 16, 32),
    "A128CBC-HS256": (16, 16, 32),
    "A192CBC-HS384": (16, 24, 48),
    "A256CBC-HS512": (16, 32, 64),
}
_CBC_CONTENT_ENCRYPTION = frozenset({"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"})
_DIRECT_ALGORITHMS = frozenset({"dir", "ECDH-ES"})
_RSA_ALGORITHMS = frozenset({
    "RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
})
_RSA_JWS_ALGORITHMS = frozenset({f"RS{bits}" for bits in (256, 384, 512)})
_PSS_JWS_ALGORITHMS = frozenset({f"PS{bits}" for bits in (256, 384, 512)})
_KNOWN_JWS_ALGORITHMS = frozenset({
    "none", "HS256", "HS384", "HS512", "ES256", "ES384", "ES512", "EdDSA",
}) | _RSA_JWS_ALGORITHMS | _PSS_JWS_ALGORITHMS
_AES_KW_ALGORITHMS = frozenset({"A128KW", "A192KW", "A256KW"})
_ECDH_KW_ALGORITHMS = frozenset({
    "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
})
_GCM_KW_ALGORITHMS = frozenset({"A128GCMKW", "A192GCMKW", "A256GCMKW"})
_PBES2_ALGORITHMS = frozenset({
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
})
_KNOWN_KEY_ALGORITHMS = (
    _DIRECT_ALGORITHMS | _RSA_ALGORITHMS | _AES_KW_ALGORITHMS
    | _ECDH_KW_ALGORITHMS | _GCM_KW_ALGORITHMS | _PBES2_ALGORITHMS
)


@dataclass(frozen=True)
class StructuralMatch:
    """A source span and format label; never stores the matched source value."""

    start: int
    end: int
    entity_type: str
    score: float


def _b64url_decoded_length(segment: str) -> int | None:
    if len(segment) % 4 == 1 or any(char not in _B64URL for char in segment):
        return None
    groups, remainder = divmod(len(segment), 4)
    if remainder:
        last_value = _B64URL_ALPHABET.index(segment[-1])
        if (remainder == 2 and last_value & 0b1111) or (remainder == 3 and last_value & 0b11):
            return None
    return groups * 3 + (0 if remainder == 0 else remainder - 1)


def _decode_b64url(segment: str) -> bytes | None:
    decoded_length = _b64url_decoded_length(segment)
    if decoded_length is None:
        return None
    padded = segment + "=" * ((-len(segment)) % 4)
    try:
        decoded = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, TypeError):
        return None
    if len(decoded) != decoded_length or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != segment:
        return None
    return decoded


def _decode_header(segment: str) -> dict[str, Any] | None:
    if not segment or len(segment) > MAX_HEADER_SEGMENT_CHARS:
        return None
    decoded_length = _b64url_decoded_length(segment)
    if decoded_length is None or decoded_length > MAX_HEADER_BYTES:
        return None
    raw = _decode_b64url(segment)
    if raw is None:
        return None

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non-standard JSON constant")

    try:
        if len(raw) > MAX_HEADER_BYTES:
            return None
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        return None
    if type(value) is not dict:
        return None
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_HEADER_DEPTH:
            return None
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value


def _string_param(header: dict[str, Any], name: str) -> str | None:
    value = header.get(name)
    if (type(value) is not str or not value or len(value) > 80
            or not value.isascii() or any(ord(char) < 0x21 or ord(char) > 0x7e for char in value)):
        return None
    return value


def _segment_lengths(parts: list[str]) -> list[int] | None:
    lengths = []
    for part in parts:
        decoded_length = _b64url_decoded_length(part)
        if decoded_length is None:
            return None
        lengths.append(decoded_length)
    return lengths


def _ecdh_header_status(header: dict[str, Any]) -> str:
    """Classify epk shape without curve arithmetic: supported, unsupported, invalid."""
    epk = header.get("epk")
    if type(epk) is not dict:
        return "invalid"
    for name in ("kty", "crv"):
        value = epk.get(name)
        if type(value) is not str or not value or len(value) > 80 or not value.isascii():
            return "invalid"
    x_length = _b64url_decoded_length(epk.get("x")) if type(epk.get("x")) is str else None
    if x_length is None or x_length == 0 or len(epk["x"]) > 256:
        return "invalid"

    kty, crv = epk["kty"], epk["crv"]
    if kty == "EC":
        y = epk.get("y")
        y_length = _b64url_decoded_length(y) if type(y) is str else None
        if y_length is None or y_length == 0 or len(y) > 256:
            return "invalid"
        widths = {"P-256": 32, "P-384": 48, "P-521": 66}
        expected = widths.get(crv)
        if expected is None:
            return "unsupported"
        return "supported" if x_length == y_length == expected else "invalid"
    if kty == "OKP":
        if "y" in epk:
            y = epk["y"]
            if type(y) is not str or _b64url_decoded_length(y) is None:
                return "invalid"
            return "unsupported"
        widths = {"X25519": 32, "X448": 56}
        expected = widths.get(crv)
        if expected is None:
            return "unsupported"
        return "supported" if x_length == expected else "invalid"

    y = epk.get("y")
    if y is not None and (type(y) is not str or _b64url_decoded_length(y) is None):
        return "invalid"
    return "unsupported"


def _valid_crit(header: dict[str, Any]) -> bool:
    if "crit" not in header:
        return True
    critical = header["crit"]
    if (type(critical) is not list or not critical
            or any(type(name) is not str or not name or len(name) > 80 for name in critical)
            or len(set(critical)) != len(critical)):
        return False
    return all(name in header and name not in {"alg", "enc", "crit"} for name in critical)


def _valid_known_jwe(header: dict[str, Any], parts: list[str], lengths: list[int]) -> bool:
    alg = _string_param(header, "alg")
    enc = _string_param(header, "enc")
    if alg is None or enc is None or alg not in _KNOWN_KEY_ALGORITHMS or enc not in _CONTENT_ENCRYPTION:
        return False
    iv_length, tag_length, cek_length = _CONTENT_ENCRYPTION[enc]
    if lengths[2] != iv_length or lengths[4] != tag_length:
        return False
    if alg in _DIRECT_ALGORITHMS:
        if parts[1] != "":
            return False
    else:
        if not parts[1]:
            return False
        if alg in _RSA_ALGORITHMS and not MIN_RSA_BYTES <= lengths[1] <= MAX_RSA_BYTES:
            return False
        if alg in _AES_KW_ALGORITHMS | _ECDH_KW_ALGORITHMS | _PBES2_ALGORITHMS:
            if lengths[1] != cek_length + 8:
                return False
        if alg in _GCM_KW_ALGORITHMS and lengths[1] != cek_length:
            return False
    if alg in _GCM_KW_ALGORITHMS:
        kw_iv = header.get("iv")
        kw_tag = header.get("tag")
        if (type(kw_iv) is not str or type(kw_tag) is not str
                or _b64url_decoded_length(kw_iv) != 12
                or _b64url_decoded_length(kw_tag) != 16):
            return False
    if alg in _PBES2_ALGORITHMS:
        p2s = header.get("p2s")
        p2c = header.get("p2c")
        if (type(p2s) is not str or _b64url_decoded_length(p2s) is None
                or _b64url_decoded_length(p2s) < 8
                or type(p2c) is not int or not 1 <= p2c <= MAX_PBES2_ITERATIONS):
            return False
    return True


def _jwe_match(token: str, start: int, end: int) -> StructuralMatch | None:
    if token.count(".") != 4 or len(token) > MAX_TOKEN_CHARS:
        return None
    parts = token.split(".")
    if len(parts) != 5 or any(len(part) > MAX_TOKEN_CHARS for part in parts):
        return None
    header = _decode_header(parts[0])
    if header is None:
        return None
    lengths = _segment_lengths(parts)
    if lengths is None or not all((parts[0], parts[2], parts[4])):
        return None
    alg = _string_param(header, "alg")
    enc = _string_param(header, "enc")
    if alg is None or enc is None:
        return None
    if not _valid_crit(header):
        return None
    if alg in _DIRECT_ALGORITHMS:
        if parts[1] != "":
            return None
    elif not parts[1] and alg in _KNOWN_KEY_ALGORITHMS:
        return None
    if enc in _CONTENT_ENCRYPTION:
        iv_length, tag_length, _cek_length = _CONTENT_ENCRYPTION[enc]
        if lengths[2] != iv_length or lengths[4] != tag_length:
            return None
        if enc in _CBC_CONTENT_ENCRYPTION and (lengths[3] == 0 or lengths[3] % 16):
            return None
    known_alg = alg in _KNOWN_KEY_ALGORITHMS
    known_enc = enc in _CONTENT_ENCRYPTION
    ecdh_status = (
        _ecdh_header_status(header)
        if alg in (_DIRECT_ALGORITHMS | _ECDH_KW_ALGORITHMS) and alg != "dir"
        else None
    )
    if ecdh_status == "invalid":
        return None
    constraints_valid = known_alg and known_enc and _valid_known_jwe(header, parts, lengths)
    if known_alg and known_enc and not constraints_valid:
        if alg in _RSA_ALGORITHMS and parts[1] and not MIN_RSA_BYTES <= lengths[1] <= MAX_RSA_BYTES:
            return StructuralMatch(start, end, UNVERIFIED_ENTITY, 0.40)
        return None
    if (known_alg and known_enc and ecdh_status != "unsupported"
            and "crit" not in header and header.get("zip", "DEF") == "DEF"):
        return StructuralMatch(start, end, JWE_ENTITY, 0.99)
    return StructuralMatch(start, end, UNVERIFIED_ENTITY, 0.40)


def _jws_score(header: dict[str, Any], parts: list[str], lengths: list[int]) -> float | None:
    alg = _string_param(header, "alg")
    if alg is None:
        return None
    signature_length = lengths[2]
    if alg == "none":
        return 0.96 if parts[2] == "" else None
    exact_lengths = {
        "HS256": 32, "HS384": 48, "HS512": 64,
        "ES256": 64, "ES384": 96, "ES512": 132,
        "EdDSA": -1,
    }
    if alg in exact_lengths:
        expected = exact_lengths[alg]
        if expected == -1:
            return 0.96 if signature_length in {64, 114} else None
        return 0.96 if signature_length == expected else None
    if alg in _RSA_JWS_ALGORITHMS | _PSS_JWS_ALGORITHMS:
        return 0.93 if MIN_RSA_BYTES <= signature_length <= MAX_RSA_BYTES else None
    return None


def _jws_match(token: str, start: int, end: int) -> StructuralMatch | None:
    if token.count(".") != 2 or len(token) > MAX_TOKEN_CHARS:
        return None
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or any(len(part) > MAX_TOKEN_CHARS for part in parts):
        return None
    header = _decode_header(parts[0])
    if header is None:
        return None
    lengths = _segment_lengths(parts)
    if lengths is None:
        return None
    if not _valid_crit(header):
        return None
    alg = _string_param(header, "alg")
    if alg is None:
        return None
    b64 = header.get("b64", True)
    if type(b64) is not bool:
        return None
    if b64 is False and ("crit" not in header or "b64" not in header["crit"]):
        return None
    score = _jws_score(header, parts, lengths)
    if (alg in _RSA_JWS_ALGORITHMS | _PSS_JWS_ALGORITHMS
            and not MIN_RSA_BYTES <= lengths[2] <= MAX_RSA_BYTES):
        return StructuralMatch(start, end, UNVERIFIED_ENTITY, 0.40)
    if score is None and alg in _KNOWN_JWS_ALGORITHMS:
        return None
    if score is not None and "crit" not in header and b64 is True:
        return StructuralMatch(start, end, JWS_ENTITY, score)
    # Unknown algorithms and critical extensions remain visible as uncertainty.
    return StructuralMatch(start, end, UNVERIFIED_ENTITY, 0.40)


def _is_token_char(char: str) -> bool:
    return char in _TOKEN_CHARS


def _oversized_jose_candidate(run: str) -> bool:
    """Recognize a bounded header in an over-cap compact candidate without payload decoding."""
    start = 0
    end = len(run)
    for _ in range(MAX_EDGE_DOTS):
        if start < end and run[start] == ".":
            start += 1
        else:
            break
    for _ in range(MAX_EDGE_DOTS):
        if start < end and run[end - 1] == ".":
            end -= 1
        else:
            break
    candidate = run[start:end]
    dot_count = candidate.count(".")
    if dot_count not in {2, 4}:
        return False
    header_segment = candidate.split(".", 1)[0]
    if len(header_segment) <= MAX_HEADER_SEGMENT_CHARS:
        header = _decode_header(header_segment)
        if header is not None:
            alg = _string_param(header, "alg")
            if alg is None:
                return False
            return dot_count == 2 or _string_param(header, "enc") is not None

    # For an over-cap protected header, inspect only a small decoded prefix so
    # a recognizable JOSE header cannot be silently treated as a clean scan.
    prefix_chars = min(len(header_segment), (MAX_HEADER_SEGMENT_CHARS // 4) * 4)
    if prefix_chars == 0 or any(char not in _B64URL for char in header_segment[:prefix_chars]):
        return False
    try:
        prefix = base64.urlsafe_b64decode(header_segment[:prefix_chars])
    except (ValueError, TypeError):
        return False
    if not prefix.lstrip().startswith(b"{") or re.search(rb'"alg"\s*:', prefix) is None:
        return False
    return dot_count == 2 or re.search(rb'"enc"\s*:', prefix) is not None


def _paired_markdown_emphasis(text: str, start: int, end: int) -> bool:
    left = 0
    while left < 3 and start - left - 1 >= 0 and text[start - left - 1] == "*":
        left += 1
    right = 0
    while right < 3 and end + right < len(text) and text[end + right] == "*":
        right += 1
    if left not in {1, 2} or right != left:
        return False
    before = text[start - left - 1] if start - left - 1 >= 0 else None
    after = text[end + right] if end + right < len(text) else None
    if before is not None and (
        _is_token_char(before) or before in _INVALID_BASE64_PREFIXES | _INVALID_BASE64_SUFFIXES
    ):
        return False
    if after is not None and after != "." and (
        _is_token_char(after) or after in _INVALID_BASE64_PREFIXES | _INVALID_BASE64_SUFFIXES
    ):
        return False
    return True


def _match_run(text: str, start: int, end: int) -> StructuralMatch | None:
    # A sentence can end directly after a compact value. Periods are also JOSE
    # separators, so trim only empty edge segments and preserve internal dots.
    paired_emphasis = _paired_markdown_emphasis(text, start, end)
    if end < len(text) and text[end] in _INVALID_BASE64_SUFFIXES and not paired_emphasis:
        return None
    edge_dots = 0
    while start < end and text[start] == "." and edge_dots < MAX_EDGE_DOTS:
        start += 1
        edge_dots += 1
    if start >= end:
        return None
    if start > 0 and text[start - 1] in _INVALID_BASE64_PREFIXES and not paired_emphasis:
        return None
    trimmed = 0
    candidate_end = end
    while candidate_end > start and candidate_end - start <= MAX_TOKEN_CHARS:
        token = text[start:candidate_end]
        dots = token.count(".")
        if dots == 4:
            match = _jwe_match(token, start, candidate_end)
            if match is not None:
                if (candidate_end == len(text) or text[candidate_end] not in _INVALID_BASE64_SUFFIXES
                        or paired_emphasis):
                    return match
                return None
        elif dots == 2:
            match = _jws_match(token, start, candidate_end)
            if match is not None:
                if (candidate_end == len(text) or text[candidate_end] not in _INVALID_BASE64_SUFFIXES
                        or paired_emphasis):
                    return match
                return None
        if (candidate_end <= start or text[candidate_end - 1] != "."
                or trimmed >= MAX_EDGE_DOTS):
            break
        candidate_end -= 1
        trimmed += 1
    return None


def scan_compact_tokens(text: str) -> list[StructuralMatch]:
    """Return bounded compact JWE/JWS structural candidates in source order.

    The scan is linear in the input size, retains no source values, and caps
    each candidate, total candidate input, and result count. A source larger
    than the configured ceiling fails explicitly so it cannot look like a
    successful clean scan.
    """
    if type(text) is not str:
        raise TypeError("text must be str")
    if len(text) > MAX_SOURCE_CHARS:
        raise ValueError("JOSE input exceeds the bounded source limit")

    matches = []
    candidate_chars = 0
    index = 0
    while index < len(text) and len(matches) < MAX_CANDIDATES and candidate_chars < MAX_CANDIDATE_CHARS:
        while index < len(text) and not _is_token_char(text[index]):
            index += 1
        start = index
        dots = 0
        while index < len(text) and _is_token_char(text[index]):
            if text[index] == ".":
                dots += 1
            index += 1
        end = index
        length = end - start
        if not start < end or dots < 2:
            continue
        if candidate_chars + length > MAX_CANDIDATE_CHARS:
            raise ValueError("JOSE candidate scan budget exceeded")
        candidate_chars += length
        if length > MAX_TOKEN_CHARS:
            if _oversized_jose_candidate(text[start:end]):
                raise ValueError("JOSE candidate exceeds the bounded token limit")
            continue
        first_dot = text.find(".", start, end)
        if first_dot >= 0 and first_dot - start > MAX_HEADER_SEGMENT_CHARS:
            if _oversized_jose_candidate(text[start:end]):
                raise ValueError("JOSE candidate exceeds the bounded header limit")
            continue
        match = _match_run(text, start, end)
        if match is not None:
            matches.append(match)
    if index < len(text) and (len(matches) >= MAX_CANDIDATES or candidate_chars >= MAX_CANDIDATE_CHARS):
        raise ValueError("JOSE candidate scan budget exceeded")
    return matches
