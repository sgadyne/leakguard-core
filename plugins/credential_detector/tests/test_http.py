import base64

import pytest

from credential_detector.http import scan_http
from credential_detector.types import CredentialSpan


def basic(value):
    return base64.b64encode(value.encode()).decode()


@pytest.mark.parametrize("header,rule,token", [
    ("Authorization: Basic dXNlcjpwYXNz", "credential-http-basic", "dXNlcjpwYXNz"),
    ("aUtHoRiZaTiOn:\t bAsIc\t" + basic("üser:päss:more") + "  ", "credential-http-basic", basic("üser:päss:more")),
    (" \tAuthorization: Bearer a", "credential-http-bearer", "a"),
    ("AUTHORIZATION: bearer Az09-._~+/==\t", "credential-http-bearer", "Az09-._~+/=="),
])
def test_literal_headers_and_original_unicode_offsets(header, rule, token):
    text = "π first\r\n" + header + "\r\nlast"
    start = len("π first\r\n") + header.rfind(token)
    assert scan_http(text) == (CredentialSpan(rule, start, start + len(token)),)
    assert text[start:start + len(token)] == token
    assert repr(scan_http(text)) == repr((CredentialSpan(rule, start, start + len(token)),))


def test_span_repr_does_not_include_token():
    assert "synthetic-secret-123" not in repr(scan_http("Authorization: Bearer synthetic-secret-123"))


def test_multiple_lines_and_end_of_input():
    text = "GET / HTTP/1.1\nAuthorization: Bearer abc\nAuthorization: Basic dTpw"
    spans = scan_http(text)
    assert [s.rule for s in spans] == ["credential-http-bearer", "credential-http-basic"]
    assert [text[s.start:s.end] for s in spans] == ["abc", "dTpw"]


@pytest.mark.parametrize("line", [
    "Proxy-Authorization: Bearer abc", "X-Authorization: Bearer abc",
    "prefix Authorization: Bearer abc", "Authorization : Bearer abc",
    "Authorization:Bearer", "Authorization: Bearer", "Authorization:Bearerabc",
    "Authorization: Bearer abc trailing", "Authorization: Bearer abc,def",
    "Authorization: Bearer abc\rjunk", "Authorization: Bearer abc\v",
    "Authorization: Bearer abc\u2028Authorization: Bearer def",
    "Authorization: Bearer abc=def", "Authorization: Bearer ===",
    "Authorization: Bearer $TOKEN", "Authorization: Bearer ${TOKEN}",
    "Authorization: Bearer {{TOKEN}}", 'Authorization: Bearer "${TOKEN}"',
    "Authorization: Bearer <token>", "Authorization: Bearer %TOKEN%",
    "Authorization: Basic dTpw!", "Authorization: Basic dTpw=",
    "Authorization: Basic dTpwAAAA=", "Authorization: Basic dT",
])
def test_reject_incomplete_malformed_and_non_headers(line):
    assert scan_http(line) == ()


@pytest.mark.parametrize("value", [
    "no-colon", "user:", "user:  ",
    "user:pass\nInjected: value", "user:pass\rnext", "user:pass\x00",
    "user:${PASSWORD}", "${USER}:secret", "user:$PASSWORD", "user:$(secret)",
    "user:%PASSWORD%", "user:{{password}}", "user:<password>",
    'user:"${PASSWORD}"',
])
def test_basic_requires_literal_printable_user_password(value):
    assert scan_http("Authorization: Basic " + basic(value)) == ()


@pytest.mark.parametrize("value", ["u:foo${BAR}baz", 'u:"$PASSWORD"', "u:literal$NAMEsuffix"])
def test_basic_embedded_or_quoted_dollar_is_literal(value):
    token = basic(value)
    assert len(scan_http("Authorization: Basic " + token)) == 1


def test_basic_requires_valid_utf8_and_canonical_base64():
    assert scan_http("Authorization: Basic " + base64.b64encode(b"user:\xff").decode()) == ()
    # Non-zero unused padding bits decode to the same bytes, but are not canonical.
    assert scan_http("Authorization: Basic dTpwZh==") == ()


def test_bounds_and_line_ending_edges():
    token = "a" * 4096
    text = "Authorization: Bearer " + token + "\nAuthorization: Bearer z"
    spans = scan_http(text)
    assert len(spans) == 2
    assert text[spans[0].start:spans[0].end] == token
    assert scan_http("Authorization: Bearer a\r\n") == (CredentialSpan("credential-http-bearer", 22, 23),)
    assert scan_http("Authorization: Bearer a\rAuthorization: Bearer b") == ()
    assert scan_http("Authorization: Bearer a\r") == ()
    assert scan_http("Authorization: Bearer a\r\n continued") == ()
    assert scan_http("Authorization: Bearer a\n\tcontinued") == ()
    assert len(scan_http("Authorization: Bearer a\n Authorization: Bearer b")) == 2
    assert scan_http("Authorization: Basic " + basic(basic("user:pass"))) == ()


def test_empty_basic_username_is_permitted():
    token = basic(":password")
    assert scan_http("Authorization: Basic " + token) == (
        CredentialSpan("credential-http-basic", 21, 21 + len(token)),
    )


@pytest.mark.parametrize("line", [
    "Authorization: Bearer " + "a" * 4097,
    "Authorization: Basic " + "Y" * 4100,
    "unrelated " + "x" * 8192,
    "Authorization: Bearer " + " " * 8192 + "abc",
])
def test_exceeding_scan_bound_fails_closed_without_values(line):
    with pytest.raises(ValueError, match="exceeds scan bound") as exc:
        scan_http(line)
    assert line not in str(exc.value)
