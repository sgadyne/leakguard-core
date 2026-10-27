from __future__ import annotations

import base64
import json
import os

import pytest

from jose_recognizers.scanner import (
    JWE_ENTITY,
    JWS_ENTITY,
    MAX_HEADER_BYTES,
    MAX_SOURCE_CHARS,
    MAX_TOKEN_CHARS,
    UNVERIFIED_ENTITY,
    scan_compact_tokens,
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _header(**values) -> str:
    return _b64(json.dumps(values, separators=(",", ":")).encode())


def _jwe(alg="dir", enc="A256GCM", *, encrypted_key="", iv=None, ciphertext="", tag=None, header=None):
    if iv is None:
        iv = _b64(b"i" * 12)
    if tag is None:
        tag = _b64(b"t" * 16)
    protected = header if header is not None else _header(alg=alg, enc=enc)
    return f"{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}"


def test_direct_jwe_accepts_legitimate_empty_encrypted_key_and_exact_offsets():
    token = _jwe()
    text = "before=\"" + token + "\"\r\nafter"
    found = scan_compact_tokens(text)
    assert len(found) == 1
    assert (found[0].start, found[0].end) == (text.index(token), text.index(token) + len(token))
    assert found[0].entity_type == JWE_ENTITY
    assert found[0].score == 0.99
    assert token not in repr(found[0])


@pytest.mark.parametrize("alg", ["A256KW", "dir"])
def test_crypto_library_generated_a256gcm_jwe_with_leading_header_whitespace(alg):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap

    protected = _b64(b' \t{"alg":"' + alg.encode("ascii") + b'","enc":"A256GCM"}')
    cek = os.urandom(32)
    encrypted_key = _b64(aes_key_wrap(os.urandom(32), cek)) if alg == "A256KW" else ""
    iv = os.urandom(12)
    ciphertext_and_tag = AESGCM(cek).encrypt(
        iv, b"disposable synthetic plaintext", protected.encode("ascii")
    )
    token = ".".join(
        (protected, encrypted_key, _b64(iv), _b64(ciphertext_and_tag[:-16]), _b64(ciphertext_and_tag[-16:]))
    )

    text = "Authorization: " + token
    found = scan_compact_tokens(text)
    assert len(found) == 1
    assert found[0].entity_type == JWE_ENTITY
    assert (found[0].start, found[0].end) == (len("Authorization: "), len(text))


def test_assignment_delimiter_before_candidate_is_preserved_as_context():
    token = _jwe()
    text = "ACCESS_TOKEN=" + token + "\n"
    found = scan_compact_tokens(text)
    assert len(found) == 1
    assert (found[0].start, found[0].end) == (len("ACCESS_TOKEN="), len(text) - 1)


def test_ecdh_es_direct_jwe_accepts_empty_key_but_wrapped_ecdh_does_not():
    epk = {"kty": "OKP", "crv": "X25519", "x": _b64(b"x" * 32)}
    direct = _jwe("ECDH-ES", header=_header(alg="ECDH-ES", enc="A256GCM", epk=epk))
    wrapped = _jwe("ECDH-ES+A256KW", header=_header(alg="ECDH-ES+A256KW", enc="A256GCM", epk=epk))
    assert [item.entity_type for item in scan_compact_tokens(direct)] == [JWE_ENTITY]
    assert scan_compact_tokens(wrapped) == []


def test_ecdh_supported_curves_require_canonical_full_width_coordinates():
    def candidate(epk):
        return _jwe("ECDH-ES", header=_header(alg="ECDH-ES", enc="A256GCM", epk=epk))

    for curve, width in (("P-256", 32), ("P-384", 48), ("P-521", 66)):
        epk = {
            "kty": "EC", "crv": curve,
            "x": _b64(b"x" * width), "y": _b64(b"y" * width),
        }
        assert scan_compact_tokens(candidate(epk))[0].entity_type == JWE_ENTITY
        assert scan_compact_tokens(candidate({**epk, "x": _b64(b"x")})) == []

    x448 = {"kty": "OKP", "crv": "X448", "x": _b64(b"x" * 56)}
    assert scan_compact_tokens(candidate(x448))[0].entity_type == JWE_ENTITY
    p256 = {
        "kty": "EC", "crv": "P-256",
        "x": _b64(b"x" * 32), "y": _b64(b"y" * 32),
    }
    unsupported = {**p256, "crv": "P-224"}
    unknown_kty = {**p256, "kty": "FUTURE"}
    noncanonical_x = _b64(b"x")[:-1] + "B"
    noncanonical = {**p256, "x": noncanonical_x}
    assert scan_compact_tokens(candidate(unsupported))[0].entity_type == UNVERIFIED_ENTITY
    assert scan_compact_tokens(candidate(unknown_kty))[0].entity_type == UNVERIFIED_ENTITY
    assert scan_compact_tokens(candidate(noncanonical)) == []


def test_pbes2_registry_is_exact_and_unsupported_pairs_stay_unverified():
    p2s = _b64(b"salt1234")
    for alg in ("PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"):
        header = _header(alg=alg, enc="A256GCM", p2s=p2s, p2c=4096)
        candidate = _jwe(alg, encrypted_key=_b64(b"k" * 40), header=header)
        assert scan_compact_tokens(candidate)[0].entity_type == JWE_ENTITY

    unsupported = "PBES2-HS256+A256KW"
    header = _header(alg=unsupported, enc="A256GCM", p2s=p2s, p2c=4096)
    candidate = _jwe(unsupported, encrypted_key=_b64(b"k" * 40), header=header)
    assert scan_compact_tokens(candidate)[0].entity_type == UNVERIFIED_ENTITY


def test_pbes2_salt_and_gcmkw_iv_tag_require_canonical_base64url():
    salt = _b64(b"salt1234")
    bad_salt = salt[:-1] + "B"
    pbes_header = _header(alg="PBES2-HS256+A128KW", enc="A256GCM", p2s=bad_salt, p2c=4096)
    pbes = _jwe("PBES2-HS256+A128KW", encrypted_key=_b64(b"k" * 40), header=pbes_header)

    iv = _b64(b"i" * 12)
    tag = _b64(b"t" * 16)
    bad_tag = tag[:-1] + "B"
    gcmkw_header = _header(alg="A128GCMKW", enc="A256GCM", iv=iv, tag=bad_tag)
    gcmkw = _jwe("A128GCMKW", encrypted_key=_b64(b"k" * 32), header=gcmkw_header)
    assert scan_compact_tokens(pbes) == []
    assert scan_compact_tokens(gcmkw) == []


def test_rsa_jwe_wrapped_key_sizes_route_out_of_supported_range_to_unverified():
    def candidate(size):
        return _jwe("RSA-OAEP-256", encrypted_key=_b64(b"k" * size))

    for size in (256, 1024):
        assert scan_compact_tokens(candidate(size))[0].entity_type == JWE_ENTITY
    for size in (1, 255, 1025):
        assert scan_compact_tokens(candidate(size))[0].entity_type == UNVERIFIED_ENTITY


def test_rsa_jws_signature_sizes_route_out_of_supported_range_to_unverified():
    def candidate(size):
        return f"{_header(alg='PS256')}.{_b64(b'payload')}.{_b64(b's' * size)}"

    for size in (256, 1024):
        assert scan_compact_tokens(candidate(size))[0].entity_type == JWS_ENTITY
    for size in (1, 255, 1025):
        assert scan_compact_tokens(candidate(size))[0].entity_type == UNVERIFIED_ENTITY


def test_supported_aes_kw_checks_key_wrap_and_content_encryption_lengths():
    key = _b64(b"k" * (32 + 8))
    valid = _jwe("A256KW", encrypted_key=key)
    invalid = _jwe("A256KW", encrypted_key=_b64(b"k" * 32))
    assert scan_compact_tokens(valid)[0].score == 0.99
    assert scan_compact_tokens(invalid) == []
    wrong_iv = _jwe(iv=_b64(b"i" * 16))
    assert scan_compact_tokens(wrong_iv) == []


def test_cbc_hmac_content_encryption_uses_its_own_cek_iv_tag_and_block_lengths():
    header = _header(alg="A128KW", enc="A128CBC-HS256")
    valid = f"{header}.{_b64(b'k' * 40)}.{_b64(b'i' * 16)}.{_b64(b'c' * 16)}.{_b64(b't' * 16)}"
    bad_wrap = f"{header}.{_b64(b'k' * 24)}.{_b64(b'i' * 16)}.{_b64(b'c' * 16)}.{_b64(b't' * 16)}"
    bad_ciphertext = f"{header}.{_b64(b'k' * 40)}.{_b64(b'i' * 16)}.{_b64(b'c' * 15)}.{_b64(b't' * 16)}"
    assert scan_compact_tokens(valid)[0].entity_type == JWE_ENTITY
    assert scan_compact_tokens(bad_wrap) == []
    assert scan_compact_tokens(bad_ciphertext) == []


def test_unknown_algorithms_remain_low_confidence_structural_candidates():
    candidate = _jwe("CUSTOM-DIRECT", header=_header(alg="CUSTOM-DIRECT", enc="CUSTOM-ENC"))
    found = scan_compact_tokens(candidate)
    assert len(found) == 1
    assert found[0].entity_type == UNVERIFIED_ENTITY
    assert found[0].score == 0.40


def test_three_part_jws_is_structural_candidate_and_not_jwe():
    token = f"{_header(alg='HS256')}.{_b64(b'payload')}.{_b64(b's' * 32)}"
    found = scan_compact_tokens("Authorization: Bearer " + token)
    assert len(found) == 1
    assert found[0].entity_type == JWS_ENTITY
    assert found[0].score == 0.96
    assert found[0].start == len("Authorization: Bearer ")
    assert found[0].end == found[0].start + len(token)


def test_jws_signature_lengths_and_unsecured_empty_signature_are_algorithm_aware():
    wrong_hmac = f"{_header(alg='HS256')}.{_b64(b'x')}.{_b64(b's' * 31)}"
    unsecured = f"{_header(alg='none')}.{_b64(b'payload')}."
    empty_payload = f"{_header(alg='HS256')}..{_b64(b's' * 32)}"
    assert scan_compact_tokens(wrong_hmac) == []
    assert scan_compact_tokens(unsecured)[0].entity_type == JWS_ENTITY
    assert scan_compact_tokens(empty_payload)[0].entity_type == JWS_ENTITY


def test_unknown_jws_algorithm_and_critical_extensions_are_unverified():
    unknown_alg = f"{_header(alg='CUSTOM-SIG')}.{_b64(b'payload')}.{_b64(b'signature')}"
    critical = f"{_header(alg='HS256', crit=['custom'], custom='x')}.{_b64(b'payload')}.{_b64(b's' * 32)}"
    assert scan_compact_tokens(unknown_alg)[0].entity_type == UNVERIFIED_ENTITY
    assert scan_compact_tokens(critical)[0].entity_type == UNVERIFIED_ENTITY


def test_unsupported_jwe_critical_extension_is_unverified_and_malformed_crit_rejected():
    critical = _jwe(header=_header(alg="dir", enc="A256GCM", crit=["custom"], custom="x"))
    malformed = _jwe(header=_header(alg="dir", enc="A256GCM", crit="custom"))
    assert scan_compact_tokens(critical)[0].entity_type == UNVERIFIED_ENTITY
    assert scan_compact_tokens(malformed) == []


def test_duplicate_or_malformed_json_headers_are_rejected():
    duplicate = _b64(b'{"alg":"dir","alg":"dir","enc":"A256GCM"}')
    invalid_utf8 = _b64(b'{"alg":"dir","enc":"\xff"}')
    invalid_json = _b64(b'{"alg":NaN,"enc":"A256GCM"}')
    assert scan_compact_tokens(_jwe(header=duplicate)) == []
    assert scan_compact_tokens(_jwe(header=invalid_utf8)) == []
    assert scan_compact_tokens(_jwe(header=invalid_json)) == []


def test_header_and_candidate_caps_reject_without_scanning_payload_content():
    huge_header = _b64(b" " * (MAX_HEADER_BYTES + 1))
    assert scan_compact_tokens(_jwe(header=huge_header)) == []
    deeply_nested = _b64(b'{"alg":"dir","enc":"A256GCM","x":' + b'[' * 33 + b'0' + b']' * 33 + b'}')
    assert scan_compact_tokens(_jwe(header=deeply_nested)) == []
    overlong = "A" * 16385 + ".e30..x.y"
    assert scan_compact_tokens(overlong) == []
    with pytest.raises(ValueError, match="bounded source limit"):
        scan_compact_tokens("x" * (MAX_SOURCE_CHARS + 1))


def test_recognizable_oversized_candidates_and_budget_overshoot_fail_closed(monkeypatch):
    import jose_recognizers.scanner as scanner

    huge_ciphertext = _jwe(ciphertext=_b64(b"c" * MAX_TOKEN_CHARS))
    assert len(huge_ciphertext) > MAX_TOKEN_CHARS
    with pytest.raises(ValueError, match="bounded token limit"):
        scan_compact_tokens(huge_ciphertext)

    overlong_header = _b64(b'{"alg":"dir","enc":"A256GCM","note":"' + b"h" * MAX_HEADER_BYTES + b'"}')
    assert len(overlong_header) > MAX_HEADER_BYTES * 4 // 3
    with pytest.raises(ValueError, match="bounded header limit"):
        scan_compact_tokens(_jwe(header=overlong_header))

    monkeypatch.setattr(scanner, "MAX_CANDIDATE_CHARS", 10)
    with pytest.raises(ValueError, match="candidate scan budget"):
        scan_compact_tokens(_jwe())


def test_base64url_padding_and_invalid_segment_characters_are_rejected():
    padded = _jwe(header=_header(alg="dir", enc="A256GCM") + "=")
    invalid = _jwe(ciphertext="*bad")
    assert scan_compact_tokens(padded) == []
    assert scan_compact_tokens(invalid) == []


def test_malformed_six_segment_and_invalid_alphabet_runs_are_not_truncated_to_jwe():
    valid = _jwe()
    six_segments = valid + ".extra"
    invalid_inside_ciphertext = valid.replace("..", ".*.", 1)
    invalid_after_tag = valid + "*"
    invalid_before_header = "*" + valid
    assert scan_compact_tokens(six_segments) == []
    assert scan_compact_tokens(invalid_inside_ciphertext) == []
    assert scan_compact_tokens(invalid_after_tag) == []
    assert scan_compact_tokens(invalid_before_header) == []


def test_noncanonical_base64url_segment_is_rejected():
    canonical = _b64(b"x")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(canonical[-1])
    noncanonical = canonical[:-1] + alphabet[(last & ~0b11) | ((last + 1) & 0b11)]
    assert noncanonical != canonical
    candidate = _jwe(ciphertext=noncanonical)
    assert scan_compact_tokens(candidate) == []


def test_candidate_budget_exhaustion_fails_instead_of_returning_partial_clean(monkeypatch):
    import jose_recognizers.scanner as scanner

    monkeypatch.setattr(scanner, "MAX_CANDIDATES", 1)
    token = _jwe()
    with pytest.raises(ValueError, match="candidate scan budget"):
        scan_compact_tokens(token + " " + token)


def test_no_eyj_assumption_and_friendly_adjacent_text():
    header = _b64(b'\n{"enc":"A256GCM","alg":"dir"}')
    token = _jwe(header=header)
    assert not token.startswith("eyJ")
    text = "café: " + token + "\n" + token + ",\n"
    found = scan_compact_tokens(text)
    assert [(item.start, item.end) for item in found] == [
        (text.index(token), text.index(token) + len(token)),
        (text.rindex(token), text.rindex(token) + len(token)),
    ]


def test_leading_and_trailing_sentence_periods_do_not_shift_token_offsets():
    token = _jwe()
    text = "." + token + "."
    found = scan_compact_tokens(text)
    assert len(found) == 1
    assert (found[0].start, found[0].end) == (1, 1 + len(token))


@pytest.mark.parametrize(("opening", "closing"), [("*", "*"), ("**", "**"), ("`", "`")])
def test_markdown_emphasis_and_inline_code_keep_token_offsets(opening, closing):
    token = _jwe()
    text = "before " + opening + token + closing + " after"
    found = scan_compact_tokens(text)
    assert len(found) == 1
    assert found[0].entity_type == JWE_ENTITY
    assert (found[0].start, found[0].end) == (text.index(token), text.index(token) + len(token))


def test_malformed_or_unpaired_markdown_asterisks_do_not_truncate_candidates():
    token = _jwe()
    for text in (
        "*" + token,
        token + "*",
        "***" + token + "***",
        "*" + token + "**",
        "*+" + token + "*",
    ):
        assert scan_compact_tokens(text) == []


def test_jws_empty_signature_with_sentence_punctuation_keeps_empty_signature_span():
    token = f"{_header(alg='none')}.{_b64(b'payload')}."
    text = token + "."
    found = scan_compact_tokens(text)
    assert len(found) == 1
    assert found[0].entity_type == JWS_ENTITY
    assert (found[0].start, found[0].end) == (0, len(token))
