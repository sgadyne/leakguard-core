"""Public serialization examples: structural format fixtures, not secrets."""
from __future__ import annotations

from jose_recognizers.plugin import build_recognizers
from jose_recognizers.scanner import JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY


# Canonical compact example from RFC 7516 Appendix A.1 (official rfc-editor
# text, https://www.rfc-editor.org/rfc/rfc7516.txt). Line wrapping from the
# source is removed within each base64url segment.
RFC7516_A1_RSA_OAEP_A256GCM = (
    "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
    "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
    "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
    "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
    "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
    "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
    "6UklfCpIMfIjf7iGdXKHzg."
    "48V1_ALb6US04U3b."
    "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
    "SdiwkIr3ajwQzaBtQD_A."
    "XFBoMYUZodetZdvTiFvSkQ"
)

# Canonical compact example from RFC 7516 Appendix A.2 (same official source).
RFC7516_A2_RSA1_5_A128CBC_HS256 = (
    "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
    "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"
    "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"
    "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"
    "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"
    "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"
    "-B3oWh2TbqmScqXMR4gp_A."
    "AxY8DCtDaGlsbGljb3RoZQ."
    "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
    "9hH0vgRfYgPnAHOd8stkvw"
)

# Canonical compact example from RFC 7515 Appendix A.1 (official rfc-editor
# text, https://www.rfc-editor.org/rfc/rfc7515.txt).
RFC7515_A1_HS256 = (
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)


def _assert_value_free_structural_result(token: str, expected_entity: str, expected_score: float):
    recognizer = build_recognizers({})[0]
    text = "πrefix: " + token + " :tail"
    results = recognizer.analyze(
        text,
        [JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY],
        None,
    )
    assert len(results) == 1
    result = results[0]
    assert result.entity_type == expected_entity
    assert (result.start, result.end) == (text.index(token), text.index(token) + len(token))
    assert result.score == expected_score
    assert token not in repr(result)
    assert token not in repr(vars(result))


def test_rfc7516_appendix_a1_rsa_oaep_a256gcm_is_structural_jwe():
    _assert_value_free_structural_result(RFC7516_A1_RSA_OAEP_A256GCM, JWE_ENTITY, 0.99)


def test_rfc7516_appendix_a2_rsa1_5_a128cbc_hs256_is_structural_jwe():
    _assert_value_free_structural_result(RFC7516_A2_RSA1_5_A128CBC_HS256, JWE_ENTITY, 0.99)


def test_rfc7515_appendix_a1_hs256_is_structural_jws_candidate():
    _assert_value_free_structural_result(RFC7515_A1_HS256, JWS_ENTITY, 0.96)
