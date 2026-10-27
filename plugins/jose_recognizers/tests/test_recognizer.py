from __future__ import annotations

import base64
import json

import pytest

from jose_recognizers.plugin import build_recognizers
from jose_recognizers.scanner import JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_native_factory_returns_explicit_presidio_recognizer_and_value_free_spans():
    recognizer = build_recognizers({})[0]
    token = f"{_b64(json.dumps({'alg':'dir','enc':'A256GCM'}, separators=(',', ':')).encode())}..{_b64(b'i' * 12)}..{_b64(b't' * 16)}"
    text = "leading " + token + " trailing"
    results = recognizer.analyze(text, [JWE_ENTITY], None)
    assert len(results) == 1
    assert results[0].entity_type == JWE_ENTITY
    assert (results[0].start, results[0].end) == (text.index(token), text.index(token) + len(token))
    assert results[0].score == 0.99
    assert not any(item.entity_type == JWS_ENTITY for item in results)
    assert token not in repr(results[0])
    assert recognizer.supported_entities == [JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY]


@pytest.mark.parametrize("options", [None, [], {"threshold": 0.5}])
def test_factory_rejects_unspecified_configuration(options):
    with pytest.raises(ValueError, match="invalid JOSE recognizer options"):
        build_recognizers(options)
