"""Synthetic, installed-package pattern-only acceptance through the worker API.

No model downloads or source import paths are configured. Run in a Python 3.11
environment with the adapter, core and firm example installed from wheels.
"""
from __future__ import annotations

import base64
import json
import socket
import sys
from unittest.mock import patch

from leakguard_core import models, plugins
from presidio_detector.plugin import create_plugin


def main():
    factory = "firm_presidio_recognizer.plugin:build_recognizers"
    jose_factory = "jose_recognizers.plugin:build_recognizers"
    from jose_recognizers.scanner import JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY

    def b64(value):
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    # Structural fixtures deliberately carry no valid upstream authority.
    jwe = ".".join((b64(b' {"alg":"dir","enc":"A256GCM"}'), "",
                    b64(b"i" * 12), b64(b"synthetic"), b64(b"t" * 16)))
    jws = ".".join((b64(b'{"alg":"HS256"}'), b64(b"synthetic"), b64(b"s" * 32)))
    unverified = ".".join((b64(b'{"alg":"Future-Algorithm","enc":"A256GCM"}'),
                           b64(b"k" * 40), b64(b"i" * 12), b64(b"synthetic"), b64(b"t" * 16)))
    expected_entities = {"EMAIL_ADDRESS", "FIRM_ACCOUNT_ID", JWE_ENTITY, JWS_ENTITY, UNVERIFIED_ENTITY}
    options = {
        "entities": sorted(expected_entities),
        "ner-mode": "pattern-only",
        "recognizer-modules": [factory, jose_factory],
        "recognizer-options": json.dumps({factory: {"prefix": "FIRM-DEMO"}}),
    }
    positive = "person@example.com\naccount_id=FIRM-DEMO-73K9Q2PD\n" + "\n".join((jwe, jws, unverified))
    negative = "account_id=BUILD-73K9Q2PD\nnot.a.token\nredacted.value.with.five.parts"

    def deny_network(*_args, **_kwargs):
        raise AssertionError("pattern-only analyzer attempted network access")

    with patch.object(socket.socket, "connect", deny_network), patch.object(socket, "create_connection", deny_network):
        detector = create_plugin(options)
        try:
            assert detector.capabilities()["ner_enabled"] is False
            direct = list(detector.detect(positive, context=None))
            assert {row.analysis.entity_type for row in direct} == expected_entities
            assert list(detector.detect(negative, context=None)) == []
        finally:
            detector.close()

    # macOS explicitly exercises the RSS-supervised alpha policy. Linux and
    # Windows keep their strict allocation/Job Object containment policy.
    policy = "supervised-alpha" if sys.platform == "darwin" else "strict"
    limits = models.ScanLimits(90, 2, worker_memory_bytes=2 * 1024**3)
    instances = plugins.load([{"module": "presidio_detector.plugin", "options": options}],
                             timeout=30, limits=limits, worker_policy=policy)
    try:
        findings = list(plugins.detect(instances, positive, "synthetic.txt", "text",
                                       timeout=60, limits=limits, worker_policy=policy))
        assert {row.analysis.entity_type for row in findings} == expected_entities
        assert {row.severity for row in findings} == {"review"}
        assert all(row.analysis.model_id == "no-op-nlp" for row in findings)
        assert "73K9Q2PD" not in repr(findings)
        assert "person@example.com" not in repr(findings)
        for token, entity in ((jwe, JWE_ENTITY), (jws, JWS_ENTITY), (unverified, UNVERIFIED_ENTITY)):
            matches = [row for row in findings if row.analysis.entity_type == entity]
            assert len(matches) == 1
            assert (matches[0].analysis.start, matches[0].analysis.end) == (
                positive.index(token), positive.index(token) + len(token))
            assert token not in repr(findings)
        assert list(plugins.detect(instances, negative, "negative.txt", "text",
                                   timeout=30, limits=limits, worker_policy=policy)) == []
        metrics = plugins.session_metrics(instances)
        assert metrics[0]["starts"] == 1 and metrics[0]["requests"] == 2
        process = instances[0].session.worker.process
    finally:
        plugins.close(instances)
    assert process.poll() is not None
    print(json.dumps({"outcome": "passed", "worker_policy": policy,
                      "ner_enabled": False, "positive_entities": len(expected_entities),
                      "jose_exact_spans": True, "explicit_factories": 2,
                      "negative_findings": 0, "session_starts": 1}))


if __name__ == "__main__":
    main()
