"""Synthetic, installed-package pattern-only acceptance through the worker API.

No model downloads or source import paths are configured. Run in a Python 3.11
environment with the adapter, core and firm example installed from wheels.
"""
from __future__ import annotations

import json
import socket
import sys
from unittest.mock import patch

from leakguard_core import models, plugins
from presidio_detector.plugin import create_plugin


def main():
    factory = "firm_presidio_recognizer.plugin:build_recognizers"
    options = {
        "entities": ["EMAIL_ADDRESS", "FIRM_ACCOUNT_ID"],
        "ner-mode": "pattern-only",
        "recognizer-modules": [factory],
        "recognizer-options": json.dumps({factory: {"prefix": "FIRM-DEMO"}}),
    }
    positive = "person@example.com\naccount_id=FIRM-DEMO-73K9Q2PD"
    negative = "account_id=BUILD-73K9Q2PD"

    def deny_network(*_args, **_kwargs):
        raise AssertionError("pattern-only analyzer attempted network access")

    with patch.object(socket.socket, "connect", deny_network), patch.object(socket, "create_connection", deny_network):
        detector = create_plugin(options)
        try:
            assert detector.capabilities()["ner_enabled"] is False
            direct = list(detector.detect(positive, context=None))
            assert {row.analysis.entity_type for row in direct} == {"EMAIL_ADDRESS", "FIRM_ACCOUNT_ID"}
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
        assert {row.analysis.entity_type for row in findings} == {"EMAIL_ADDRESS", "FIRM_ACCOUNT_ID"}
        assert {row.severity for row in findings} == {"review"}
        assert all(row.analysis.model_id == "no-op-nlp" for row in findings)
        assert "73K9Q2PD" not in repr(findings)
        assert "person@example.com" not in repr(findings)
        assert list(plugins.detect(instances, negative, "negative.txt", "text",
                                   timeout=30, limits=limits, worker_policy=policy)) == []
        metrics = plugins.session_metrics(instances)
        assert metrics[0]["starts"] == 1 and metrics[0]["requests"] == 2
        process = instances[0].session.worker.process
    finally:
        plugins.close(instances)
    assert process.poll() is not None
    print(json.dumps({"outcome": "passed", "worker_policy": policy,
                      "ner_enabled": False, "positive_entities": 2,
                      "negative_findings": 0, "session_starts": 1}))


if __name__ == "__main__":
    main()
