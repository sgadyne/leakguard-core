from __future__ import annotations

from pathlib import Path
import socket
from types import SimpleNamespace

import pytest

from presidio_detector.plugin import (
    ANALYZER_VERSION,
    MANIFEST,
    PresidioConfigurationError,
    create_plugin,
    installed_model_sha256,
)


_EXAMPLE_SOURCE = Path(__file__).parents[1] / "examples" / "firm_presidio_recognizer" / "src"


def _findings(detector, text):
    return list(detector.detect(text, context=None))


def test_pattern_only_emits_value_free_character_locations():
    detector = create_plugin({
        "entities": ["EMAIL_ADDRESS"],
        "ner-mode": "pattern-only",
    })
    text = "release notes\ncontact=person@example.com\nbuild=2.2.365"
    try:
        findings = _findings(detector, text)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule == "presidio-entity"
        assert finding.line == 2
        assert finding.severity == "review"
        assert finding.analysis is not None
        assert finding.analysis.schema_version == 1
        assert finding.analysis.entity_type == "EMAIL_ADDRESS"
        # Presidio's built-in email recognizer includes the explicit field
        # label in its span when the value is written as a key/value pair.
        assert finding.analysis.start == text.index("contact=")
        assert finding.analysis.end == text.index("\nbuild=")
        assert finding.analysis.score == 1.0
        assert finding.analysis.analyzer_id == "presidio"
        assert finding.analysis.recognizer_id.startswith("presidio-builtin-")
        assert len(finding.analysis.recognizer_id) <= 200
        assert finding.analysis.analyzer_version == ANALYZER_VERSION
        assert finding.analysis.model_id == "no-op-nlp"
        assert "person@example.com" not in repr(finding)
        assert MANIFEST.result_schema == 2
        assert MANIFEST.worker_lifetime == "session"
        assert detector.capabilities()["ner_enabled"] is False
    finally:
        detector.close()


def test_builtin_email_recognizer_works_with_egress_denied(monkeypatch):
    def reject_network(*_args, **_kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", reject_network)
    monkeypatch.setattr(socket, "create_connection", reject_network)
    detector = create_plugin({"entities": ["EMAIL_ADDRESS"], "ner-mode": "pattern-only"})
    try:
        findings = _findings(detector, "contact=person@example.com")
        assert len(findings) == 1
        assert findings[0].analysis.entity_type == "EMAIL_ADDRESS"
    finally:
        detector.close()


def test_newline_start_offset_uses_core_line_convention():
    detector = create_plugin({"entities": ["EMAIL_ADDRESS"], "ner-mode": "pattern-only"})

    class FixedResultAnalyzer:
        def analyze(self, **_kwargs):
            return [SimpleNamespace(
                entity_type="EMAIL_ADDRESS",
                start=1,
                end=2,
                score=0.5,
                recognition_metadata={},
            )]

    detector._analyzer = FixedResultAnalyzer()
    try:
        findings = _findings(detector, "a\nb")
        assert len(findings) == 1
        assert findings[0].analysis.start == 1
        assert findings[0].line == 1
    finally:
        detector.close()


def test_confidence_does_not_promote_severity_and_session_reuses_engine():
    review = create_plugin({"entities": ["EMAIL_ADDRESS"], "ner-mode": "pattern-only"})
    blocking = create_plugin({
        "entities": ["EMAIL_ADDRESS"],
        "ner-mode": "pattern-only",
        "block-entities": ["EMAIL_ADDRESS"],
    })
    try:
        email = "person@example.com"
        review_engine = review._analyzer
        review_first = _findings(review, email)
        review_second = _findings(review, email)
        assert review._analyzer is review_engine
        assert review._calls == 2
        assert review_first[0].analysis.score == 1.0
        assert review_first[0].severity == "review"
        assert review_second[0].severity == "review"
        assert _findings(blocking, email)[0].severity == "block"
    finally:
        review.close()
        blocking.close()


def test_reviewed_native_firm_recognizer_and_negative_control(monkeypatch):
    monkeypatch.syspath_prepend(str(_EXAMPLE_SOURCE))
    module_spec = "firm_presidio_recognizer.plugin:build_recognizers"
    detector = create_plugin({
        "entities": ["FIRM_ACCOUNT_ID"],
        "ner-mode": "pattern-only",
        "recognizer-modules": [module_spec],
        "recognizer-options": '{"firm_presidio_recognizer.plugin:build_recognizers":{"prefix":"FIRM-DEMO"}}',
    })
    try:
        positive = _findings(detector, "account_id=FIRM-DEMO-73K9Q2PD")
        negative = _findings(detector, "account_id=BUILD-73K9Q2PD")
        assert len(positive) == 1
        assert positive[0].analysis.entity_type == "FIRM_ACCOUNT_ID"
        assert positive[0].analysis.recognizer_id.startswith("presidio-firm-")
        assert len(positive[0].analysis.recognizer_id) <= 200
        assert negative == []
        assert detector.capabilities()["custom_recognizer_count"] == 1
        assert "73K9Q2PD" not in repr(positive[0])
        another = create_plugin({
            "entities": ["FIRM_ACCOUNT_ID"],
            "ner-mode": "pattern-only",
            "recognizer-modules": [module_spec],
            "recognizer-options": '{"firm_presidio_recognizer.plugin:build_recognizers":{"prefix":"FIRM-DEMO"}}',
        })
        try:
            second_positive = _findings(another, "account_id=FIRM-DEMO-73K9Q2PD")
            assert second_positive[0].analysis.recognizer_id == positive[0].analysis.recognizer_id
        finally:
            another.close()
    finally:
        detector.close()


def test_required_ner_fails_clearly_when_configured_model_is_missing():
    with pytest.raises(ModuleNotFoundError, match="configured Presidio NER model is unavailable"):
        create_plugin({"entities": ["PERSON"], "model-name": "model_not_installed", "model-sha256": "0" * 64, "ner-mode": "required"})


def test_pattern_only_rejects_entities_without_pattern_recognizers():
    with pytest.raises(PresidioConfigurationError, match="not supported by the selected recognizers"):
        create_plugin({"entities": ["PERSON"], "ner-mode": "pattern-only"})


def test_required_spacy_ner_uses_configured_model_without_fallback():
    detector = create_plugin({
        "entities": ["PERSON"],
        "ner-mode": "required",
        "model-sha256": installed_model_sha256("en_core_web_sm"),
    })
    try:
        capabilities = detector.capabilities()
        assert capabilities["ner_enabled"] is True
        assert capabilities["model_id"].startswith("en_core_web_sm:3.8.0:")
        findings = _findings(detector, "meeting with Jane Exampleton")
        assert any(f.analysis.entity_type == "PERSON" for f in findings)
    finally:
        detector.close()


def test_required_ner_rejects_a_model_for_the_wrong_language():
    with pytest.raises(PresidioConfigurationError, match="model does not support language"):
        create_plugin({
            "entities": ["PERSON"],
            "language": "fr",
            "model-name": "en_core_web_sm",
            "ner-mode": "required",
            "model-sha256": installed_model_sha256("en_core_web_sm"),
        })


def test_required_ner_rejects_a_mismatched_model_identity(monkeypatch):
    monkeypatch.setattr("presidio_detector.plugin._build_analyzer", lambda _config: pytest.fail("model loaded before identity check"))
    with pytest.raises(ModuleNotFoundError, match="configured Presidio NER model identity mismatch"):
        create_plugin({
            "entities": ["PERSON"],
            "ner-mode": "required",
            "model-name": "en_core_web_sm",
            "model-sha256": "0" * 64,
        })


def test_custom_recognizer_requires_an_explicit_entity_allowlist(monkeypatch):
    monkeypatch.syspath_prepend(str(_EXAMPLE_SOURCE))
    with pytest.raises(PresidioConfigurationError, match="capabilities do not match"):
        # The actual module is loaded only after options validation. This first
        # failure documents that a custom type must be present in entities.
        create_plugin({
            "entities": ["EMAIL_ADDRESS"],
            "ner-mode": "pattern-only",
            "recognizer-modules": ["firm_presidio_recognizer.plugin:build_recognizers"],
            "recognizer-options": '{"firm_presidio_recognizer.plugin:build_recognizers":{"prefix":"FIRM-DEMO"}}',
        })
