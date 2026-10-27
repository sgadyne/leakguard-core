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


def test_selected_presets_are_additive_and_do_not_enable_every_entity():
    detector = create_plugin({"presets": ["financial"]})
    try:
        capabilities = detector.capabilities()
        assert capabilities["presets"] == ["financial"]
        assert "US_BANK_NUMBER" in capabilities["entities"]
        assert set(capabilities["entities"]) == {
            "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN",
            "IBAN_CODE", "IP_ADDRESS", "US_BANK_NUMBER",
        }
        assert not {"URL", "UUID", "MAC_ADDRESS", "DATE_TIME"} & set(capabilities["entities"])
        assert set(detector._recognizer_context_terms)
    finally:
        detector.close()


def test_explicit_entities_union_with_preset_without_duplicate_expansion():
    detector = create_plugin({
        "entities": ["EMAIL_ADDRESS", "US_BANK_NUMBER"],
        "presets": ["financial"],
    })
    try:
        assert detector.capabilities()["entities"] == ["EMAIL_ADDRESS", "US_BANK_NUMBER"]
    finally:
        detector.close()


def test_unrecognized_preset_is_rejected_before_analyzer_construction():
    with pytest.raises(PresidioConfigurationError, match="invalid recognizer presets"):
        create_plugin({"presets": ["all"]})


@pytest.mark.parametrize("options", [
    {"entities": ["EMAIL_ADDRESS", "EMAIL_ADDRESS"]},
    {"presets": ["financial", "financial"]},
])
def test_duplicate_explicit_entities_and_preset_names_are_rejected(options):
    with pytest.raises(PresidioConfigurationError):
        create_plugin(options)


def test_invalid_context_mode_is_rejected_before_analyzer_construction():
    with pytest.raises(PresidioConfigurationError, match="invalid context mode"):
        create_plugin({"context-mode": "document"})


def test_context_enhancement_is_bounded_to_each_match_and_keeps_offsets():
    detector = create_plugin({"entities": ["US_BANK_NUMBER"]})
    text = "routing number: 998877665\nother: 987654321"
    first_start = text.index("998877665")
    second_start = text.index("987654321")

    class FixedResultAnalyzer:
        def analyze(self, *, score_threshold, **_kwargs):
            assert score_threshold == 0.0
            assert _kwargs["return_decision_process"] is True
            return [
                SimpleNamespace(
                    entity_type="US_BANK_NUMBER", start=first_start, end=first_start + 9,
                    score=0.05, recognition_metadata={"recognizer_identifier": "bank-recognizer"},
                ),
                SimpleNamespace(
                    entity_type="US_BANK_NUMBER", start=second_start, end=second_start + 9,
                    score=0.05, recognition_metadata={"recognizer_identifier": "bank-recognizer"},
                ),
            ]

    detector._analyzer = FixedResultAnalyzer()
    detector._recognizer_context_terms = {"bank-recognizer": (("routing", "number"),)}
    try:
        findings = _findings(detector, text)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.analysis.start == first_start
        assert finding.analysis.end == first_start + 9
        assert finding.analysis.entity_type == "US_BANK_NUMBER"
        assert finding.analysis.score == pytest.approx(0.4)
        assert finding.line == 1
        assert "998877665" not in repr(finding)

        no_context = create_plugin({"entities": ["US_BANK_NUMBER"], "context-mode": "none"})
        try:
            no_context._analyzer = FixedResultAnalyzer()
            no_context._recognizer_context_terms = {"bank-recognizer": (("routing", "number"),)}
            assert no_context.capabilities()["context_mode"] == "none"
            assert _findings(no_context, text) == []
        finally:
            no_context.close()
    finally:
        detector.close()


def test_context_window_is_bounded_and_respects_cr_and_crlf_lines():
    detector = create_plugin({"entities": ["EMAIL_ADDRESS"]})
    terms = (("routing", "number"),)
    try:
        far_text = "routing number " + ("x" * 4096) + " 998877665"
        far_start = far_text.index("998877665")
        assert detector._has_local_context(far_text, far_start, far_start + 9, terms) is False

        # A bounded slice may begin/end inside a longer word. Its fragment is
        # not a complete context token.
        left_crop = "Xbank" + (" " * 92) + "998877665"
        left_start = left_crop.index("998877665")
        assert detector._has_local_context(left_crop, left_start, left_start + 9,
                                           (("bank",),)) is False
        left_complete = "X bank" + (" " * 91) + "998877665"
        left_complete_start = left_complete.index("998877665")
        assert detector._has_local_context(left_complete, left_complete_start,
                                           left_complete_start + 9, (("bank",),)) is True
        right_crop = "998877665" + (" " * 92) + "banker"
        assert detector._has_local_context(right_crop, 0, 9, (("bank",),)) is False
        right_complete = "998877665" + (" " * 91) + "bank next"
        assert detector._has_local_context(right_complete, 0, 9, (("bank",),)) is True

        split_phrase = "routing 998877665 number"
        split_start = split_phrase.index("998877665")
        assert detector._has_local_context(split_phrase, split_start, split_start + 9,
                                           (("routing", "number"),)) is False

        cr_separated = "routing number\r998877665"
        cr_start = cr_separated.index("998877665")
        assert detector._has_local_context(cr_separated, cr_start, cr_start + 9, terms) is False

        crlf_separated = "routing number\r\n998877665"
        crlf_start = crlf_separated.index("998877665")
        assert detector._has_local_context(crlf_separated, crlf_start, crlf_start + 9, terms) is False

        same_cr_line = "routing number: 998877665\rnext"
        cr_candidate_start = same_cr_line.index("998877665")
        assert detector._has_local_context(same_cr_line, cr_candidate_start,
                                           cr_candidate_start + 9, terms) is True
    finally:
        detector.close()


def test_context_fallback_skips_presidio_already_enhanced_results():
    detector = create_plugin({"entities": ["US_BANK_NUMBER"]})
    text = "routing number: 998877665 and routing number: 887766554"
    first_start = text.index("998877665")
    second_start = text.index("887766554")

    class PresidioEnhancedResults:
        def analyze(self, **_kwargs):
            assert _kwargs["return_decision_process"] is True
            return [
                SimpleNamespace(
                    entity_type="US_BANK_NUMBER", start=first_start, end=first_start + 9,
                    score=0.4,
                    recognition_metadata={"recognizer_identifier": "bank-recognizer",
                                          "is_score_enhanced_by_context": True},
                ),
                SimpleNamespace(
                    entity_type="US_BANK_NUMBER", start=second_start, end=second_start + 9,
                    score=0.4,
                    recognition_metadata={"recognizer_identifier": "bank-recognizer"},
                    analysis_explanation=SimpleNamespace(supportive_context_word="routing"),
                ),
            ]

    detector._analyzer = PresidioEnhancedResults()
    detector._recognizer_context_terms = {"bank-recognizer": (("routing", "number"),)}
    try:
        findings = _findings(detector, text)
        assert [finding.analysis.score for finding in findings] == [0.4, 0.4]
    finally:
        detector.close()


def test_financial_preset_uses_real_recognizer_context_at_match_scope():
    text = "bank account routing number: 998877665"
    start = text.index("998877665")
    local = create_plugin({"presets": ["financial"], "score-threshold": "0"})
    none = create_plugin({
        "presets": ["financial"], "score-threshold": "0", "context-mode": "none",
    })
    try:
        local_findings = _findings(local, text)
        bank = [item for item in local_findings if item.analysis.entity_type == "US_BANK_NUMBER"]
        assert len(bank) == 1
        assert bank[0].analysis.score == pytest.approx(0.4)
        assert (bank[0].analysis.start, bank[0].analysis.end) == (start, start + 9)
        # The SSN pattern sees the same digits, but this recognizer's unrelated
        # context terms do not raise its raw candidate score.
        ssn = [item for item in local_findings if item.analysis.entity_type == "US_SSN"]
        assert len(ssn) == 1
        assert ssn[0].analysis.score == pytest.approx(0.05)
        none_bank = [item for item in _findings(none, text)
                     if item.analysis.entity_type == "US_BANK_NUMBER"]
        assert len(none_bank) == 1
        assert none_bank[0].analysis.score == pytest.approx(0.05)
    finally:
        local.close()
        none.close()


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


@pytest.mark.parametrize(("text", "start", "line"), [
    ("a\rb", 2, 1),
    ("a\r\nb", 3, 2),
])
def test_line_numbers_match_core_lf_convention_and_preserve_offsets(text, start, line):
    detector = create_plugin({"entities": ["EMAIL_ADDRESS"]})

    class FixedResultAnalyzer:
        def analyze(self, **_kwargs):
            return [SimpleNamespace(
                entity_type="EMAIL_ADDRESS",
                start=start,
                end=start + 1,
                score=0.5,
                recognition_metadata={},
            )]

    detector._analyzer = FixedResultAnalyzer()
    try:
        findings = _findings(detector, text)
        assert len(findings) == 1
        assert findings[0].analysis.start == start
        assert findings[0].analysis.end == start + 1
        assert findings[0].line == line
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


def test_custom_recognizer_same_name_as_pruned_builtin_is_preserved(monkeypatch, tmp_path):
    module_path = tmp_path / "firm_collision_recognizer.py"
    module_path.write_text(
        "from presidio_analyzer import Pattern, PatternRecognizer\n"
        "def build_recognizers(options):\n"
        "    if options != {}:\n"
        "        raise ValueError('unexpected options')\n"
        "    return [PatternRecognizer(\n"
        "        name='CreditCardRecognizer',\n"
        "        supported_entity='FIRM_COLLISION_ID',\n"
        "        supported_language='en',\n"
        "        patterns=[Pattern(\n"
        "            name='synthetic firm collision identifier',\n"
        "            regex=r'\\bFIRM-COLLISION-[A-Z0-9]{8}\\b',\n"
        "            score=0.8,\n"
        "        )],\n"
        "    )]\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    module_spec = "firm_collision_recognizer:build_recognizers"
    detector = create_plugin({
        "entities": ["EMAIL_ADDRESS", "FIRM_COLLISION_ID"],
        "recognizer-modules": [module_spec],
    })
    text = "contact=person@example.com; firm=FIRM-COLLISION-73K9Q2PD"
    email = "person@example.com"
    firm_id = "FIRM-COLLISION-73K9Q2PD"
    try:
        findings = _findings(detector, text)
        by_entity = {finding.analysis.entity_type: finding for finding in findings}
        assert set(by_entity) == {"EMAIL_ADDRESS", "FIRM_COLLISION_ID"}
        # Presidio's built-in email recognizer includes its key/value label.
        assert (by_entity["EMAIL_ADDRESS"].analysis.start,
                by_entity["EMAIL_ADDRESS"].analysis.end) == (
                    text.index("contact="), text.index("; firm"),
                )
        assert (by_entity["FIRM_COLLISION_ID"].analysis.start,
                by_entity["FIRM_COLLISION_ID"].analysis.end) == (
                    text.index(firm_id), text.index(firm_id) + len(firm_id),
                )
        assert by_entity["FIRM_COLLISION_ID"].analysis.recognizer_id.startswith("presidio-firm-")
        assert email not in repr(findings)
        assert firm_id not in repr(findings)
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
