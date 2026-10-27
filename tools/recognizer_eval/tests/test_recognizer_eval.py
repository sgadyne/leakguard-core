"""Dedicated checks for independent JOSE corpus generation and scoring."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

from tools.recognizer_eval.corpus import (
    DEFAULT_SEED, POSITIVE_COUNT, NEGATIVE_COUNT, _concat_kdf, _derive, _ec_private,
    _unb64url, build_adversarial_cases, build_cases, make_jwe,
)
from tools.recognizer_eval.documents import DocumentCase, evaluate_document_cases
from tools.recognizer_eval.freeze import make_manifest
from tools.recognizer_eval.metrics import score_rows, score_threshold_sweep
from leakguard_core.extraction import ExtractionResult, TextPart


def _decrypt(token, seed):
    protected, encrypted_key, iv, ciphertext, tag = token.split(".")
    header = json.loads(_unb64url(protected))
    algorithm = header["alg"]
    if algorithm == "A256KW":
        cek = aes_key_unwrap(_derive(seed, "kek", 32), _unb64url(encrypted_key))
    elif algorithm == "dir":
        assert encrypted_key == ""
        cek = _derive(seed, "direct-content-encryption-key", 32)
    else:
        assert algorithm == "ECDH-ES" and encrypted_key == ""
        numbers = header["epk"]
        peer = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_unb64url(numbers["x"]), "big"),
            int.from_bytes(_unb64url(numbers["y"]), "big"),
            ec.SECP256R1(),
        ).public_key()
        shared = _ec_private(seed, "recipient-p256").exchange(ec.ECDH(), peer)
        cek = _concat_kdf(shared, "A256GCM", 256)
    return AESGCM(cek).decrypt(_unb64url(iv), _unb64url(ciphertext) + _unb64url(tag), protected.encode("ascii"))


def test_jwe_generator_emits_five_parts_and_independently_decryptable_cases():
    seed = bytes(range(32))
    for algorithm in ("A256KW", "dir", "ECDH-ES"):
        token = make_jwe(seed, algorithm=algorithm, header_variant=2)
        parts = token.split(".")
        assert len(parts) == 5
        assert all("=" not in part for part in parts)
        header = json.loads(_unb64url(parts[0]))
        assert header["alg"] == algorithm
        assert header["enc"] == "A256GCM"
        assert bool(parts[1]) is (algorithm == "A256KW")
        assert json.loads(_decrypt(token, seed))["sub"].startswith("synthetic-")


def test_corpus_counts_labels_and_grouped_holdout_are_frozen():
    cases = build_cases(DEFAULT_SEED)
    assert sum(case.format_outcome == "positive" for case in cases) == POSITIVE_COUNT
    assert sum(case.format_outcome == "negative" for case in cases) == NEGATIVE_COUNT
    assert {case.split for case in cases} == {"dev", "holdout"}
    families = {}
    seed_groups = {}
    for case in cases:
        assert families.setdefault(case.template_family, case.split) == case.split
        assert seed_groups.setdefault(case.seed_group, case.split) == case.split
    assert not ({key for key, split in families.items() if split == "dev"}
                & {key for key, split in families.items() if split == "holdout"})
    assert not ({key for key, split in seed_groups.items() if split == "dev"}
                & {key for key, split in seed_groups.items() if split == "holdout"})
    positives = [case for case in cases if case.format_outcome == "positive"]
    assert all(case.text[start:end].count(".") == 4 for case in positives
               for start, end in case.expected_spans)
    public = [case for case in positives if case.actionability == "public"]
    assert public and all(case.label_dict()["spans"][0]["format_positive"] is True
                          and case.label_dict()["spans"][0]["actionable_exposure"] is False
                          for case in public)
    manifest = make_manifest(DEFAULT_SEED)
    assert manifest["counts"]["positive"] == 2_000
    assert manifest["counts"]["negative"] == 10_000
    assert manifest["counts"]["split"] == {"dev": 9_600, "holdout": 2_400}


def test_adversarial_derivatives_are_never_benign_negative_labels():
    cases = build_adversarial_cases()
    assert len(cases) == 120
    assert all(case.format_outcome == "adversarial" and case.split == "adversarial" for case in cases)
    assert {case.adversarial_reason for case in cases} == {
        "bad-authentication-tag", "duplicate-header-member", "padded-base64url",
        "wrong-algorithm-fields", "invalid-base64url", "extra-segment",
        "truncated-header", "unsupported-algorithm", "oversized-header",
        "wrong-encrypted-key-shape", "empty-ciphertext", "malformed-json",
    }
    result = score_rows([{
        "format_outcome": "adversarial", "candidate_count": 0, "jwe_candidate_count": 0,
        "review_alert": False, "block_alert": False, "high_score_alert": False,
        "input_error": "ValueError", "adversarial_reason": "oversized-header",
        "template_family": "adversarial", "expected_spans": [], "candidate_spans": [],
        "span_score_count": 0, "candidates": [], "actionability": "unknown",
        "mode": "standalone", "category": "malformed-or-unsupported-jose",
        "algorithm": "unknown", "expected_other_spans": [],
    }])
    assert result["population"]["binary_metric_cases"] == 0
    assert result["adversarial"]["cases"] == 1
    assert result["adversarial"]["input_errors"] == 1
    assert result["adversarial"]["by_reason"]["oversized-header"]["input_errors"] == 1
    assert "tn" not in result["adversarial"]["by_reason"]["oversized-header"]
    assert result["fixed_thresholds"]["review"]["tn"] == 0


def test_jws_cases_are_negative_for_jwe_but_positive_for_jws_entity():
    cases = [case for case in build_cases() if case.category == "three-part-jws"]
    assert len(cases) == 1_000
    assert all(case.format_outcome == "negative" and len(case.expected_other_spans) == 1
               for case in cases)
    for case in cases[:10]:
        start, end, entity = case.expected_other_spans[0]
        assert case.text[start:end].count(".") == 2
        assert entity == "JOSE_COMPACT_JWS_CANDIDATE"


def test_jws_findings_do_not_count_as_jwe_false_positives():
    jws = {
        "format_outcome": "negative", "expected_spans": [],
        "expected_other_spans": [[0, 8, "JOSE_COMPACT_JWS_CANDIDATE"]],
        "candidate_spans": [], "candidate_count": 1, "candidates": [
            {"start": 0, "end": 8, "score": 0.9, "severity": "review",
             "entity": "JOSE_COMPACT_JWS_CANDIDATE"}],
        "template_family": "jws", "actionability": "unknown", "mode": "standalone",
        "category": "three-part-jws", "algorithm": "HS256", "input_error": None,
        "review_alert": False, "block_alert": False, "high_score_alert": False,
        "supported_jwe_alert": False, "score_available": False, "max_score": None,
        "review_threshold": 0.35, "block_threshold": 0.8,
    }
    jwe_positive = {
        **jws, "format_outcome": "positive", "expected_spans": [[0, 8]],
        "expected_other_spans": [], "candidate_spans": [[0, 8]],
        "candidate_count": 1, "jwe_candidate_count": 1,
        "candidates": [{"start": 0, "end": 8, "score": 1.0, "severity": "review",
                         "entity": "JOSE_COMPACT_JWE"}],
        "review_alert": True, "supported_jwe_alert": True,
        "score_available": True, "max_score": 1.0,
    }
    metrics = score_rows([jws, jwe_positive])
    assert metrics["fixed_thresholds"]["review"]["fp"] == 0
    assert metrics["jws_candidate_metrics"]["counts"]["tp"] == 1
    assert metrics["jws_candidate_metrics"]["counts"]["fp"] == 0


def test_binary_jwt_rule_attribution_keeps_other_gitleaks_alerts_as_jwe_fps():
    from tools.recognizer_eval.gitleaks import _binary_alerts

    assert _binary_alerts(["jwt"]) == (False, True)
    assert _binary_alerts(["generic-api-key", "jwt"]) == (True, True)


def test_binary_jwt_rule_on_clean_case_is_visible_as_jws_and_union_false_alert():
    from tools.recognizer_eval.gitleaks import _binary_alerts

    clean = {
        "format_outcome": "negative", "expected_spans": [], "expected_other_spans": [],
        "candidate_spans": [], "jws_candidate_spans": [], "jws_review_candidate_spans": [],
        "candidate_count": 1, "jwe_candidate_count": 0, "candidates": [{
            "rule": "jwt", "entity": "binary-gitleaks", "score": None}],
        "template_family": "clean", "seed_group": "clean-seed", "actionability": "unknown",
        "mode": "embedded", "category": "clean-non-jose", "algorithm": "none",
        "input_error": None, "review_alert": False, "jws_review_alert": True,
        "binary_jws_alert": True, "binary_only": True, "block_alert": False,
        "high_score_alert": False, "supported_jwe_alert": False, "score_available": False,
        "max_score": None, "review_threshold": None, "block_threshold": None,
        "span_score_count": 0, "jws_span_score_count": 0,
        "review_span_score_count": 0, "jws_review_span_score_count": 0,
    }
    assert _binary_alerts(["jwt"]) == (False, True)
    metrics = score_rows([clean])
    assert metrics["jws_candidate_metrics"]["counts"]["fp"] == 1
    assert metrics["jose_union_metrics"]["counts"]["fp"] == 1


def test_gitleaks_baseline_scrubs_inherited_configuration(monkeypatch):
    from tools.recognizer_eval.gitleaks import _subprocess_environment

    monkeypatch.setenv("GITLEAKS_CONFIG", "/tmp/unrelated.toml")
    monkeypatch.setenv("GITLEAKS_CONFIG_TOML", "title = 'unrelated'")
    environment = _subprocess_environment()
    assert "GITLEAKS_CONFIG" not in environment
    assert "GITLEAKS_CONFIG_TOML" not in environment


def test_binary_gitleaks_metrics_do_not_invent_severity_spans_or_score_ranking():
    from tools.recognizer_eval.gitleaks import _binary_only_metric_semantics

    rows = [
        {"format_outcome": "positive", "expected_spans": [[1, 5]], "candidate_spans": [],
         "template_family": "positive", "candidate_count": 1, "candidates": [{
             "rule": "literal-client-secret", "entity": "binary-gitleaks", "score": None}],
         "review_alert": True, "block_alert": False, "high_score_alert": False,
         "supported_jwe_alert": False, "score_available": False, "max_score": None,
         "expected_other_spans": [], "actionability": "exposed", "input_error": None},
        {"format_outcome": "negative", "expected_spans": [], "candidate_spans": [],
         "template_family": "negative", "candidate_count": 0, "candidates": [],
         "review_alert": False, "block_alert": False, "high_score_alert": False,
         "supported_jwe_alert": False, "score_available": False, "max_score": None,
         "expected_other_spans": [], "actionability": "unknown", "input_error": None},
    ]
    metrics = _binary_only_metric_semantics(score_rows(rows))
    assert metrics["fixed_thresholds"]["review"]["tp"] == 1
    assert metrics["fixed_thresholds"]["review"]["decision"] == "file has any applicable Gitleaks rule hit"
    assert metrics["fixed_thresholds"]["block"]["available"] is False
    assert metrics["supported_jwe_entity"]["available"] is False
    assert metrics["actionability_on_valid_jwe"]["block_decision"]["available"] is False
    assert metrics["span_metrics"]["available"] is False
    assert metrics["raw_scores"]["roc_auc"] is None
    assert metrics["jwe_candidates_by_returned_severity"]["available"] is False


def test_single_candidate_score_level_is_reported_as_binary_like_ranking():
    rows = [
        {"format_outcome": "positive", "expected_spans": [[0, 8]], "candidate_spans": [[0, 8]],
         "review_candidate_spans": [[0, 8]], "candidate_count": 1, "jwe_candidate_count": 1,
         "candidates": [{"start": 0, "end": 8, "score": .99, "severity": "review",
                         "entity": "JOSE_COMPACT_JWE"}],
         "template_family": "positive", "actionability": "exposed", "mode": "standalone",
         "category": "jwe", "algorithm": "A256KW", "input_error": None,
         "span_score_count": 1, "review_span_score_count": 1, "score_available": True,
         "max_score": .99, "review_alert": True, "block_alert": False,
         "high_score_alert": False, "supported_jwe_alert": True, "expected_other_spans": []},
        {"format_outcome": "negative", "expected_spans": [], "candidate_spans": [],
         "review_candidate_spans": [], "candidate_count": 0, "jwe_candidate_count": 0,
         "candidates": [], "template_family": "negative", "actionability": "unknown",
         "mode": "standalone", "category": "clean", "algorithm": "none", "input_error": None,
         "span_score_count": 0, "review_span_score_count": 0, "score_available": False,
         "max_score": None, "review_alert": False, "block_alert": False,
         "high_score_alert": False, "supported_jwe_alert": False, "expected_other_spans": []},
    ]
    raw_scores = score_rows(rows)["raw_scores"]
    assert raw_scores["candidate_score_levels"] == [.99]
    assert raw_scores["pr_auc_average_precision"] == 1.0
    assert raw_scores["roc_auc"] is None
    assert "binary-like presence ranking" in raw_scores["ranking_scope"]


def test_predeclared_score_sweep_uses_raw_scores_and_reports_wilson_intervals():
    rows = [
        {"format_outcome": "positive", "max_score": 0.4, "candidates": [],
         "mode": "standalone", "category": "supported", "algorithm": "A256KW",
         "actionability": "exposed", "input_error": None},
        {"format_outcome": "negative", "max_score": 0.1, "candidates": [],
         "mode": "embedded", "category": "lookalike", "algorithm": "none",
         "actionability": "unknown", "input_error": None},
    ]
    sweep = score_threshold_sweep(rows, group_fields=("mode",))
    at_040 = next(row for row in sweep["overall"] if row["threshold"] == 0.4)
    assert at_040["tp"] == 1 and at_040["tn"] == 1
    assert at_040["wilson_95"]["recall"] is not None
    assert set(sweep["by_slice"]["mode"]) == {"standalone", "embedded"}


def test_raw_candidate_adapter_retains_jwe_scores_and_separates_jws():
    from tools.recognizer_eval.adapter import Candidate
    from tools.recognizer_eval.evaluate import _run_one
    from tools.recognizer_eval.corpus import Case

    class Detector:
        review_threshold = 0.35
        block_threshold = 0.80

        def __init__(self, entity):
            self.entity = entity

        def detect(self, text, context):
            return [Candidate(0, len(text), 0.9, "review", "fixture", self.entity)]

    jwe_text = "a.b.c.d.e"
    jwe = Case("test-jwe", "holdout", "family", "seed", "intact-supported-jwe",
                "standalone", jwe_text, ((0, len(jwe_text)),), "positive", "unknown")
    result, _ = _run_one(Detector("JOSE_COMPACT_JWE"), jwe)
    assert result["review_alert"] is True
    assert result["max_score"] == 0.9
    assert result["supported_jwe_alert"] is True

    jws_text = "a.b.c"
    jws = Case("test-jws", "holdout", "family-jws", "seed-jws", "three-part-jws",
                "standalone", jws_text, (), "negative", "unknown",
                expected_other_spans=((0, len(jws_text), "JOSE_COMPACT_JWS_CANDIDATE"),),
                expected_entity=None)
    result, _ = _run_one(Detector("JOSE_COMPACT_JWS_CANDIDATE"), jws)
    assert result["review_alert"] is False
    assert result["candidate_count"] == 1
    assert result["jwe_candidate_count"] == 0


def test_auxiliary_evaluation_preserves_raw_candidates_and_sweeps_target_scores():
    from tools.recognizer_eval.adapter import Candidate
    from tools.recognizer_eval.auxiliary import build_auxiliary_cases, evaluate_auxiliary_cases

    class Detector:
        review_threshold = 0.35
        block_threshold = 0.80

        def detect(self, text, context):
            entity = ("US_BANK_NUMBER" if "bank account routing number:" in text else
                      "US_ITIN" if "taxpayer identification number:" in text else None)
            if entity is None or "ordinary synthetic record" in text:
                return []
            value = text.rsplit(": ", 1)[-1]
            start = text.index(value)
            return [Candidate(start, start + len(value), 0.4, "review", "fixture", entity)]

    cases = [case for case in build_auxiliary_cases() if case.split == "dev"]
    result = evaluate_auxiliary_cases(Detector(), cases)
    assert result["by_category"]["financial-positive"]["tp"] == 20
    assert result["by_category"]["identity-positive"]["tp"] == 20
    assert result["by_category"]["distant-context-negative"]["tn"] == 20
    assert result["dev_score_sweep"]["available"] is True
    at_point_four = next(row for row in result["dev_score_sweep"]["overall"]
                         if row["threshold"] == 0.4)
    assert at_point_four["tp"] == 40 and at_point_four["tn"] == 40


def test_detector_errors_on_positive_are_fn_and_negative_error_cannot_be_tn():
    metrics = score_rows([
        {"format_outcome": "positive", "expected_spans": [[1, 5]], "candidate_spans": [],
         "template_family": "positive-family", "candidate_count": 0, "candidates": [],
         "input_error": "TimeoutError", "actionability": "exposed", "block_alert": False,
         "review_alert": False, "high_score_alert": False, "supported_jwe_alert": False,
         "expected_other_spans": [], "score_available": False, "max_score": None},
        {"format_outcome": "negative", "expected_spans": [], "candidate_spans": [],
         "template_family": "negative-family", "candidate_count": 0, "candidates": [],
         "input_error": "TimeoutError", "actionability": "unknown", "block_alert": False,
         "review_alert": False, "high_score_alert": False, "supported_jwe_alert": False,
         "expected_other_spans": [], "score_available": False, "max_score": None},
    ])
    counts = metrics["fixed_thresholds"]["review"]
    assert counts["fn"] == 1
    assert counts["tn"] == 0
    from tools.recognizer_eval.metrics import _binary_counts
    zero_fp = _binary_counts([{"format_outcome": "negative", "review_alert": False}],
                             lambda row: row["review_alert"])
    assert zero_fp["wilson_95"]["fpr"][0] == 0.0
    assert metrics["population"]["incomplete_cases"] == 2


def test_document_extraction_failure_is_not_a_true_negative():
    positive = DocumentCase("positive", "office-word", "p.docx", b"not-a-docx",
                            "positive", "exposed", "synthetic.token.value", "intact-supported-jwe")
    negative = DocumentCase("negative", "office-word", "n.docx", b"not-a-docx",
                            "negative", "unknown", None, "safe-document-lookalike")

    class Detector:
        def detect(self, text, context):
            return ()

    class Adapter:
        detector = Detector()

    def omission(data, path, *, limits=None):
        return ExtractionResult("office-word", "error", (), ("extract-failed",))

    result = evaluate_document_cases(Adapter(), [positive, negative], extractor=omission)
    assert result["counts"] == {"tp": 0, "fp": 0, "tn": 0, "fn": 1}
    assert result["extraction"]["positive_omissions"] == 1
    assert result["incomplete_files"] == 1
    assert result["cases"][1]["status"] == "incomplete"


def test_document_gate_matches_candidate_within_the_correct_extracted_part():
    token = "synthetic.token.value"
    text = f"Authorization: Bearer {token}"
    positive = DocumentCase("positive", "plain-text", "p.txt", b"file",
                            "positive", "exposed", token, "intact-supported-jwe")

    class Detector:
        def detect(self, source, context):
            start = source.index(token)
            return [{"analysis": {"start": start, "end": start + len(token),
                                  "score": 0.9, "entity_type": "JOSE_COMPACT_JWE"},
                     "severity": "review", "rule": "fixture"}]

    class Adapter:
        detector = Detector()

    def extracted(data, path, *, limits=None):
        return ExtractionResult("plain-text", "extracted",
                                (TextPart("part-1", text, "plain-text"),), ())

    result = evaluate_document_cases(Adapter(), [positive], extractor=extracted)
    assert result["counts"] == {"tp": 1, "fp": 0, "tn": 0, "fn": 0}
    assert result["cases"][0]["candidate_match"] is True


def test_auxiliary_context_preset_cases_have_grouped_labels():
    from tools.recognizer_eval.auxiliary import build_auxiliary_cases

    cases = build_auxiliary_cases()
    assert len(cases) == 160
    assert sum(case.format_outcome == "positive" for case in cases) == 80
    assert sum(case.format_outcome == "negative" for case in cases) == 80
    family_splits = {}
    seed_splits = {}
    for case in cases:
        assert family_splits.setdefault(case.template_family, case.split) == case.split
        assert seed_splits.setdefault(case.seed_group, case.split) == case.split
    assert sum(case.split == "holdout" for case in cases) == 80


def test_missing_token_after_successful_extraction_is_positive_miss():
    token = "synthetic.token.value"
    positive = DocumentCase("positive", "office-word", "p.docx", b"file",
                            "positive", "exposed", token, "intact-supported-jwe")

    class Detector:
        def detect(self, text, context):
            return ()

    class Adapter:
        detector = Detector()

    def omitted_token(data, path, *, limits=None):
        return ExtractionResult("office-word", "extracted", (TextPart("office-word-1", "no target here", "office-word"),), ())

    result = evaluate_document_cases(Adapter(), [positive], extractor=omitted_token)
    assert result["counts"]["fn"] == 1
    assert result["counts"]["tn"] == 0
    assert result["extraction"]["positive_omissions"] == 1


def test_generated_document_fixtures_extract_all_labeled_positive_tokens():
    from tools.recognizer_eval.documents import build_document_cases
    from leakguard_core.extraction import extract

    cases = build_document_cases()
    assert len(cases) == 72
    for case in cases:
        result = extract(case.data, case.logical_path)
        assert result.disposition == "extracted", (case.case_id, result.disposition, result.issues)
        assert not result.issues, (case.case_id, result.issues)
        if case.token:
            assert any(case.token in part.text for part in result.parts), case.case_id
