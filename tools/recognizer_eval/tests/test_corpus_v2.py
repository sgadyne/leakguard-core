"""V2 corpus independence, labels, and metric accounting regressions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))

from tools.recognizer_eval.auxiliary import build_auxiliary_cases as build_v1_auxiliary_cases
from tools.recognizer_eval.auxiliary_v2 import build_auxiliary_cases
from tools.recognizer_eval.corpus import (
    DEFAULT_SEED as V1_SEED, _concat_kdf, _derive, _ec_private,
    build_cases as build_v1_cases,
)
from tools.recognizer_eval.corpus_v2 import (
    CLEAN_NEGATIVE_COUNT, DEFAULT_SEED, JWE_COUNT, JWS_COUNT, _header_shape,
    _make_jwe, _make_jws, _unb64url, build_adversarial_cases, build_cases,
    v1_normalized_rendering,
)
from tools.recognizer_eval.freeze_v2 import holdout_authorized, make_manifest
from tools.recognizer_eval.metrics import _span_metrics, score_rows


def test_v2_counts_grouping_and_actual_render_fingerprints_are_frozen():
    cases = build_cases(DEFAULT_SEED)
    manifest = make_manifest(DEFAULT_SEED)
    assert len(cases) == JWE_COUNT + JWS_COUNT + CLEAN_NEGATIVE_COUNT == 13_000
    assert manifest["counts"]["split"] == {"dev": 10_400, "holdout": 2_600}
    assert manifest["counts"]["by_split_and_class"] == {
        "dev": {"total": 10_400, "jwe_positive": 1_600,
                "jws_candidate_positive": 800, "clean_all_jose_negative": 8_000},
        "holdout": {"total": 2_600, "jwe_positive": 400,
                    "jws_candidate_positive": 200, "clean_all_jose_negative": 2_000},
    }
    family_split = {}
    seed_split = {}
    family_fingerprint = {}
    for case in cases:
        assert family_split.setdefault(case.template_family, case.split) == case.split
        assert seed_split.setdefault(case.seed_group, case.split) == case.split
        assert hashlib.sha256(case.normalized_template.encode()).hexdigest() == case.template_fingerprint
        assert family_fingerprint.setdefault(case.template_family, case.template_fingerprint) == case.template_fingerprint
    assert len([name for name, split in family_split.items() if split == "dev"]) == 32 + 16 + 40
    assert len([name for name, split in family_split.items() if split == "holdout"]) == 8 + 4 + 10

    auxiliary = build_auxiliary_cases(DEFAULT_SEED)
    auxiliary_family_split = {}
    for case in auxiliary:
        assert auxiliary_family_split.setdefault(case.template_family, case.split) == case.split
        assert hashlib.sha256(case.normalized_template.encode()).hexdigest() == case.template_fingerprint

    dev_fingerprints = {case.template_fingerprint for case in cases + auxiliary if case.split == "dev"}
    holdout_fingerprints = {case.template_fingerprint for case in cases + auxiliary if case.split == "holdout"}
    assert dev_fingerprints.isdisjoint(holdout_fingerprints)

    # Recompute normalized concrete V1 dev renderings; do not trust family IDs
    # or the overlap count stored in the generated manifest.
    v1_dev = [case for case in build_v1_cases(V1_SEED) if case.split == "dev"]
    v1_dev += [case for case in build_v1_auxiliary_cases(V1_SEED) if case.split == "dev"]
    v1_surfaces = {v1_normalized_rendering(case) for case in v1_dev}
    v2_holdout_surfaces = {case.normalized_template for case in cases + auxiliary if case.split == "holdout"}
    assert v1_surfaces.isdisjoint(v2_holdout_surfaces)

    def actual_header_recipe(case):
        spans = list(case.expected_spans) + [(start, end) for start, end, _ in case.expected_other_spans]
        if not spans:
            return None
        token = case.text[spans[0][0]:spans[0][1]]
        try:
            return _header_shape(_unb64url(token.split(".", 1)[0]).decode("utf-8"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return None

    v1_header_recipes = {actual_header_recipe(case) for case in v1_dev
                         if actual_header_recipe(case)}
    v2_dev_header_recipes = {actual_header_recipe(case) for case in cases
                             if case.split == "dev" and actual_header_recipe(case)}
    v2_holdout_header_recipes = {actual_header_recipe(case) for case in cases
                                 if case.split == "holdout" and actual_header_recipe(case)}
    assert len(v1_header_recipes) == 10
    assert len(v2_dev_header_recipes) == 4
    assert len(v2_holdout_header_recipes) == 4
    assert v2_dev_header_recipes.isdisjoint(v2_holdout_header_recipes)
    assert v2_holdout_header_recipes.isdisjoint(v1_header_recipes)
    assert manifest["v2_holdout_vs_v1_dev_render_overlap"] == 0


def test_v2_tokens_are_valid_without_recognizer_regex_or_live_keys():
    seed = bytes(range(32))
    for algorithm in ("A256KW", "dir", "ECDH-ES"):
        for heldout_recipe in (False, True):
            token, raw_header = _make_jwe(seed, algorithm=algorithm, heldout_recipe=heldout_recipe)
            protected, encrypted_key, iv, ciphertext, tag = token.split(".")
            header = json.loads(_unb64url(protected))
            assert header == json.loads(raw_header)
            assert header["alg"] == algorithm and header["enc"] == "A256GCM"
            assert len(token.split(".")) == 5
            assert bool(encrypted_key) is (algorithm == "A256KW")
            assert len(_unb64url(iv)) == 12 and len(_unb64url(tag)) == 16
            assert ciphertext
            if algorithm == "A256KW":
                cek = aes_key_unwrap(_derive(seed, "jwe-v2/kek", 32), _unb64url(encrypted_key))
            elif algorithm == "dir":
                cek = _derive(seed, "jwe-v2/direct-content-encryption-key", 32)
            else:
                ephemeral = header["epk"]
                peer = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(_unb64url(ephemeral["x"]), "big"),
                    int.from_bytes(_unb64url(ephemeral["y"]), "big"), ec.SECP256R1()).public_key()
                shared = _ec_private(seed, "jwe-v2/recipient-p256").exchange(ec.ECDH(), peer)
                cek = _concat_kdf(shared, "A256GCM", 256)
            plaintext = AESGCM(cek).decrypt(
                _unb64url(iv), _unb64url(ciphertext) + _unb64url(tag), protected.encode("ascii"))
            assert json.loads(plaintext)["scope"] == "synthetic-evaluation"

    root = hashlib.sha256(f"jose-synthetic-v2-true-template-2026-10:{DEFAULT_SEED}:generator-v2".encode()).digest()
    token_seed = _derive(root, "v2-token-seed/v2-jws/p2-jws-jws-angle/000", 32)
    token, raw_header = _make_jws(token_seed, heldout_recipe=True)
    protected, payload, signature = token.split(".")
    assert json.loads(_unb64url(protected)) == json.loads(raw_header)
    expected = hmac.new(_derive(token_seed, "jws-v2/signing-key", 32),
                        f"{protected}.{payload}".encode("ascii"), hashlib.sha256).digest()
    assert hmac.compare_digest(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), expected)


def test_v2_jws_is_separate_and_adversarial_cases_never_enter_confusion_metrics():
    cases = build_cases()
    jws = [case for case in cases if case.negative_kind == "jws-candidate"]
    assert len(jws) == JWS_COUNT
    assert all(case.format_outcome == "negative" and not case.expected_spans
               and len(case.expected_other_spans) == 1 for case in jws)
    adversarial = build_adversarial_cases()
    assert len(adversarial) == 120
    assert all(case.format_outcome == "adversarial" for case in adversarial)


def _metric_row(outcome, family, *, expected=(), other=(), candidates=(), jwe_alert=False,
                jws_alert=False, actionability="unknown"):
    jwe_candidates = [candidate for candidate in candidates
                      if candidate["entity"] in {"JOSE_COMPACT_JWE", "JOSE_COMPACT_UNVERIFIED"}]
    jws_candidates = [candidate for candidate in candidates
                      if candidate["entity"] == "JOSE_COMPACT_JWS_CANDIDATE"]
    return {
        "format_outcome": outcome, "expected_spans": [list(span) for span in expected],
        "expected_other_spans": [list(span) for span in other],
        "candidate_spans": [[candidate["start"], candidate["end"]] for candidate in jwe_candidates],
        "review_candidate_spans": [[candidate["start"], candidate["end"]] for candidate in jwe_candidates
                                    if candidate["score"] >= .35],
        "jws_candidate_spans": [[candidate["start"], candidate["end"]] for candidate in jws_candidates],
        "jws_review_candidate_spans": [[candidate["start"], candidate["end"]] for candidate in jws_candidates
                                       if candidate["score"] >= .35],
        "candidate_count": len(candidates), "jwe_candidate_count": len(jwe_candidates),
        "jws_candidate_count": len(jws_candidates), "span_score_count": len(jwe_candidates),
        "jws_span_score_count": len(jws_candidates), "candidates": candidates,
        "max_score": max((candidate["score"] for candidate in jwe_candidates), default=None),
        "score_available": any(candidate["score"] is not None for candidate in jwe_candidates),
        "review_threshold": .35, "block_threshold": .80,
        "review_alert": jwe_alert, "jws_review_alert": jws_alert,
        "block_alert": False, "high_score_alert": False, "supported_jwe_alert": jwe_alert,
        "template_family": family, "input_error": None, "actionability": actionability,
        "mode": "embedded", "category": outcome, "algorithm": "A256KW",
    }


def test_jwe_clean_negative_jws_and_union_denominators_are_distinct():
    rows = [
        _metric_row("positive", "jwe", expected=((0, 5),),
                    candidates=({"start": 0, "end": 5, "score": .99, "severity": "review",
                                "entity": "JOSE_COMPACT_JWE"},), jwe_alert=True, actionability="exposed"),
        _metric_row("negative", "jws", other=((0, 5, "JOSE_COMPACT_JWS_CANDIDATE"),),
                    candidates=({"start": 0, "end": 5, "score": .98, "severity": "review",
                                "entity": "JOSE_COMPACT_JWS_CANDIDATE"},
                               {"start": 0, "end": 5, "score": .70, "severity": "review",
                                "entity": "JOSE_COMPACT_JWE"}), jwe_alert=True, jws_alert=True),
        _metric_row("negative", "clean-a"),
        _metric_row("negative", "clean-b",
                    candidates=({"start": 0, "end": 5, "score": .60, "severity": "review",
                                "entity": "JOSE_COMPACT_JWE"},), jwe_alert=True),
    ]
    metrics = score_rows(rows)
    clean = metrics["jwe_vs_clean_negatives"]
    assert clean["positive_jwe_cases"] == 1 and clean["clean_negative_cases"] == 2
    assert clean["jws_candidates_excluded_from_clean_negative_denominator"] == 1
    assert clean["counts"]["tp"] == 1 and clean["counts"]["fp"] == 1
    assert metrics["jwe_alerts_on_jws_candidates"] == {
        "cases": 1, "jwe_review_alerts": 1, "rate": 1.0,
    }
    union = metrics["jose_union_metrics"]
    assert union["jose_positive_cases"] == 2 and union["clean_negative_cases"] == 2
    assert union["counts"]["tp"] == 2 and union["counts"]["fp"] == 1
    assert metrics["jws_candidate_metrics"]["counts"]["tp"] == 1


def test_span_metrics_one_to_one_partial_overlap_and_review_threshold_are_separate():
    rows = [{
        "expected_spans": [[1, 3], [8, 9]],
        "candidate_spans": [[0, 10], [1, 3], [20, 21]],
        "review_candidate_spans": [[0, 10], [20, 21]],
        "span_score_count": 3,
    }]
    result = _span_metrics(rows)
    assert result["exact"] == {"tp": 1, "fp": 2, "fn": 1,
                               "precision": 1 / 3, "recall": 1 / 2, "f1": .4}
    assert result["overlap"]["tp"] == 2
    assert result["overlap"]["fp"] == 1 and result["overlap"]["fn"] == 0
    point = score_rows([{
        **_metric_row("positive", "below-threshold", expected=((1, 3),),
                      candidates=({"start": 1, "end": 3, "score": .2, "severity": "info",
                                  "entity": "JOSE_COMPACT_JWE"},)),
        "review_alert": False,
    }])
    assert point["span_metrics"]["exact"]["tp"] == 1
    assert point["review_threshold_span_metrics"]["exact"]["tp"] == 0
    assert point["review_threshold_span_metrics"]["exact"]["fn"] == 1
    assert point["span_metrics"]["prediction_source"] == "raw candidates"
    assert point["review_threshold_span_metrics"]["prediction_source"] == "review-threshold candidates"


def test_document_gate_reports_raw_and_review_point_and_never_credits_missing_token():
    from tools.recognizer_eval.adapter import Candidate
    from tools.recognizer_eval.documents import DocumentCase, evaluate_document_cases
    from leakguard_core.extraction import ExtractionResult, TextPart

    token = "five.part.synthetic.token.value"
    source = f"Authorization: Bearer {token}"
    case = DocumentCase("below-review", "plain-text", "fixture.txt", b"fixture",
                        "positive", "exposed", token, "intact-supported-jwe")

    class Detector:
        review_threshold = .35
        block_threshold = .80

        def detect(self, text, context):
            start = text.index(token)
            return [Candidate(start, start + len(token), .2, "info", "fixture", "JOSE_COMPACT_JWE")]

    class Adapter:
        detector = Detector()
        review_threshold = .35

    def extractor(data, path, *, limits=None):
        return ExtractionResult("plain-text", "extracted", (TextPart("part", source, "plain-text"),), ())

    metrics = evaluate_document_cases(Adapter(), [case], extractor=extractor)
    assert metrics["raw_candidate_counts"]["tp"] == 1
    assert metrics["counts"]["fn"] == 1
    assert metrics["span_metrics"]["raw_candidates"]["exact"]["tp"] == 1
    assert metrics["span_metrics"]["review_threshold_candidates"]["exact"]["fn"] == 1


def test_holdout_runner_authorization_is_read_from_lead_contract(tmp_path):
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({"evaluation": {"holdout_authorized": False}}))
    assert holdout_authorized(contract) is False
    contract.write_text(json.dumps({"evaluation": {"holdout_authorized": True}}))
    assert holdout_authorized(contract) is True


def test_holdout_runner_calls_are_blocked_by_current_lead_contract():
    import pytest
    from tools.recognizer_eval.evaluate import run as run_evaluation
    from tools.recognizer_eval.gitleaks import run as run_gitleaks

    with pytest.raises(PermissionError, match="holdout-not-authorized"):
        run_evaluation(Path("unused-profile"), Path("unused-output"), split="holdout")
    with pytest.raises(PermissionError, match="holdout-not-authorized"):
        run_gitleaks(Path("unused-gitleaks"), split="holdout")
