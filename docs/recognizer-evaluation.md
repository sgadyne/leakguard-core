# Recognizer implementation and evaluation handoff

This document describes the historical recognizer evaluation. Its results do not
qualify the current CLI deployment kit. Exact 0.2.1a3 artifact/platform outcomes
belong in the separately retained release receipts.

The optional native profiles now detect the described compact JWE format,
distinguish JWS candidates, and retain bounded unsupported JOSE candidates for
review. Installed CLI, Git hooks and encrypted host tests pass. The sealed
synthetic holdout has 400/400 JWE and 200/200 JWS detections with exact spans and
no JOSE false alerts on 2,000 clean negatives. This establishes synthetic format
coverage, not production precision, credential validity or provider identity.

The identity preset remains noisy: every one of the 20 ITIN-shaped auxiliary
negatives produced a review alert. The low false-alert goal is not established
for broad sensitive-information profiles.

## Delivered behavior

- `plugins/jose_recognizers` supplies the native Presidio factory
  `jose_recognizers.plugin:build_recognizers`. Frozen entity IDs are
  `JOSE_COMPACT_JWE`, `JOSE_COMPACT_JWS_CANDIDATE`, and
  `JOSE_COMPACT_UNVERIFIED`. Header JSON/base64url and algorithm constraints are
  bounded; direct modes can have an empty encrypted key. There is no payload
  decryption, decompression, key retrieval or authentication.
- The Presidio adapter adds recognizer-specific local context within 96
  characters on each side of a match, bounded by line breaks. It avoids
  document-wide boosting, cropped-word artifacts and duplicate enhancement.
  Financial/identity presets are selected explicitly; healthcare is optional.
  `DetectionContext` has path, part and format fields, with no semantic column
  or field-name member. Paths are not treated as field context.
- `leakguard-recognizer-profile` composes explicit credentials, sensitive and
  firm configurations while retaining existing firm factories/options. Core
  defaults remain Gitleaks-only and lack general compact JWE coverage. Installing
  a wheel does not enable its factory. Native packages require Python 3.11;
  core gains no mandatory NLP dependency. See [setup and coverage](recognizer-coverage.md).
- Findings contain offsets and safe analysis metadata, with no matched values.
  Generic JOSE severity is review. Structure scores are not calibrated
  probabilities or exposure decisions. Gitleaks and its shipped rules remain
  available for provider credentials, assignments and private keys.

Source review found a firm-seam regression in name-based recognizer pruning.
The final implementation filters recognizer instances and verifies requested
entity support after pruning. A real installed synthetic probe and regression
test confirm a firm recognizer sharing an unselected builtin's name remains
active. This source-derived correction preceded the sealed evaluation; no
detector changes followed heldout results.

## Corpus and threshold discipline

The independent evaluator derives disposable-key JWEs from RFC 7516/7518 and
PyCA cryptography, with HMAC JWS examples. The quality corpus covers A256KW,
direct and ECDH-ES key management with A256GCM; other supported combinations
have focused structural tests, not this corpus's measured recall guarantee.
Public RFC compact examples also pass as format positives.

V1 used nominal family IDs that reused actual render recipes. It is preserved
and explicitly superseded; its results are not final quality evidence. V2 uses
fresh domain-separated seeds and concrete wrapper/header fingerprints. Its 110
main and 16 auxiliary families have 126 distinct fingerprints. Dev/holdout
fingerprints are disjoint, and independently parsed heldout header recipes and
normalized renderings do not overlap V1 dev.

| Frozen V2 population | Development | Holdout |
| --- | ---: | ---: |
| Intact JWE | 1,600 | 400 |
| Intact JWS candidates | 800 | 200 |
| Clean of either JOSE form | 8,000 | 2,000 |
| Auxiliary context/preset examples | 80 | 80 |

The 120 adversarial cases and 72 PDF/DOCX/XLSX files are shared integration
regressions, not independent holdout performance samples. Corrupted/unsupported
examples are never ordinary TNs. Positive extraction omissions are FNs;
negative extraction failures are incomplete, never TNs.

Review `0.35` and numeric comparison `1.0` were frozen using V2 development
only. Review preserves unsupported candidates at `0.40` and weak local bank
scores at `0.39999999999999997`; an exact `0.40` cutoff loses those bank matches.
The numeric comparison does not set production severity. Generic JOSE
`block-entities` remains empty. Final source/profile hashes were recorded and
installed gates passed before the single sealed pass for each frozen profile.
No labels, templates, detector rules or thresholds were tuned to heldout errors.

## Sealed results

The following is the JOSE union: a labelled JWE or JWS span is positive; only
the 2,000 clean non-JOSE examples are negatives. Precision is undefined when
there are no alerts. All four JOSE-enabled ablations have identical format
results; context/presets affect the separate information-recognition slices.

| Detector/component | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Presidio baseline, default entities, context off | 0 | 0 | 2,000 | 600 | — | 0 | 0 |
| Stock Gitleaks 8.30.1 | 100 | 0 | 2,000 | 500 | 1 | 0.167 | 0.286 |
| Gitleaks with shipped LeakGuard rules | 100 | 0 | 2,000 | 500 | 1 | 0.167 | 0.286 |
| +JOSE, context off | 600 | 0 | 2,000 | 0 | 1 | 1 | 1 |
| +JOSE, local context | 600 | 0 | 2,000 | 0 | 1 | 1 | 1 |
| +JOSE/presets, context off | 600 | 0 | 2,000 | 0 | 1 | 1 | 1 |
| +JOSE/presets, local context | 600 | 0 | 2,000 | 0 | 1 | 1 | 1 |

Each enabled native profile has JWE TP/FP/TN/FN **400/0/2,000/0** against clean
negatives and JWS **200/0/2,400/0** against its class-conditional negatives.
Exact and overlap span TP are 400 JWE and 200 JWS, with zero span FP/FN.
JWE standalone and embedded positives are 100/100 and 300/300. Both binary
Gitleaks configurations miss all JWE and detect 100/200 JWS. Binary results have
no invented continuous scores, token spans or block/exposure decisions.

Observed JOSE false alerts are **0 per 1,000 clean files**. The 95% Wilson FPR
upper bound is approximately **0.192%**, so this sample cannot establish an FPR
below 0.1% at 95% confidence. The point targets are met for the JOSE component;
they are not a production guarantee. Template bootstrap intervals are degenerate
at perfect separation and cannot reveal unseen failure modes.

Native JWE and JWS average precision are 1.0 but presence-equivalent: each has
one candidate score level (`0.99` and `0.96`), so individual ROC-AUC is omitted.
The union's two discrete ranks yield AP/ROC-AUC 1.0 on this synthetic corpus.
None is a calibrated validity probability or a measured AUC for the user's
previous missed token.

Actual native JOSE block severity returns no blocks: JWE block-point
TP/FP/TN/FN is 0/0/2,200/400, and the frozen score-only `1.0` comparison is the
same. This is the intentional review policy, not successful exposure
classification. Public format examples remain structure positives.

## Context, extraction and alert burden

With presets, local context changes heldout bank-number TP/FP/TN/FN from
**0/0/20/20** to **20/0/20/0**. ITIN remains **20/20/0/0** with or without local
context: all ITIN-shaped negatives alert at score `0.50`. Across both auxiliary
entities, local+presets has **40/20/20/0**, precision 0.667, recall 1, F1 0.8,
and 500 false alerts per 1,000 auxiliary negatives. Development bank recall was
10/20, so the small heldout success should not be generalized to unseen aliases.
Local context raises scores; it does not suppress misleading numeric shapes.
Optional healthcare registration was verified, not clinical recall.

All 72 shared documents extracted completely: 36 positive and 36 negative
files, twelve of each per format. Enabled JOSE profiles have 36/0/36/0 and
36 exact positive spans, with zero extraction omissions. Baseline native
Presidio has 0/0/36/36. These gates use core text extraction, not OCR or archive
expansion.

The 120 shared adversarial cases produce 30 JOSE candidate cases (including
bad-tag shapes, legitimate empty ciphertext and unsupported algorithms) and
10 explicit oversized-header errors. They are excluded from TP/FP/TN/FN.
Preset profiles also produce two unrelated driver-license alerts in that set.

Considering **all** enabled native entities plus shipped Gitleaks, 264/2,000
JOSE-clean heldout files have review alerts (132 per 1,000), including baseline
PII entities. Those files are not gold-labelled for every PII type, so this is
review burden, not a validated global PII FPR. The shipped-Gitleaks + JOSE-only
combination has zero alerts on those clean files. No overall low-false-alert
claim is made for sensitive or firm presets.

## Verification and measured runtime

| Gate | Result |
| --- | --- |
| Fresh installed core wheel/sdist, documents extra and public conformance | 378 passed, 5 platform/helper skips; 383 total |
| JOSE focused suite, including two RFC JWE and one RFC JWS vectors | 38 passed |
| Adapter/context/preset/firm-collision suite | 21 passed; 3 optional model cases deselected |
| Independent evaluation/method suite in integrated tree | 27 passed |
| Fresh native CLI, encrypted host, actual local commit/push hooks | All three profiles passed |
| Exact JWE/JWS/unverified spans, redaction, missing factories, source immutability, child cleanup | Passed |
| Default strict policy, 512 MiB, all three composed profiles | Complete; all three JOSE entities observed |

The first full core run exposed stale baseline test fixtures. The same six test
IDs failed against unchanged baseline source. Repairs updated existing field
and dependency expectations, forwarded current mock arguments, and made one
fixture's paging order deterministic. Runtime traversal and CI were not edited.

On this Linux/Python 3.11.2 host, the local+presets heldout run measured median
0.488 ms and p95 1.066 ms per input call, approximately 1,379 calls per summed
call-second. Whole harness time was 8.117 s including auxiliary/document gates
and statistical calculation. Largest waited-child high-water RSS was about
180 MB; it is not the in-process detector's RSS. The installed operational gate
sampled a largest child of 119,943,168 bytes and aggregate children of
159,002,624 bytes every 50 ms; the complete gate took 74.69 s. These are scoped
measurements, not performance promises. Optional NER models were not downloaded.
This run does not verify new Windows/macOS behavior.

## Evidence and reproduction

The full evaluator report, holdout artifact index and compact machine-readable
results are retained in the reviewed Git history and private qualification
evidence. Those historical run artifacts are excluded from the CLI source
archive. Frozen manifests,
seeds and hashed evaluation locks are in `tools/recognizer_eval`; preserve V1
as superseded. The run handoff contains raw candidates/scores, exact wheel
digests, source freeze, threshold/profile hashes, installed receipts and the
reproduction commands. The feature bundle requires baseline
`1fe366f86cf174862b3894042e96345200b5365a` and leaves main untouched.

The user's real token and vault were never accessed or authenticated. The prior
real miss remains one observed FN per tested prior profile; it is not an AUC.
This implementation covers its described format class on synthetic inputs.
The real token was not retested and the local Mac runtime was not changed.
