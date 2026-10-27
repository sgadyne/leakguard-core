# JOSE recognizer evaluation report

**Status:** V2 DEV and the single lead-authorized sealed holdout run are complete
at the lead-frozen review threshold 0.35 and numeric block-score comparison
1.0. The V1 metrics remain superseded diagnostics and did not inform threshold
selection. No detector, template, label, preset, or threshold was changed after
the V2 DEV freeze.

## Frozen data and execution

The active, text-free `split_manifest_v2.json` has label SHA-256
`605e3ad37b9f762fc7863ec390b09cff1f581b5bf57f71a253b6c689183c96c1`, rendering
fingerprint map SHA-256
`51cd9a228250253b5ecbf73cf989a58ee120fb5685fdbe0f7ddb2932b1cb3a7d`, and file
SHA-256 `813ce2075d226a9d482ec184f40e57d4059b2f6fdd75b9443bd8678ad6c71021`.
The freeze check regenerates labels and fingerprints, checks family and seed
group separation, and compares normalized concrete V2 holdout surfaces against
V1 dev, including its auxiliary set. Measured overlap is zero. A separate test
parses the generated protected headers and compares member-order/field-shape
recipes directly: V1 dev has 10, V2 dev has 4, V2 holdout has 4, and V2
holdout shares none with either V2 dev or V1 dev. The original V1
manifest remains unchanged (SHA-256
`c332e245658672828b7a818d8293f58f81785f2f12150036b4d48d6d91a7184b`).

| Set | JWE | JWS candidate | Clean non-JOSE | Total |
|---|---:|---:|---:|---:|
| Dev | 1,600 | 800 | 8,000 | 10,400 |
| Holdout, detector sealed | 400 | 200 | 2,000 | 2,600 |
| Total main corpus | 2,000 | 1,000 | 10,000 | 13,000 |

V2 uses 32 dev / 8 holdout JWE rendering families, 16 / 4 JWS families, and 40
/ 10 clean-negative families. Each JWE/JWS family has 50 seed groups; each clean
family has 200. The separate finance/identity context slice has 80 dev and 80
holdout examples in distinct template families and seed groups. The 120
adversarial cases and 72 PDF/DOCX/XLSX files are shared regression gates, not
independent holdout performance samples.

Generators use JOSE structure and PyCA cryptography, not detector expressions.
JWE cases use disposable, independently decryptable A256KW, `dir`, or ECDH-ES
keys with A256GCM; JWS cases use synthetic HS256. Labels include exact
half-open Unicode offsets and distinguish format structure from exposure.
JWS candidates remain negative for JWE, positive for their own target, and are
separately labeled as positives for the JOSE union. Unknown actionability is
null and is not treated as benign.

The final valid V2 DEV reruns used Python 3.11.2 and cryptography 50.0.2. All
five detector source hashes match lead detector freeze v2 (freeze-file
SHA-256 `96adcf2d1b694875b31378271fa782e355cf3f84b5238ec705cfd94c6d19a0a9`),
including the updated Presidio plugin. The lead tree advanced during the
five-profile run; per-output source commits are recorded in raw JSON, and
historical hash checks verified all five detector files matched the freeze
at every recorded commit. Final metric semantics are committed at
`138584cf795c0f620585239403d538dd35b01c5f`, with Gitleaks provenance at
`f81121d5892ab8d814b2ef8dc0ad5d03af007c1a`. Presidio used `pattern-only`, raw
`score-threshold: "0"`, review 0.35 and high-score comparison 1.0. The five
profile SHA-256 values were sent to the lead and final Gitleaks outputs under
`RUN_ROOT/artifacts/evaluation-v2-final-f81121d/`
and native outputs under
`RUN_ROOT/artifacts/evaluation-v2-final-freeze2/`
record evaluator commits and clean trees.

| DEV profile | SHA-256 |
|---|---|
| baseline | `c9c1362f34e0c2c99ea4f3a6dc17bf1be5b97581f5d9196163777adc91f01112` |
| JOSE, no context | `bcc341590ad9a5998ca689044c005dbb612907857eb353aab638bf66d5472848` |
| JOSE, local context | `6ff7f9bcb50f5a1f8c9ae8eabec01263502c45969eba71d31fa788c275c95edd` |
| JOSE + presets, no context | `d553ae90e06b33e36ec8c5e5f06075c95addb7fb59c050a82be2a4271cd5b22b` |
| JOSE + presets, local context | `21c729735fa80e25ad249c8a606212aabef274895e0108f076d24d77ff7fbb9c` |

## Baseline and JOSE development results

Primary JWE review counts use 1,600 JWE positives and 8,800 JWE negatives,
including 800 separately labeled JWS cases. The class-conditional JWE table
excludes those 800 JWS candidates and uses only 8,000 clean negatives. JWS
metrics use 800 positives and 9,600 negatives (the 1,600 JWE plus 8,000 clean
cases). The JOSE union uses 2,400 positives and 8,000 clean negatives.

All rows below use the lead-frozen review threshold 0.35. `+JOSE` variants
include `JOSE_COMPACT_UNVERIFIED`; preset profiles add financial and identity
entities. Counts are TP / FP / TN / FN.

| Detector/profile | JWE target | JWE vs clean negatives | JWS target | JOSE union |
|---|---:|---:|---:|---:|
| Presidio baseline | 0 / 0 / 8,800 / 1,600 | 0 / 0 / 8,000 / 1,600 | 0 / 0 / 9,600 / 800 | 0 / 0 / 8,000 / 2,400 |
| +JOSE, no context | 1,600 / 0 / 8,800 / 0 | 1,600 / 0 / 8,000 / 0 | 800 / 0 / 9,600 / 0 | 2,400 / 0 / 8,000 / 0 |
| +JOSE, local context | 1,600 / 0 / 8,800 / 0 | 1,600 / 0 / 8,000 / 0 | 800 / 0 / 9,600 / 0 | 2,400 / 0 / 8,000 / 0 |
| +JOSE, presets, no context | 1,600 / 0 / 8,800 / 0 | 1,600 / 0 / 8,000 / 0 | 800 / 0 / 9,600 / 0 | 2,400 / 0 / 8,000 / 0 |
| +JOSE, local context and presets | 1,600 / 0 / 8,800 / 0 | 1,600 / 0 / 8,000 / 0 | 800 / 0 / 9,600 / 0 | 2,400 / 0 / 8,000 / 0 |
| Gitleaks 8.30.1 built-in defaults, binary presence only | 0 / 0 / 8,800 / 1,600 | 0 / 0 / 8,000 / 1,600 | 0 / 0 / 9,600 / 800 | 0 / 0 / 8,000 / 2,400 |
| Gitleaks 8.30.1 + shipped `rules.toml`, binary presence only | 0 / 0 / 8,800 / 1,600 | 0 / 0 / 8,000 / 1,600 | 0 / 0 / 9,600 / 800 | 0 / 0 / 8,000 / 2,400 |

The `+JOSE` results also hold in both placement modes at 0.35:

| Mode / profile | JWE positives | JWE negatives | `+JOSE` counts (TP / FP / TN / FN) |
|---|---:|---:|---:|
| Standalone, baseline | 300 | 2,200 | 0 / 0 / 2,200 / 300 |
| Embedded, baseline | 1,300 | 6,600 | 0 / 0 / 6,600 / 1,300 |
| Standalone, each `+JOSE` variant | 300 | 2,200 | 300 / 0 / 2,200 / 0 |
| Embedded, each `+JOSE` variant | 1,300 | 6,600 | 1,300 / 0 / 6,600 / 0 |

The two Gitleaks baselines each use one invocation on 10,400 DEV rows plus 120
shared adversarial regressions. Both emitted zero rule hits. The shipped config
SHA-256 is
`18b69dbd64b74486a42bc9db414910208ec69f049b911618becd80a16d9e42c8`; stock
uses Gitleaks 8.30.1 built-in defaults, with inherited config environment
variables removed. A hit is a file-level binary finding. The `jwt` rule maps
to the JWS target independently of gold labels, and the JOSE union includes
either JWS or generic file-level alerts. Block/severity, actionability, spans,
and ranking metrics are unavailable for Gitleaks.

For native JOSE profiles, raw and review-threshold span results are both 1,600
exact and overlapping JWE spans with no false or missed spans. The separate JWS
span target is also exact for all 800 dev JWS cases. Gitleaks has no continuous
scores or span outputs; no block/severity or actionability policy, AUC, or span
metrics are claimed for either binary baseline.

At fixed 0.35, native JOSE JWE recall is 100% and JWE false alerts are 0/8,800;
conditional clean-negative false alerts are 0/8,000. JWS recall is 800/800
with 0/9,600 false alerts. The JOSE union is 2,400/2,400 with 0/8,000 clean
false alerts. JWE-on-JWS false alerts are 0/800. Native JWE has one nonzero
candidate score level (0.99); average precision 1.0 is presence-equivalent and
ROC AUC is omitted as binary-like. JWS likewise has one level (0.96) and
presence-equivalent average precision 1.0 with ROC omitted. The JOSE union has
two discrete levels (0.96 and 0.99), AP 1.0 and ROC AUC 1.0 on these synthetic
cases. These are ranking summaries, not calibrated probabilities or evidence
of continuous score discrimination.

The predeclared JWE sweep at 0.05 through 0.99 gives the same counts; at 1.00
all 1,600 JWE cases are missed. JWE candidate scores are all 0.99 in this dev
sample; JWS candidate scores are 0.96 (all pass through 0.96 and fail at 0.99).
The unsupported-algorithm regression produces ten
`JOSE_COMPACT_UNVERIFIED` candidates with score 0.40. At the frozen numeric
comparison point 1.0, JWE high-score counts are 0 TP / 0 FP / 8,800 TN / 1,600
FN. Actual returned block severity has the same counts. Neither is a generic
JOSE production block decision: the lead freeze keeps generic JOSE block
entities empty.

Format labels and exposure labels remain separate. In the DEV JWE slice, 1,300
examples are labeled exposed, 300 have unknown actionability, and no public
valid JWEs are present. No JOSE block severity is returned, so the detector
blocks 0/1,300 labeled exposed examples; this is not used as a format miss or
as evidence that structure establishes exposure. Public valid format
positives are reserved for the holdout split.

### Uncertainty

At 0.35, native JOSE Wilson 95% intervals are:

| Target / denominator | Recall interval | FPR interval |
|---|---:|---:|
| JWE, 1,600 positives / 8,800 negatives | 99.760%–100% | 0%–0.0436% |
| JWE, 1,600 positives / 8,000 clean negatives | 99.760%–100% | 0%–0.0480% |
| JWS, 800 positives / 9,600 negatives | 99.522%–100% | 0%–0.0400% |
| JOSE union, 2,400 positives / 8,000 clean negatives | 99.840%–100% | 0%–0.0480% |

The stratified template-family bootstrap (1,000 resamples; 32 positive and 56
negative dev families for JWE) is degenerate at 100% recall and 0% FPR for the
perfectly separated native run. That reflects these generated families only;
it does not remove uncertainty about unseen token and document distributions.
A holdout of 2,000 clean negatives cannot establish the approved FPR target
below 0.1% at 95% confidence: even zero observed false alerts has a Wilson
upper bound of about 0.19%.

## Context, presets, extraction, and adversarial gates

The 80-case dev context/preset slice has 40 positives and 40 negatives. At
0.35, `+presets` without local context detects all 20 ITIN positives and none
of 20 bank-number positives; 20 of 40 misleading/distant negatives alert. With
local context, the slice detects 10/20 bank-number positives and 20/20 ITIN
positives, with the same 20/40 false alerts. Thus local context raises bank
scores for one of two bank template families to 0.39999999999999997; the other
family stays at 0.05. At an exact 0.40 cutoff the raised bank score falls just
below threshold. Context raises ITIN positive scores from 0.50 to 0.85, while
ITIN-shaped misleading and distant negatives remain at 0.50 and alert at 0.35.
At 0.80, the local+presets slice has 20 ITIN TP, 0 FP, 40 TN, and 20 bank FN.
These auxiliary false alerts are kept separate from the JOSE structure FPR.
The small slice has only two dev families per class/entity; its intervals are
wide and recipe-dependent.

All 72 document fixtures extracted completely with zero positive token
omissions. The baseline had 0/36 positive detector hits and 36/36 negative
TN. Each native JOSE profile had 36/36 positive hits, 36/36 negative TN, and
36 exact positive spans at both raw and review points. These files are shared
integration checks, not an independent document holdout estimate.

The shared 120-case adversarial gate is outside all confusion matrices. Native
JOSE profiles return 30 JWE/uncertainty candidates: ten bad-tag structures,
ten empty-ciphertext structures, and ten unsupported-algorithm candidates.
Ten oversized-header inputs produce bounded `ValueError` input errors. Those
results are not labeled TNs or ordinary clean negatives. No main dev JWE/JWS
or clean-negative case produced an input error.

Stock Gitleaks ran in 0.543 seconds (19,377 cases per scanner second); shipped
rules ran in 0.655 seconds (16,065 cases per scanner second). Timing excludes
staging and report parsing. Neither run emitted a rule hit. Final native
full-harness time, including auxiliary and document gates, was 12.90–14.06
seconds. Separate main/adversarial detector-call throughput was 1,793–2,131
calls per sum-of-call-seconds; full-harness eval units per second were 759–827.
Median per-input detection latency was 0.38–0.50 ms and p95 was 1.01–1.21 ms.
Reported waited-child high-water RSS was 204–209 MB; this is not the evaluator
process's own RSS.

## Sealed V2 holdout

Contract revision 10 authorized one final holdout pass at
`2026-10-26T22:07:08.768063Z`. The run used the unchanged V2 manifest and labels,
the final five profile hashes, detector freeze v2, review threshold 0.35, score
comparison 1.0, and an empty generic JOSE block-entity list. All five native
outputs recorded lead source commit `ddddd050ed3127a513169cb537c61fcb4cc34296`
and all five detector file hashes matched freeze v2. The evaluator tree was
clean at commit `ca97e1e82fb120874dc3ade3346ebb6cba65d76c`. Authorization,
provenance, exact commands, profile hashes, artifact paths, and output hashes
are indexed in [HOLDOUT_ARTIFACTS.json](HOLDOUT_ARTIFACTS.json).

The holdout has 400 JWE positives, 200 JWS candidates, and 2,000 clean
negatives. For the JWE target, JWS candidates remain negative; the separate
class-conditional JWE table uses only the 2,000 clean negatives. The JWS target
uses 2,400 negatives (JWE plus clean), and JOSE union uses 2,000 clean
negatives. Counts are TP / FP / TN / FN at the frozen review point. Gitleaks
counts are file-level binary alerts and do not carry score thresholds.

| Detector | JWE target (2,200 negatives) | JWE vs clean (2,000 negatives) | JWS target (2,400 negatives) | JOSE union (2,000 negatives) |
|---|---:|---:|---:|---:|
| Presidio baseline | 0 / 0 / 2,200 / 400 | 0 / 0 / 2,000 / 400 | 0 / 0 / 2,400 / 200 | 0 / 0 / 2,000 / 600 |
| +JOSE, no context | 400 / 0 / 2,200 / 0 | 400 / 0 / 2,000 / 0 | 200 / 0 / 2,400 / 0 | 600 / 0 / 2,000 / 0 |
| +JOSE, local context | 400 / 0 / 2,200 / 0 | 400 / 0 / 2,000 / 0 | 200 / 0 / 2,400 / 0 | 600 / 0 / 2,000 / 0 |
| +JOSE, presets, no context | 400 / 0 / 2,200 / 0 | 400 / 0 / 2,000 / 0 | 200 / 0 / 2,400 / 0 | 600 / 0 / 2,000 / 0 |
| +JOSE, local context and presets | 400 / 0 / 2,200 / 0 | 400 / 0 / 2,000 / 0 | 200 / 0 / 2,400 / 0 | 600 / 0 / 2,000 / 0 |
| Gitleaks 8.30.1 built-in defaults | 0 / 0 / 2,200 / 400 | 0 / 0 / 2,000 / 400 | 100 / 0 / 2,400 / 100 | 100 / 0 / 2,000 / 500 |
| Gitleaks 8.30.1 + shipped `rules.toml` | 0 / 0 / 2,200 / 400 | 0 / 0 / 2,000 / 400 | 100 / 0 / 2,400 / 100 | 100 / 0 / 2,000 / 500 |

Every native JOSE profile found all 100 standalone and 300 embedded JWE
examples, and all 200 JWS candidates. Each had zero false alerts among 2,000
clean negatives and zero JWE alerts on the 200 JWS examples. At review 0.35,
all 400 JWE spans and 200 JWS spans were exact and overlapping at both raw and
review-filtered points. The baseline found none of the JWE or JWS targets.
Both Gitleaks runs found 100/200 JWS examples (50%) and none of the JWE
examples. Their binary output provides no spans, severity, block decision,
actionability classification, or continuous ranking score.

At the numeric 1.0 score comparison, no native JOSE candidate crosses the
point; returned severity also remains non-blocking. The native block table is
therefore 0 / 0 / 2,200 / 400 for the JWE target, with generic JOSE blocking
still disabled. Of 300 JWE examples with known actionability, 150 are exposed
and 150 are public valid examples; none were blocked. Another 100 positives
have unknown actionability and are excluded from this policy slice. Format
detection does not establish exposure or justify blocking.

Native JOSE Wilson 95% intervals at the review point are:

| Target and denominator | Recall interval | FPR interval |
|---|---:|---:|
| JWE, 400 positives / 2,200 negatives | 99.049%–100% | 0%–0.1743% |
| JWE, 400 positives / 2,000 clean negatives | 99.049%–100% | 0%–0.1917% |
| JWS, 200 positives / 2,400 negatives | 98.115%–100% | 0%–0.1598% |
| JOSE union, 600 positives / 2,000 clean negatives | 99.364%–100% | 0%–0.1917% |

The family-stratified bootstrap used 1,000 resamples. Native rows are
degenerate at perfect holdout separation (recall [1, 1], FPR [0, 0]); the
holdout contains only eight JWE, four JWS, and fourteen JWE-negative families.
With zero false alerts in 2,000 clean negatives, the Wilson upper bound is
still about 0.192%, above the approved 0.1% target. A perfect result on these
synthetic families does not establish the target for deployment data.

JWE and JWS each have a single nonzero native score level (0.99 and 0.96).
Their AP of 1.0 is presence-equivalent and ROC AUC is omitted. The JOSE union
has two discrete score levels; its AP and ROC AUC are 1.0 on this synthetic
set. These scores are not calibrated probabilities or fine-grained evidence
of deployment ranking quality.

The separate 80-case auxiliary holdout contains 20 bank positives, 20 ITIN
positives, and 40 negatives. With local context and presets, bank recall was
20/20 with zero bank false alerts; ITIN recall was 20/20 but all 20 ITIN-shaped
negatives alerted. Ten of 20 distant-context negatives and ten of 20
misleading-numeric negatives alerted. Presets without local context detected
0/20 bank positives and 20/20 ITIN positives, with the same ITIN negative
burden. Local context without presets does not register these entities and
detected neither class. There are only two families per auxiliary entity, so
these point estimates are recipe-sensitive.

All 72 shared document regression files extracted completely: zero positive
omissions and zero incomplete negatives. Baseline detection was 0/36 positive
files; each native JOSE profile detected all 36 positives with exact spans and
recorded 36/36 negative TNs. These PDF/DOCX/XLSX cases are shared integration
regressions, not independent document holdout samples. Parser omissions remain
misses or incomplete coverage, never TNs.

All native JOSE profiles were evaluated on the shared 120-case adversarial
gate, outside confusion counts. Each produced candidates for ten bad-tag, ten
empty-ciphertext, and ten unsupported-algorithm cases; ten oversized-header
cases produced bounded input errors. The two profiles with financial/identity
presets also emitted two unrelated `US_DRIVER_LICENSE` review candidates on
the wrong-algorithm-fields adversarial slice. This is adversarial alert burden,
not a JOSE match or an ordinary clean-negative false positive.

| Native profile | Full harness (s) | Median / p95 latency (ms) | Detector calls/s | Harness units/s | Waited-child high-water RSS (MB) |
|---|---:|---:|---:|---:|---:|
| Baseline | 7.501 | 0.366 / 0.907 | 1,641 | 383 | 178.6 |
| JOSE, no context | 7.162 | 0.384 / 1.065 | 2,065 | 401 | 179.2 |
| JOSE, local context | 7.501 | 0.378 / 1.049 | 1,538 | 383 | 179.0 |
| JOSE + presets, no context | 7.791 | 0.482 / 1.088 | 1,360 | 369 | 180.0 |
| JOSE + local context + presets | 8.117 | 0.488 / 1.066 | 1,379 | 354 | 179.6 |

The full harness includes main/adversarial scoring, the auxiliary slice,
document extraction, and uncertainty calculations. Waited-child RSS is not the
evaluator process RSS. Stock and shipped-config Gitleaks took 0.419 s and
0.413 s per scan (about 6,493 and 6,582 staged cases/s); timing excludes file
staging and report parsing. Each used one invocation over 2,600 holdout rows
plus the shared 120 adversarial cases.

The seven redacted raw outputs are retained under
`RUN_ROOT/artifacts/evaluation-v2-holdout-freeze2/`.
Their SHA-256 values and exact rerun commands are in
[HOLDOUT_ARTIFACTS.json](HOLDOUT_ARTIFACTS.json); the manifest, labels,
thresholds, source freeze, profiles, binary, and shipped config are also
fingerprinted there.

## Operating-point status and limits

The checked-in profiles match the lead's frozen review point 0.35 and numeric
block comparison 1.0; generic JOSE block entities remain empty. The single
authorized holdout run used contract revision 10 and detector freeze v2. The
authorization was scoped to this one run; these artifacts are the only sealed
run made. No tuning was performed from holdout errors.

These results cover only synthetic supported algorithms and wrappers. They do
not estimate deployment prevalence, issuer, exposure, validity of observed
real-world values, or severity. A bad-tag derivative still receives a
structural candidate because this recognizer does not authenticate tokens.
Three supported JWE algorithms and one JWS algorithm do not represent every
JOSE extension or deployment. The holdout's 150 public valid JWEs were all
review candidates but none were blocked; generic JOSE block severity remains
absent. PDF/DOCX/XLSX results cover generated text fixtures without OCR,
nested archive expansion, or production file diversity.
