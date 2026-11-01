# Evaluation and focused refinement helper

Model: Terra xhigh. Work with the engine lead from your own ILMR box. Own the
measurement tools, synthetic fixtures/tests and comparison receipts. Do not edit
the scheduler/store/UI concurrently with their owners. Do not spawn more agents.

## T0 — freeze the comparison

Record starting SHA, tool versions, configuration, fixture manifests/hashes and
warm/cold procedure. Use only repository synthetic fixtures or new structurally
equivalent synthetic cases; no Mac private baseline, vault or filesystem transfer.
Distinguish original unchanged baseline comparisons from deliberately new tests.

## T1 — paired cost attribution

Use/extend `tools/measure_pipeline_cost.py`. Measure acquisition, parsing,
recognition, subprocess startup, output/publication and cache hits/misses with
bounded redacted aggregate reports. Cover text, PDF, OOXML and MSG where the
installed optional parser is actually available; name unavailable parsers.

Compare identical fixtures under cold/warm, same-size edit, rename, config/alias
change, parser/runtime identity change, cancellation and restart. Record required
coverage and findings equality before reporting timing. At least three repeated
bounded paired samples for any claimed improvement; retain raw safe counters,
median and range. Do not use noisy timing thresholds as correctness assertions.

For SSH, use existing deterministic protocol/session tests and an owned synthetic
directory fixture on the authorized host if the lead approves the exact test.
No scanning real home directories. Distinguish simulated failure handling from
live acquisition evidence; measure bytes/page trips where the seam exposes them.

## T2 — labelled recognition and dedup counterexamples

Prioritize existing catalogue LG-A011 (JOSE/native overlap, two secrets on a line)
and LG-A008/A009 (bounded encoded-container review vs mixed/literal siblings).
Give each case an originating detector, representation, desired disposition and
close positive/negative. Keep uncertain cases reviewable; no entropy-only or
filename-wide suppression. Do not invent missing aliases to fill the queue.

Only implement a detector/core fix after the engine lead agrees the narrow scope.
Any grouping/dedup must preserve distinct fields and detector provenance when
absolute native spans are unavailable. Do not delete canonical observations just
to make a UI list shorter. If no sound improvement is established, deliver the
regression fixture/report and explicitly recommend no logic change.

## T3 — independent integration audit

Fetch the integrated candidate supplied by engine lead into your own worktree.
Re-run the relevant paired fixtures and redaction/capacity tests. Verify tests
exercise installed product bytes, not a mixed source tree or stale wheel set.
Review UI/backend metric semantics: unknown vs zero, selection vs completion,
page count vs total, policy omission vs clean, and source-version attribution.

Deliver a short verdict per acceptance gate: pass/fail/not-run/platform-unavailable,
command, source SHA, evidence path and material limit. No population recall claim,
no full-Mac testing claim, no silent omission of failures. Commit fixtures/fixes,
export your bundle and give the engine lead actionable findings early enough to fix.
