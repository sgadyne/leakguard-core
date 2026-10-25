# Acceptance ledger

P0/P1 implementation and the runnable Linux acceptance are verified. Native macOS
and Windows execution remains outstanding, so the cross-platform acceptance is
partial. No release or real-data scan was performed. See [the index](README.md),
[machine-readable ledger](acceptance-ledger.json), and
[native follow-up commands](PLATFORM_CHECKS.md).

| Gate | Executed evidence | Status |
| --- | --- | --- |
| A01 hooks | Actual commit/push rejection; execute bits, atomic backup/chaining, original stdin/args; repository/PYTHONPATH spoof refusal | Linux pass; native Windows open |
| A02 replay | Identical positive IDs/provenance/severity on cold/reused/uncached scans; same-size/mtime byte changes and dependency/context changes invalidate reuse | Pass |
| A03 coverage | Required malformed/no-text/encrypted/missing-parser/limit/timeout failures; named binary and document nontext omissions; parser import spoof refusal | Pass |
| A04 redaction | Unique-marker API/CLI/explain/current/history test; live/closed SQLite logical/raw DB/WAL/SHM; plugin/script failures and artifact audits | Pass |
| A05 provenance | Exact index/commit/blob, independent parts and inclusive lines; spaces, Unicode/newline bytes, roots/intermediate/merge commits | Linux pass |
| A06 proof | Same-version narrow built-in proof; duplicate/ambiguous/mixed/missing/changed/truncated context denies waiver; most-restrictive collision merge | Pass |
| A07 lifecycle | Comparable clean resolution; partial/failed/offline/events become unknown; anchored absence, migration rollback/newer refusal | Pass |
| A08 concurrency | Actual concurrent audit/drain publication orders; separate SQLite connections, leases/generations, resumable checked directories and deadline contention; POSIX allocation/descendant tests | Linux pass; native Job Objects open |
| A09 Git scope | Staged/worktree isolation, historical/root/merge/new-branch pushes, tags, deletion-only/shallow/bare cases, 1,001-commit/101-document caps, replace/graft isolation | Pass |
| A10 SDK | Installed v1 and independent v2 detector/extractor conformance; malformed output/severity/foreign waiver/crash/hang/limits; unknown closure denies reuse | Pass |
| A11 API/CLI | Inert imports; shared typed service/policy; one-object JSON, inventory/block/incomplete exits, bounded closed report schemas and rendering | Pass |
| A12 artifacts/platforms | Four production-freeze Linux wheel cells on 3.11/3.13 base/docs; refreshed 250-test cells; final 251-test source and installed docs wheel; member/origin checks | Linux pass; native macOS/Windows open |
| A13 corpus/performance | Catalog v3: 48 executed, 35 classification cases, 14 TP/21 TN/0 FP/0 FN, 13 separately tested proof/coverage cases; category/rule counts; complete repeated reference curves and paired baseline measurements | Pass with stated measurement limits |
| A14 footprint | Verified branch bundles and copied artifacts before exact worker-box cleanup; 598,666,700 bytes of transients removed; lead temporary files cleaned and checkout retained | See cleanup record |
| A15 storage/scripts | Injected store is the only durable sink; bounded keyed material observations; fixed-argv script schema/identity/limits/redaction; no vault capability | Pass |

The final source execution is [Python 3.11 with document parsers](lead-source-9111c9c-py311-docs-summary.json):
251 total, 249 passed, two Windows-only skips. The final
[installed Python 3.13 document wheel](evidence-wheel-py313-docs-final-9111c9c.json)
has the same totals and passes all three v1/v2 conformance cases. Both executions
use exact committed source `9111c9caa7426148d2412244be00542ac2989bde`; subsequent
delivery changes contain validation documents only.

The [corpus receipt](evidence-corpus-seed20261025-9111c9c.json) separates category
presence classification from expected-rule hit/miss/extra-rule observations.
Category confusion counts sum to the global classification counts; rule-level
counts are observations of specific declared rules and need not sum to a binary
case count in general. Proof, omission and collision cases are excluded from
classification denominators. The [parser-free counterpart](base-corpus-9111c9c-summary.json)
records five uncovered PDF/MSG cases and excludes them from scoring.

The [reference benchmark](PERFORMANCE.md) completes three repetitions at every
1/10/50/200-file clean/positive point, nine document-part cases and three installed
clean/blocked hook pairs. Warm file scans launch zero backend workers and preserve
normalized findings and coverage. No optimization was accepted. SQLite boundary
and sampled-RSS limits are explicit; the input manifest covers the file/document
curves, with hook/identity probes outside that manifest's scope.

Native Windows Job Object tests are skipped on Linux. No macOS or Windows pass is
inferred from the CI declaration. Existing hooks must be reinstalled to use the
isolated pinned core launcher. Product compatibility and format limits remain
documented in [COMPATIBILITY.md](../../../COMPATIBILITY.md).
