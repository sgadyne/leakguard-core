# Standalone overnight implementation queue — November 1–2, 2026

User scope: implement standalone UI polish from the prepared assets and deepen
the existing scanner. Exactly two Sol xhigh workers and one Terra xhigh helper;
all implementation/build/test work in fresh ILMR boxes on devbox. No Sampo work.

Hard lease end: **2026-11-02 06:00 America/New_York (EST), 11:00 UTC**.
Stop adding scope by 04:30 EST, code freeze by 05:00 EST, integration/evaluation by
05:35, artifact/status handoff and owned-process cleanup by 05:50. Finish earlier
if the acceptance gates pass; the lease is a ceiling, not time to fill.

The isolation waiver and host-specific paths belong in the external private
dispatch receipt, not this repository. A previous task's expired waiver is not
valid for this run. All heavy commands use the supplied deadline-aware ILMR
runner and existing shared admission limits; no direct unguarded test loops.

## Ownership and coordination

| Worker | Model | Owned surfaces | Handoff |
| --- | --- | --- | --- |
| UI lead | gpt-6.1-sol / xhigh | `apps/buddy-ui/**`, shipped Buddy static assets, `apps/desktop/**`, desktop packaging, `design/**`, UI/e2e fixtures and tests | Polished functioning UI, rendered evidence, behavior checks, commit/bundle, remaining native-Mac gate |
| Engine lead / final integrator | gpt-6.1-sol / xhigh | host scheduler/discovery, encrypted inventory, Buddy backend/server, associated tests; final integration branch | Queue chronology/diagnostics, truthful read projection, integrated tested revision, complete vs deferred report |
| Evaluation/helper | gpt-6.1-terra / xhigh | measurement tools, synthetic regression fixtures/tests, recognition comparison reports; scoped core/detector fixes only after lead agreement | Paired performance/correctness evidence, independent acceptance audit, bounded evidence-led fixes |

UI never edits backend Python to bypass an API gap. Engine lead never edits UI
without an explicit handoff. Terra does not change scheduler/store ownership.
Send additive API/fixture changes between the leads before depending on them.
Fetch sibling commits read-only; do not modify another worker's checkout. Engine
lead merges reviewed worker commits on its own integration branch and reruns the
affected combined gates. No force push, main push, release publication or Actions.

## Priority sequence

1. UI: apply shell/tokens/brand and state semantics; engine: define additive
   contract and failing chronology/diagnostic controls; Terra: freeze baseline and
   measurement fixture identities.
2. UI: Settings and Findings/review flow; engine: persist chronology and execution
   evidence, then expose bounded projection; Terra: paired cache/parser/acquisition
   measurements and labelled detector/dedup counterexamples.
3. UI: Sources/Activity/Vault/Plugins finish and browser workflow checks; engine:
   saturated backlog/restart proof and migration; Terra: independently audit output
   equality, privacy, receipts and observed failures. Fix only demonstrated issues.
4. Integrate, qualify from installed wheels, freeze artifacts and report. Anything
   lacking proof stays explicitly incomplete; do not make the dashboard look green.

## Shared finish line

- Clean worker commits and one clean integrated review branch; source identities
  attached to each test report. Git bundle(s) and final report retained remotely.
- UI is functional against the real authenticated backend with synthetic isolated
  state, not only snapshots or mocked successful HTTP responses.
- Existing capabilities preserved: automatic local scope, explicit remote sources,
  cursor paging, profile preflight/rollback, review, storage movement, independent
  locks and plugin trust. Missing metrics are visibly unknown.
- Fairness proof counts actual completed old work; cache/performance comparisons
  preserve findings/coverage and name every exclusion or unsupported platform gate.
- No real Mac/private credentials, private filesystem snapshots, live vaults or
  private scan reports are copied to ILMR. Synthetic fixtures + product source only.
- Linux/browser results do not certify macOS keychain, Finder/tray rendering,
  signing or full-machine freshness on this Mac. List the exact remaining local
  native acceptance run for the morning; do not pretend it ran remotely.
- Final report contains: commits, changed behavior, acceptance matrix, failures,
  deferred scope, source/build hashes, artifact paths, cleanup and next action.

See `UI.md`, `ENGINE.md`, `EVALUATION.md`, `CONTRACT.md` and `acceptance.json`.
