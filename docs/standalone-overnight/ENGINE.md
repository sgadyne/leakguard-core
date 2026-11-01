# Engine lead / integrator queue

Model: Sol xhigh. Own backend/store/scheduler changes and final integration in
your assigned ILMR box. Coordinate with UI and Terra, but do not spawn more agents.

## E0 — exact baseline, additive contract

Record source SHA and installed package/runtime identities. Run relevant current
tests once. Review `CONTRACT.md`; agree the small optional projection with UI before
implementation. Unknown chronology remains null. Use existing authenticated
status/jobs/settings surfaces rather than introducing a second service.

## E1 — durable queue chronology and redacted diagnostics

Persist first-observed pending time and last complete inspection for each relevant
source-generation/content version, separate from monotonic ordering clocks.
Historical rows without evidence have unknown age. Unchanged metadata refresh
cannot reset age; changed versions cannot inherit a fabricated wait history.
Preserve encrypted journal/replay/rollback and bounded capacity semantics.

Record a bounded diagnostic code, approved stage, safe exception class, occurrence
time and retry count. Never record exception messages/args, secret contents,
private paths or trace locals. Keep one recovered failure visible as recovered;
success later does not erase the fact. Bound retention and output size.

Inject failures at acquisition, parse, detector execution, publication and shutdown.
Prove correct stage attribution, privacy, retry semantics and no false clean result.

## E2 — completed-work fairness proof

Extend existing fairness/backfill tests before changing scheduling again. Seed
old ordinary work, then sustained observed arrivals, sparse pages, saved page
remainders, deadline deferral, lock/reopen and source replacement. Count actual
complete results with correct versions, not selected rows or findings alone.

For a finite synthetic workload, each item must complete or carry a truthful
terminal gap within an explicit bounded test. Preserve age of unexecuted rows.
Report oldest-work and new-arrival latency/counters together. A bounded synthetic
proof is not full-Mac coverage or a population SLO. Only adjust scheduler shares
when the failing test shows the remaining problem.

## E3 — bounded read projection and profile semantics

Expose genuine aggregate chronology/diagnostics through the agreed optional
projection. Status polling must not decrypt and walk the entire footprint on
every refresh. Measure/preserve bounded query cost; use durable/incremental
summaries with explicit observation windows or a bounded cached read as appropriate.

Support UI's readable resolved-profile preview with safe old/new values and
provenance. Retain transactional preflight, stale preview, rollback and per-source
overrides. Keep acquisition exclusion, inspection omission and alert suppression
distinct. Do not silently add new v1 config keys or turn unsupported event/archive/
access modes on. Coordinate a minimal backend seam needed by the existing vault
handoff; do not add automatic migration/removal of source secrets.

## E4 — incorporate evidence-led improvements

Review Terra's fixed-fixture cost/correctness report. Accept only scoped changes
with paired output equality / labelled regression evidence. Preserve cache closure
and partial coverage. No Dagster, language rewrite, generic graph framework,
recursive archives, native event provider or fleet/Sampo work this night.

## E5 — integrate and qualify

Fetch UI and Terra commits read-only into your box and integrate on your branch.
Do not push main or publish. Rebuild all changed wheels, install outside the source
tree and run relevant installed tests including `tools/check_alpha_ci.py` locally
(its filename does not authorize Actions). Use pinned Gitleaks and native controls.
Do not blanket-ignore Linux filesystem/platform failures: report exact unsupported
gates separately, and pass all applicable assertions.

Check migration/reopen, independent locks, review persistence, protected-store
handling, profile rollback, signature/policy/cache invalidation and publication
failure. Run the integrated UI build and coordinate a final real-backend synthetic
browser smoke with UI. Capture source SHA, wheel hashes and test results.

By 05:50 EST export integrated bundle + change report + acceptance matrix + exact
remaining Mac checklist. Release task-owned reservations/processes before the
06:00 EST ceiling without deleting evidence or another lane's work. If a blocker
remains, preserve the last good tested revision and name the failing gate.
