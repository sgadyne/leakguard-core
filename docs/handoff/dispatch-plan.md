# LeakGuard execution and dispatch plan

Prepared 2026-10-25. Planning is complete; implementation and its eight-hour clock
have not started. Read [ADR 0001](../architecture/0001-scanning-contract.md) as the
proposed contract and [HANDOFF.md](../../HANDOFF.md) for preserved safety boundaries.
User direction in this session: target **devbox**, not archbox; SSH access was
restored and rechecked. This overrides the host choice in the original handoff.
Subsequent product direction: an installable **Password Buddy** companion with
periodic scans and an encrypted local vault, including actual secrets saved only
with explicit user approval; shared open-source engine/plugins and firm-specific
script checks. The ADR now captures that product architecture. This is design
steering, not an instruction to start the agents or enable a local scheduler.

## Readiness and decisions to carry forward

The plan is ready for review and team dispatch. Remote provisioning is deliberately
not claimed complete. Before mutation, the lead must establish a valid LeakGuard
agent-isolation grant on devbox; the existing grants inspected during planning
name other work. Do not silently use the default principal=user for agent boxes.

Recommended scope: the three blocking corrections first; one shared typed service;
correct content/proof-based replay; conservative current/history lifecycle; standard
text/document extraction and trusted extension contracts with runnable examples;
then adversarial acceptance and measured optimization. No OCR/archive expansion,
no new database sources, no new service/daemon in this engine phase, no publication
or real-data scans. Add the storage injection seam and standard script-check
adapter to the engine work. Password Buddy's installer/UI/scheduler and actual
encrypted credential vault are the next product milestone, not an eight-hour
release claim. Preserve room for them without adding raw secrets to scan results.

Important deliberate product choices in the ADR:

- Default Git requires supported text/document surfaces, including optional parser
  availability when those formats are encountered. Unknown binary content is a
  visible named omission, not a clean scan. Strict all-format policy can block it.
- Manual inventory reports findings without exit 1 unless `--fail-on block` is
  selected; incomplete work exits 2. This changes 0.1's always-zero scan behavior.
- Semantic cache hits read/hash bytes and verify context, then replay evidence.
  Stat-only acceleration is not a supported correctness mode.
- Current findings are active/resolved/unknown with timestamps; old evidence and
  failed/partial scans cannot manufacture resolution. Companion routing stays out
  of Git decisions.
- v1 plugins remain usable; undeclared runtime closure disables reuse. v2 separates
  detectors/extractors and adds explicit static capabilities/identity. Parsers and
  extensions use common core supervision; Python plugins remain trusted code.
- Public and private firm checks share the SDK; a maintained script adapter accepts
  bounded stdin JSON and validated findings from a fixed configured command.
- Password Buddy uses an encrypted observation store plus a separate credential
  vault. Background scans cannot unlock saved secrets. Save to vault requires
  user approval and source revalidation; it does not remediate the original leak.

### Planning-session environment evidence

| Check | Observed result | Consequence |
| --- | --- | --- |
| Source | HEAD `7600d922be176cb0c07c91ac47da363a6e51ed62`; handoff/baseline/probe initially untracked; no AGENTS.md found in checkout or checked ancestors | Preserve those files, snapshot them explicitly for remote work; no implementation changes made during planning |
| Local toolchain | Python 3.13 available; Gitleaks not found on PATH | No new source-suite/probe results claimed; install/select checksum-verified scanner only in execution |
| Local ILMR | 0.1.0 help works; host ls fails opening normal SQLite ledger under sandbox | Use direct SSH + remote ILMR, without changing the Mac ledger/config |
| Devbox SSH | Restored; noninteractive SSH with ClearAllForwardings=yes succeeds | Avoid the SSH config's automatic remote port forward during tests |
| Devbox runtime | Linux x86_64, Python 3.11.2 at /usr/bin/python3.11, ILMR 0.1.0 at ~/.local/bin/ilmr; approximately 20 CPUs/125 GiB reported | Pin interpreter; newer Python availability still needs checking/provisioning in owned environment |
| Devbox queue | Four heavy slots, five CPUs each, 35-minute class cap; 0 held/0 waiting at check | At most two concurrent heavy jobs for this repo; this observation is not a reservation |
| Devbox isolation | Already a container; ILMR dir runtime available, docker/podman unavailable; default principal=user; existing none/agent waivers refer to other named work | A LeakGuard-scoped class-none authorization or an actually available approved runtime is a launch prerequisite; no borrowed waiver, new runtime install or host-config rewrite during planning |
| Remote host registry | host ls returned no hosts in the inspected existing repository context | Direct remote invocation needs no `--on devbox`; do not double-forward or infer Mac registration |
| Existing shared footprint | ILMR doctor reports large pre-existing scratch/cache usage and many existing boxes | None belongs to this run; no pruning, cleanup or budget changes on their behalf |
| Archbox | Reachable; Python 3.11.17/3.14.7, ILMR and Docker observed | Not selected; no work or boxes dispatched there |

Host probes used an existing repository only to obtain CLI/config/queue information;
no project source was changed. No execution checkout, box, daemon, watcher, hook,
venv, scanner download or agent was created. ILMR diagnostic commands can record
normal ledger events; devbox queue reported no released stale holders. Planning
adds only the ADR and this dispatch plan. Do not copy unrelated host diagnostics,
paths or operational state into the release package.

## Minimum coherent deliverable and scope order

| Priority | Deliverable | Must be true before moving on |
| --- | --- | --- |
| P0 | Hook chmod/execution, evidence-preserving cache result, required document failure | Portable reproduction passes `--assert-fixed`; focused regressions prove installed hook behavior, warm positives and direct required-scan rejection |
| P1a | Models, explicit config, core service + Git/file adapters, coverage/exit semantics | API/CLI/Git return equivalent redacted outcomes on equivalent bytes; no bypass path; v1 compatibility is tested |
| P1b | Content/runtime/context identity, lifecycle + transactional migration, injectable redacted ScanStore | Cache never outlives content/source proof; interrupted or stale concurrent work never resolves findings; old state imports as unknown; custom store has no hidden plaintext state mirror |
| P1c | Maintained extraction modules, supervised extension boundary, v2 SDK + examples + script-check adapter | Both independent example packages and script example pass conformance; required failures/hangs/crashes fail closed; no unbounded capture path |
| P1d | Corpus, wheel/platform checks, receipts and cleanup | Acceptance ledger accounts for each requirement; final Linux/Mac results uncached; Windows verified on a runner or explicitly outstanding |
| P2 | Performance experiments and safe improvements | P0/P1 pass; differential result equivalence before any speed claim |
| P3 | Format/back-end expansion and historical import niceties | Deferred beyond this execution window |

The complete P0+P1 set is the intended minimum release candidate. If it does not
fit, return integrated verified fixes and explicitly incomplete acceptance; do not
label that partial result the completed contract. Cut P2/P3 first. Allowed practical
simplifications: per-part scanning rather than batching; no cache for an extension
with unprovable closure; serialized per-scope queue/audit updates instead of parallel
claims; retain old wrapper modules; new indexed history plus explicit access to old
JSON instead of an archive import. None permits losing findings, hiding omissions,
weakening proof, skipping redaction checks or claiming untested platforms.

Deferred implementation details: multi-level dedup caches, persistent Gitleaks
processes, a separate adapter distribution, legacy archive importer, multi-host
queues and all additional formats. Module extraction is incremental; avoid moving
working code solely to satisfy a diagram under deadline pressure.

### Next product milestone: Password Buddy

| Dependency order | Deliverable | Release gate |
| --- | --- | --- |
| PB1 after shared core contract | Installable companion, opt-in scopes/schedule, pause/resume, local status/notifications, encrypted findings/catalog store | Bounded periodic reconciliation; sleep/login recovery; no hidden plaintext metadata mirror; uninstall stops owned tasks |
| PB2 after vault threat-model and key/storage decision | Local credential vault, explicit save/import with source verification, unlock/reveal/copy/export, entry history | Actual secrets enter only the vault-specific flow; background scans cannot unlock; key protection, corruption/crash, encrypted backup/restore and recovery behavior verified |
| PB3 after platform verification | Cohesive desktop distribution with optional Git installation, documented enterprise deployment and private check packages | Supported-OS installer/update/uninstall checks; vault review; no false claim that saving a credential removes its original exposure |

These are required product follow-ups, not discarded features. Do not start a new
password-vault implementation as spare-time stretch work in the eight-hour engine
run. Preserve actual secret storage as a separate capability; report schema v1 and
detector/plugin findings remain redacted. Broader service integrations reuse the
engine and can adopt their own explicitly configured storage/authentication.

## Team and exclusive file ownership

Start only after the user starts execution. Use one **Sol xhigh lead** plus exactly
three subagents: **Sol xhigh**, **Luna xhigh**, **Luna xhigh**. Recommended explicit
model IDs in the current tool catalog: lead/worker A `gpt-6.1-sol`, workers B/C
`gpt-6-luna`, all reasoning_effort `xhigh`. If the execution environment uses other
Sol aliases, resolve them before launch and record the actual IDs. No nested
delegation; maximum four active agents including the lead. The lead spends its
time implementing owned infrastructure and integrating, not as a fourth worker
editing everyone else's files.

Create isolated clones/ILMR-owned checkouts with unique branches per agent. Never
share an index, branch or state directory. One lane's .git config and test hooks
must not affect another lane. This file ownership applies even in separate clones:

| Owner | Files owned | Delivery and review obligation |
| --- | --- | --- |
| Lead — Sol xhigh | `plugins.py`, `plugin_worker.py`, `script_checks.py`, `extraction.py`, `documents.py`, `extract_worker.py`, `backends.py`, `finding_details.py`, `settings.py`, `scan_policy.py`, `rules.toml` if necessary; ADR amendments | Supervision, standard adapters including script checks, v1/v2 adapters/manifest validation, backend isolation, config/identity closure helper; reviews every policy, identity, proof, redaction and Git change |
| A — Sol xhigh | `engine.py`, `sources.py`, `git_scanning.py`, `scan_store.py`, `catalog.py`, `hooks.py`, existing `policies.py`; `tests/test_scan_state.py`, `tests/test_git_policy.py` | Three fixes, snapshot acquisition, shared pipeline, cache replay/proof dependency checks, migration/lifecycle, bounded audit/drain; sole engine.py owner |
| B — Luna xhigh | `models.py`, `api.py`, `cli.py`, `manage.py`, `presentation.py`, `__init__.py`, `__main__.py`, `leakguard.py`; README/PLUGIN_API/compatibility docs, examples; `tests/test_public_api.py` | Models/serializer first, then thin API/CLI adapters, durable-query presentation and examples; no scanning or suppression logic in facade |
| C — Luna xhigh | `conformance.py`, new corpus/benchmark/acceptance tools, all existing test files, `tests/test_conformance.py`, `tests/test_script_checks.py`, `tests/test_corpus.py`, fixtures; pyproject/MANIFEST/CI/release validation docs | Reproduce baseline, adversarial corpus, reusable harness including script protocol, benchmark receipts, packaging/CI, artifact redaction inspection and validation ledger |

Lead sends production bugs found by C to the production-file owner; C supplies
failing regressions rather than editing their implementation. B sends config needs
to lead and engine integration requests to A. A's new focused test files are not
edited by C. Cross-file changes require an explicit ownership handoff recorded in
the checkpoint; no concurrent edits to the same file. No agent edits HANDOFF.md or
the original baseline to make the new results appear historical.

### Contract checkpoint (first 45 minutes)

B publishes a small models/serializer commit; lead reviews enums/invariants and
freezes names before other workers import them. A publishes service/store protocol
stubs so B can wire thin adapters without designing a second engine. Lead publishes
extraction/backend/identity protocol stubs and sample plugin manifest. C adds tests
against those interfaces, not private implementation shapes. All lanes rebase once
onto this interface checkpoint before larger independent commits.

Internal contracts to settle at that checkpoint (all declared in the ADR):
`acquire(input, budget)->Snapshot`,
`extract(snapshot, budget)->ExtractionResult`,
`detect(part, context, budget)->tuple[Observation,...]`,
`classify(observations, snapshot, proof_reader)->tuple[FindingRecord,...]`,
`evaluate(results, enumeration, policy)->PolicyDecision`,
`store.record_attempt(result, generation)->CommittedAttempt`,
`store.query_findings(state, profile, limit)->page`,
`service.scan/scan_git` as the sole public-result producers.
Snapshot/Observation are private types; no raw detector JSON crosses serialization.
Freeze ScanStore injection and the bounded script request/response at this same
checkpoint. The store seam must include catalog state, not just final JSON reports.

## Dependency-ordered eight-hour schedule

Clock starts with the execution phase, not these planning probes. Record UTC
start/deadline and monotonic elapsed time; queue waits and setup count. Each repo
gets eight elapsed hours, not eight per agent. Checkpoints include remaining scope,
test failures, source commit and owned footprint.

| Elapsed | Lead | A: semantics/state/Git | B: surface/docs | C: evidence/packaging | Exit gate |
| --- | --- | --- | --- | --- | --- |
| 0–0.75h | Confirm scoped runtime authorization; immutable source transfer; freeze contracts; review baseline | Read three failure paths; write hook/cache/document regressions and narrow fixes | Models/serializer + facade signatures; CLI migration note | Reproduce baseline and portable probe; seed corpus; record environment | Remote exact source verified; interface commit integrated; expected failures accounted for |
| 0.75–2.5h | Extraction status propagation, independent parts, backend/plugin supervision | Land P0; content-based replay, required Git decisions and proof invalidation | Thin Python API and JSON CLI/explain; examples scaffold | Invalid-output/redaction cases; installed-hook tests; wheel harness | P0 assertions pass; no regression masked by a non-running hook |
| 2.5–4.5h | Manifest/closure policy, format matrix, parser budgets, classifier review | Transactional migration/lifecycle; snapshot Git paths; audit/drain fencing and deadlines | Current/history queries, exit codes, v1 adapter docs; installable examples | Lifecycle/adversarial Git/crawl cases; conformance external-package run; CI matrix | P1 integration checkpoint: one service; migrated state; SDK/extractors exercised |
| 4.5–5.75h | Review all security-sensitive diffs; profile reference path | Fix integration/corpus failures; conservative Git history fallback | Check documentation against actual installed behavior | Labelled corpus, cold/warm/uncached measurements; crash/timeout stress under ILMR | No unresolved correctness defect before optimization work |
| 5.75–6.5h | Approve only equivalence-proven optimization; otherwise keep reference path | Optimize only after correctness gate; supply results to lead | Finish API/example and compatibility acceptance | Repeated clean/positive performance curves, wheel/sdist contents and redaction | Before/after evidence or explicit “no optimization accepted” |
| 6.5–7.5h | Sequential integration, final code review, uncached acceptance | Final Git/state fixes and source identity receipts | Independent wheel-installed examples/API/CLI checks | Linux 3.11 + newer, local Mac, available Windows CI, conformance + full suite | Release acceptance ledger complete or failures explicitly listed |
| 7.5–8h | Stop new features; collect/integrate commits; exact-footprint cleanup and final handback | Return patch IDs, remaining risks, clean owned resources | Return patch IDs/docs discrepancies, clean owned resources | Final compact receipts/checksums; verify owned cleanup | Integrated tree, durable evidence, exact leftovers and unfinished work |

At hour 3, if P0 is not green, reassign discretionary work to diagnosing it and
drop all batching experiments. At hour 5, freeze feature scope; P1 gaps outrank
optimization. At hour 6.5, no architectural rewrite. At the deadline stop new work,
preserve useful commits/evidence and report incomplete items honestly. A failing
Windows resource bound is a real acceptance gap, not a reason to mark Windows as
passed from Linux results.

## Acceptance ledger

Each row receives command, source identity, host/runtime, executed/reused/skipped,
duration and receipt path. A skipped required row is incomplete acceptance.

| ID | Exact acceptance |
| --- | --- |
| A01 hooks | Portable probe `--assert-fixed` exits 0; actual `git commit`/`git push` execute installed hooks and reject staged/history synthetic credentials. Existing clean-commit success alone is insufficient. POSIX execute bit asserted; Windows Git invocation exercised. Chaining retains stdin/args and failure. |
| A02 replay | Cold and warm positive scans contain identical normalized finding sets/severities/part/ranges/proof; warm outcome reused with prior execution and new verification time. Same-size/mtime changed bytes miss cache. No-cache result agrees. |
| A03 coverage | Malformed Content Types-only DOCX, encrypted/no-text PDF, missing parser, decode failure, excessive parts/output/size, crash and timeout produce explicit issue codes. Required Git scans return nonzero. Unknown binary/exclusion cases show named omissions and cannot render clean/PASS. |
| A04 redaction | A unique synthetic marker never appears in public JSON/text/stdout/stderr, persisted report/SQLite logical dump/WAL bytes, exception output, conformance logs or shipped artifacts. Source fixtures and transient parser input are the deliberate exceptions. Test exceptions, arbitrary extra fields and data-derived labels; no traceback with input. |
| A05 provenance | Every finding maps to exact file/blob, index tree or commit, independently extracted part and inclusive start/end lines. Cases include spaces/non-ASCII/newlines, multiline matches, boundary-spanning near-matches, identical blob at different paths/contexts and merge-only contents. |
| A06 proof | Correct same-index/same-commit file/AST digests may downgrade only the built-in eligible heuristic observation. Wrong/missing/changed source, duplicate JSON keys, compact ambiguous lines, mixed credentials and plugin collisions cannot waive detection. Dependency-only changes invalidate cached proof. |
| A07 lifecycle | Complete comparable rescan can resolve absent evidence; timeout/skipped/root-offline/partial crawl/delete notification cannot. Missing-source confirmation is distinct from clean-content resolution. Policy removal gives unknown/obsolete, not remediation. Old migration rows unknown; interrupted migration rolls back; newer schema rejected. |
| A08 concurrency | Concurrent audit/drain cannot overwrite newer state or double-resolve; interrupted enumeration and expired claims resume; failed directory enumeration prevents complete_cycle. Deadline checked inside large directories; all owned child processes reaped. |
| A09 Git scope | Staged secret/clean worktree blocks; unstaged secret/clean index does not. Intermediate/root/new-branch/merge commits checked; deletion-only push accepted if otherwise complete; missing ancestry/shallow gaps/bounds fail closed. Companion profile never weakens Git. |
| A10 SDK | v1 detector example still executes; independently installed v2 detector and extractor run without private/source-path dependencies. Invalid schema/lines/severity, exception, hang/crash, excessive output and attempted foreign-rule waiver all fail sanitized conformance. Unknown closure disables reuse. |
| A11 API/CLI | Importing models/api has no config/state/process effects. API/CLI/Git adapters share schema/policy outcome. JSON stdout is one object; exit table and report rendering tested; legacy wrappers documented/tested. |
| A12 artifacts/platforms | Source suite and wheel-installed suite pass without unexplained regressions; clean wheel imports outside checkout with PYTHONPATH unset; example packages installed from their distributions; wheel/sdist member inspection. Linux/Python 3.11 and newer, macOS/local 3.13, Windows available CI. Optional parser absent and present environments are separate receipts. |
| A13 corpus/performance | Deterministic case-labelled corpus reports TP/FP/FN by rule/category and separate coverage, with exact synthetic denominator; zero unexpected false negatives in declared must-detect cases and zero forbidden metadata waivers/redaction leaks. Report false-positive categories without claiming real-world accuracy. Record correct before/after performance, including regressions. |
| A14 footprint | All owned jobs stopped/reaped; useful commits/evidence retained; only exact owned scratch/boxes removed after dry-run inspection. Remaining artifacts and retention reasons enumerated. No new global hooks/config/services left behind. |
| A15 Buddy seams / firm checks | Injected ScanStore is the only durable observation/catalog sink; no hidden plaintext SQLite/JSON mirror. A fixed-argv script check works as a DetectorV2 adapter; malformed output, extra value fields, nonzero exit, timeout, unreaped child processes and excessive output are sanitized failures. Script identity changes invalidate reuse. No actual secrets enter ScanReport, and no credential-vault capability is passed to checks. |

Corpus seed: `20261025`; case IDs stable across machines. Labels distinguish
provider credentials, weak literal passwords, exact placeholders versus plausible
prefixes, benign hashes, source/AST proof, mixed values, duplicate keys, nonstandard
extensions, UTF-16 and Office parts. Optional PDF/MSG fixtures must be real synthetic
format fixtures, not only mocked imports. Cases that cannot run are counted as
uncovered and cannot inflate precision/recall. No test authenticates a credential.

## Remote workflow: devbox and ILMR

Run SSH with `-o BatchMode=yes -o ConnectTimeout=8 -o ClearAllForwardings=yes`.
Use remote `$HOME/.local/bin/ilmr` explicitly. Do not assume the local registry can
forward or that same-version CLI builds have identical flags; devbox has additional
owner/profile options not seen on archbox. Read current `host`, `queue`, `df`, `up`,
`run`, `down`, `rm` help before using them. Those were inspected during planning.

Preflight must be concrete:

1. Record exact HEAD, tracked diff digest and hashes of intended untracked source
   inputs (including the handoff/probe/plans). Preserve unrelated user changes.
   Produce a Git bundle plus explicit patch/untracked-file manifest, or a private
   snapshot commit in an isolated checkout. Never rely on dirty-file host sync.
2. Create a unique owned remote namespace `leakguard-core-YYYYMMDDTHHMMSSZ-SUFFIX`.
   Transfer only this public-core tree and declared planning inputs, never parent
   project/private config/state. Verify commit, patch and file hashes on devbox.
   Do not use the existing paumanok checkout as the LeakGuard working tree.
3. Establish permitted isolation. The concrete proposed grant is: this LeakGuard
   run only, exactly lead/A/B/C owned private checkouts on devbox, principal=agent,
   class=none within the existing devbox container, through the eight-hour deadline
   plus bounded cleanup, max two heavy jobs, no cross-repo access or shared cleanup.
   This grant was NOT created in planning. Existing reason-scoped grants do not
   establish it. If no applicable authorization exists, obtain that narrow grant
   through the installation's supported mechanism; do not switch principal,
   override floors, add a generic host waiver or silently use archbox.
4. Check `ilmr -C ACTUAL_LEAKGUARD_CHECKOUT doctor`, queue and `df --no-extents`;
   inspect effective shared admission and footprint limits. Use an owned profile
   only if supported/authorized. Do not let shared host defaults publish to another
   project's remote; integrate by commit/bundle transfer with explicit destinations.
5. Provision exactly owned boxes/checkouts and record owner/branch/root/IDs. Verify
   Python, Gitleaks and dependency closure inside the actual execution environment,
   not only the SSH shell. Use checksum-verified Gitleaks 8.30.1 and a private venv.
6. Launch a small bounded synthetic smoke through the same ILMR route before heavy
   suites. Recheck source identity before accepting any remote receipt.

Shapes below are templates for execution, not instructions to run in planning:

```sh
# On devbox, after the scoped grant and private source snapshot are in place:
task_repo=/absolute/owned/leakguard-core-checkout
task_box=leakguard-core-RUN-semantics
"$HOME/.local/bin/ilmr" -C "$task_repo" up --principal agent --class none "$task_box"
"$HOME/.local/bin/ilmr" -C "$task_repo" queue --json
"$HOME/.local/bin/ilmr" -C "$task_repo" run --class heavy --max 20m "$task_box" -- \
  /absolute/owned/venv/bin/python /absolute/owned/run_acceptance.py
```

Use current supported `--owner`/`--as` when the installed lane model requires them;
record the exact lane rather than inventing one. A direct-SSH private-clone route
may use `ilmr run` without BOX only if it meets the same installed agent-isolation
authorization, never as a bypass for `up` refusal. Do not start the unrelated ILMR
agent ticker just because doctor reports it absent: Codex owns this four-agent team,
ILMR owns its environments/admission/testing.

Shared capacity: at most two heavy jobs for this repo across all four agents;
observe existing queue and coordinate with the Data Engine run. Archbox/devbox may
share physical capacity; never treat their names as independent allocations.
Use admission, not manual slot-file edits. Set nested test/BLAS/OpenMP concurrency
to one initially; increase only within the granted five-core slot and measured
memory budget. No unbounded process-per-file or one pool per agent.

ILMR test caching cannot stand in for execution evidence. Prefer explicit bounded
`run` of unittest/tools unless a project test declaration is set up. If using
`ilmr test`, verify its detection and cache key; final run uses `--no-cache` plus
LeakGuard's own semantic no-cache setting. Record reuse as reused. Normal execution
must not depend on GitHub auth; only test gh/API access if CI dispatch becomes
necessary. No release publishing is authorized by this plan.

### Commands and evidence harness to implement

Existing diagnostic/source commands remain the first baseline (use absolute paths):

```sh
LEAKGUARD_CONFIG="$task_config" LEAKGUARD_STATE_DIR="$task_state" \
LEAKGUARD_GITLEAKS="$task_gitleaks" PYTHONPATH="$task_repo/src" \
  "$task_python" -m unittest discover -s "$task_repo/tests" -v
"$task_python" "$task_repo/tools/reproduce_review.py" --gitleaks "$task_gitleaks"
# After P0:
"$task_python" "$task_repo/tools/reproduce_review.py" \
  --gitleaks "$task_gitleaks" --assert-fixed
```

C adds `tools/run_acceptance.py`, `tools/run_corpus.py`, `tools/benchmark_scan.py`
with `--output`, `--seed`, explicit backend/config/state paths and bounded runtime.
Acceptance creates its own private config/Git config/state/synthetic repositories;
it neither installs real hooks nor reads configured real scopes. Add a wheel mode
that runs outside the source checkout, clears PYTHONPATH, verifies module origins
inside the venv, and copies only tests/fixtures into an owned test directory. The
current reproduce_review.py deliberately sets PYTHONPATH internally; it is NOT
clean-wheel acceptance. Adapt it or reuse its cases in the installed harness.

Build `python -m build`, install the wheel and example distributions in a clean
venv, then run installed acceptance. Pin exact measured optional dependency
versions in receipt/lock output even though pyproject declares compatible ranges.
CI adds macOS and newer Python (3.13, and 3.14 when parser support is confirmed),
with Linux/Windows 3.11 retained and base/document-extra legs. Workflow configuration
alone is not an executed pass; surface CI access/runner absence explicitly.

Benchmark at least three repetitions of 1/10/50/200 files, clean and positive,
separate part-count curves, cold/reused/uncached. Capture subprocess starts, total
bytes, process-tree RSS and wall timing; define warm as prior complete findings
available under the exact closure. Compare any optimized version to the uncached
per-part reference finding set including ranges/context. Do not concatenate
unrelated text and then discard boundary matches as a substitute for equivalence.

Receipt fields: `run_id`, `lane`, `host_label`, `source_commit`, `patch_digest`,
`input_manifest_digest`, `python`, `dependency_lock_digest`, `gitleaks_identity`,
`policy_id`, `runtime_id`, `command`, `seed`, `started_utc`, `elapsed_seconds`,
`cache_status`, `outcome`, `counts`, `peak_rss_bytes`, `subprocess_count`,
`artifact_sha256`. Sanitize workstation paths in durable public receipts; keep
full ownership paths in the private run manifest. No raw findings/fixture content
or host-wide diagnostics in benchmark summaries.

## Integration and cleanup

Workers return small commit IDs (or exact patches), tests/receipts, source identity,
remaining risks and owned-resource manifest. Lead integrates sequentially, checks
for conflicting ownership and reviews security-sensitive logic itself. Test the
integrated tree, not just lane heads. Never report a reused ILMR result as a new
pass or let one platform's pass stand in for another.

Maintain a private ownership manifest from first mutation: exact local/remote
roots, boxes, owner lane, branches, processes/groups, downloaded tools, environments,
cache roots, evidence outputs, byte usage and intended retention. Stop only owned
workers; collect useful commits before deleting their trees. Copy compact redacted
receipts and benchmark/corpus summaries into `docs/validation/RUN/` before cleanup.

For each exact owned box inspect `down --clean --dry-run BOX` and `rm --dry-run BOX`
and then apply corresponding commands if their targets match the manifest. Respect
owner/plan-digest checks and preserve unintegrated branches. Delete only task-owned
scratch and downloads. No global gc, teardown --all, docker prune, shared stash,
broad git clean, process-name kills, shared cache deletion or other-chat cleanup.
Verify owned processes/boxes are gone; compare task footprint before/after.

Final handback: integrated commit/tree identity, implemented public surface,
compatibility changes, acceptance ledger/corpus/performance links, incomplete work,
platform limitations, exact retained artifacts and cleanup result. Never describe
unknown coverage, absent runners or remaining boxes as completed work.

## Copy-ready launch instructions

Lead prompt (after the user starts execution):

> Implement the agreed LeakGuard plan in docs/architecture/0001-scanning-contract.md
> and docs/handoff/dispatch-plan.md for eight elapsed hours. You are the Sol xhigh
> lead with exactly three workers: Sol xhigh semantics/state/Git, Luna xhigh
> API/CLI/docs/examples, Luna xhigh corpus/conformance/performance/packaging. Follow
> exclusive file ownership and the first-45-minute contract checkpoint. Target
> devbox via direct SSH and existing remote ILMR; resolve the scoped agent-isolation
> launch prerequisite before mutation. Preserve user edits, snapshot exact source,
> use private checkouts/state, at most two shared heavy jobs and no nested agents.
> Land hook/cache/document fixes first, then the minimum coherent contract.
> Include ScanStore injection and the maintained firm-script detector adapter;
> preserve the Password Buddy encrypted-vault boundary as a follow-on milestone.
> Review every redaction, proof, identity, lifecycle and Git-policy change yourself. Drop
> optional optimization before correctness. End with uncached installed acceptance,
> redacted receipts, explicit incomplete work and exact owned-footprint cleanup.

Worker A prompt:

> Own only lane A files in dispatch-plan.md. Implement the three reproduced fixes,
> shared engine integration, immutable Git acquisition/context, content/proof-valid
> replay, migration/current-history lifecycle and bounded queue/audit state. Depend
> on the agreed models and lead-owned extraction/backend/plugin contracts. Start
> with focused regression tests in your owned new test files.
> Ensure injected storage covers findings and catalog state without plaintext mirrors.
> Return small commits, executed test receipts and remaining risks; do not edit another lane's files or
> spawn agents. No real-data scans, global hooks/config changes or independent
> full-machine test pool. All proof/policy decisions go through lead review.

Worker B prompt:

> Own only lane B files. Publish typed models and the safe serializer first, get
> lead agreement, then implement the thin Python/CLI/report adapters, stable JSON,
> documented exits/current-history views, v1 compatibility and independently
> installable detector/extractor examples.
> Include the standard script-check example and document Password Buddy's separate
> user-approved actual-secret storage flow without implementing a vault this phase.
> Do not implement another scanning engine or policy evaluator.
> Keep examples aligned with the lead's extension contracts.
> Run wheel-installed API/examples with C. Return commits/tests/compatibility notes;
> no delegation or edits outside ownership.

Worker C prompt:

> Own only lane C files. Reproduce and distinguish the recorded baseline, then
> implement the reusable conformance harness, deterministic labelled corpus,
> adversarial Git/cache/document/crawl cases, safe benchmark and acceptance tools,
> packaging and cross-platform CI. Test invalid output, hangs/crashes and redaction
> across durable state/stdout/stderr. Submit production defects to their owners.
> Exercise the script-check protocol and injected-store no-mirror requirement too.
> Use remote ILMR admission with the lead's shared two-heavy-job cap. Final wheel
> acceptance must run outside source with PYTHONPATH unset; the current portable
> probe alone is insufficient. Return compact receipts and honest uncovered cases.
