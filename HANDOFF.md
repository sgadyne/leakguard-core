# LeakGuard architecture planning and eight hour implementation handoff

Begin a new chat in this repository. Astra should first design the public scanning surface and internal spine, then produce a concrete feature and optimization plan. The following execution phase is eight hours of Sol and Luna work with three subagents. This handoff is planning input, not a frozen replacement API.

The user wants clean community abstractions: specify the functionality implemented once by the engine and the functionality exposed as reusable, idiomatic plugins. Data Engine's standard database source plugins belong in its separate repo; apply the same standard here to detectors, document extractors and reusable extension contracts without coupling the two runtimes.

**Start here.** Read README.md, PLUGIN_API.md, SECURITY.md, RELEASING.md, VALIDATION.md, pyproject.toml and [the baseline](docs/handoff/baseline.json). Review any current AGENTS.md before editing. The reviewed commit is `7600d922be176cb0c07c91ac47da363a6e51ed62`, package 0.1.0. The source checkout was clean before the handoff additions. Treat subsequent user changes as authoritative.

## Philosophy and boundaries to preserve

LeakGuard is offline detection, opt-in Git protection and local inventory. Source files are read, never moved or rewritten by scanning. Reports carry locations, rules and evidence classifications, never matched values or snippets. The built-in engine does not validate credentials or send telemetry. No real folders or shares are scanned until configured or explicitly passed.

An incomplete crawl is incomplete; an unsupported document is not proof of cleanliness. Git guards fail closed when a required scan cannot complete. Historical inventory is evidence of an observation, not proof of current presence. Companion profile inventory must not weaken Git blocking.

Only narrow contextual proof may classify a heuristic match as metadata. Keep same-index/same-commit source verification, duplicate-key rejection, ambiguous-line handling and most-restrictive severity merging. Do not add filename-wide hash exceptions, broad placeholders, entropy-only suppression or plugin waivers of other detectors. Plugins are explicitly installed trusted code, not a security sandbox.

## Surface and spine for Astra to design

Define one coherent Python scanning API and result schema consumed by the CLI, Git guards, audit queue and reports. Separate extraction, detection, evidence classification, policy decisions and presentation. Consolidate engine.py without changing its ownership of scan outcomes. Specify exact types/interfaces and migration effects; map each addition to existing code rather than inventing another scanning engine beside it.

| Concern | Engine responsibility | Reusable plugin responsibility |
| --- | --- | --- |
| Inputs and provenance | Bound input size, retain path/blob/index/commit and part/line provenance, preserve immutable observations | Identify supported content or detector capabilities without changing source files |
| Extraction | Budget, process boundary, part/offset mapping, empty/unsupported/error dispositions | Extract bounded named text parts from a supported format |
| Detection | Invoke backends, validate results, sanitize failures, merge observations and redact reports | Return only rule, line and permitted severity with a versioned narrow schema |
| Classification | Verify contextual metadata proof and prevent unrelated waivers | Supply detections; extension results do not authorize global suppression |
| Scan policy and coverage | Explicit completeness and omission reasons, cache validity, deadline/cancellation and Git decisions | Declare honest format/limit/version requirements |
| Crawl and state | Resumable queues, durable observations, active/resolved/unknown finding lifecycle and report queries | Source notifications or content support only through a declared extension boundary |
| Integration | CLI, Python API and Git hooks consume one result contract | Independently installed reviewed extensions and examples |

A candidate result model must distinguish scanned, reused, skipped, error and interrupted/incomplete outcomes, with policy and content identity and stable redacted error codes. A cache hit must preserve findings and provenance. Define which formats are required for Git checks and how explicit omissions are surfaced. Specify CLI exit behavior rather than assuming every filesystem scan has the same policy as a Git guard.

## Community plugin and standard extension design

Have Astra identify the exact abstractions that should be reused by community authors, including detector and extractor protocols, configuration validation, version compatibility, capability declarations, policy fingerprints, conformance tests and examples. Preserve explicit registration/loading: no automatic downloading or broad plugin discovery.

The existing v1 detector interface returns Finding(rule, line, severity) with block/review severity only. Keep secret values and free-form exception messages out of the result schema. Specify how detector and extractor implementation/dependency versions enter scan identity. Treat built-in Gitleaks, rule content and extractor behavior as part of that identity too. A version string without a defined compatibility/identity policy is insufficient.

Build document support once as maintained standard extractors, with optional dependencies and reusable safety limits. Current UTF-8/UTF-16-BOM text, Office XML, PDF text and Outlook MSG are the starting set. Define ownership of format sniffing, extension hints, decoding, part labels, timeout/memory/output bounds, parser isolation and offset mapping. Keep unsupported/encrypted/no-text content explicit. Assess future extractor/backend extensions as a ranked backlog; do not expand into OCR, recursive archives or executable analysis merely to grow a feature list.

Require a detector example, an extractor example and a conformance harness that independent packages can run without a private deployment. Test invalid output, hangs/crashes, excessive part/output counts, invalid lines and attempted severity downgrades. Standard core behavior must not be copied into each extension. Preserve the trust distinction: the existing in-process plugin interface runs with the scanner's account; isolating untrusted parsers does not turn arbitrary trusted Python extensions into sandboxes.

## Reproduced correctness work

The existing source suite on macOS arm64, Python 3.13.13 and Gitleaks 8.30.1 produced 26 passes and 7 failures out of 33 checks in 6.232 seconds. All seven failures involve newly installed hooks being ignored by Git on POSIX because hooks.install_at writes them without an executable bit. Tests whose clean commit succeeds can mask this absence; assert both installed hook execution and blocking of a staged synthetic credential.

Two additional synthetic probes exposed result problems:

1. scan_file returns one finding for a synthetic credential, then returns status unchanged and zero findings on a cache hit. Historical database/report observations remain; the current scan result omits evidence for the unchanged file. Repair replay and current-versus-historical semantics rather than merely changing the displayed count.
2. A DOCX-shaped ZIP containing only a Content Types XML member returns skipped-binary-or-no-text. The direct pre-commit guard exits zero because git_hook ignores the returned extraction status. This is separate from executable permissions; it was invoked directly. Preserve policy-visible coverage issues and reject incomplete required document scans.

[The portable reproduction](tools/reproduce_review.py) uses an empty external config, private temporary state, synthetic files and a disposable repository. It also checks actual installed-hook behavior. No user repository hook or global Git configuration is changed.

## Implementation map

| Area | Starting files |
| --- | --- |
| Main lifecycle, cache, Git and queues | src/leakguard_core/engine.py |
| Hook installation and chaining | hooks.py |
| Config and paths | settings.py, policies.py |
| Extractors and bounded subprocess | documents.py, extract_worker.py |
| Extension API | plugins.py, PLUGIN_API.md, examples/example_plugin.py |
| Narrow metadata evidence | finding_details.py |
| Inventory and reporting | catalog.py, manage.py, presentation.py |
| Rule pack and tests | rules.toml, tests/test_integration.py, test_extensions.py, test_catalog.py, test_presentation.py |
| Build and existing CI | pyproject.toml, .github/workflows/test.yml, tools/install_gitleaks.py |

## Findings lifecycle and cache correctness

Make current findings, historical observations and unknown current state explicit. A complete successful rescan may resolve evidence for the exact content/policy scope it checked. A timeout, skipped file, partial audit, unavailable root or lost event cannot mark old findings resolved. Preserve detections on cache reuse and update last-verified semantics deliberately. Define how content changes, deletes/renames, policy upgrades and source/AST context changes invalidate or reclassify observations.

Assess the existing SCAN_POLICY, which hashes finding_details.py, rule bytes and configuration but not a complete detector/extractor/runtime closure. Plugin source/version, scanner version, extractor behavior/dependencies and classification context can change while path/size/mtime remain unchanged. Specify a sound practical identity and invalidation strategy, and keep cached proof from outliving its referenced source version.

Implement a stable explain/report JSON surface carrying coverage, policy and provenance without raw values. Avoid reparsing an unbounded archive of historical JSON reports for every summary if measurements justify a durable query model. Any schema change needs a migration and compatibility strategy.

## Synthetic testing and optimization

Build a labelled, deterministic corpus of synthetic credentials and benign lookalikes across text, JSON/XML/config, unusual extensions, UTF-16, Office parts and optional PDF/MSG fixtures. Include weak literals, exact placeholders, mixed metadata/credentials, duplicate JSON keys and valid versus invalid source/AST digests. Preserve same-index/same-commit proof. Measure precision/recall by declared rule/case category plus coverage, false-positive categories and redaction; do not claim real-world rates from synthetic data.

Exercise staged/unstaged isolation, historical/intermediate commits, initial/new-branch pushes, deletions, merges, worktrees, hook chaining/stdin, filenames with spaces/non-ASCII/newlines, plugin failures, parser timeouts, empty/encrypted/unsupported documents, size/part limits, interrupted audit resumption, directory enumeration budgets and simultaneous queue/audit work. Check persisted reports/database dumps/stdout/stderr for the synthetic marker. No test authenticates a credential.

The original tiny-file sample scanned 50 clean UTF-8 files in 9.7839 seconds cold and 0.0021 seconds warm. It is a single host/run, and warm hits currently omit findings. Per-file Gitleaks startup suggests batching as a profiling target, not a proven general speedup. Compare startup cost, files/bytes per second, peak RSS, subprocess count, SQLite work and hook latency.

If batching, preserve per-file, per-part, start/end-line and commit mapping, independent detector context and redaction. Test boundary-spanning patterns and plugin isolation so combining text does not manufacture or lose matches. Use bounded admission rather than one scanner process per CPU per agent. Benchmark clean and positive corpora, cold and correctly replayed cache results, and batch/corpus size curves. Keep an uncached correctness path.

## Astra planning deliverables

Write an architecture decision and prioritized roadmap naming the public scanning/result/policy/plugin interfaces, internal ownership boundaries, finding lifecycle, scan identity, persistence/migration plan and supported-format matrix. State which reusable functionality becomes a standard module or optional plugin, what remains core, and what a community extension author implements once. Include example CLI/Python flows and exact acceptance criteria for redaction, completeness and Git enforcement.

Separate verified failures, design choices and performance hypotheses. Return a dependency-ordered eight-hour plan with a minimum coherent deliverable, stretch work and three disjoint worker assignments. Do not start long execution while the user is still discussing surface and feature priorities.

## Sol and Luna execution brief

After the user starts execution, use a Sol lead at xhigh with exactly three subagents: one Sol at xhigh for scan semantics/state/cache/Git policy, one Luna at xhigh for the public API/CLI/plugin documentation and examples, and one Luna at xhigh for corpus/conformance/performance/packaging. Keep at most four active agents including the lead, with no nested delegation exceeding the budget. Sol reviews every redaction, proof exception, cache identity, completeness and Git enforcement change.

The budget is eight elapsed execution hours per repo, not eight hours per worker. Both repo chats may share archbox concurrently. Track start/deadline, checkpoints and remaining scope. Report incomplete work accurately when the budget ends.

| Elapsed time | Outcome |
| --- | --- |
| 0 to 1 hour | Reproduce baseline, verify remote workflow, define schemas/file ownership and acceptance commands |
| 1 to 3 hours | Fix executable hooks, cache replay and required document coverage with focused regressions |
| 3 to 5 hours | Implement agreed scan/plugin surface and current finding lifecycle with compatibility handling |
| 5 to 6.5 hours | Run labelled adversarial corpus and measured batching/cache experiments on archbox |
| 6.5 to 7.5 hours | Wheel-install acceptance, plugin examples/conformance and cross-platform CI |
| 7.5 to 8 hours | Integrate, run uncached acceptance, clean owned footprints and hand back results |

Validate continuously. Keep engine.py under one owner or split interfaces before assigning overlapping edits. Isolated checkouts avoid shared index/ref conflicts. Workers return patch/commit IDs, tests, source identity and unresolved risks. The lead integrates sequentially and checks actual Git behavior rather than only mocked helper calls.

Acceptance requires no unexplained regressions, working opt-in hooks on POSIX/Windows as applicable, redacted and provenance-correct findings, explicit required-scan failure, correct cache replay/lifecycle, reusable extension contracts/examples, clean wheel imports without source-path injection and before/after performance evidence. Existing CI declares Linux and Windows/Python 3.11; add macOS and appropriate newer-Python coverage. Distinguish optional parser tests from environments where those dependencies were actually exercised.

## Local reproduction commands

Use a private venv/state root and separately installed, checksum-verified Gitleaks 8.30.1. The built-in installer downloads an official pinned release; the review used approved curl downloads plus checksum verification because Python network downloads failed DNS resolution in the sandbox. Never check in the binary, real config, runtime database or findings.

```sh
task_repo=$(pwd)
task_run_root=$(mktemp -d /tmp/leakguard-validation.XXXXXX)
task_gitleaks=/absolute/path/to/gitleaks
printf '{}\n' > "$task_run_root/config.json"
LEAKGUARD_CONFIG="$task_run_root/config.json" LEAKGUARD_STATE_DIR="$task_run_root/state" LEAKGUARD_GITLEAKS="$task_gitleaks" PYTHONPATH="$task_repo/src" python3.13 -m unittest discover -s tests -v
PYTHONPATH="$task_repo/src" python3.13 tools/reproduce_review.py --gitleaks "$task_gitleaks"
```

The portable reproduction creates its own valid empty config and state, isolates Git configuration and deletes its temporary directory. Use `--benchmark` for the 50-file sample. Default zero exit means the diagnostic executed, not that bugs are fixed; `--assert-fixed` requires cache findings, executable/blocking hooks, redaction and incomplete-scan rejection. Promote the cases into normal regressions.

Use an absolute source path for tests that change child working directories. The original relative PYTHONPATH run produced extra import failures; those are excluded from the 26/7 baseline. A clean installed-wheel run without PYTHONPATH is still required. Preserve compact summaries before deleting the exact task_run_root. On archbox select Python 3.11 explicitly and test a newer interpreter too.

## Archbox and ILMR testing

The user explicitly wants archbox and ILMR used to accelerate testing. A probe on 25 October 2026 verified SSH to `archbox`, Linux x86_64, 20 logical CPUs, about 125 GiB RAM, Python 3.11.17 at `~/.local/bin/python3.11`, and ILMR 0.1.0 at `~/.local/bin/ilmr`. The system Python is 3.14.7. Use the minimum supported Python deliberately; `python3` alone selects 3.14 here.

Noninteractive SSH does not include `~/.local/bin` on PATH. Call `"$HOME/.local/bin/ilmr"` explicitly on the remote. `ilmr` here is the environment/testing tool, not a second SSH hostname. The Mac also has ILMR 0.1.0, but `ilmr host ls` in this sandbox failed while opening its normal SQLite ledger. That is not evidence that archbox or its remote ILMR installation is broken.

Start from the current CLI and existing configuration:

```sh
ssh -o BatchMode=yes -o ConnectTimeout=8 archbox 'uname -sm; "$HOME/.local/bin/python3.11" --version; "$HOME/.local/bin/ilmr" --version'
ilmr --help
ilmr -C "$task_repo" host ls
ilmr -C "$task_repo" host doctor archbox
ilmr -C "$task_repo" run --help
```

`task_repo` must be the actual repository checkout, not its non-Git parent. Confirm that an ILMR host registration named `archbox` exists before using `--on archbox`; SSH reachability alone does not establish that registration. Do not overwrite host mappings or rebuild the site to make a test run work. If the Mac ledger remains unavailable, use SSH to a private remote checkout and invoke the existing remote ILMR there. Read its `--help`, `host`, `queue`, `df`, `up`, `run`, `down`, and `rm` help before using their flags.

Verified CLI shapes include `ilmr -C CHECKOUT --on archbox up BOX`, `ilmr -C CHECKOUT --on archbox run --class heavy --max 20m BOX -- COMMAND`, and `ilmr -C CHECKOUT --on archbox test --box BOX --no-cache`. These are templates, not proof that the named host is registered or that an environment was provisioned. For direct SSH, invoke `~/.local/bin/ilmr` on the remote checkout instead of forwarding twice. Isolation requirements are owned by the existing ILMR installation; use its supported class and authorization rather than silently weakening them.

Use a unique repo and run namespace such as `leakguard-core-20261025-RUN-LANE`. Prefer private ILMR checkouts or isolated clones for workers so their Git refs and edits cannot collide. Keep the exact commit plus any uncommitted patch digest in each test receipt; verify the remote tree before treating results as evidence. Do not assume a host sync includes dirty files. For cache keys, include relevant source/tests, Python, dependencies, commands, environment, scanner/rules/plugins where applicable, and the declared runtime closure. Record cached results as reused, never as newly executed passes. Run the final acceptance suite uncached.

Use archbox for Linux process/concurrency tests, generated corpora, repeated stress runs, wheel builds, and benchmarks. Keep Mac checks local and Windows checks in the existing CI or an explicitly available Windows runner. A Linux pass cannot replace either platform. Across both repo chats, use the shared ILMR heavy-class admission and begin with at most two heavy jobs per repo; the three agents do not each get an unrestricted full-machine test pool. Coordinate against the observed queue rather than raising shared slot limits. Limit nested test and BLAS/OpenMP threads. Record host, Python, dependency lock, source identity, command, seed, elapsed time, and cache status.

## Footprint and cleanup contract

Keep an ownership manifest for the run: exact local/remote roots, box IDs, branches, process groups/PIDs, downloaded tools, environments, caches and evidence outputs. Separate durable review artifacts from disposable runtime data. Use private, per-run temporary directories and explicit cache locations. Record scratch usage before and after. Do not scan or benchmark against the user's real folders, source integrations, documents or operational databases.

Before cleanup, stop only owned workers, collect their results, integrate useful commits, and copy compact synthetic receipts and benchmark summaries into the project. Use ILMR `down --clean --dry-run BOX` and `rm --dry-run BOX` for exact owned boxes, inspect the targets, then apply the corresponding non-dry-run commands. Preserve a branch until its work is integrated. Remove only owned scratch directories and task caches. Do not run global `gc`, `teardown --all`, `docker system prune`, broad `git clean`, shared `git stash`, or process-name-wide kills. Do not delete shared caches or another chat's boxes.

Leave no new daemon, watcher, queue consumer, port forward, hook installation, scheduled task, credential, or global configuration change behind. Any temporary service used for a test must be foreground/bounded or explicitly stopped and verified. Report remaining artifacts with their owners and retention reasons; do not claim cleanup if a process or box still exists.

The handoff preparation did not provision remote boxes or run the repo suites on archbox. It verified SSH, installed tool help/version, and machine capacity only. `gh auth status` reported an invalid existing token during the original review; cloning over Git worked. Recheck account access only if a later task actually needs GitHub API/CI access.

## New chat kickoff

Use Astra for this first message:

> Read HANDOFF.md, the linked baseline and portable reproduction in this leakguard-core checkout. Plan a coherent scanning surface and internal spine, including reusable community detector/extractor contracts, maintained standard content adapters, precise coverage and finding lifecycle, sound cache identity and a stable redacted report API. Ground the plan in the reproduced hook/cache/document failures. Specify concrete features, optimizations to measure, acceptance criteria and an eight-hour plan for a Sol xhigh lead with three workers using Sol and Luna xhigh. Use archbox/ILMR for synthetic testing, respect both chats' shared capacity and require owned-footprint cleanup. Plan first; implementation begins when I start it.

For the subsequent execution phase:

> Implement the agreed Astra plan for eight elapsed hours using the Sol/Luna xhigh team in HANDOFF.md. Run three subagents with disjoint ownership, use archbox/ILMR, preserve redaction and evidence/completeness semantics, integrate and test continuously, and leave a clean audited footprint. Deliver the implemented surface, conformance/corpus results, measured optimizations, compatibility notes and explicit unfinished work.


