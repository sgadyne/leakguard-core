# LeakGuard implementation acceptance, 20261025T175327Z

The Linux implementation repairs executable Git hooks, positive cache replay and
required-document enforcement, and integrates the typed scanning service, bounded
extension/extraction contracts, redacted reporting and durable finding lifecycle. Native
macOS and Windows execution is outstanding. Their CI matrix and portable commands are
present; configuration is not evidence of execution.

The production package subtree is `9d3597b34f0471645869b77c396d3136dfd5dc1a`. Receipt
commits identify the exact source used for each execution. Later benchmark/corpus test
and validation-document changes do not change that package subtree. Git identifies the
delivery revision; these immutable receipt commits are the validation identities.

## Execution evidence

All acceptance executions use synthetic input, an empty private config, disposable
state/repositories and checksum-verified Gitleaks 8.30.1. The Linux binary SHA-256 is
`88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`. Python 3.11.2 and
3.13.15 are separate executed runtimes. Document-extra runs use `pypdf` 6.21.2 and
`olefile` 0.47; base environments omit both. Packaging 26.3 is recorded with the exact
builder dependency versions and artifact hashes.

The source baseline ran 33 tests: 26 passed and seven hook checks failed. Portable
baseline diagnostics also reproduced disappearing warm findings and a required no-text
document being allowed. Three fresh integrated portable probes pass all repaired
behaviors, including actual Git execution, current warm finding IDs and sanitized
incomplete-document rejection.

The four production-freeze installed-wheel cells execute 249 tests each: base
environments pass 243 and skip six; document environments pass 247 and skip two. After
the benchmark repetition fix, refreshed installed Python 3.11 base and Python 3.13
document cells execute 250 tests: 244/6 and 248/2 respectively. The fresh Python 3.13
document source suite also passes 248 with two Windows-only skips. Those counts preserve
the distinction between total, passed and skipped tests. The final exact `9111c9c`
Python 3.11 document source suite and Python 3.13 document wheel suite each execute 251
tests: 249 pass and two Windows-only tests skip. Both are fresh executions with
unchanged committed source.

Each wheel run installs core and independent v2 detector/extractor distributions outside
the checkout, clears PYTHONPATH, verifies the installed import origin, runs v1/v2
conformance, and audits wheel/sdist members. An independent console and module CLI check
verifies positive/inventory exit behavior and redaction. The refreshed wheels' 31
package Python/TOML members also match the committed core bytes independently.

## Interpretation and limits

Cold/warm/uncached final measurements compare normalized findings, severity, provenance,
proof and coverage. They record backend launches, throughput, SQL statement/write
counts, process memory and installed-hook latency. No optimization was accepted. The
paired legacy 50-file diagnostic records the added correctness cost; baseline warm
replay omits positive findings and is not equivalent work. OS page caches were not
flushed and other admitted host activity was possible.

SQLite measurements use actual store connections and directly timestamp acquisition
calls, definite lock-hold windows and transaction boundaries. Internal VFS
acquisition/release instants are uninstrumented. Process-tree RSS is sampled on Linux
and can miss short-lived children and double-count shared pages.

Parser and Python extension workers have tested POSIX resource limits and owned
process-group cleanup. Gitleaks has bounded IPC/time and a Go managed-heap target; a
hard Go address-space cap is not claimed. Windows Job Object tests must execute on a
native runner. Trusted configured extensions retain account permissions; this is
resource containment, not an OS sandbox. The finite AST probes do not establish a hard
memory limit for an embedding parent process.

Filesystem traversal revalidates sequential observations; it is not an atomic filesystem
snapshot. Absolute inherited Gitleaks config references remain external and disable
semantic cache reuse. Existing installed hooks require reinstallation to use the pinned
isolated core launcher.

See [platform commands](PLATFORM_CHECKS.md), the acceptance ledger and individual
redacted receipts for executed scope and outstanding native gates. Product and migration
details are in [COMPATIBILITY.md](../../../COMPATIBILITY.md),
[PLUGIN_API.md](../../../PLUGIN_API.md) and [VALIDATION.md](../../../VALIDATION.md).

## Corpus accounting

Catalog v3 executes 48 labelled cases with document parsers: all 48 pass, with no
uncovered case. Classification metrics use only 35 eligible cases: 14 TP, 21 TN, 0 FP, 0
FN. The 13 additional proof, omission and collision cases are tested but excluded from
that denominator. A pinned static GitHub PAT-format case contributes one `github-pat`
TP; literal-client-secret contributes 12 and literal-password one. Category confusion
counts and rule-level TP/FP/FN are explicit. These are synthetic finite results, not
real-world accuracy rates.

The parser-free counterpart covers 43 cases and records 5 PDF/MSG cases as uncovered;
its 32 eligible cases yield 11 TP / 21 TN / 0 FP / 0 FN. Its focused corpus suite
executes 10 tests: 7 pass and 3 skip. Unavailable parser cases never inflate
classification metrics. In this corpus, covered means the declared case behavior
executed; omitted/no-text/proof cases are not claims that every document surface was
inspected. The corpus policy/runtime fields originate from its collision-service
integration case; the source/catalog/backend/dependency identities also bind the direct
detector/extractor cases.

See the [acceptance ledger](ACCEPTANCE.md), [full category/rule corpus
summary](evidence-corpus-seed20261025-9111c9c.json), [base
counterpart](base-corpus-9111c9c-summary.json), and [performance
record](PERFORMANCE.md). The final built distributions have exact archive/member hashes
in [installed acceptance](evidence-wheel-py313-docs-final-9111c9c.json).

## Cleanup

All three worker boxes were removed after inspected dry runs and verified
branch/artifact retention. Exact run-owned environments, generated inputs/state, caches
and downloads totaling 598,666,700 bytes were removed. Audited 327 heavy-invocation
receipts; none remained marked running and no matching live wrapper/ILMR job process
remained. The active lead checkout is retained with its temporary files cleaned; the
bounded supervisor exits after final completion/lead exit or its deadline. The bundle,
28 validated distribution archives, receipts, original source snapshot and finite
diagnostic scripts remain for review. See the [cleanup inventory](cleanup.json).
