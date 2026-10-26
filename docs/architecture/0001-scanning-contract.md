# ADR 0001: one scanning contract, explicit coverage, reusable extensions

Status: implementation in progress for 0.2.0. The requirements below remain the acceptance contract; implementation and platform execution are recorded separately in the validation ledger.
Date: 2026-10-25. Reviewed source: `7600d922be176cb0c07c91ac47da363a6e51ed62` (0.1.0).
Execution sequence and ownership: [dispatch plan](../handoff/dispatch-plan.md).

## Decision and scope

Keep LeakGuard an offline scanner, opt-in Git guard and local inventory. Introduce
one typed scanning service underneath every entry point. Separate byte acquisition,
extraction, detection, contextual classification, policy evaluation and reporting.
The service owns outcomes; an extractor or detector cannot declare a file clean,
waive another detector, resolve old evidence or decide whether Git proceeds.

Ship text and the existing document families as maintained standard adapters in
this distribution. Put their parser dependencies behind optional extras. Publish
the same small detector/extractor contracts for independent packages. Do not build
a second engine, a separate plugin runtime product, a database connector layer or
a dependency on Data Engine. Notification inputs remain internal queue messages in
this iteration; a source-plugin SDK is future work.

The minimum coherent increment includes the three reproduced fixes, a shared
result/policy model, sound reuse, conservative finding lifecycle, explicit extension
contracts, examples, conformance and installed-wheel acceptance. Optimizations and
additional formats cannot displace those items. Version the next package as 0.2.0
if the new CLI exit behavior ships; do not silently change the published 0.1.0 contract.

## Product direction: Password Buddy and enterprise checks

User clarification, 2026-10-25: deliver an installable Password Buddy companion
that scans periodically and maintains an encrypted local vault, alongside Git,
CLI and service integrations. The vault may hold **actual passwords/secrets with
explicit user approval to save**, as well as encrypted findings/location metadata.
The engine and reusable open-source plugins also support firms' private checks for
sensitive information. This is the product direction; the desktop/vault release
is a distinct milestone after the eight-hour engine foundation.

```text
Password Buddy desktop app       CLI / Git guards / service integrations
  onboarding, scope, schedule                 |
  review and local notifications              |
                 +---------- Scan service ---+
                                |
                    standard / community / private
                    extractors and detectors
                    (including script-check adapter)
                                |
                       redacted observations
                                |
             encrypted findings store and current/history views

User-approved Save to vault
  -> unlock + revalidate source version + select exact secret
  -> dedicated local secret-transfer path
  -> encrypted credential vault
```

One end-user installation can bundle these maintained components. Password Buddy
is a first-party application consuming the engine API; scheduling, notifications,
vault unlock and secret retrieval do not belong in detector plugins. Headless Git,
CLI and service deployments remain independently installable and usable without
the companion app or an unlocked credential vault. Version their dependencies on
the core contract explicitly. Broader services consume the same reports and policy,
with their own explicit authentication/storage boundaries when developed.

Buddy onboarding chooses folders, exclusions, schedule and resource limits before
any crawl starts. A per-user scheduler submits bounded resumable audit jobs;
notifications/watch events accelerate checks but periodic reconciliation remains
necessary. Coalesce duplicate jobs, prevent overlapping work for a scope, back off
on failures, resume after sleep/login, and expose pause/status/last-complete times.
Installing the app does not opt into every home folder or install Git hooks. App
uninstallation stops its owned tasks while offering explicit vault retention/export.

“Clean vault” means organized entries, reviewed duplicate suggestions, provenance,
timestamps, version history and explicit stale/revoked labels. It does not mean
credentials are valid or that originals/history no longer contain them. Save to
vault neither deletes/rewrites a source nor resolves a finding. Source remediation,
credential rotation and vault-entry deletion are separate user actions. A scan's
negative or unknown result must never silently delete a saved credential.

### Encrypted storage and explicit secret capture

The current plaintext SQLite/redacted JSON state is not an encrypted vault. Buddy
must supply an encrypted ScanStore implementation for its findings/location history
and a separate CredentialVault capability for actual secret values; there must be
no automatic plaintext SQLite, WAL, JSON-report or search-index mirror. Introduce
the storage injection seam now; select and exercise the encryption implementation
in the Buddy milestone. Git/CLI's ordinary store may continue to hold only redacted
observations. Explicit user exports have their own destination/privacy choice.

Use a maintained authenticated-encryption implementation and platform-backed key
protection, with keys separated from stored ciphertext. Specify key loss/recovery,
encrypted backup/restore and rotation before calling the vault shippable. These
requirements follow [OWASP cryptographic storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
No custom cipher or provisional plaintext fallback. Choose the actual library,
file format and OS key-store bindings in a dedicated vault threat-model decision.

Separate background scan capability from interactive secret read/unlock capability.
The scheduler does not receive the credential-vault unlock key. Use distinct keys
for encrypted observation storage and credential storage; background access to
observation metadata must not imply access to saved passwords. If required storage
keys are unavailable, pause/requeue rather than spool plaintext. OS key-store access
control and the user-session/lock threat model need platform-specific verification;
process separation alone cannot contain malicious same-account Python plugins.

Never add a raw-value field or `include_secrets` flag to ScanReport, FindingRecord,
plugin findings, report JSON or ordinary logs. A Save action identifies a finding,
revalidates its source content identity, then a separate local vault import flow
lets the unlocked user select/confirm the exact value. A line-only finding may
contain multiple candidates; do not guess which value or save the entire line.
Changed/missing source requires renewed review. Manual entry is another explicit
vault-only path. Secret bytes travel only through that private import channel,
never command arguments, environment variables, normal reports or script plugins.
Vault entry IDs can link to observations without exposing values.

Credential storage needs explicit unlock/auto-lock, reveal/copy/export controls,
encrypted metadata and backups, crash-safe writes, versioned migrations and tested
restore/key-loss behavior. Minimize plaintext lifetime; do not promise reliable
zeroization of Python strings or protection from an already compromised unlocked
account. Define vault audit events using entry IDs and actions, never secret values.
Access scoping, lifecycle audit and restore testing are consistent with
[OWASP secrets-management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).

Buddy release acceptance additionally requires: user-approved save only; unchanged
source verified; locked vault cannot reveal values; periodic jobs cannot unlock it;
no plaintext persistence in databases/WAL/temp/log/crash paths; correct corruption,
crash, backup/restore and key-loss handling; pause/uninstall stops owned scheduling;
and saving an entry never marks a source leak remediated. Test platform key access
on each supported OS. Vault implementation/review is a real follow-on deliverable,
not a claim implied by adding an encryption checkbox to the engine release.

### Organization-specific rules and scripts

Use the same extension contract for public packages and privately distributed firm
packages. Checks may identify passwords, tokens, private keys, organization-specific
identifiers, regulated-data patterns or document sensitivity markers. Rule IDs,
static descriptions and declared optional category tags describe the detection;
matched values/snippets stay out of reports. Detection suggests sensitivity, not
credential validity or legal/compliance certification.

Provide a maintained `script_checks` detector adapter, explicitly selected in
configuration. A firm supplies a fixed executable/argv, static manifest/options
and its check logic; it need not build a Python package. The adapter implements the
same DetectorV2 interface and uses core supervision, result validation, budgets,
identity and conformance. Do not build a second script-specific scanning engine.

Script protocol v1: one bounded JSON request on stdin per independently extracted
part, containing protocol version, logical path, core-generated part/format IDs and
text. Stdout must be exactly one bounded JSON response with `schema_version: 1` and
`findings: [{rule, line, severity}]`; an empty list with exit 0 is a completed check.
Reject extra fields, malformed responses, nonzero exit and invalid rule/line/severity;
never interpret a crash as zero findings. Stderr is discarded/sanitized, never
forwarded. Commands use argv with shell=False and no interpolation of scanned
content; environment is minimal, working/scratch directories private, stdin/stdout
not logged. Apply existing timeout, output, memory and child-process cleanup limits.

Identity covers script/executable bytes, interpreter/tool versions, declared
dependencies and options. Unknown external state disables reuse. A script cannot
waive another rule or read the credential vault through its API. Scripts receive
source text, so installation remains an explicit trusted-code decision; supervision
does not imply an OS sandbox or automatic network denial. Default check behavior
is offline with no credential validation; any future network integration must have
its own explicit capability/policy and cannot be silently invoked by this adapter.
Ship a tiny script example and adversarial protocol tests. Repository-wide custom
checks needing additional context require a later bounded context capability;
do not grant a broad filesystem API merely to extend this first contract.

## Evidence versus inference

The [baseline](../handoff/baseline.json) records 26 passing and seven failing checks
on macOS/Python 3.13.13/Gitleaks 8.30.1. The [portable probe](../../tools/reproduce_review.py)
records missing POSIX hook executability, one finding becoming zero on a warm hit,
and direct pre-commit success for an unextractable DOCX. These are reproduced
handoff evidence, not new test runs in this planning session. The earlier Windows
33/33 result in VALIDATION.md has a different host/scope and remains historical.

Source review confirms the mechanisms: `hooks.install_at` writes without chmod;
`engine.scan_file` returns early with an empty finding list; both document paths in
`engine.git_hook` discard `scan_blob`'s status. Further source-review concerns below
require regressions before they are described as reproduced failures:

- `scan_blob` already concatenates document parts. Only StartLine is remapped;
  EndLine remains in batch coordinates and matches can cross part boundaries.
- Git's native text scan and document/plugin scan follow different paths. UTF-16,
  unsupported content and per-input coverage are not consistently accounted for.
- The pre-push document dedup key is only blob OID, losing path/commit/context
  distinctions. Merge enumeration and a new branch's `--not --remotes` exclusion
  require conservative reachability tests.
- `SCAN_POLICY` omits much of the runtime closure; stat equality does not prove
  content equality or continued validity of sibling-source metadata proof.
- Extraction subprocesses have wall time limits, but `capture_output` and parser
  allocations are not a hard memory/output boundary. Built-in Office parts have
  no parent-enforced count bound. UTF-16 replacement decoding can hide corruption.
- Audit enumeration checks its deadline outside the directory iterator, removes
  failed directories, and derives completion from empty queues. Concurrent work
  lacks durable claim/completion fencing. `catalog.match_materials` changes state
  before the entire scan is known to be complete.
- `manage.report` reparses all reports. Its cost is unmeasured; durable lifecycle
  queries are needed for semantics regardless of the eventual performance gain.

Performance hypotheses: per-file Gitleaks startup, repeated blob scans, SQLite
transactions and history-report parsing may dominate. The recorded 9.7839s cold /
0.0021s warm 50-file run is neither a target nor evidence of correct caching.

## Public Python surface

Add `leakguard_core.api` and `leakguard_core.models`; importing either must not read
operator configuration, create state, import configured plugins or spawn processes.
Configuration loading and backend setup occur when explicitly opening a Scanner.
Use frozen dataclasses, tuples and string enums; JSON uses a single allowlisted
serializer, not arbitrary dataclass/plugin dictionaries. `schema_version = 1` is
the first public report schema, independent of package and plugin API versions.

```python
class Scanner:
    @classmethod
    def open(cls, *, config: ScanConfig,
             state_dir: Path | None = None,
             store: ScanStore | None = None) -> Scanner: ...
    def scan(self, inputs: Iterable[FileInput | BytesInput], *,
             policy: ScanPolicy, limits: ScanLimits,
             use_cache: bool = True,
             cancel: Callable[[], bool] | None = None) -> ScanReport: ...
    def scan_git(self, repo: Path, *, request: GitRequest,
                 limits: ScanLimits,
                 cancel: Callable[[], bool] | None = None) -> ScanReport: ...
    def close(self) -> None: ...
    # Also implements a context manager.

@dataclass(frozen=True)
class FileInput:
    path: Path                 # a single file; CLI/crawler expands directories

@dataclass(frozen=True)
class BytesInput:
    data: bytes                # bounded before admission; never serialized
    logical_path: str          # caller-supplied location, not source text

@dataclass(frozen=True)
class GitRequest:
    kind: Literal['index', 'push']
    updates: tuple[RefUpdate, ...] = ()  # required for push; validated OIDs

@dataclass(frozen=True)
class RefUpdate:
    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str
```

`ScanConfig.from_mapping(mapping)` validates the existing configuration keys and
the new explicit extension/capability settings; `from_file(path)` is opt-in. Reject
unknown keys, booleans masquerading as numeric limits, bad types, invalid enums and
unbounded/negative values with a fixed code and safe field name, never the value.
Provide defaults equivalent to the current empty source/plugin configuration.
`Scanner.open` may raise a typed ConfigurationError/StateError with stable code.
Expected per-input failures become results; no backend traceback escapes. State
failure while recording a required Git scan fails closed with a report if possible.

BytesInput cannot assert a verified Git revision or supply arbitrary metadata proof.
The Git adapter constructs internal immutable snapshots and source readers from
Git objects. Filesystem proof uses bounded same-observation sibling reads and
revalidation; it never reads siblings from another Git version. With no state_dir,
the API uses private ephemeral scratch and no persistent catalog or cache unless
an explicit store is supplied. ScanStore stores only the redacted observation,
cache and lifecycle types; it never exposes CredentialVault methods. The default
state_dir-backed implementation remains SQLite. With an injected store, all durable
scan metadata goes through it; state_dir may provide private scratch but must not
silently create a second persistent database or report archive. CLI exports are
explicit presentation operations. The companion's encrypted store must cover all
catalog/location state as well as findings; encrypting only the final report is
insufficient.

### Exact result vocabulary

| Type | Required fields and meaning |
| --- | --- |
| SourceRef | `kind: filesystem/bytes/git-index/git-commit`, `path: str`, `repository: str|null`, `commit: str|null`, `blob_oid: str|null`, `index_tree_oid: str|null`; Git paths retain their exact repository-relative identity |
| ContentIdentity | `algorithm: sha256`, `digest: str`, `size_bytes: int`; null as a whole if bytes could not be acquired |
| RuntimeIdentity | `policy_id: str`, `runtime_id: str`, `context_id: str`, `cache_eligible: bool`; context includes proof dependency identities and missing dependencies |
| FindingRecord | `id: str`, `source: SourceRef`, `part_id: str`, `start_line: int`, `end_line: int`, `rule: str`, `detector_id: str`, `detector_severity: block/review`, `severity: block/review/info`, `classification: credential-candidate/heuristic/verified-file-sha256/verified-function-ast-sha256`, `proof_id: str|null` |
| CoverageIssue | `code: ErrorCode`, `source: SourceRef|null`, `part_id: str|null`, `required: bool`, `omission_id: str|null`; no exception text |
| ScanResult | `source`, `content: ContentIdentity|null`, `identity: RuntimeIdentity`, `outcome: scanned/reused/skipped/error/interrupted`, `coverage: complete/omitted/incomplete`, `findings: tuple[FindingRecord,...]`, `issues: tuple[CoverageIssue,...]`, `observed_at: UTC timestamp`, `last_executed_at: UTC timestamp|null`, `last_verified_at: UTC timestamp|null`, `reused_from: str|null` |
| CoverageSummary | `enumeration_complete: bool`, `required_complete: bool`, `omission_count: int`, `pending_files: int|null`, `pending_directories: int|null`, `cycle_id: str|null`; null means unknown, never zero by assumption |
| PolicyDecision | `verdict: allow/allow-with-omissions/block/incomplete`, `reason_codes: tuple[ErrorCode,...]`, `policy_id: str` |
| ScanReport | `schema_version: 1`, `run_id: str`, `started_at`, `finished_at`, `policy_id`, `results: tuple[ScanResult,...]`, `coverage: CoverageSummary`, `decision: PolicyDecision`, `counts` derived only from results, `issues` for run/enumeration failures |

Identity values are hashes of canonical, version-tagged encodings. Finding IDs
cover source/version, content identity, part/range, rule and detector; they never
hash a matched value separately. Internal evidence records may retain contributor
IDs when merging. Duplicate observations merge at source/version/part/range/rule,
keeping the most restrictive severity; a plugin with the same rule string does
not inherit a built-in detector's metadata exemption. Profile routing controls
inventory presentation, never FindingRecord severity or Git policy.

All lines are 1-based inclusive in the independently extracted text part.
`end_line >= start_line`; both must be within the supplied part. A v1 detector's
end_line defaults to line. Original byte offsets are absent unless a future adapter
can establish exact reversible mapping. Do not pretend a PDF line is a source-file
line. Part IDs are core-created from declared static kinds plus integer ordinals,
e.g. `text`, `office-word-1`, `pdf-page-2`, `msg-body-1`; archive member names,
document titles, subjects and arbitrary extension output are not report labels.

ErrorCode is a closed registry, initially: `input-missing`, `input-unreadable`,
`input-nonregular`, `input-changed`, `input-limit`, `unsupported-format`,
`format-mismatch`, `ambiguous-format`, `decode-failed`, `encrypted`, `no-text`,
`dependency-unavailable`, `extract-failed`, `extract-timeout`, `extract-crashed`,
`extract-output-limit`, `extract-part-limit`, `resource-bound-unavailable`,
`detector-failed`, `detector-timeout`, `detector-output-invalid`, `detector-output-limit`, `plugin-invalid`,
`plugin-timeout`, `plugin-crashed`, `policy-omission`, `budget-exhausted`,
`cancelled`, `enumeration-failed`, `source-unavailable`, `git-range-incomplete`,
`git-input-invalid`, `state-failed`, `configuration-invalid`. Multiple issues may
coexist. Classification absence is not an error or permission to downgrade.

`scanned` means detection actually ran over every available part; coverage can
still be incomplete when another part failed. Retain positive findings from
completed parts. `reused` requires a previously complete eligible scan and current
identity/proof checks; replay the complete finding and issue payload with current
source provenance. Never reuse an error as a successful negative. `skipped` must
explain a policy omission or missing capability. `interrupted` retains results
already computed, never infers negatives for remaining inputs.

## Policy and command behavior

`ScanPolicy` has `mode: inventory/git`, `block_severities: tuple`,
`required_formats: tuple[FormatId,...]`, `omissions: tuple[Omission,...]`, and
`report_schema: 1`. `Omission(id, selector, reason_code)` uses validated explicit
format/path selectors and fixed reason codes, never free-form public explanation.
The configured effective policy and omissions enter policy_id. Filesystem scope
exclusions do not automatically become Git exclusions. Rule-severity overrides are
operator policy, included in identity; plugin suggestions cannot change them.

Default Git coverage requires every selected text blob (UTF-8/UTF-16 BOM), detected
Office/PDF/MSG text surface, and explicitly configured required extractor format.
Missing optional dependencies for an encountered required format block Git. Known
document hints cannot fall back to an apparent clean text scan after parser error.
Unknown binary formats are a named default omission (`unsupported-binary`), shown
as allow-with-omissions if nothing else blocks. Operators may require all formats,
which makes such content incomplete. This is intentionally not a claim to inspect
every binary. A per-format explicit operator omission can relax a requirement;
it is recorded, fingerprinted, visible and never removes findings already obtained.
Empty valid plain text is complete; empty/no-text/encrypted documents are required
coverage failures unless explicitly omitted. A filesystem crawl exposes the same
issues even when it has no blocking findings.

Decision precedence: required incompleteness or unfinished enumeration => incomplete;
otherwise any policy-blocking finding => block; otherwise omissions =>
allow-with-omissions; otherwise allow. `counts` and findings remain visible under
all decisions. A completed enumeration with intentional exclusions is complete
only relative to the declared scope, not proof of excluded contents.

| Command | Exit semantics in 0.2.0 |
| --- | --- |
| `leakguard scan` / `audit` / one `drain` batch | 0: policy completed (findings are inventory by default); 1: `--fail-on block` requested and a blocking finding exists; 2: error, required incomplete scan, bounded unfinished work or invalid configuration |
| `leakguard hook pre-commit/pre-push` | 0: allow or allow-with-omissions; 1: blocking findings; 2: required incomplete/error; an existing chained hook's nonzero code is preserved |
| `leakguard-manage explain/report` | 0: successfully read/rendered a report even if it describes a block; 2: missing/invalid report or state failure |
| SDK conformance | 0: every selected check passed; 1: contract failure; 2: setup/capability failure; skipped optional capabilities are separately counted |

No `PASS`/“clean” heading on an incomplete or omitted report. JSON stdout is exactly
one schema object when `--format json` is used; human progress goes to stderr.
Version 0.1 callers relying on `scan` always returning zero get a migration note.
Existing command names and defaults remain; explain includes policy, identity,
provenance, result counts and completeness instead of dropping them in sanitization.

```python
from pathlib import Path
from leakguard_core.api import Scanner, ScanConfig, ScanPolicy, ScanLimits
from leakguard_core.models import FileInput

with Scanner.open(config=ScanConfig.from_mapping({}),
                  state_dir=Path('/private/synthetic-state')) as scanner:
    report = scanner.scan([FileInput(Path('/private/fixture.txt'))],
                          policy=ScanPolicy.inventory(),
                          limits=ScanLimits(deadline_seconds=30, max_files=100))
    print(report.to_json())  # redacted serialization; no source content
```

```sh
leakguard scan ./synthetic-corpus --format json --no-cache --fail-on block
leakguard audit synthetic --budget-seconds 120 --max-files 1000 --format json
leakguard-manage explain --repo ./disposable-repo --format json
leakguard-manage report general --state current --format json
leakguard-manage report general --state history --format json
```

These are implementation targets, not commands claimed available in 0.1.0.

## Internal ownership and migration of existing code

| Module | Responsibility and existing origin |
| --- | --- |
| `models.py`, `api.py` | Immutable public contracts and thin facade; facade delegates to the engine service, owns no detector logic |
| `engine.py` | Scan service orchestration, budgets, assembly and atomic outcome publication; migrate current scan_blob/scan_file into this service, retain temporary wrappers |
| `sources.py` | Bounded file/snapshot acquisition, provenance and source-context readers, from scan_file/git_findings |
| `git_scanning.py` | Index/push input enumeration and policy invocation from git_hook; hook chaining stays in hooks.py or a thin engine wrapper |
| `extraction.py`, `documents.py`, `extract_worker.py` | Core routing/limits/IPC versus maintained text/Office/PDF/MSG implementations; adapters use the public extraction types |
| `backends.py` | Gitleaks subprocess adapter from engine(), narrowed report validation; native Git backend optimization is optional |
| `plugins.py`, `plugin_worker.py` | Explicit registration, compatibility/identity manifests, detector/extractor protocols and supervised execution |
| `script_checks.py` | Maintained DetectorV2 adapter for explicitly configured external checks; reuses core supervision and validation |
| `finding_details.py` | Sole narrow metadata-proof authority; preserve duplicate-key/ambiguous-line checks and same-version readers |
| `scan_policy.py`, existing `policies.py` | Decision and coverage policy versus existing path/profile routing; no decision logic in renderers |
| `scan_store.py`, existing `catalog.py` | Injectable redacted scan/cache/evidence and catalog state, default SQLite; material resolution moves behind scan completion; actual-secret vault remains a separate application capability |
| `cli.py`, `manage.py`, `presentation.py` | CLI adapters, durable queries and safe renderers; existing scripts call these through compatibility wrappers |

Extract in dependency order, not all at once. `engine.scan_blob` can temporarily
return the old tuple and `scan_file` the old dictionary via a result adapter;
`unchanged` maps from reused only in that legacy adapter. Internal Git and new API
must use typed results. Legacy wrappers are deprecated in 0.2 and removed no
earlier than the next minor after documented migration. Keep `plugins.Finding`
unchanged for v1 source compatibility. Avoid wholesale classifier rewrites.

## Extraction routing, formats and safety

Core owns bounded signature sniffing and extension hints. Decode any non-document
candidate as strict UTF-8 (optional BOM) or strict BOM UTF-16, independent of suffix.
Recognize PDF magic, bounded ZIP/OOXML manifests and OLE MSG indicators; hints can
require an expected parser but never prove successful coverage. Conflicting format
evidence returns format-mismatch/ambiguous-format, not fallback success. For v1
custom extractors that intentionally override built-ins, require an explicit
migrated override mapping; default v2 extractors only claim declared formats.

| Format ID / maintained adapter | Text surface in this release | Dependency / required behavior |
| --- | --- | --- |
| `text` | strict UTF-8/BOM UTF-16, including unusual extensions and empty files | stdlib; decode errors are explicit; no replacement decoding |
| `office-word`, `office-sheet`, `office-slides` | supported XML text nodes in word/, worksheet/shared strings, slides and document properties, matching current supported families .docx/.xlsx/.xlsm/.pptx | stdlib ZIP/XML; validate package shape; bounded members, decompression and XML; drawings/images, embedded objects and macros are outside the declared text surface |
| `pdf-text` | extracted text per page, up to limit | documents extra/pypdf; encrypted, parser failure and pages without extractable text are visible required gaps under conservative Git policy; no OCR |
| `outlook-msg` | supported subject/body/header streams, separately numbered | documents extra/olefile; no attachment or recursive embedded message scan; malformed/encrypted or unsupported body encodings explicit |
| explicitly registered format | declared text parts through ExtractorV2 | reviewed optional package; same budgets and contract; required when configured |
| other binary / legacy Office / generic ZIP | no detector claim | explicit unsupported-format omission or required failure; no recursive extraction |

Coverage is for these declared text surfaces, never all information in a document.
MSG attachments, Office images/embedded objects and PDF images remain declared
format omissions. Record their policy-level omission IDs even if parser detection
of individual embedded objects is unavailable. Missing text on a document/page
cannot be treated as a successful empty plain-text file. Future adapters may
distinguish positively proven blank pages from unextractable pages.

Core `ScanLimits` defaults: max_file_bytes 20,971,520; max_parts 1,000;
max_text_bytes 12,000,000 across all UTF-8 parts; max_member_bytes 5,000,000;
max_archive_members 10,000; max_pages 300; extract_timeout_seconds 25;
detector_timeout_seconds 45; max_findings 100,000 per input and per report;
max_report_bytes 64,000,000; worker_memory_bytes 512 MiB; max_ipc_bytes 80,000,000.
The IPC allowance accounts for JSON escaping,
not extra extracted text. Aggregate scan deadline and max_files are mandatory
bounded settings; each subprocess gets the smaller remaining budget. Add bounded
directory-enumeration admission (default 10,000 entries per scheduling slice).
On report/finding admission exhaustion, retain a bounded positive subset with an
explicit detector-output-limit or budget-exhausted coverage issue and mark the
run incomplete; never silently truncate a report and declare success. CLI default
deadline_seconds/max_files remain 120/1,000 for scan and 600/3,000 for audit.

Core enforces byte/part/finding/IPC limits while streaming, before collecting
unbounded lists. Acceptance requires worker parser memory bounds to be exercised on Linux/macOS
with an OS mechanism, and on Windows with a Job Object mechanism. If a required hard
bound cannot be established, report resource-bound-unavailable; do not claim an
ordinary wall timeout is a memory cap. Treat platform implementation trouble as a
release limitation, not a reason to silently remove the bound. Kill/reap the owned
worker process group on deadline/cancel, drain/discard raw stderr, and sanitize
crash output. Disable core dumps for workers where supported. No source bytes or
raw parser/Gitleaks reports in durable receipts; ephemeral state is private.

Extracted text and parser IPC are sensitive transient data. They never enter the
report schema or logging. Plugins remain trusted code, even when a worker isolates
parser crashes. This architecture does not promise sandboxing arbitrary Python.

## Community extension contract

Keep v1 `API_VERSION = 1`, `create_plugin(options)` and
`detect(text, path, part) -> Iterable[Finding(rule,line,severity)]`. An adapter
validates exactly that type, rejects extra fields, bool/nonpositive/out-of-range
lines and severities other than block/review, and converts to the new records.
Legacy `extract` works through an adapter with core-generated report part IDs.
Legacy packages without a verifiable runtime manifest remain executable but
uncacheable. Execute configured module-backed plugins in supervised workers so
hangs fail boundedly. Parent-side in-memory instances used by old internal tests
are not a supported persistent deployment/containment mechanism.

Add API v2 for distinct detector-only or extractor-only packages. No entry-point
discovery, auto-download or scan of installed modules. Configuration selects exact
module and component IDs. The static module manifest is read/validated inside the
worker before untrusted input is passed to the extension:

```python
API_VERSION = 2
MANIFEST: PluginManifest
def create_plugin(options: Mapping[str, JsonValue]) -> DetectorV2 | ExtractorV2: ...

class DetectorV2(Protocol):
    def detect(self, text: str, context: DetectionContext) -> Iterable[Finding]: ...

class ExtractorV2(Protocol):
    def extract(self, data: bytes, context: ExtractionContext) -> Extraction: ...

# DetectionContext: logical_path, part_id, format_id; no policy mutation handles.
# ExtractionContext: logical_path, format_id, immutable ExtractionLimits.
# ExtractedPart: kind (declared static token), ordinal (positive int), text.
# Extraction: disposition (extracted/unsupported/encrypted/no-text),
#             parts (iterable of ExtractedPart), issues (fixed extraction codes).
```

`PluginManifest` fields: `id`, `implementation_version`, `api_major`,
`api_minor`, `requires_core` (minimum/maximum API minor, not Python import magic),
`kind: detector/extractor`, `rules: tuple[RuleSpec,...]`,
`formats: tuple[FormatId,...]`, `part_kinds: tuple[str,...]`,
`options_schema: OptionSchema`, `dependencies: tuple[DistributionSpec,...]`,
`deterministic: bool`, `external_state: none/declared/unknown`.
RuleSpec declares rule ID and minimum severity. OptionSchema supports a small
documented closed vocabulary (bool/int/string/enum/list with size/range limits);
core rejects unknown keys and does not echo option values. Do not implement an
open-ended JSON Schema interpreter in this increment. DistributionSpec names a
dependency; core resolves installed versions and artifact content identity.

API major must match; unknown required minor capability is rejected. Optional
unknown capabilities do not silently become coverage. Implementation_version is
descriptive and participates in identity but cannot alone authorize reuse.
Declared rules/part kinds prevent data-derived result labels in v2. V1's narrower
syntactic guarantee and trust limitations remain documented; malicious installed
Python can leak outside any return schema, so conformance is not a security seal.

Extractors cannot mark arbitrary unrelated formats supported, replace detectors,
return findings or provide metadata waivers. Core routes one declared extractor
per format; ambiguity is configuration-invalid unless an explicit override exists.
Unsupported from the selected required extractor is a coverage issue, not success.
Both Gitleaks and every enabled detector run independently on each extracted part.
The maintained adapters implement this same contract, with core-only routing and
resource supervision rather than copied boilerplate in every package.

Publish `leakguard_core.conformance` with programmatic
`check_detector(module, options, cases)` / `check_extractor(module, options, cases)`
returning redacted ConformanceReport and a `python -m leakguard_core.conformance`
CLI. Include runnable independently installable detector and extractor example
packages, each with tiny pyproject/README and synthetic fixtures. Keep the old
example_plugin.py as the v1 compatibility example. The harness ships in the wheel,
needs no private deployment and tests invalid output, line bounds, duplicate parts,
output/part limits, exceptions, hangs/crashes, severity downgrades and foreign-rule
waiver attempts. Use adversarial harness fixtures as well as author-provided cases;
never claim arbitrary plugin correctness from a few samples.

## Cache identity and proof validity

Always bound and read/hash file bytes before semantic reuse; stat values are
admission/change-detection hints, not a correctness cache key. Git uses immutable
blob OIDs plus SHA-256 content identity and snapshot context. Re-stat opened files
and relevant sibling dependencies before publishing results; changed observations
are incomplete. No claim of an atomic filesystem-wide snapshot.

Maintain separate IDs for policy, runtime and context. Policy covers normalized
effective rules/options, required surfaces, omissions, severity settings, limits,
schema and relevant path/profile policy. Runtime covers core package version AND
content digest of behavior-bearing core files/rules, Python implementation/version,
OS/architecture, Gitleaks binary digest/version, parser distributions and actual
installed artifact digests, enabled plugin manifests/code and their transitive
dependency closure. Built-in Gitleaks/rules/extractors are ordinary members of this
closure, not implicit constants. Include native libraries/external tools when used.

Compute closure once per opened scanner; pin it for a batch and reject/reopen on
observed modification. Normal wheel installs can use verified RECORD/file content;
do not trust stale RECORD hashes without verification. Editable/local modules
require an explicit complete hashed source/dependency manifest; otherwise disable
persistent reuse. External plugin state, undeclared dependencies, unknown dynamic
imports or nondeterministic behavior disable reuse. This is a practical trusted
extension contract, not proof against an author lying about dependencies. Include
policy-relevant environment; scrub or declare the remainder for worker execution.

Cache key: `(content identity, runtime_id, policy_id, source kind, logical path,
context_id)`. Paths matter to plugins and format selection. Context includes exact
referenced sibling bytes/OIDs, missing-source sentinels and classifier ABI. On
filesystem reuse, re-read those dependencies; a previous missing source appearing
invalidates reuse. On index scans, capture a tree/snapshot and read all proof
dependencies from it; verify index identity before allowing commit. On commit
scans, use that commit's tree, never working-tree content. Do not reuse a metadata
classification solely because the JSON file is unchanged.

Known-material detection is a core optional detector with per-part mapping. Its
identity includes registration and bounded reference-content changes (opaque keyed
identity, no raw reference values in manifests/reports). Missing reference sources
are explicit detector coverage gaps, not successful empty lists. The existing
30-second _VALUE_CACHE cannot authorize persistent reuse or resolution. A registered
material is not silently made a Git rule; Git's enabled-detector set is explicit.

Replay preserves all findings/classifications and provenance, returns outcome
reused, advances last_verified_at only after content/context checks, preserves
last_executed_at, and references the original complete scan. Reuse in a different
commit/path requires fresh provenance and proof evaluation; the minimum version
may simply rescan rather than implement multi-level cache complexity. `--no-cache`
bypasses semantic read reuse and is the final correctness reference path.

## Persistence and finding lifecycle

Introduce SQLite user_version 2 (old databases have 0/no migration version), with
transactional, idempotent migration under a short write lock. WAL/busy timeout
remain. Refuse a newer unknown schema without writes. Back up existing state to
an explicitly owned private sibling before migration; never modify old JSON
reports. Concurrent startup sees either old or completed new schema, never half.

Add these tables alongside the existing catalog/location/review tables:

- `scan_runs`: run ID, schema/policy/runtime identity, timestamps, coverage/decision.
- `input_scans`: scan ID/run ID, source/version/content/context identity, disposition,
  redacted complete result payload, observation/execution/verification times.
- `scan_findings`: scan ID/finding ID, redacted typed fields; index source/rule/state.
- `current_inputs`: host/scope/path key, generation, last complete scan ID, latest
  attempt ID, current_state and state reason. Git commit evidence stays historical;
  an index result is an index snapshot, not a working-tree inventory update.
- `finding_state`: current input key/evidence ID, active/resolved/unknown,
  first_seen, last_seen, last_verified, resolved_at and fixed transition reason.
- `scan_cache`: identity key to complete input_scan; no cached transient errors.
- `audit_work`/`audit_cycles`: generation, bounded work items, lease owner/expiry,
  attempts, enumeration/scan failures and completion marker.

No raw values, snippets, extracted text, exception text or raw plugin dictionaries
in these tables. Keep whole-content hashes for identity; no new value fingerprints
in public findings. Existing keyed material fingerprints remain private catalog
metadata. Scan outside the write transaction; atomically commit observation,
evidence, cache and lifecycle only after validation. Fence updates by input/cycle
generation so an older worker cannot overwrite a newer observation.

| Event | Current-state transition |
| --- | --- |
| Complete fresh or verified reused scan, comparable policy | Matching findings active; absent prior findings resolved for this exact input/detector scope; observation history retained |
| Changed file, unreadable source, skip, timeout, unsupported required part, cancelled scan | Prior evidence becomes unknown, never resolved; new positive partial evidence remains recorded with incomplete coverage |
| Policy/runtime upgrade | Old evidence unknown until comparable coverage; a removed/disabled rule is policy-obsolete/unknown, not proof of remediation; rescan enabled detector scope |
| Dependency-only context change | Reclassify/rescan before reuse; old metadata proof cannot authorize Git |
| Deleted/renamed notification | Mark location absent/unverified as appropriate and finding state unknown; notification alone is not remediation proof; new path gets its own input identity |
| Bounded explicit absence check or successful full reconciliation | May resolve old-path evidence with `source-absent` reason, distinct from a successful clean content scan; rename does not erase history |
| Root offline, lost events, partial enumeration, failed audit | No bulk resolution; current assurance for affected scope becomes unknown; pending/failed work persists |

Unknown means “last observed evidence, current presence not established,” not a
negative. Even active evidence is explicitly “as of last_verified_at”; watcher
delivery cannot guarantee real-time state. Human review disposition is separate
from scanner lifecycle and cannot suppress Git blocking.

Migration imports old `findings` as historical/unknown, never active or resolved;
invalidate old `cache`. Preserve catalog and review data. Retain legacy JSON access
through `explain --report` with schema-0 adapter and `coverage unknown`; don't
perform an unbounded implicit archive import. An explicit bounded import tool for
additional old report metadata is stretch work. New `report --state current/history`
queries indexed tables; default report is current with active+unknown and timestamps.
Index latest Git report by repository/run instead of reparsing an unbounded archive.

Audit enumeration must check deadline within iteration. Partial directories remain
pending; bounded re-enumeration with dedup is acceptable initially and must declare
that a perpetually changing/huge directory may not complete. Never retain an open
directory iterator across process restarts. Complete-cycle requires successfully
exhausted enumeration, no pending/leased work and no unresolved failures. Retry
failed items with bounded attempts; exhausted items remain failed coverage, not
silently removed. Serialize audit/drain mutations per scope initially or use leases
with generation fencing; full multi-host queue scheduling is outside this release.

## Git enforcement

Fix chmod idempotently, preserving existing permission bits and adding executable
bits on POSIX. Verify actual Git invocation for both new and upgraded managed
hooks, worktrees, custom hooksPath and chained hooks. Preserve pre-push stdin and
arguments exactly; do not alter global Git configuration during tests.

Prefer one input-based pipeline: enumerate index blobs or outgoing commit blobs,
then call the same scan service used for files. Retain the Gitleaks subprocess
backend; replace native `gitleaks git` orchestration only after differential tests
cover existing history/rules behavior. If native Git mode is temporarily retained,
normalize its output into the same report and merge conservatively with per-blob
coverage; no independent “passed” path may bypass policy. Disable inline/source
allow directives for required scans where they could waive detection without
declared policy, and test any existing rule allowlists explicitly.

For push, validate every stdin record; malformed input is git-input-invalid. Use
the advertised remote OID as a boundary only when locally available and ancestry
is established. Otherwise conservatively traverse all reachable local-tip commits
(bounded, with explicit failure on limits); local remote-tracking refs alone do
not prove server coverage. Deletion-only ref updates need no new content scan.
For each commit include paths changed relative to any parent, root trees, and merge
results; source proof always comes from that commit. Missing history/shallow gaps
are git-range-incomplete. Keep current 1,000-commit/100-document-blob bounds as
explicit fingerprinted limits until measurement justifies adjustments.

Blob reuse cannot drop commit/path/part provenance. A detector context depending
on path or sibling source invalidates naive OID-only reuse. Synthetic tests must
include the same blob at two paths/commits with different source proof, a secret
introduced then removed, merge-only content and a new branch with no remote base.
No filesystem companion configuration can turn a Git finding into inventory-only.

## Optimization and ranked backlog

First fix existing document batching by scanning each part independently. Splitting
after detection cannot repair a manufactured cross-boundary match or altered regex
context. Only reintroduce batching with a backend supporting independent records or
demonstrated full equivalence to independent scanning; a newline delimiter alone
is insufficient. Gitleaks directory mode may be evaluated using private synthetic
part files, complete path/range mapping and the uncached reference path. No raw
part files survive the run.

Ranked after correctness: (1) safe immutable-blob/detection reuse with fresh proof,
(2) bounded per-file Gitleaks batching or persistent backend if supported,
(3) query/transaction tuning measured with many historical runs, (4) packaging
standard adapters into independently versioned packages only if maintenance needs
justify it, (5) additional text encodings/RTF/HTML mail adapters with explicit
semantics, (6) optional alternative detector backend via the same conformance
contract. OCR, recursive archives, executable analysis, fleet services and a source
plugin SDK are outside this eight-hour scope.

No speedup is accepted with a coverage/redaction/provenance regression. Compare
clean and positive corpus sizes 1/10/50/200, cold, correctly replayed warm and
uncached runs; record files/s, bytes/s, median/p95 hook latency, peak process-tree
RSS, subprocess count, SQLite writes/lock time and exact runtime identity. Warm
runs still read/hash bytes; compare on equivalent correctness, not the broken
stat-only hit. Label synthetic precision/recall by rule/case category and report
coverage failures separately; do not infer real-world rates.


## Implementation checkpoint (2026-10-25)

The 0.2 candidate uses one per-part service for filesystem, caller bytes, immutable
Git inputs, audit/drain and deprecated result adapters. There is no accepted
batching optimization. Unknown extension closure disables reuse; available module,
script, backend and dependency artifact bytes still participate in runtime identity.

`ScanStore.query_findings_page` provides bounded indexed pages; the compatibility
`query_findings` wrapper returns only its first bounded page. The separate findings
query envelope is schema 2 with `page_count`, `has_more` and `next_cursor`; the scan
report remains schema 1. Catalog/material/work state stays behind the injected
store. No encrypted credential vault is implemented or implied by this seam.

The Windows Job Object candidate starts workers suspended, assigns memory and
kill-on-close ownership, then resumes the owned thread. Assignment failure is
`resource-bound-unavailable`. Native Windows and macOS execution must have their
own receipts before either platform is marked accepted. Linux checks do not stand
in for them. The Go backend has output/time bounds and a managed heap target; the
parser's address-space hard limit cannot be applied to Go's virtual arena. This
limitation remains explicit in validation rather than being reported as a hard
backend memory cap.
