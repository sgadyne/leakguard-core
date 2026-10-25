# Compatibility and migration

LeakGuard 0.2 introduces one typed scan report for Python callers, the CLI and
Git adapters. The report schema version is `1`; it is independent of the package
version and plugin API major. Reports contain source locations, rule identifiers,
severity and evidence classifications. They never include matched values or
source snippets.

## Python callers

New integrations should use `leakguard_core.api.Scanner` and the immutable types
from `leakguard_core.models`:

```python
from pathlib import Path

from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.models import FileInput, ScanLimits, ScanPolicy

config = ScanConfig.from_mapping({})
with Scanner.open(config=config, state_dir=Path("/private/leakguard-state")) as scanner:
    report = scanner.scan(
        [FileInput(Path("./sample.txt"))],
        policy=ScanPolicy.inventory(),
        limits=ScanLimits(deadline_seconds=30, max_files=100),
    )
    print(report.to_json())
```

`ScanConfig.from_mapping()` validates and copies an explicit mapping. Use
`ScanConfig.from_file(path)` only when the caller intentionally selects a config
file. Importing `leakguard_core.api` or `leakguard_core.models` does not read
environment configuration, create state, load extensions or start a process.
Without `state_dir` or an injected store, the API uses private temporary work and
does not persist a catalog or semantic cache. `Scanner.scan()` accepts one
`FileInput` per file or bounded `BytesInput`; `Scanner.scan_paths()` delegates
directory expansion and enumeration coverage to the shared service.
Public source paths, repository identities and `BytesInput.logical_path` values
are limited to 4,096 Unicode code points and reject NUL. Valid POSIX
surrogateescaped path characters remain accepted and are escaped safely in
JSON. This matches the public report metadata bound.
Audit directory enumeration is bounded per step. An unusually large or
continuously changing directory may remain pending indefinitely, in which case
the audit cycle remains incomplete and does not establish a complete inventory.

An injected store is trusted application code. A conforming full store implements
`set_deadline(deadline)` with an absolute `time.monotonic()` deadline and clears
it with `None`; the service propagates budgets when this capability is available
but cannot preempt a custom store that ignores them. SQLite bounds busy waits and
SQL execution, while the in-memory store tracks deadlines per calling thread.
Store implementations must also accept `record_report(report, repository=...)`
and preserve the explicit repository identity, including for empty Git reports
with no result sources.

The complete `ScanStore` protocol includes bounded current/history page queries,
material snapshots, lifecycle methods and optional work-queue capabilities. A
store used for `audit()` or `drain()` must implement the queue and event methods:
`acquire_cycle`, `lease_valid`, `enqueue_work`, `claim_work`,
`finish_directory(claim, *, success, signature=None, omitted=False)`,
`directory_page(lease, *, limit=256)`, `record_directory_checks(lease, checks)`,
`cycle_status`, `release_cycle`, `invalidate_scope` and `record_event`. A
`DirectorySnapshot` contains a path and either no signature or the bounded
filesystem signature `(device, inode, mode, mtime_ns, ctime_ns)`. Directory pages
are limited to 1,000 rows; directory-check batches are also bounded. Completed
directories that have not passed the post-scan signature check remain pending.
Changed or unavailable signatures requeue the directory and refresh its direct
file entries; newly queued/enumerated work revokes earlier checks. The service
does not claim an atomic filesystem snapshot: traversal is sequential, and
changes after final validation or changes hidden by coarse filesystem metadata
remain possible until a later audit. A rooted audit also requires
`reconcile_cycle(lease, root)`. If a required method is missing or fails, that
batch is incomplete; it cannot publish a complete cycle. `record_metadata` is an
optional bounded hint used when importing change events. Delete and rename events
make prior observations unknown; they do not prove absence.

The filesystem-anchor extension is a paired optional capability. Such a store
must accept `anchor=None` on `record_result(...)` and implement
`source_anchor(source)` and `confirm_absent(proof, *, generation)`. It retains
only the verified directory identity anchor needed by the core's internal
absence proof, and accepts a proof only when the input generation and stored
anchor still match. The public `Scanner` facade and CLI do not expose an absence
confirmation action. A successful `reconcile_cycle` marks unobserved prior paths
unknown; it does not resolve them. Stores that omit the anchor capability keep
the same conservative behavior.

Inventory scans call `material_snapshot(max_bytes=1_000_000,
max_sources=100)`, including when the store has no registered references; a store
with no materials should return an empty valid snapshot. A missing or failed
snapshot makes required inventory coverage incomplete. The corresponding
`record_result(...)` call accepts the bounded material observations and completion
flags, keeping reference locations and match state behind the injected store. The
scan service does not create a second durable mirror for a custom store.

#### Gitleaks rule configuration

Gitleaks runs from a private temporary working directory so a caller's
`.gitleaksignore` cannot suppress a required scan. The backend reads the
explicit top-level TOML file and follows at most two `[extend].path` inheritance
edges. Each top-level or inherited config file must be a regular file no larger
than 1 MB. The admitted top-level bytes are staged as private `rules.toml`.
Relative inherited paths keep Gitleaks' caller-working-directory meaning and are
staged under the private working directory with their reference paths preserved;
the scanned source content remains on stdin and is never copied into staging.
Absolute inherited paths remain external references: their bytes participate in
the observed runtime identity, but the worker follows the configured original
path rather than a private copy, so concurrent changes to those files are not
isolated by staging. Path/URL, relative, and unknown inheritance disables
persistent cache reuse.
An explicit config path may be a symlink to a regular file; symlink loops fail
with the same fixed `configuration-invalid` error as other malformed paths.
Relative references with more than 32 `..` components, unavailable files,
non-files, malformed TOML, and staging-name collisions fail with the fixed
`configuration-invalid` error. In particular, a reference that aliases the
private `.gitleaksignore` staging name fails closed. Local inherited file bytes
contribute to the runtime identity. Incomplete or unknown closures are not
eligible for persistent cache reuse, even when the local bytes that were
available could be hashed.

The temporary `engine.scan_file()` and `engine.scan_blob()` compatibility wrappers
remain for existing internal callers. Their legacy return shapes are not the new
contract. Legacy cache status `unchanged` maps to the typed `reused` outcome only
inside that adapter. New code should read `ScanResult.outcome`, preserve its
finding tuple on reuse and inspect coverage before drawing conclusions.

`plugins.Finding`, `API_VERSION = 1`, `create_plugin(options)` and the v1 detector
signature remain supported. V1 plugins without a complete declared runtime
closure can execute but cannot authorize semantic cache reuse. See
[PLUGIN_API.md](PLUGIN_API.md) for the distinct v2 detector and extractor API.

## Legacy inventory severity setting

`review_only_rules` is retained for compatibility as an inventory presentation
setting for built-in Gitleaks findings. It may display those findings at
`review` severity during inventory scans. It does not weaken a plugin's
declared minimum severity, and it never changes Git-mode findings. The
`detector_severity` field preserves the detector's native `block` or `review`
result; final `severity` may be `review` for inventory presentation or `info`
when a verified metadata classification applies. Git mode ignores the inventory
review override, while verified core metadata classifications still apply.
Older releases applied this setting too broadly, including to Git scans; that
behavior was a bug. Configurations that relied on Git findings being downgraded
must no longer expect that behavior. Keep inventory-only review choices
separate from Git protection.

## CLI behavior

For `leakguard scan` and one audit/drain batch, a completed inventory returns 0
even when it reports findings. Add `--fail-on block` to return 1 for a blocking
finding. Required coverage failures, errors, invalid configuration or bounded
unfinished work return 2. JSON mode writes exactly one report object to stdout;
human progress and sanitized setup errors go to stderr.
CLI bounds can be set with `--budget-seconds` and `--max-files`; validated
configuration supplies the maximum input size and per-detector timeout. Python
callers choose those values explicitly through `ScanLimits`. The strict report
byte cap defaults to 64 MB and must be at least 2,048 bytes for the bounded
diagnostic envelope.

Git hooks use the same report schema and policy decision. Allow or allow-with-
omissions returns 0, a blocking finding returns 1, and required incomplete work
returns 2. A chained hook's nonzero status remains authoritative. `manage explain`
renders the indexed latest typed report for the selected/current repository;
`manage explain --report PATH` explicitly reads a bounded schema-0 archive or
schema-1 report file. Explicit report input is capped at 64 MB; duplicate JSON
keys, malformed schema-1 payloads and unsupported schema versions fail with a
fixed redacted error.

Managed hook launchers use isolated Python startup and pin the trusted core
installation before importing the hook entry point. Built-in parser and
configured extension workers likewise pin core imports, so the input
repository's working directory or a later `PYTHONPATH` cannot replace LeakGuard
inside those workers. At hook installation, LeakGuard captures a bounded set of
absolute Python search paths for explicitly configured extensions, excluding
the target repository and installer working directory. Reinstall managed hooks
after upgrading LeakGuard to refresh an existing launcher; the installer keeps
the normal hook backup and chaining behavior.

This worker and launcher isolation does not sandbox Python API callers or
ordinary `leakguard` and `leakguard-manage` console entry points; those use the
selected interpreter environment. Configured plugins remain explicitly chosen
trusted code and retain the scanner account's permissions. Pinning a worker's
core import does not make extension code safe or remove its trust.

`manage report PROFILE` defaults to indexed current active and unknown findings,
with `--state history` for prior observations. Both current/history views include
timestamps. The indexed query is bounded and paginated: `--limit` accepts 1 to
10,000 and defaults to 1,000; pass a returned `next_cursor` with `--cursor` to
continue. JSON uses the closed redacted `findings-page` envelope with
`schema_version: 2`, `page_count`, `has_more`, `next_cursor` and `findings`. This
envelope version is independent of ScanReport schema version 1. It reports the
page size, not a total count. The store preserves cursor order; pagination does
not promise a snapshot while concurrent scans change the indexed observations.
Successful reads return 0 even when reports contain blocking findings; read or
state failures return 2. The query path opens the store without initializing
detectors. `--legacy-archive` retains the older archive reader and does not accept
page cursors. The legacy view is explicitly coverage-unknown, bounded to 1,000
directory entries, 4 MB per file and 64 MB total, and exposes only allowlisted
path, line, rule, severity-derived labels and timestamps. It omits legacy
material names and free-form review text.
Current findings describe the latest observed state, not confirmed filesystem
absence. An observed delete or rename makes prior evidence unknown rather than
resolving it; notifications can be lost. A bounded internal service check may
resolve old-path evidence as `source-absent` only after validating its directory
identity chain; this reason differs from a successful clean content scan. The
CLI and public `Scanner` facade do not expose that confirmation action. Partial
or failed audits do not establish absence.

This differs from 0.1 callers that treated a zero scan exit as evidence of a clean
scan. A zero means the requested inventory completed under its declared policy;
review the report's decision and coverage. An incomplete or omitted report is
never described as clean.

## Password Buddy boundary

The 0.2 engine release provides redacted observations and an injectable
`ScanStore` seam. It does not implement a credential vault or accept actual
secret values in scan reports, plugins, normal logs or JSON exports. Password
Buddy's separate milestone will provide an encrypted observation store and a
distinct user-approved credential vault flow with source revalidation. Saving a
credential will not resolve or alter the source finding.
