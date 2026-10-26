# Navigation and private memory cache

This development branch extends checkpoint `69bc6214` without changing installed
profiles, scanner rules, plugin manifests or credential handling. It is not a new
desktop release. Native Windows acceptance has not been performed.

## One navigation interface

Filesystem scans, audits and resumed directory slices enter
`sources.scoped_scandir()` and use the service's `Navigation` instance. The default
backend remains Python and requires no Rust toolchain. An explicitly selected
Rust helper uses the pinned `ignore` crate's parallel walker (at most two threads)
behind the same API. Missing, failed or malformed requested helpers produce an
error/incomplete coverage; they never silently switch backend.

Hidden and Git-ignored files remain visible. Ambient Git/global/`.ignore` filters
are disabled. Existing explicit `exclude_roots` and `exclude_components` policy
still applies in the engine and records omissions. Descendant links are not
followed. Hardlinked paths remain separate coverage locations; repeated detector
work may be reused by content. The existing scan-store directory graph, source
anchors, prefix cursors, leases and final validation remain authoritative.

`navigation_same_filesystem` defaults to `false` to preserve existing explicit
scope behavior. Set it to `true` to reject cross-device entries with incomplete
coverage. Network/removable roots are a scope-selection decision; this option
does not classify mount ownership or turn remote shares into local identities.
There is no new whole-machine or cross-share coverage database.

Each directory listing is sorted by filesystem name bytes and bounded to 100,000
entries. The POSIX helper receives the already-open directory FD through a private
socket, walks its inode-bound working directory, checks identity before/after,
and emits a versioned JSONL stream. A 128-row channel and socket backpressure bound
queued output. Deadlines, cancellation, early iterator close and protocol failure
are handled before another request. Service close reaps its owned helper.

Build on a developer POSIX machine with Cargo, then distribute the resulting
platform-specific executable separately with its hash:

```sh
python tools/build_navigation_helper.py --output /absolute/artifacts/leakguard-scan-walk
```

Select it in a supported config (alongside your existing backend/settings):

```json
{
  "navigation_helper": "/absolute/artifacts/leakguard-scan-walk",
  "navigation_same_filesystem": true
}
```

The inherited-FD native bridge is currently POSIX-only. Windows uses the Python
backend when no helper is configured; explicitly requesting the unsupported
native bridge fails. No customer compiler, native wheel or automatic download
is required. Installer artifacts have not yet been rebuilt with a native helper.
CLI `doctor --format json` and SDK `Scanner.capabilities()` report the selection.

## Bounded cache

`cachetools==7.2.5` provides LRU bookkeeping. Our wrapper owns the lock, opaque
per-service/profile scopes, single-flight coordination and invalidation. The
process shares an 8 MiB estimated byte budget and a 2,048-entry limit. Weight
includes keys, immutable values and conservative per-entry bookkeeping; it is
not a hard process RSS limit. There is no TTL or external cache service.

Only successful validated Gitleaks observations are retained: rule ID, first/last
line and severity. Source bytes, extracted text, secret values, plugin results,
proof context and final finding objects are never cache values. Keys contain
digests and opaque owner IDs, not source paths or contents. The native component
key binds actual UTF-8 part bytes/size, runtime and policy identities, worker
policy, finding limit and the verified binary/rule closure. Cache-enabled native
execution uses a bounded private executable snapshot and staged rules, so its
bytes cannot be replaced through the configured executable path after hashing.
External/unverifiable rule inheritance disables this component cache.

Native observations may be reused even with a plugin enabled: extraction,
plugin execution, path-dependent classification and final findings are still
computed for every source. Whole-file/durable semantic reuse remains disabled
for plugins until their dependency closure can be verified. `use_cache=False`
(CLI `--no-cache`) bypasses both reuse paths.

Single-flight waiting occurs only within one invocation's cancellation/deadline
domain. A cancelled waiter cannot cancel another producer. Errors are not
retained; close/reset fences late writes. `Scanner.clear_memory_cache()` clears
that scanner's scope. Closing the scanner removes its observations and helper.
`Scanner.capabilities()` exposes aggregate counters/budgets, never keys or rows.
This cache is process memory: it cannot speed up a new CLI process by itself.

An acquired immutable source snapshot now computes its SHA-256 once. One final
source/context validation remains immediately before result publication;
duplicate earlier full-file revalidation was removed. Content changes with
unchanged size/mtime still revoke complete coverage and retain accepted positives.

## Measurement and remaining work

`tools/benchmark_memory_cache.py` runs an invented, labeled corpus with a fixed
manifest and redacted result signature. Use the same interpreter, backend and
arguments against checkpoint and candidate trees. It separately measures repeated
identity access and reports self/largest-child peak RSS (not a simultaneous
process-tree sum). Duplicate-content measurements must not be extrapolated to
unrelated files. Traversal performance needs separate measurement; native
integration alone does not establish a speedup.

The immutable installed alpha5 broad scan is a separate baseline. Its incomplete
PDF/encoding/changed-input coverage, unreviewed findings and plugin startup costs
remain visible. The manifest `formats`/`part_kinds` dispatch ambiguity, plugin
dependency closure, worker reuse, parser expansion and heuristic false-positive
noise are not changed here. No accuracy claims are inferred from cache parity.
