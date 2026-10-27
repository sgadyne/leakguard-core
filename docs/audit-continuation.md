# Audit continuation identities

`Scanner.work_identity(policy=..., limits=...)` returns `policy_id` and
`runtime_id` for a prepared scanner. Hosts may compare this descriptor before
resuming a persisted job. Its policy digest excludes slice duration, file and
directory admission counts, report size, finding count and scan worker count.
Acquisition, extraction and detector limits still participate. A report's own
`policy_id` continues to describe its complete selected limits.

For inventory scans, the continuation policy digest also includes the keyed
identity of registered material references: their registrations and current
bounded source contents. The snapshot admits at most 100 registrations and
1 MiB aggregate source bytes, further limited by `max_file_bytes`. Unreadable,
invalid or changed snapshots fail the identity query with a fixed acquisition
error. Reference values and registration names are absent from the descriptor.
The separate credential vault is never consulted.

The audit queue uses the same service helper as the public identity query. It
captures one reference snapshot for both binding and executing a slice, then
revalidates it before accepting results and after final enumeration. A reference
change between slices resets the cycle conservatively, marks prior positive
observations unknown and requeues the root. A reference failure or change during
a slice leaves coverage incomplete, including a slice with no file results.
The store's persistent material key makes this identity stable across process
restarts. This adds no report schema, storage schema or runtime provenance change.

Report results, finding counts and `coverage.omission_count` describe the current
slice. A completed audit's verdict uses accepted evidence from its exact cycle:
earlier blocking findings retain `BLOCK`, and earlier file omissions or operator
exclusions retain `ALLOW_WITH_OMISSIONS`. Exclusions use durable omitted queue
markers and never authorize reading an excluded path. `audit-cycle-evidence`
explains when the completed decision includes aggregate evidence; the text
renderer labels counts as belonging to this slice. CLI `--fail-on block` exits
1 for a completed blocking cycle even when this slice has zero blocking findings;
incomplete coverage continues to exit 2.

Reconciliation orders reservations and cycle starts even when the operating
system clock returns the same timestamp for both. Memory stores advance a local
microsecond counter; SQLite stores use one `ordering_clock` row inside the
existing write transaction, shared by connections and retained on reopening.
This metadata table is created alongside existing state without rewriting prior
evidence or changing the public report schema. The ordering timestamps are
fences, not measurements of elapsed time. A newer reservation cannot be marked
unknown by an older cycle merely because their wall clock readings tie.
