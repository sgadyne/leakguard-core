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
