# UI / engine handoff contract

Additive optional projection, agreed before implementation. Existing `/status`,
`/jobs`, `/sources`, `/findings` and settings APIs retain their authentication and
semantics. Existing observation/credential lock fields remain authoritative.

The intended new shape is `status.host.inspection_evidence`, with `schema_version:1`.
Engine lead may refine the exact field names once, before UI depends on them; send
that commit to UI and update this contract and its shared fixture together.

```json
{
  "schema_version": 1,
  "measured_at": null,
  "observation_started_at": null,
  "last_complete_inspection_at": null,
  "pending": {
    "with_known_age": 0,
    "with_unknown_age": 0,
    "oldest_observed_pending_at": null,
    "age_buckets": {"under_5m": 0, "5m_to_1h": 0, "over_1h": 0}
  },
  "completed": {
    "observed_change": 0,
    "ordinary": 0,
    "reserved_oldest": 0,
    "oldest_observed_wait_seconds": null
  },
  "diagnostics": []
}
```

This example is a schema sketch, **not a fallback object to fabricate in the UI**.
Omit the whole projection if not implemented/available. `measured_at:null` means
unavailable, not “just measured zero”. Counts apply only to the explicit observation
window; partial/unknown timestamps never imply historical completeness. If counts
cannot be computed soundly within bounded work, leave that optional metric out and
document it rather than introduce an expensive whole-store status query.

Times are UTC Unix seconds or null. Durations are nonnegative seconds or null.
Historical rows without enqueue observation increment unknown age; they must not
receive a migration-time “first pending” date. New content versions and source
generation changes have explicit chronology rules, tested across encrypted replay.
Existing `machine_inventory` is still the inventory count projection; do not sum
incompatible windows into a new total or confuse inspected-with-omissions with
fully completed inspection.

A diagnostic contains bounded approved `code`, `stage`, safe `exception_type`,
`at`, nonnegative `retry_count`, optional opaque source/job ID and recovered flag.
Never arbitrary exception text, tracebacks, locals, private paths or content.
Stage vocabulary: enumerate/acquire/parse/recognize/publish/shutdown/unknown.
Do not guess a stage from unrelated errors. Keep a small bounded retention list.

`/jobs` can carry a corresponding optional per-job evidence object when measured.
The UI must not reconstruct fake live progress from a fixed stage timer. Existing
last-successful-reconciliation timestamps must not be relabelled as last content
inspection. For source-level timing, only use a source-scoped complete result.

Profile preview: use the shared resolver and actual current values for a safe
field-by-field comparison. If the engine adds an explicit `changes` projection,
keep field, prior/effective value, and provenance, with only non-secret settings.
Do not interpret a locally edited JSON document as successfully applied.

Before UI consumes the additions, engine supplies one synthetic available fixture,
one historical/unknown-age fixture and one locked/unavailable case. UI supplies
render checks for those exact cases. These fixtures are test-only and never used
as production fallback responses.


## Implemented safe profile comparison

Profile preview includes changes, a list of {field, prior, effective, provenance}
for changed inspection.mode, inspection.recognizers, inspection.max_file_bytes,
inspection.scan_workers and jobs.reconcile fields. Unsupported jobs remain the
fixed existing polling/off modes. Values come from the resolver's actual current
config/protection input. Plugin option values, paths and aliases are excluded.
An empty list means the compared safe fields are unchanged; it does not waive
runtime preflight or prove arbitrary plugin options unchanged.


## Implemented chronology projection

The test-only fixtures are in fixtures/inspection-evidence.json (available,
historical unknown-age, and locked with the projection omitted). They are captured
from the production encrypted store projection with synthetic inputs.

The projection is a last-encrypted-checkpoint catalog summary. Polling opens no
inventory partitions and runs no inventory SQL. Mutation-time aggregation adds
bounded metadata to each of the at most 256 inventory catalog entries.
Counts cover the observed window; completion counters require an actual fully
inspected result and exclude inspected-with-omissions and terminal gaps.
Repeated unchanged inspected transitions do not count twice. Reserved-oldest
counts identify the actual reserved selection subset that completed, not all
work in that scheduling slice.

Age buckets are omitted, with age_buckets_available:false. Recomputing live
buckets soundly is not part of this bounded projection. Oldest-observed-pending
timestamps still let a client display elapsed observed age. measured_at is the
latest mutation checkpoint summary time; unchanged partition summaries remain
valid for pending counts/timestamps. This is not a historical full-scope census.

Diagnostics retain at most eight events per bounded job and sixteen in the status
projection. exception_type:null means a supervised component reported a safe code
without exposing its underlying exception. Recovery is conservative: the finite
source must complete without terminal inspection gaps; successful unrelated work
does not erase or recover an earlier failure. Source/job IDs are opaque.


A replacement source ID cannot inherit an inspected classification from another
source, even if the metadata signature matches. Regular and saved content
admission both fence the job's inventory generation. A same-source recurring
reconciliation may retain the already inspected exact metadata/content version;
that optimization does not increment a completion counter or supply a fresh
inspection timestamp in the new generation.
