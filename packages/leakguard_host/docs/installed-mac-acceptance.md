# Installed Mac host acceptance recipe

This is a qualification procedure, not a passed benchmark. Use the exact final
signed/unsigned-as-applicable installed app, packaged backend and clean private
beta profile selected by the lead; record the app artifact hash, source commit,
Mac model/OS, packaged Python and plugin/config/resource identities, worker policy,
worker count, and `slice_seconds`/`slice_max_files` returned by the running app.
The configuration must activate the composed credential, Presidio and JOSE
plugins. Do not use a source checkout, CLI timing, or a mocked scanner as the
host receipt.

The initial real-source permission is limited to the previously approved
38-file manifest. A directory root can contain other files: do not register a
parent directory unless its exact contents and exclusions have been reviewed to
ensure that no unapproved files can be read. If the installed source UI cannot
represent that manifest safely, mark the real-source test blocked and ask the
lead for a reviewed representation; do not broaden the root. Use a separate
private synthetic fixture for mutation and interruption tests. Do not print
file names, paths, matches, values, passphrases or raw findings in shared
receipts; protect local evidence and delete temporary fixtures after testing.

1. Launch the installed app with the test profile and create/unlock its encrypted
   observation store through the protected UI. Record observation store size and
   capacity, chosen approved roots and exclusions in private local evidence.
   Select a 300-second schedule and trigger an immediate scan through Sources.
   Record monotonic elapsed time from submission to durable `completed`, all
   pending counts, scanned/reused counts, omission count, failure code and
   last-completed time. A partial, backoff, paused or missing result is failure.
   Repeat at least three cycles with the exact composed plugins. Watch actual
   app/backend and scanner descendants during the entire cycle and record peak
   aggregate RSS, sampling interval and method. Track host CPU and device load;
   report these observations without claiming a hard peak if only sampled.
2. Candidate acceptance requires every full cycle to finish in one invocation,
   with zero unexplained omissions and no required incomplete result, in at most
   30 seconds against the 60-second limit, including host checkpoint overhead.
   Record the actual file/byte counts and differences from the approved manifest.
   If the bound fails, split into smaller approved roots, remeasure all of them,
   and verify the combined scheduled work has sufficient capacity for freshness.
   If representation or split cannot be made safe, the gate is blocked. A single
   passing source is not evidence that other sources meet the bound.
3. Leave scheduling enabled and observe at least two periodic cycles. Verify the
   oldest cycle's age is below the candidate 600-second target throughout, and
   the 480-second warning occurs before target breach when a controlled delay is
   introduced. This is a target only until demonstrated under representative
   system load, sleep and wake. Pause an in-flight job, restart, unlock scan
   storage if necessary and confirm the interrupted job remains visibly paused
   until explicit resume. Test actual sleep/wake: enabled scheduled sources are
   reconciled by the desktop wake bridge; paused jobs remain paused. Locked,
   offline, failed and stale states must be visible and alert as applicable.
4. In the owned synthetic fixture, create, edit, rename and delete files; repeat
   with an unreadable file, unavailable root, concurrent mutation and interrupted
   scan. Verify affected existing positives remain active or unknown until a
   complete, comparable scan proves absence. Missing/offline or incomplete work
   must never resolve an exposure. Confirm a changed/new fixture observation
   alerts once; repeated scans of the same active finding do not. Verify alert
   baseline on app restart and locked observation state. Never infer provider
   revocation from source cleanup or a vault link.
5. Record encrypted serialized bytes before and after repeated cycles, including
   finding-heavy cycles. History is not automatically pruned. Reject the planned
   scope if the observed growth extrapolated over the intended soak plus a safety
   margin reaches the 75% capacity warning; alert and stop on checkpoint/capacity
   failure rather than claiming monitoring continues. The default limit is 64 MiB.
   Exercise a synthetic near-capacity profile separately; preserve the last
   durable checkpoint and confirm its visible failure. Record the checks and
   omissions, profile/config identity, elapsed times, resource measurements,
   source and OS wake events, final scan ages and clean shutdown in the receipt.

An installed full-cycle pass, independent review, native alerts, 48–72 hour
post-onboarding soak, protected real onboarding and recovery remain separate
acceptance gates. This recipe does not authorize broader scanning or infer any of
them from unit tests.
