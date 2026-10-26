# Alpha worker execution policy

Select one policy in the external JSON configuration used by CLI, Buddy, and
selected repository hooks:

```json
{"worker_policy":"supervised-alpha","scan_workers":2}
```

The default remains `strict`. On macOS, strict rejects required parser/plugin
work with `resource-bound-unavailable`: this runtime cannot supply its hard
allocation bound. This is not an extraction omission and cannot allow Git.

`supervised-alpha` explicitly uses an RSS watchdog on macOS, with bounded
input/output, a wall timeout, and owned process group cleanup. It samples the
worker and observed descendants every 50 ms. RSS can overshoot between samples;
this is **not a hard allocation limit**. Exceeding the sampled budget produces
`worker-memory-limit` and incomplete coverage. Missing or unreadable watchdog
support rejects the worker. Plugins remain trusted account-level code; process
supervision is not a code/network sandbox.

Linux workers continue to use POSIX resource limits and Windows workers retain
Job Objects. Gitleaks cannot run under the Python worker's virtual address cap
because Go reserves a large virtual arena. It keeps its Go soft memory limit;
in supervised alpha mode its RSS is also watched. Native platform verification
is recorded separately in release receipts.

Run `leakguard doctor --config /private/profile.json --format json` to probe the
selected worker primitive, backend location, and SQLite serialization support.
The Python facade exposes the same worker capability via
`Scanner.capabilities()`. A doctor result does not establish a successful scan.
Reports under the supervised policy carry a non-required
`supervised-alpha-policy` issue, preserving the v1 report schema and coverage
semantics. The selected policy and watchdog implementation/dependency bytes
participate in cache identity; switching policy cannot reuse a strict-policy
result as supervised evidence or vice versa.

Worker concurrency is bounded to two files by default. Set `scan_workers` to 1
for the sequential reference path. Admission, source acquisition, result order,
provenance, and the durable store writer remain coordinated by the scan owner.
