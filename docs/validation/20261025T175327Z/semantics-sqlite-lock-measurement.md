# SQLite transaction and contention measurement

Exact source `ce1ea500fd832ea7c15a0a3558918fbf674f0eb4`, tree `bde92968ad8cdb29fc620b1bae22a4499dc5a953`. Python 3.11.2 (`/usr/bin/python3.11`), SQLite 3.40.1, Linux. Actual SQLiteScanStore connections use a private runtime-only sqlite3.Connection subclass to timestamp transaction-control categories, statement returns, commit calls and context exits. No SQL text, bound parameters or fixture contents are recorded.

Run-owned heavy receipt `job-4a37a25e58784f798fc602c12bfa5dc7.json` contains the exact structured command, before/after source identities and empty patch/untracked digests. Exit 0, `source_stable=true`, elapsed 1.821 seconds. Private script: `scratch/semantics/measure_sqlite_locks.py`; complete monotonic timestamps: `semantics-sqlite-lock-measurement.json`; output: `.log`. Overall invocation has a 20-second process timeout. Synthetic database files were removed on completion; no production changes.

| Measurement | Samples | Median ms | Min–max ms |
| --- | ---: | ---: | ---: |
| Uncontended reserve transaction window | 20 | 1.640 | 1.443–4.489 |
| Reserve definite pre-commit hold window | 20 | 0.0126 | 0.0064–0.0357 |
| Uncontended explicit writer-acquisition call | 10 | 0.0350 | 0.0205–0.0522 |
| Uncontended cycle transaction window | 10 | 2.257 | 2.107–6.274 |
| Cycle definite pre-commit hold window | 10 | 0.2045 | 0.1368–0.4904 |
| Controlled holder definite hold window, release cases | 3 | 120.339 | 120.262–120.414 |
| Competing acquisition call, eventual success | 3 | 128.757 | 128.740–129.008 |
| Competing acquisition call, 120 ms deadline | 3 | 119.846 | 119.845–120.053 |
| Successful retry operation after timeout/release | 3 | 3.934 | 3.510–4.981 |

All three release cases acquired only after the controlled holder began committing. All three deadline cases failed while the other connection still held the writer lock, with fixed internal category `SQLITE_BUSY` translated by the store to `state-failed`; full method duration was 119.940–120.420 ms. Every timed-out connection successfully retried after release, and all six contender deadlines were explicitly cleared.

These are boundary measurements, not SQLite VFS lock counters. Acquisition-call duration includes actual lock waiting and Python/SQLite overhead. A successful explicit acquisition return establishes that the writer lock is held; from that return until commit invocation is a directly observed definite-hold window. For implicit reserve transactions, the corresponding window begins at the first write's successful return. Commit/context-exit time includes persistence and lock release, whose precise internal instants are uninstrumented. Transaction windows include acquisition and commit work. None of these values are inferred from total scan time; no scan or detector ran. Opening/schema migration is excluded, instrumentation adds overhead, and the small synthetic sample is not a cross-platform performance guarantee. No correctness defect was observed.
