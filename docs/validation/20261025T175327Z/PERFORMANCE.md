# Measured reference-path performance

Exact source `cc48a6cf84f063c21ac9e51f954f1c5352799755`, Python 3.11.2, Linux, seed 20261025. Fresh execution completed in 1119.054 seconds; all equivalence, cache, coverage, installed-hook and identity checks passed. Three repetitions cover every file count/content combination. No optimization was accepted.

| Files | Content | Median cold seconds | Median warm seconds | Median uncached seconds |
| ---: | --- | ---: | ---: | ---: |
| 1 | clean | 0.3920 | 0.0620 | 0.4096 |
| 1 | positive | 0.3884 | 0.0621 | 0.4429 |
| 10 | clean | 3.5949 | 0.0968 | 3.4370 |
| 10 | positive | 3.3939 | 0.1067 | 3.4748 |
| 50 | clean | 17.0496 | 0.2624 | 17.2809 |
| 50 | positive | 17.3192 | 0.3011 | 17.2673 |
| 200 | clean | 68.5046 | 1.3238 | 68.4693 |
| 200 | positive | 69.5941 | 1.2078 | 68.5378 |

The file curves launched 1,566 backend workers cold, zero warm, and 1,566 uncached. Warm results preserve the normalized finding sets, severity, part/ranges, context and coverage. Nine document curves separately exercise 1/5/20 extracted text parts with three repetitions; each retains the named `office-nontext` omission rather than claiming complete Office content coverage.

Three installed clean/blocked commit pairs have median/p95 latencies of 0.748834/0.787287 seconds clean and 0.786641/0.837238 seconds blocked. Every positive output is redacted and blocked.

The maximum sampled process-tree RSS is 132,644,864 bytes, sampled every 20 ms; this can miss brief children and double-count shared pages. Parent/child lifetime high-water metrics have distinct definitions in the original receipt. SQLite trace/write counts discard SQL text and parameters; the benchmark itself does not instrument lock timing. The separate SQLite supplement measures actual acquisition-call and definite-hold/transaction boundaries, with internal VFS instants unavailable.

See [compact curves and metric definitions](benchmark-cc48a6c-summary.json), [actual file/document input identities](benchmark-input-manifest-cc48a6c-summary.json), [SQLite boundaries](semantics-sqlite-lock-measurement.md), and [paired baseline diagnostics](semantics-portable-before-after.md). The input manifest covers 1,575 file/document contexts and 4,707 persisted observations; its scope excludes Git-hook and identity probes. Full private receipt SHA-256 is `0b29a2a540c1237e8a120da2530c48796d31a0f7cebc368d1f803acd8a6ed732`.

Cold means fresh semantic state, not flushed OS page caches. Other admitted host activity was possible. The synthetic sample does not establish real-world throughput, accuracy or a cross-platform performance guarantee.
