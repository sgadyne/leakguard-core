# Cache and navigation development checkpoint

Product source: `0d7bac406a594f05faa0d930491ff82eb715de33` on
`perf/scoped-cache-navigation-20261026`, based on the preserved published plugin
checkpoint `69bc6214e92062f3eb8a365b2a8377c0e2f25e18`.

This is a local development checkpoint, not a production or native Windows
acceptance claim. The implementation/configuration contract is documented in
[`../navigation-cache.md`](../navigation-cache.md).

## Focused verification

91 checks passed in 6.840 seconds on macOS arm64 / Python 3.13.13. The selected
checks covered cache hit/miss/content and artifact invalidation, owner isolation,
entry/byte eviction, cancellation domains, late close/reset fencing, immutable
executable pinning, plugin reruns and no-cache bypass; both navigation backends,
hidden/Git-ignored files, links/cycles/alias ancestors, denied/retargeted boundary,
limits/cancellation/early close, protocol rejection and killed-helper failure;
source mutation, final validation, ordered execution, runtime identity,
continuation cursors, SDK/CLI redaction and public API contracts.

```sh
PYTHONPATH=src:tests LEAKGUARD_GITLEAKS=/absolute/gitleaks \
  /private/runtime/python -B -m unittest \
  test_result_cache test_navigation test_navigation_integration test_execution \
  test_source_boundaries test_runtime_identity test_public_api \
  test_scan_state.DirectoryMutationTests \
  test_scan_state.DirectoryValidationPagingTests \
  test_scan_state.IdentityBudgetServiceTests test_scan_state.FindingAdmissionTests
```

The optional native tests require a built POSIX helper. The Mac temporary root
was a real directory outside `/var` aliases so the existing FIFO replacement
test's exact-path injection targeted the resolved artifact. Actual detector
checks used the explicit bundled Gitleaks 8.30.1 path and supervised-alpha Mac
resource policy; no hard RSS cap is claimed for that policy.

The new pure-Python core wheel and `cachetools==7.2.5` were installed offline into
an isolated venv. `pip check` passed. All 37 packaged core Python/rule files were
byte-equal to product source. With isolated mode and a working directory outside
the checkout, actual installed CLI scans through Python and Rust navigation each
returned complete coverage over two synthetic files, detected the ignored hidden
`.env` specimen, and returned 1 with explicit `--fail-on block`. The approved
`firm-example` wheel installed disabled into that private runtime and passed all
four bundled conformance cases (0 failed/skipped). No user profile was modified.

`cachetools` wheel metadata requires Python `>=3.10`, compatible with the
project's Python `>=3.11`. The dependency pin, offline recipe and release manifest
were updated; existing release artifacts were not rewritten.

## Paired synthetic measurement

Same interpreter, native detector and invented corpus; baseline source was
`69bc6214`, candidate product source was `0d7bac4`. These are single paired
measurements under concurrent background workload, not a statistical benchmark.

| Measurement | Baseline | Candidate |
| --- | ---: | ---: |
| 48 text files, 12 distinct contents, 470,984 bytes | 6.568 s | 2.054 s |
| Complete results / findings | 48 / 48 | 48 / 48 |
| Native L1 hits / misses | unavailable | 36 / 12 |
| Retained L1 entries / estimated bytes | unavailable | 12 / 10,140 |
| Peak self RSS | 70.8 MB | 68.2 MB |
| Largest child peak RSS, measured separately | 69.3 MB | 69.0 MB |
| One 10 MiB snapshot, 100 identity accesses including acquisition | 0.346 s | 0.00412 s |

Corpus SHA-256 and normalized redacted result SHA-256 matched exactly. The
approximately 3.2x elapsed improvement applies to duplicate detector input in
this fixture. The RSS values are separate process maxima, not simultaneous
process-tree totals or evidence of a general memory reduction. No corresponding
gain is claimed for unrelated cold files or a new CLI process.

Reproduce a pair using `tools/benchmark_memory_cache.py --source <tree>
--backend <gitleaks> --output <new-private-receipt.json>` with the same environment
and default 48-file/12-unique corpus. Select the candidate's native helper with
`--navigation-helper <helper>`. `--no-cache` verifies the explicit bypass path.

## Traversal measurement

A separate metadata-only fixture enumerated 2,048 empty regular files three times
per backend after one discarded warmup. Metadata collection, sorting and result
hashing were included in both paths; no content bytes were read. All hashes
matched. Python median was 11.748 ms; Rust helper median was 44.663 ms, **3.80x
slower** on this flat fixture. Helper startup/handshake was 3.925 ms. Sampled parent
RSS peaked at 36.8 MB and helper RSS at 15.2 MB, measured separately.

The Rust integration is real and feature gated, but this measurement supports
keeping Python as the default. IPC, structured metadata and per-directory walker
setup can cost more than local enumeration. No native traversal speedup is
claimed. Broad-content throughput still needs phase-separated profiling before
redesigning worker lifetime, batching or parser execution.

## Artifacts and limits

Core wheel SHA-256:
`ad865511170323b05666e4b08d96cfadfd92d5a24ccbf3b1f39d428ad3bf53b5`.

Mac arm64 helper SHA-256:
`560ae0a8685508c8ae1d5c61a744c213c829a20a6eccee342c89c6eaa30aa9e6`.

The helper is distributed separately, not hidden in a platform-independent wheel.
Windows keeps Python navigation; its native bridge is unsupported, and native
Windows acceptance of this incremental checkpoint remains unverified.

The ongoing real-file baseline uses the unchanged installed alpha5 runtime. Its
private reports and findings are outside Git and this handoff. Broad scan
completion, format omissions, heuristic noise and plugin format/part-kind dispatch
ambiguity remain separate readiness gates; these synthetic checks provide no
real-data recall, precision or whole-machine clean claim.
