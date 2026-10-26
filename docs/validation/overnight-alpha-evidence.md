# Overnight alpha evidence

## Independent labels

`tests/fixtures/independent_literal_labels.json` is a fixed text-only set with
six positive short literal assignments and six negative controls. The positives
include client-secret and password field aliases, quoted and unquoted values,
and assignments shorter than the baseline detector thresholds. Four negatives
are explicit placeholders; two mention passwords without assigning a value.
Labels were written from product intent before evaluating detector output.

The older 48-case corpus now labels its six short literal assignments as
positives. This prevents the known misses from inflating true-negative counts.
The separate independent set keeps its six-control balance and is scored on its
own. Neither set estimates performance on real company data.

Run the independent set with:

```sh
python tools/run_independent_labels.py \
  --gitleaks /path/to/pinned/gitleaks \
  --output /private/new-label-receipt.json
```

The receipt includes case IDs, declared and observed rule IDs, per-case fixture
hashes, and aggregate TP/FP/TN/FN counts. It never includes fixture text.

## Bounded performance and equivalence

The benchmark runner supports a bounded 50/500-file profile while retaining
the existing larger default curve. One file/document repetition plus three
hook samples keeps the requested case count small:

```sh
python tools/benchmark_scan.py \
  --output /private/new-benchmark-receipt.json \
  --state /private/empty-state \
  --config /private/empty-config.json \
  --gitleaks /path/to/pinned/gitleaks \
  --file-counts 50 500 --repetitions 1 --hook-repetitions 3
```

Run measurements through the run-owned heavy-job wrapper. Compare cold, warm,
and uncached findings, provenance, and coverage within each case; record launch
counts and observed memory without claiming a speedup from a single synthetic
host. The existing worker-tree RSS metric is sampled on Linux only; macOS uses
process lifetime high-water values, and unavailable metrics remain null.

## Platform receipts

Platform status is based on an installed artifact running on that platform.
Linux results do not imply macOS or Windows support. The available Mac bridge
runs a committed source bundle on the user's macOS host; Windows remains
unverified until a native runner is supplied.
