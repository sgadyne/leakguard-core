# Validation

LeakGuard 0.2 is validated with synthetic inputs and disposable local Git
repositories. The checks measure implementation behavior; they do not establish
real-world detector precision or recall, exhaustive format coverage, or the
absence of unknown defects.

## Local checks

Install Gitleaks 8.30.1 separately, create an empty JSON object for configuration,
and use a fresh private state directory. The main source checks are:

```sh
python -m pip install -e .
LEAKGUARD_CONFIG=/private/leakguard-config.json \
LEAKGUARD_STATE_DIR=/private/leakguard-state \
python -m unittest discover -s tests -v
python -m compileall -q src
```

For optional PDF and Outlook message parsing, install `.[documents]` before
running the suite. If `pypdf` or `olefile` is absent, their real-format tests are
reported as skipped and those formats remain uncovered. Synthetic fixtures use
fixed seeds and stable archive metadata; generated case labels and test outcomes
are distinct from unittest regression counts.

All CPU-heavy suites and measurements in the development run use the shared
`heavy.py` wrapper, which enforces a global two-job limit. The disposable review
probe can be run with `tools/reproduce_review.py --assert-fixed`; it verifies
positive warm-cache reuse, a real local hook rejection with redacted output, and
fail-closed handling of an unextractable required document. `tools/benchmark_scan.py`
records cold, warm and uncached timings for clean and positive synthetic file
sets, plus document-part curves. Its JSON receipt includes identities, coverage,
worker counts and report-equivalence checks, but no fixture content.

## Clean artifact checks

`tools/run_acceptance.py --mode wheel` builds an sdist, a core wheel and the v2
example wheels; inspects archive members; installs them into a new isolated
environment; verifies that imports resolve from the installed target; runs v1
and v2 detector/extractor conformance; and runs the full test suite with
`PYTHONPATH` unset. Add `--documents-extra` to install and test PDF and MSG
parsers. The receipt reports artifact member names, byte counts and digests,
installed versions, test count and source identity. Use a new output path for
each run; receipts and their private work directories belong outside the source
tree.

CI runs the source suite on Windows, macOS and Linux with Python 3.11 and 3.13,
with and without optional document parsers. Separate Linux jobs exercise the
clean wheel on both Python versions with the same parser matrix. CI limits
parallel work to two jobs.

These checks do not claim OCR, archive recursion, arbitrary binary extraction,
or complete coverage of every file format. Platform-specific process-lifetime
and hard-memory behavior is exercised on native CI; a platform not run locally
must be listed as unverified in the accompanying evidence.
