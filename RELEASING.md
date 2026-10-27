# Release procedure

## Integrated CLI-first alpha

Build from the reviewed integrated commit into fresh target-specific
wheelhouses and verify the receipt and hashes. Use the [CLI install and
rollback guide](docs/CLI-INSTALL.md) for the Python 3.11 Presidio/JOSE and firm
wheel path. Run the combined installed Linux gate from the clean integrated
checkout with an unused private artifact directory outside it, an approved
Gitleaks 8.30.1 executable and an available `uv` binary:

```sh
python3.11 tools/qualify_combined_installed.py \
  --artifacts /private/new-combined-gate --gitleaks /approved/bin/gitleaks \
  --uv /approved/bin/uv
```

The gate records the commit, wheel hashes, source/wheel/installed identity and
synthetic installed receipts. Check its exit status and receipt, plus the
independent security review and cross-platform CI. The [Mac CLI qualification
recipe](docs/MAC-CLI-QUALIFICATION.md) is a separate local gate, including the
synthetic vault and Mac client to Linux broker; report completed and deferred
checks. Native Windows core/plugin CI does not qualify a Windows broker. Never
publish private receipts or real state.

## Core release checks

1. Build from this standalone source tree. Do not include a deployment folder,
   runtime database, local configuration, private plugin package, scanner binary,
   or unrelated Git history.
2. Run the synthetic suite with a private empty configuration and fresh state.
   Install Gitleaks separately and record its version and digest in the external
   validation receipt.
3. Run `tools/run_acceptance.py --mode wheel` for the supported Python versions,
   then repeat with `--documents-extra`. Each run uses a new isolated install,
   records the target Python version and whether installation used a venv or
   private Python user base, verifies import origin outside the checkout,
   inspects the sdist and wheel, executes plugin conformance checks, and runs
   the full suite.
4. Review the archive member lists and digests recorded in each receipt. Confirm
   that `MANIFEST.in` includes public compatibility, release and validation
   documents plus the plugin example source and documentation. Keep receipts,
   private deny-lists and temporary build state outside the published artifacts.
5. Review notices, license terms, plugin API, examples and deterministic corpus
   results. Treat benchmark timings as measurements for that environment, not as
   a performance promise or detector quality score.
6. Confirm publication rights, destination and version, then publish the reviewed
   artifacts through the approved release process. This repository's checks do
   not upload or publish packages.

LeakGuard 0.2 provides typed redacted observations and supervised extension
interfaces. These release checks do not assert exhaustive file-format coverage,
OCR/archive handling, fleet services, or real-world precision and recall.
