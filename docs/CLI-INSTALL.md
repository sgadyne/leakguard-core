# Integrated CLI internal alpha deployment kit

The current CLI kit is **0.2.1a3**, built from the exact tracked commit/tree in
its manifest. The user receives these separately hashed artifacts:

- `leakguard-cli-0.2.1a3-linux-x86_64-cp311.zip`
- `leakguard-cli-0.2.1a3-macos-arm64-cp311.zip`
- `leakguard-cli-0.2.1a3-windows-x86_64-cp311.zip` (qualification depends on native CI receipt)
- `leakguard-examples-0.2.1a3.zip` (optional synthetic extensions)
- `leakguard-source-0.2.1a3-COMMIT12.tar.gz` (the receipt gives the exact filename)

Each deployment zip contains the complete target-specific pinned wheelhouse,
native Gitleaks 8.30.1 executable/provenance/license, licenses inventory,
`requirements.lock`, `manifest.json`, and the standalone `kit.py` installer,
verifier and repeatable synthetic smoke. No source checkout or network is needed
at installation time. Follow [the shipped kit instructions](../deploy/cli/README.md)
for external prerequisites, exact commands, profile activation, limits, upgrade
and rollback. Check trusted archive/manifest SHA-256 values before extraction.
Keep kits and private evidence separate. A hash is integrity, not a signature.

Core 0.2.1a3 and credential detector 0.1.0a2 distinguish the changed Phase 1
runtime from prior same-name wheels. Presidio and JOSE remain at unchanged
0.1.0a2; third-party dependency pins remain the existing reviewed Presidio lock.
Sensitive/firm presets are optional; no real firm rules are installed by default.
The base explicitly activates the credential/JOSE profile. Core-only defaults
remain Gitleaks-only. Broker, GUI, vault, Tika and Phase 2 are outside this kit.

## Staging a kit

Build only from a clean reviewed task checkout, in a fresh staging environment
with CPython 3.11, pip, setuptools 80.9.0 and wheel 0.45.1. The builder archives
tracked HEAD, builds local wheels there, downloads hash-locked target-native
dependencies from the approved package index, and verifies official Gitleaks
release checksums. Staging requires network access to that index and GitHub;
build inputs and target-specific locks/hashes are preserved. No byte-reproducible
claim is made. Refuse existing output directories and never overwrite artifacts.

```sh
python3.11 -m venv /private/new-lg-build
/private/new-lg-build/bin/python -m pip install setuptools==80.9.0 wheel==0.45.1
/private/new-lg-build/bin/python deploy/cli/build.py \
  --output /private/new-lg-dist \
  --target linux-x86_64 --target macos-arm64 --target windows-x86_64
```

Use the run's `run-heavy.py lead -- ...` wrapper for shared-host staging. Native
CI builds and independently installs its exact target zip; target selection alone
is not native qualification. Release receipts record source commit/tree, all
archive/manifest hashes, installed checks and actual platform outcomes. Native
corporate Windows remains pending even when hosted Windows CI passes.
