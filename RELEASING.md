# Release procedure

## GitHub Actions policy

`quick.yml` runs one Linux/Python 3.11 installed-wheel regression job for PRs
targeting `main` and pushes to `main`. Ordinary feature-branch pushes do not
build release artifacts. Superseded quick checks are cancelled. The check covers
filter controls, encrypted vault safety, backfill refresh, publication failures,
runtime identity, native observation-cache invalidation and desktop migration.
It does not replace platform qualification or the full compatibility suite.

`test.yml` retains the broad compatibility matrix as a manual workflow.
`alpha-kit.yml` manually builds and qualifies one selected platform (or all three),
including clean installation and prior-alpha upgrade/rollback; these are CLI kits,
not desktop installers. Both workflows require an explicit Run workflow action.
Once these workflow files are on the default branch, select the intended release
branch/tag in the Actions UI. Record its resolved commit in the release receipt.
Manual builds may test a candidate branch; a published release should identify a
commit reachable from main. No commit-message markers or automatic publication.

Desktop releases currently use `deploy/desktop/build_backend.py` and
`deploy/desktop/build.py` on a native Mac with verified runtime/kit inputs.
Do not claim the CLI workflow produces the desktop app. Moving those verified
runtime inputs and native acceptance into a hosted Mac release job is follow-up
work; it is not a prerequisite for using the already qualified local alpha.

Publish only the exact archives that passed installation and identity checks,
with source commit, SHA-256 sums, test scope and signing status. Retain temporary
Actions artifacts for seven days; durable releases are a separate deliberate
promotion. Developer ID signing/notarization remains required for the intended
public Mac distribution. Do not upload private replay data, profiles or run logs.

The 2026-10-31 Mac alpha is described by `docs/alpha-release-20261031.json`.
Its app identifies product commit `0c2a394`; later CI/documentation commits do not
change or relabel that qualified binary.

The 2026-11-01 closeout candidate is recorded in `docs/alpha-closeout-20261101.json`.
Its product commit is `28eeaef`; a later documentation commit does not relabel the
binary. Installed, private-continuity, native upgrade/restart and archive checks
passed. Distribution remains held: the bounded automatic whole-machine run did
not complete its freshness and lower-priority controls under a large backlog.
Do not treat successful selected-source GUI checks as whole-machine acceptance.

## Integrated CLI-first alpha

Use the [CLI kit staging and install guide](docs/CLI-INSTALL.md). Build from a
clean tracked task commit into a new output directory with `deploy/cli/build.py`.
The independent target kit CI and native Mac checks must install the actual
archive offline outside source and repeat its smoke. Retain SHA-256/source/tree
identity and independent review receipts separately from the user kit. Verify
profile activation, fail-closed corruption controls and upgrade/rollback. Do not
publish packages/tags or merge main during internal alpha packaging.

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
