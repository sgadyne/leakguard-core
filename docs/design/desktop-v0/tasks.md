# Desktop v0 — dispatch and acceptance

Frozen 2026-10-26. Implementation starts after both Astra design commits are integrated. Three disjoint implementation lanes on devbox; root is sole integration-worktree writer and native Mac operator. No implementation lane edits another lane's files. Ask root to route a needed cross-boundary change, not the user.

## Ownership and ready-to-send tasks

### Sol A — shell, backend session and lifecycle

Own:
- `apps/desktop/src/**` (main/preload), `apps/desktop/assets/**`, `apps/desktop/package.json`, its lockfile/build config.
- `apps/buddy/src/leakguard_buddy/*.py`, `apps/buddy/pyproject.toml`, and focused `apps/buddy/tests/test_desktop*.py` / necessary existing server-test edits.
- `apps/desktop/README.md` for developer shell run instructions.

Task: Implement architecture.md's one owned backend, private control channel, narrow preload interface, single instance, separate profile, tray/hide/reopen/safe quit, lock policy, nonce injection/session recovery and static whitelist. Bump Buddy to 0.1.0a2. Do not edit generated static files or build a runtime bundler. Shell consumes only `process.resourcesPath/buddy/desktop-manifest.json` and the fixed bootstrap receipt. Use Electron 45.0.0 with local compiled sources and icon assets. Confirm plugin/Git calls still use installed venv and shared backend. Add only focused auth/ownership/shutdown boundary checks. Commit a usable shell before polishing.

First contract receipt to root: main entry path (freeze to `apps/desktop/dist/main.cjs`), preload output `apps/desktop/dist/preload.cjs`, exact npm build command, passing server tests, one protocol ready/bootstrap/shutdown smoke with synthetic isolated state. Package main is `dist/main.cjs`. Use CommonJS bundles for Electron main/preload; renderer remains Vite module JS. No import of release lane source except at runtime through the resource contract.

### Luna — React/MUI application

Own:
- `apps/buddy-ui/**`, including package/lock, components, theme, API client, desktop.d.ts and Vite build.
- `apps/buddy/src/leakguard_buddy/static/{index.html,app.js,app.css}` generated assets only.

Task: Implement all six accepted screens and real existing workflows, not just a dashboard shell. Use README/tokens/wireframe for composition; use contracts.md and current Python for API semantics. Sources/browse/jobs, findings pagination/review, manual vault CRUD/reveal/copy/backup/restore, plugin install/conformance/profile enable, per-repository Git guards, settings and independent lock/empty/error states must work. No synthetic production data or fabricated counters. Finding inspector uses selected page metadata. Native integration is optional window.buddyDesktop; browser remains supported. Single flat app.js/app.css output and nonce meta marker. Pin libraries and commit generated assets. Do not touch Python, Electron shell or packaging.

First receipt: npm build/typecheck and vertical slice first-run scan storage → choose folder → add source → submit → jobs/findings. Then complete remaining workflows; rely on backend behavior rather than duplicating scanner/vault logic. Keep manual secret inputs/reveal state out of persistent caches.

### Sol B — standalone runtime/release and integration harness

Own:
- `deploy/desktop/**` (manifest builder, bootstrap.py, package orchestration, signing helper if needed, target resource assembly).
- `tools/check_desktop*.py` / `tools/check_desktop*.mjs`, `tools/desktop/**` fixtures/harness.
- `docs/desktop-install.md`, `docs/validation/desktop-v0-*.md`.

Task: Build self-contained desktop resource trees using the already prepared standalone runtime inputs and verified alpha wheelhouses. Generate a new Buddy 0.1.0a2 wheel from integrated sources/static files; preserve other wheel bytes, regenerate honest desktop manifests and hashes. Implement the stdlib bootstrap contract and first-launch private-runtime installer without system Python/uv/network. No runtime mutation in app bundle. Restore executable bits lost in ZIP extraction. Package Mac arm64 and Windows x64 app directories with @electron/packager 20.3.0; Linux x64 if closure/smoke is feasible. Do not edit shell/preload, Buddy Python or UI files. Packaging tooling has its own `deploy/desktop/package.json`/lockfile and points to the shell package's already-built `dist/main.cjs`.

The packaging CLI is `python3 deploy/desktop/build.py --target <target> --runtime-input <dir> --backend-input <LeakGuard-dir> --output <dir>`; root runs it against integrated sources. It must build/consume UI and shell deterministically, assemble resources, record source commit and hashes, and produce a target artifact/manifest. Add `--stage-only` for payload assembly before Electron download/signing if useful. Emit an artifact receipt JSON; do not publish externally. Use build tooling only on devbox; final native Mac signing/acceptance is root-owned.

Focused harness should exercise built runtime/desktop boundary with explicit synthetic temp profile and never target a default/legacy profile. Reuse existing product journey utilities where suitable; no new exhaustive feature suite.

## Integration sequence

1. Root merges both design commits and dispatches these three lanes simultaneously in their isolated worktrees. Each lane reads architecture/contracts before editing.
2. Sol A and Luna land the vertical slice; Sol B prepares target runtime resources against their documented fixed interfaces. Root merges clean incremental commits. Changes to the interface go through root and are reflected in these docs.
3. Root runs the first integrated boundary check: flat static build, real Python startup/bootstrap/cookie/CSRF, source add and bounded synthetic scan; encrypted stores and paths correct, no legacy profile interaction. Failures go to the owning lane.
4. Root merges complete UI workflows and shell lifecycle, then Sol B builds the frozen target artifacts from that integrated commit. Do not package stale per-lane static assets or an earlier Buddy wheel. Root records final artifact hash and source commit.
5. Copy the final Mac artifact to an isolated test location/profile. Native acceptance follows below. Only after passing does root place the candidate in Simon's normal app location and give a concrete launch path. Old installation/state remains preserved; any root-owned old test process cleanup is explicit and never inferred from a matching port.
6. Windows cross-built artifacts receive static/closure evidence and a clear native-unverified label. A native Windows runner can upgrade that status later. Signing/notarization limitations are documented, not disguised as successful installer acceptance.

## Bounded checks

A working devbox headless-browser environment is recorded in /home/dev/projects/leakguard-desktop-v0-20261026/native-browser-inputs.json with Playwright/Chromium paths and LD_LIBRARY_PATH for the copied native-libs closure. Sol B should reuse it; no system package installation or phase-1 recheck is needed.

Each lane: relevant typecheck/build plus existing directly affected tests. Avoid full suites after each component. Full journeys run at integration boundaries, and rerun only after relevant changes or failures.

Necessary checks at integration:
- Auth boundary: unauthenticated API rejected; wrong Host/Origin/CSRF rejected; token never in desktop URL/log; repeat bootstrap/refresh works; renderer has no Node or arbitrary IPC; nonce enables MUI/grid without script unsafe-inline/eval.
- Runtime boundary: verified resource manifest, correct native interpreter/wheels/Gitleaks, private venv prefix, pip available, plugin private-runtime check passes; no checkout/Miniconda/system Python dependency.
- Profile boundary: separate desktop root, duplicate launch reopens existing window, backend ownership lock rejects another writer even while stores locked, incomplete preparation preserves state.
- Data boundary: synthetic scan completes or truthfully reports incomplete; cancel/pause/resume stays honest; review labels are separate from evidence; history/late page inspector works without limited lookup.
- Credential boundary: explicit synthetic Save/reveal/copy/edit/lock/backup/restore, restore replacement confirmation, no secret retained after lock/reload/disconnect, no accidental empty replacement field.
- Native lifecycle: tray opens app, close hides, hide locks credential vault while scans remain independent, reopen works, quit stops owned backend and leaves no owned scanner process; a blocked stop remains visible and retains ownership.
- Existing plugin/Git workflow: reviewed fixture wheel installs offline and enables only when explicit; disposable repository guard install/check/remove with stable runtime path. Do not modify a real repository.
- Native Mac: launch the relocated app with synthetic profile, restart with encrypted data retained, inspect logs for fixture secret canary, verify keyring opt-in separately from credential lock, login settings only if explicitly toggled as part of authorized native acceptance and restored afterward.
- Native OS-lock event must be checked on Mac if claiming verified; never lock Simon's OS session without coordinating the exact action. Simulated event handler coverage is reported separately from native event receipt.

Completion receipt: commit, artifact/hash, Mac app path/launch instructions, standalone runtime identity, native test results, Windows/Linux scope, signing/notarization status, retained legacy state, known limits and owned-process cleanup. Design/prototype alone is not completion of the user's desktop task.
