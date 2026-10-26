# Password Buddy desktop v0 — initial design and implementation plan

Requested 2026-10-26. Start from `df73f85b5f1e502a9f3d763d244212e1ccb0eebb`
(alpha.5 plus Mac acceptance and test portability fixes). Build on devbox;
bring the final app to Simon's Apple Silicon Mac for native acceptance and use.
Use Astra for two sequential design decisions, then Sol/Luna for implementation.
The request authorizes proceeding through these phases; this is not another
approval gate. The old overnight deadline/waiver does not apply to this run.

## Outcome

A local desktop application with an ordinary window, Mac menu-bar icon and
Windows notification-area icon. Opening it starts or connects to the existing
local Buddy backend; users can configure scan storage, select folders, scan,
review findings, and manage their separate credential vault. No cloud service
or Penpot dependency. Penpot comes after v0; retain tokens and wireframes in
the repository so the design can move there later.

The backend, API, Git guards and plugin contracts remain shared with CLI and
headless Linux installations. Preserve existing encrypted user state. Desktop
packaging must have an explicit runtime strategy and must never pretend that
an app which depends on a developer checkout is a standalone release.

## Initial visual direction

Calm, compact workbench: warm off-white canvas, white panels, dark slate text,
teal accent, thin neutral borders. Use familiar desktop controls, visible
labels and restrained status colors. Avoid oversized dashboard cards, gradients,
decorative graphs and anonymous icon-only actions. Severity and coverage have
text labels as well as color. Default light, with a coherent dark mode.

Initial tokens: canvas #F5F7F9, surface #FFFFFF, text #172B4D, muted #596779,
border #DCE3EB, accent #087F8C, danger #B42318, warning #9A6700. System font
stack, 14px body, 12px secondary labels, 24px page title, monospace paths.
8px spacing scale, 6px control radii, 36px standard control/row height. Minimum
window about 1000x680; primary reference 1440x900. Respect zoom and keyboard
navigation; do not hide essential actions at small supported sizes.

Use React + TypeScript + Vite, MUI for the component and theme system,
AG Grid Community for findings, ECharts only for actual available summaries.
MUI is the primary design language; do not mix MUI, Ant and Blueprint widgets
in one screen. Evaluate Dockview for the findings workspace in Astra phase 1;
include it only if the information layout benefits from movable panels.
Use OSS/community features without commercial license requirements. Pin
compatible versions from the package registry and retain the lockfile.

## Information architecture and wireframes

Permanent sidebar: Overview, Sources, Findings, Vault, Plugins, Settings.
Git guards live under Sources/repository detail; remote SSH is a source type
only to the extent the existing host API actually supports it. Never present
unimplemented deployment or scan controls as working. Footer reports connection,
scan-storage lock, vault lock and background capability separately.

```text
+-------------------+-----------------------------------------------------+
| Password Buddy    | Overview                         Scan selected       |
| Local workspace   |-----------------------------------------------------|
|                   | Setup / attention strip (only when needed)          |
| Overview          | Last successful scan    Active jobs    Needs review |
| Sources           |-----------------------------------------------------|
| Findings          | Sources and coverage        | Recent activity       |
| Vault             | Documents  Ready / Partial  | Scanned ...           |
| Plugins           | Repository Offline          | Waiting for unlock    |
| Settings          | Add source                  | Open job              |
|                   |-----------------------------------------------------|
| Connected locally | Coverage explains what was checked and omitted.     |
+-------------------+-----------------------------------------------------+
```

```text
Sources: [Add source] [Scan selected]         Files / repositories / mounts
+----------------------+--------------------------+-----------------------+
| Source name + status | Root / exclusions        | Scope details         |
| selected folder      | Last complete scan       | Scan / Cancel / Resume|
| selected repository  | Current job + progress   | Schedule + Git guards |
+----------------------+--------------------------+-----------------------+
Add source: browse permitted roots, choose exact folder, exclusions, confirm.
Show inaccessible/offline locations; never silently report them clean.

Findings: [Search] [Source] [Severity] [Review state] [Coverage]
+-----------------------------------------------+-------------------------+
| AG Grid: severity, rule, location, last checked | Finding detail          |
| rows are redacted; bounded pages from API       | File / part / line      |
| selectable row; explicit pagination            | Evidence / coverage     |
|                                                | Review / Dismiss        |
|                                                | Add to vault (manual)   |
+-----------------------------------------------+-------------------------+

Vault: [Lock] [Add credential] [Encrypted backup]
+-----------------------------+-------------------------------------------+
| Search entry titles         | Entry title / username / location         |
| Entry list (no secret text) | Secret: masked        [Reveal] [Copy]     |
| Empty and locked states    | Notes                 [Edit]              |
+-----------------------------+-------------------------------------------+
Create/unlock is a focused dialog. Save is explicit; cancel clears values.
Lock immediately clears all secret-bearing component state and pending reveals.
```

First run is a short setup screen: create encrypted scan storage, optionally
create credential vault, add first folder. Explain why the stores unlock
separately in one sentence. Do not demand a credential vault to scan.
No dummy production metrics or synthetic credentials in normal app mode.
Demo fixtures are opt-in and clearly marked in their own state directory.

Tray menu: Open Buddy, status, Scan selected/configured sources, Pause/Resume
schedules (where supported), Lock credential vault, Start at login, Quit.
Unavailable actions explain the prerequisite. Closing the window hides it;
Quit stops only the backend process owned by this desktop instance. External
CLI/service processes must not be killed. Single-instance behavior brings the
existing window forward. Lock credentials on OS session lock and according to
idle policy only if reliable events/support can be implemented and verified.

## Architecture boundaries to freeze

`apps/buddy-ui/`: React sources, components, theme, API client and compiled
static output. `apps/desktop/`: Electron main/preload, tray, process supervisor,
packaging and native smoke harness. Existing Python Buddy owns auth, API,
scanning and vaults. Avoid duplicating business logic in Electron.

Keep authenticated loopback bootstrap, exact origin/host checks and CSRF.
Renderer has no Node integration, uses context isolation and sandbox, and has
no generic filesystem, shell or fetch IPC. Preload exposes narrowly typed
desktop actions. Do not load remote UI or CDN fonts/scripts. Restrict navigation,
popups, permissions, devtools in release and unnecessary network access.
Secrets/passphrases stay out of URLs, logs, persisted UI state and telemetry.
Use a deliberate CSP compatible with MUI's runtime styles without relaxing
script execution. Static assets should work in both browser and Electron.

Prefer bundled, relocatable backend/runtime for the final Mac app. A dependency
on the existing validated per-user alpha install is an explicit interim mode,
not a claimed standalone corporate installer. Windows needs a compatible
runtime/package path and a clearly stated native validation status. Do not
ship unchecked claims of Windows service or keychain behavior. Signing or
notarization requiring unavailable identities is a recorded distribution limit.

## Astra phase 1 — product and visual decision

Review this draft against actual API/UI capabilities. Decide the library mix,
navigation and screen composition. Produce a self-contained clickable HTML
wireframe with all major screens and first-run/locked/empty/error examples,
plus an amended design record. Wireframes must be labelled as non-production.
Choose one direction rather than leaving implementation agents options.

## Astra phase 2 — execution and integration decision

Review phase 1, endpoint contracts and native packaging feasibility. Freeze
component/API ownership, app lifecycle, authentication/IPC/CSP, runtime bundle
strategy, task splits and acceptance gates. Resolve UX/backend mismatches before
implementation. Record cuts explicitly; no new approval gate is required.

## Sol/Luna implementation lanes

- Sol: Electron shell, backend lifecycle, static serving/auth integration,
  packaging, shared contracts and integration ownership.
- Luna: React/MUI application, tables, theme, forms and all existing workflows.
- Luna or Sol support after contracts freeze: demo fixtures, integration journey,
  installation guide and release evidence; no concurrent edits to owned files.

All implementation uses isolated branches/worktrees on devbox. One integrator
merges commits. The coordinator performs Mac native acceptance here. Do not
restart the old eight-agent run or modify its historical receipts. Preserve the
current working Mac installation until the desktop candidate passes isolation.

## Major integration checkpoints and completion

1. First vertical slice: built React assets + Electron + real backend, start,
   first-run storage, folder selection and a bounded synthetic scan.
2. Feature integration: findings and vault workflows, plugins/Git/settings,
   tray/single instance/close/reopen/quit, restart and unavailable states.
3. Frozen artifact: native Mac install/start journey, real UI interaction,
   synthetic Save/reveal/lock/backup, scan and cancellation, process cleanup,
   retained encrypted state and secret-free logs. Windows build/static review
   is separate from native Windows acceptance if no runner exists.

Keep incremental testing light: build/typecheck and focused failures. Full
integration at these boundaries, not after each component edit. Reuse existing
backend tests and add only consequential desktop/renderer boundary checks.
Native Mac work should use an isolated demo profile before opening Simon's
real installed state. Never choose or type his real vault passphrases.

Completion means a committed monorepo, design decisions and wireframes,
reproducible desktop artifact with hash, native Mac result and an app Simon can
open here. Include Windows/Linux artifact scope, launch instructions, remaining
limits and owned-process cleanup. Do not mark complete at plan or mockup alone.

## Reference documentation

- https://mui.com/material-ui/getting-started/installation/
- https://www.ag-grid.com/react-data-grid/getting-started/
- https://dockview.dev/docs/
- https://www.electronjs.org/docs/latest/api/tray
- https://www.electronjs.org/docs/latest/tutorial/security

## Phase 1 decision — frozen 2026-10-26

The product design in [desktop-v0/README.md](../design/desktop-v0/README.md),
[tokens.json](../design/desktop-v0/tokens.json) and the self-contained
[clickable prototype](../design/desktop-v0/wireframe.html) supersedes the
tentative UX choices above. Prototype fixtures are synthetic and never ship
in normal application mode.

- React 19 + MUI 9/Emotion + AG Grid Community 36. No Dockview, chart dependency,
  second widget family or commercial grid feature in v0.
- Fixed sidebar and list/detail workbench. Native titlebar; six main routes.
- Findings use explicit API filters and bounded cursor pages. No invented total,
  global sorting, exposure score or scan percentage. Latest source coverage is
  labeled separately from evidence and review state.
- Credential list is metadata-only, including hidden username/notes until
  explicit reveal. Both stores have independent gates and visible status.
- Existing source scope is read-only; enabled/schedule can be changed.
  SSH stays CLI-only. Git guards are a Sources subview and remain per-repository.
- Tray opens Sources; no fictitious global Pause schedules action.
- Phase 2 must resolve direct finding lookup/page-row detail, native lifecycle,
  standalone resources, session/CSP bootstrap and honest capability gates.
## Phase 2 decision — frozen 2026-10-26

Implementation is now authorized against the frozen
[architecture](../design/desktop-v0/architecture.md),
[UI/native contracts](../design/desktop-v0/contracts.md) and
[three-lane task prompts](../design/desktop-v0/tasks.md).
These override earlier tentative runtime, tray and ownership choices.

Electron owns one native shell and one private backend. The separate Password
Buddy desktop profile never auto-attaches to legacy LeakGuard state. Bundle
standalone CPython and offline wheels; prepare a stable per-user private venv
for existing plugin/Git behavior. Buddy is a new 0.1.0a2 wheel with generated
flat React assets, with honest manifest provenance. Main/preload uses a narrow
private JSONL control channel and exact-origin IPC; renderer API remains
same-origin cookie/CSRF authenticated with per-response style nonces.

Sol A owns shell/backend; Luna owns React/static files; Sol B owns standalone
runtime/package tooling and integration harness. Root alone merges and performs
native Mac acceptance. Windows packages remain native-unverified until tested.
Native OS session-lock behavior is not verified by simulated events, and Simon's
OS session must not be locked without coordinating that exact action.
