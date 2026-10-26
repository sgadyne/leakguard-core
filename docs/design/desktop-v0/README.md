# Password Buddy desktop v0 — product design decision

Status: phase 1 frozen for implementation planning, 2026-10-26. This document supersedes the tentative UX choices in the initial handoff. Phase 2 freezes runtime, security and implementation contracts separately.

Open [wireframe.html](wireframe.html) directly in a browser. It is a self-contained, clickable design prototype, with synthetic fixtures only. It performs no network requests, persistence, filesystem writes, downloads or clipboard writes. The prototype controls at the top are design-review tools and must not ship in the normal application.

## One direction

Build a quiet desktop workbench: warm gray canvas, white working surfaces, dark slate type, teal primary actions and thin borders. Information should feel like a familiar file manager and inspector. Use ordinary page headings and compact tables. Avoid a promotional welcome dashboard, security scores, invented trends, decorative charts and a blanket “safe” or “clean” verdict.

The product name is **Password Buddy**; “LeakGuard engine” belongs in About and diagnostics. Navigation is **Overview / Sources / Findings / Credential vault / Plugins / Settings**. Use “Scan storage” for observations in user-facing text. Always say “credential vault” where “vault” alone would confuse the two stores.

The default window is 1280 × 820, reference 1440 × 900, minimum 1000 × 680. Keep a 208px sidebar and 32px page gutters. At less than 1200px, findings detail moves into a right-side MUI Drawer; it remains reachable from the selected row. Sources use a 300px inspector above that breakpoint. No draggable docking or floating panels. Layout is predictable, with normal document scrolling and a bounded grid viewport. Native titlebar/chrome stays native; the prototype title strip only provides context.

## Library decision

Use React 19 + TypeScript + Vite, Material UI 9 with Emotion, Material SVG icons, and AG Grid Community 36 for findings. Pin exact mutually compatible releases and lock the dependency graph in phase 2. MUI owns all shell, form, dialog, alert, tab, list and button primitives. Override its typography with the OS system font, not downloaded Roboto. AG Grid takes the same color/type/row tokens as MUI.

AG Grid uses the **client-side row model for one bounded API page at a time**. The application owns “Previous page / Next page” cursor navigation and a short in-memory cursor stack. Show “24 rows on this page”, never “24 total” unless the server supplies a trustworthy count. Disable grid filtering and sorting in v0: API filters have defined semantics, while the API has no global sort contract. External filters submit together with Apply; Reset restores defaults. Do not put an offset-based infinite-row adapter over opaque cursors. An empty filtered page with a next cursor must still offer Next page.

No AG Grid Enterprise imports, server-side row model, master/detail grid, grouping, pivot, integrated charts, premium tool panels, Excel export or commercial MUI X packages. Finding detail is an ordinary sibling MUI panel. No Ant Design, Blueprint or Dockview in v0. Dockview's IDE layout model is unnecessary for one table and one inspector. No ECharts dependency in v0: existing APIs provide status counters and scan activity, not a trend series or a reliable progress denominator. Add a chart only when a later feature has real data and a concrete question.

Official references checked 2026-10-26:
- [MUI installation and React peer support](https://mui.com/material-ui/getting-started/installation/): use Material UI + Emotion and React 19.
- [AG Grid Community capabilities and licence](https://www.ag-grid.com/react-data-grid/community-vs-enterprise/): required table features are community features.
- [AG Grid row models](https://www.ag-grid.com/react-data-grid/row-models/): the page-owned client-side choice above is deliberate.
- [Dockview scope](https://dockview.dev/docs/): docking, floating and popout layouts are deferred.

## Screen contract

| Screen | Composition and primary action | Truth and restrictions |
| --- | --- | --- |
| Overview | A compact status strip; source/coverage table; recent jobs; separate storage panel. Primary: Add source when empty, Open sources otherwise. | Derive configured-source and active-job counts from returned collections. No global finding count or completion percentage. “2 of 3 latest scans complete” is a derivation of latest jobs, not overall filesystem coverage. |
| Sources | Configured sources table and selected-source inspector. Tabs: Sources, Scan activity, Git guards. Primary: Add source. | Local folders, mounted shares, and Windows UNC only when platform capability permits. No SSH GUI or remote deployment. Mount/authentication remain OS tasks. |
| Sources → inspector | Exact path; source kind; latest coverage; last successful scan; exclusions; enabled state; schedule; Scan now. | Enable/disable and schedule are editable. Existing root, label and exclusions are read-only because PATCH does not accept them. Change scope by adding a new source. Retain old evidence; no invented “edit folder” save. |
| Sources → activity | Job rows with source, state, files checked, pending counts when known, update time and reason. Pause/resume/cancel only where supported. | Indeterminate running indicator; never fabricate a percentage. Cancelling may wait for the current slice. Interrupted jobs remain paused until explicit resume. |
| Sources → Git guards | Selected repository path, Check guards, effective profile/config/worker policy, install/remove. | Git inspection is explicit; selecting a folder is not proof it is a repository. Per-repository only, no global hook toggle. Do not promise the new profile affects an already installed snapshot. |
| Findings | Current/History segmented control; API filters; AG Grid page; selected-finding inspector. | Review annotation and engine evidence state are distinct. Keep redacted metadata only. Columns: severity, rule, location, evidence state, review state. Put last verified, part/line, category and latest source coverage in inspector. |
| Credential vault | Independent gate, title/location list, selected-entry metadata, explicit Reveal details / Copy secret / Edit / Delete. | List endpoint does not return username or notes. Do not render fake masked username values as known. “Reveal details” fetches secret, username and notes; lock clears all revealed and pending values. Add is manual and Save is explicit. |
| Plugins | Installed local extensions, profiles enabled, conformance result; install reviewed wheel dialog. | No marketplace/cloud/update checker. Install wheel first, inspect, then explicitly enable for chosen nondefault profile. Do not imply installation already enables it. |
| Settings | Scan profile/workers, shared read-only policy and limits; independent scan-store and credential-store actions; appearance; desktop behavior/About. | Keyring is opt-in for scan storage only and must report verified availability. Shared policy is not an editable GUI field. Native settings and runtime provenance are finalized in phase 2. |

The source table uses three separate concepts: **Job state**, **Coverage**, and **Last successful scan**. A source with a completed scan yesterday and an offline attempt today shows “Offline / Incomplete / Yesterday”, never a green current verdict.

## Coverage and evidence language

- Job coverage is “Complete”, “Incomplete”, or “Not yet checked” when there is no job. Unknown/unavailable values show “Unknown”; do not coerce them to complete.
- “Complete” means the selected scope was checked under that job's scan policy. It does not mean there were no findings and does not cover excluded or unsupported content.
- The API attaches latest source-job coverage to finding pages; call it **Latest source coverage**. It is not per-finding or per-file coverage, nor necessarily the job that discovered the row.
- Engine evidence state (such as active/unknown/resolved) and classification are displayed exactly with friendly labels. Review state is unreviewed/reviewed/dismissed. Dismissal does not resolve engine evidence or bypass Git enforcement.
- An offline, cancelled, failed, paused or policy-reset scan retains incomplete coverage. A changed work identity can make older evidence unknown until checked again.
- No matched values, source snippets, “recover secret” control or automatic import appears in Findings. Add to credential vault pre-fills only title/location/link and leaves Secret blank.
- No results means “No findings returned for these filters.” Pair it with coverage and cursor state. Say “No findings in the completed selected scope” only if there are no more pages and coverage is actually known complete for that scope.

## Core journeys

1. **First run:** create scan storage with passphrase and confirmation (12–1024 characters); optional separate credential vault; add one exact folder. Scan storage creation is sufficient to proceed. “Skip for now” leaves the credential vault uncreated. Existing files are detected and offered Unlock, never recreated.
2. **Add source:** pick a common root or type a path; bounded in-root browser; choose folder; optional name, relative exclusions and schedule; explicit Add source. Manual schedule maps to null, not 0. Schedule is at least 60 seconds. Show selected scope before saving. Add does not automatically scan; the success state offers Scan now.
3. **Scan and review:** Scan now creates/adopts the source's job; poll reported progress; open Findings; inspect the redacted row and latest source coverage; mark Reviewed or Dismiss. Review mutations can be undone by selecting another annotation state.
4. **Manual credential save:** Add credential opens blank secret field. From a finding, title/location are prefilled and a finding link is shown. If credential vault is locked, first unlock it, then resume the metadata-only draft. Save is explicit, and cancel clears the secret. Editing metadata must preserve an unrevealed secret; an empty replacement secret means “leave unchanged”, not “erase”.
5. **Reveal/copy/lock:** reveal is an explicit action and transient; hide/close/navigation/lock clears sensitive values and revokes stale async responses. Copy is explicit. The product's precise reveal timeout and clipboard clearing policy are fixed in phase 2; do not promise an unconditional clipboard clear after another app has replaced it.
6. **Backup/restore:** backup asks for a separate backup passphrase and confirmation, then writes an encrypted file through an explicit save flow. Restore is available while the credential vault is locked/uncreated. Validate file and ask for backup/new-vault passphrases. Existing-vault replacement is a separate destructive confirmation; cancel changes nothing. Do not imply scan observations are backed up by credential backup.
7. **Plugin and Git:** reviewed wheel install → inspect/conformance → explicitly enable in a profile. Git Check guards → show selected repository and effective snapshot → explicit Install guards. Both are local workflows.

## States and recovery

| State | Presentation | Recovery |
| --- | --- | --- |
| Scan storage locked | Overview/Sources/Findings show a full in-page gate. Do not leave paths, findings or source counts behind. Credential vault and independent settings remain usable. Footer says Scan storage locked. | Unlock scan storage; warn before lock that scan work waits for safe shutdown. If lock fails because a slice is running, keep the displayed state truthful and show retry/status. |
| Credential vault locked | Vault shows one clear unlock card and Restore backup. Footer stays separate; scan jobs continue when scan storage is unlocked. | Unlock credential vault. Never offer keyring auto-unlock for credentials. |
| No sources / no jobs | Short empty state with Add source, or Scan now on an existing source. | No synthetic rows or zero-derived “safe” claims. |
| No vault entries | Add your first credential; optional Restore backup. | Add/restore remains explicit. |
| Backend disconnected | Persistent connection banner; connection state “Unavailable”. Clear sensitive reveals immediately. Replace backend-dependent panels with recovery state so stale data cannot look current. | Retry connection / diagnostic details; native restart policy is phase 2. Do not label the stores locked unless lock is confirmed. |
| Wrong passphrase | Error below passphrase field: “Passphrase was incorrect or storage could not authenticate.” Keep dialog open; clear passphrase. | Re-enter; preserve only nonsecret context. |
| Source offline / inaccessible | Status text, reason and incomplete coverage in source/job row; retain last successful scan time separately. | Reconnect/share permission, then Resume or Scan now when permitted. No mount-password form. |
| Scan storage capacity/checkpoint failure | Persistent error on affected pages and a stopped/failed job; preserve encrypted state. | Explain that progress could not be saved; stop new scans. Diagnostics/reopen; no automatic deletion or reset-store button. |
| Busy source removal | Inline “Current scan is stopping; try again when it has stopped.” | Do not hide the source before confirmed removal. |
| Findings cursor expired | Keep filter controls, discard page/selection and show a fresh-page action. | Reload first page with same filters. |
| Plugin/Git operation failure | Error remains beside affected item/dialog with stable code under Details. | Retry only after user acts; never mark success optimistically. |

## Tokens and component mapping

Machine-readable design tokens are in [tokens.json](tokens.json). Light mode is default; support System/Light/Dark. System mode follows the OS. Dark mode changes semantic surfaces, including alerts and grid, not a CSS inversion. Font: `-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`; monospace paths use `ui-monospace, SFMono-Regular, Consolas, monospace`.

Body 14/20px; secondary 12/18px; section 16/24px semibold; page title 24/32px semibold. Spacing 4/8/12/16/24/32px. Buttons/inputs 36px; dense table rows 40px. Radius 6px; surface radius 8px. Native windows provide their shadow; inside the app use borders and reserve elevation for dialogs/popovers.

Use MUI Drawer + ListItemButton (sidebar), Stack/Box (layout), Paper (surfaces), Button/TextField/Select/Checkbox/Switch (controls), Alert (persistent errors), Snackbar (noncritical confirmations), Dialog/DialogTitle/DialogContent/DialogActions (gated work), Tabs (page subviews), Chip (labeled status), Table (small source/job lists), LinearProgress indeterminate (active work), and AG Grid only for findings. No generic dashboard-card framework.

Accessibility: visible keyboard focus with 2px outline; labels on every input; names on icon buttons; semantic headings; errors associated with inputs; status text plus color; Escape cancels dialogs and returns focus to the trigger; dialog focus trap; single Enter action only where deliberate. Grid row Enter opens its inspector; keyboard-accessible close returns to the row. Respect 200% zoom, reduced motion, light/dark contrast and OS menu shortcuts. Truncated paths expose full text through keyboard-accessible detail, not only hover.

## Native shell UX intent

One main window; close hides it to the menu bar/tray while the owned backend continues. First close explains this once with an option to reopen Settings. Quit is explicit and performs safe owned-process shutdown. Menus expose Open Password Buddy, truthful storage/job status, Open Sources, Lock credential vault when available, Settings and Quit. Omit global Pause schedules: disabling a source is not equivalent to a reversible global scheduler pause. “Start at login” and lock-on-session-lock are phase-2 capabilities and must not be claimed before native validation.

Do not put finding text, source paths or credential names in notifications or tray status. Background readiness is distinct from “scheduler running”: the footer reports “Background after restart: Available / Unlock required / Unavailable” from verified scan-key availability and runtime state.

## Phase-2 issues carried forward

- Findings detail lookup currently scans only the first 1000 rows in each state. Preserve the selected page's redacted row as the inspector's source, or implement a bounded direct lookup contract; do not silently fail later-page rows.
- Findings endpoints return no total and host status has no aggregate coverage field. Derive only defensible overview summaries from sources and latest jobs.
- Source PATCH supports only enabled/schedule. No in-place root/exclusions editing.
- Credentials list omits username/notes; reveal and edit contracts must preserve that boundary.
- Restore replaces a store only when replace=true; design requires a concrete replacement confirmation.
- Native folder picker, file save, login, tray, lock events, app session recovery and standalone resource paths need explicit runtime contracts in phase 2.
- Exact dependency pins and native validation are implementation gates, not a claim made by this HTML mock.


## Prototype check

2026-10-26: JavaScript/DOM interaction check passed on devbox using an isolated
temporary jsdom runner: all six routes, four state previews, independent stores,
reveal then lock clearing, first-run storage creation, annotation and filtering.
No JavaScript errors. No QA dependency was added to the repository.

A headless Chromium attempt on devbox was blocked by missing native browser
libraries. This is a design artifact check, not native Electron acceptance;
rendered/native acceptance remains a product implementation gate.

