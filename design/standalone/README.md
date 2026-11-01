# Standalone workbench design reference

Built before the overnight implementation dispatch. Sampo is explicitly outside
this round. All screen data is synthetic; these are editable design references,
not screenshots proving that a workflow or metric already exists.

Open `preview.html` locally for the screen index. Import each SVG into Penpot as
an editable board. Penpot MCP was unavailable in the preparing session. The PNGs
are rendered review copies; do not implement the product as screenshots.

## Screens and behavior

| Board | Implementation intent | Required real states |
| --- | --- | --- |
| 01 / 10 Overview | Quiet shell, three truthful evidence cards, locations, last inspection, recent activity, next check. Light/dark pair. | Locked, reconnecting, stale, paused, no inventory, incomplete backfill. Unknown ages/counts are not zero. No global progress percentage with an unknown denominator. |
| 02 Findings | Keep server cursor paging; evidence inspector beside the table, drawer at narrower widths. Category, rule, reason, version and review action. | Filtered empty page with next cursor, no results, deleted/changed source, stale page, lock, read error. Never expose the underlying secret in list, search, DOM attributes or logs. |
| 03 Sources | Automatic This Mac remains first-class. Separate discovery from inspection. Show explicit SSH locations and per-source schedule overrides. | Unavailable remote, identity changed, read denied, retry, paused, partial page, unsupported parser. No automatic network-wide discovery. |
| 04 Settings | Protection / Storage / Appearance / Advanced sections; one recognition configuration surface; a field-by-field change preview. | Dirty edit, stale preview, unavailable capability, preflight failure, rollback. Keep native key access, login and vault controls distinct. “15 minutes” is an illustrative edit, not a changed default. |
| 05 Vault | Independent lock state; deliberate review -> save -> verify -> recheck flow. | Lock/unlock, duplicate, cancel, write failure, changed source, clipboard cleanup. Never imply source deletion or automatic centralization. |
| 06 Activity | Existing job/run history made readable; optional measured diagnostics/stages. | No stage data -> “Not measured”; unknown/failed vs complete; selected vs inspected; recovered failure visible. Do not animate fabricated pipeline progress. |
| 07 Add location | Drawer with label, existing SSH alias, directory, bounded check, then add. | Add disabled until current fields have a successful check; edits invalidate that check. Existing keys/host trust only. |
| 08 State patterns | Consistent illustration, explanation and next action for lock, offline, no matching rows and no additional locations. | A missing backend is never represented as an empty successful scan. |
| 09 Plugins | Installed components, capabilities, profile provenance and explicit configuration. | Missing required wheel / failed preflight / untrusted wheel. Unsupported features are explanatory text, not working-looking toggles. |

## Shared components and assets

Use existing React 19, MUI 9 and AG Grid. No new UI framework, icon runtime or
animation dependency is required. Prefer small named components over further
growth of `App.tsx` and the existing `any`-typed settings components:

- `AppShell`, `PageHeader`, `StorageGateStatus`, `ConnectionBanner`.
- `EvidenceMetric`, `CoverageSummary`, `SourceStatus`, `ScheduleSummary`.
- `FindingInspector`, `ReviewActions`, `RunReceipt`, `ProfileChangeSummary`.
- `EmptyState`, `InlineError`, `ConfirmAction`, shared row/button/chip styles.

`tokens.json` and `tokens.css` define colors, typography, spacing, focus, radii and
motion. `icons/` contains 16 editable stroke icons; `illustrations/` contains four
empty-state assets. The existing three-key family in `../brand/` supplies identity.
Prefer current MUI icons where adequate; these assets define consistent styling.

### Layout, interaction and accessibility

- At >=1200px use a side inspector; below it use an accessible drawer. Preserve
  keyboard row activation and focus return. Test 1440x930, 1280x820 and 1000x680.
- Allow long paths and translated-length strings to wrap/truncate with deliberate
  accessible disclosure. No horizontal page scroll at the native minimum width.
- 14px body / 12px secondary text, 28px page heading; compact labels can be 11px.
  Screenshot label sizing is illustrative; do not shrink functional text to fit.
- Every status has a label/icon as well as color. Empty, unknown, unavailable and
  zero are separate states. Check text contrast and focus visibility in both themes.
- Buttons have pending states and reject duplicate mutations; errors preserve
  recoverable input. Keyboard Escape closes a drawer without losing unsaved edits
  silently. Confirm/cancel semantics must be explicit where existing workflows need it.
- Use 120–160ms opacity/position transitions only where helpful. Honor reduced
  motion, avoid continuous decorative animation and never animate scan progress
  when the underlying metric is unknown.
- Keep the nonce-based CSP, authenticated loopback API, desktop context isolation,
  clipboard clearing and independent locks. Do not add remote fonts or telemetry.

## Binding the drawings to real data

The board counts, paths, times and sources are fixtures. Production must use the
authenticated backend. Page counts cannot be relabelled as global totals. Render
optional new evidence fields only when their schema/semantics are available;
otherwise say “Not measured” or hide the optional panel. The overnight shared
contract lives in `../../docs/standalone-overnight/CONTRACT.md`.

The UI worker may rearrange the design for real data and native constraints. It
must preserve functions already in Sources, Settings, Plugins, Git guards,
encrypted storage relocation and VM browsing rather than drop them to match a
picture. Do not add unsupplied demo facts to the application bundle.

## Reproduce

Run `node tools/brand/standalone.mjs` after the pinned `tools/brand` dependencies
are installed. `manifest.json` records hashes of all generated references and
assets. Product integration should import only the needed assets/tokens, not this
preview gallery, whole SVG boards, or mock data.
