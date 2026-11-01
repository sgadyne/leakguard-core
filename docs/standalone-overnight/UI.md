# UI lead queue

Model: Sol xhigh. Implement in the assigned ILMR UI box, on its own branch. Use
the complete `design/standalone` reference and `design/brand` assets prepared by
root before dispatch. Read the shared README and contract first.

## U0 — freeze behavior and build inputs

Inventory current routes, actions, lock/scrub behavior and data sources. Record
which screens/actions already exist. Build current pinned UI/shell once and record
the starting SHA. Keep React/MUI/AG Grid; avoid an unrelated dependency migration.
Prepare an isolated synthetic browser/backend profile and finite process cleanup.

## U1 — shell and visual system

Implement shared tokens, light/dark appearance, three-key identity, calm sidebar,
headers, panels, semantic status components, consistent controls and empty states.
Keep desktop tray template and ICNS packaging wiring. Refactor presentational code
into focused components; preserve nonce-based styles and no remote asset requests.
At 1000x680 there must be no clipped controls or horizontal document overflow.

## U2 — Settings and preview/apply

Consolidate conflicting profile controls into a single authoritative surface.
Organize Protection, Storage, Appearance and Advanced without losing existing
Git guard/plugin/native settings. Display changed fields and provenance before
advanced JSON. Preserve source overrides, independent lock settings, trusted pack
requirements, stale-preview rejection and rollback. Do not change hourly default
cadence just because the wireframe contains an illustrative 15-minute edit.

Required browser flow against real backend: apply a custom two-alias pack and
schedule, reload, verify persistence; reject invalid JSON and unsupported event
capability; reject a stale preview; verify previous settings survive failed apply.

## U3 — Findings, sources and vault handoff

Preserve exact server cursor paging, filters, page-vs-global count semantics,
value-free provenance and keyboard inspector activation. Do not expose secrets in
DOM attributes, browser logs or screenshot fixtures. Review/dismiss remains an
annotation, not a content exclusion. Vault save remains deliberate and never
claims source removal. Existing source actions and VM directory navigation remain.

Required browser flow: add a synthetic source, inspect a synthetic positive and
negative, open inspector, review/dismiss, cancel vault save, unlock/save/verify the
synthetic entry, lock each store independently, reopen and verify annotations.
Show offline/failed/locked states and preserve input through a recoverable error.
For SSH use controlled synthetic fixtures/protocol mocks in ILMR, not a real user
filesystem. A mock proves presentation/error mapping, not live remote operation.

## U4 — Overview and Activity

Use current source/job fields and the optional additive inspection evidence
contract. No fabricated queue age, global totals, last inspection, stage progress
or clean score. Missing projection renders Not measured. If a metric cannot be
implemented truthfully, leave its optional panel out and name the limitation.

Activity is a projection of recorded work; it must distinguish a finished slice
from finished backfill. Scope actions to current source/run IDs and reject stale
state. Error text uses bounded approved codes and helpful next steps.

## U5 — evaluation and handoff

- Typecheck and production build UI/shell; copy exact built UI into shipped static
  assets. Verify no design gallery or synthetic mock dataset ships as live data.
- Browser checks at 1440x930, 1280x820 and 1000x680, light/dark. Capture actual UI
  screenshots for Overview, Findings, Sources, Settings preview, Vault locked and
  Activity. Keyboard-only drawer open/close, focus return, visible focus, reduced
  motion and semantic status labels. Check console/network errors.
- Screenshot fixtures always use synthetic values and private temp profiles.
  Browser evaluation may use test automation against the owned test app; no live
  user browser profile, installed Mac app, keychain or vault changes.
- List any visual/interaction difference from the reference and why. Fix actual
  failures, not just snapshot expectations. No broad screenshot-only test suite.
- Commit small coherent chunks, hand commit IDs/contract dependencies to engine
  lead, export bundle and report. Stop early if done; no extra feature scope.

Native Mac smoke and packaged-app signature/identity qualification are morning
gates for root, unless a separate currently authorized Mac run is arranged. Do
not describe Linux browser evidence as a new distributed Mac build.
