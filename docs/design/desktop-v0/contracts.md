# Desktop v0 — shared UI and native contracts

Frozen 2026-10-26. Coordinate any change with the root integrator before another lane consumes it. Existing `apps/buddy/src/leakguard_buddy/{server,backend}.py` is the source of truth for existing HTTP schemas; this document prevents the specific integration mismatches found during design.

## API client rules

Use same-origin fetch, credentials:same-origin, application/json bodies and X-Buddy-CSRF on POST/PATCH/DELETE. Parse errors as `{error:string}`, map known codes to helpful text, retain a stable code under Details and never show raw exception text or echo secrets. Abort stale GETs and fence all results by session/store/reveal generation. No source/finding/credential data in persisted UI state. Theme and nonsecret desktop preference keys may persist.

Ordinary blur (including a native file picker) clears revealed/copied payloads and fences pending reveals, but may retain masked form drafts. Lock, hide, navigation and disconnect clear all secret/passphrase form inputs as well. This avoids a backup file picker erasing an otherwise valid masked restore form.

Poll /api/status every 2 seconds while visible and 5 seconds hidden. Poll sources/jobs only while scan storage is unlocked; avoid overlapping polls and pause ordinary fetches while disconnected. Refresh the affected collection after acknowledged mutation, not optimistically. Do not turn temporary network failures into fabricated locked/empty states. Credential list is refetched after unlock/save/update/delete/restore; never poll reveal.

Known new server work for Sol shell:
- GET /api/session returns authenticated `{csrf,api_version:1}`.
- GET / index injects the style nonce and CSP specified in architecture.md.
- Stable owned-process/profile errors and existing lock errors must remain safe-code JSON; replace raw RuntimeError locked-store paths with BuddyOperationError as needed. Include worker-still-running, scheduler-failed, scan-progress-stalled and extension-private-runtime-required in safe error mapping where actually emitted.
- **No new finding detail endpoint required.** Luna renders the selected returned page row directly. Do not call existing GET /api/findings/:id, which currently searches only the first 1000 rows per state. Annotations remain by ID. This avoids a core-store rewrite.
- No source PATCH extension or global schedule API in v0.

## HTTP essentials

All paths are prefixed /api. “Object” below means the actual existing returned object, not an added envelope.

| Operation | Request | Response and UI notes |
| --- | --- | --- |
| Status | GET /status | {observations,vault,host,capabilities,worker_policy,detection_profile}. observations has created/unlocked/keyring_enabled/unattended_available/native_backend/keyring_error/startup_error/healthy/serialized_bytes/capacity_bytes; vault has created/unlocked. host has scheduler,active_job,pending_jobs,sources,storage_error,worker_error and limits. No host aggregate coverage. |
| Scan-store status | GET /observations/status | Same observation status object. Render capacity only when numbers are present. |
| Create/unlock scan store | POST /observations/create or /unlock {passphrase} | Observation status. New passphrases 12–1024 characters; UI confirm on creation. |
| Lock scan store | POST /observations/lock {} | {locked:true} only after safe stop. Do not clear lock status early; clear rendered source/finding data once lock confirmed, and clear sensitive reveals immediately on requested lock. |
| Scan keyring | POST /observations/keyring {enabled:boolean} | Observation status; keyring_enabled is not sufficient proof of unattended_available. |
| Root choices | GET /roots | Raw Root[]; fields name,path,kind,location_kind,status,selectable. Mounted roots initially unverified. |
| Browse | GET /browse?path=...&root=...&limit=100[&cursor=...] | {path,root,status,entries,next_cursor,truncated}; entry name,path,kind,status,selectable. An HTTP 200 may still report offline/directory-changed. Do not retain rows from changed directories. No symlink following. |
| Sources/jobs | GET /sources; GET /jobs | Raw Source[] and Job[], not {sources:[]} or {jobs:[]}. |
| Add source | POST /sources {root,label?,kind?,exclusions?,schedule_seconds?} | Source. kind local/mounted/unc; UNC capability gated. Omit empty label. Manual schedule null/omitted; positive schedules 60–31,536,000 seconds. UI presets manual/hourly/6-hourly/daily/weekly. At most 100 exclusion paths (host limit) although server parser accepts more. |
| Update source | PATCH /sources/:id {enabled?,schedule_seconds?} | Source. Only these keys; root/name/exclusions read-only after creation. |
| Remove source | DELETE /sources/:id {} | {deleted:true}; source-busy means wait for current slice, do not remove row yet. Evidence is retained. |
| Submit scan | POST /scans {source_id} | 202 Job; may return existing active source job. |
| Job control | POST /jobs/:id/pause, /resume, /cancel {} | Job. Buttons follow actual job state; cancelled != complete coverage. |
| Reveal path | POST /sources/:id/reveal {path} | Object with supported/path/status. Use backend's root-bound reveal; no generic native shell.openPath IPC. |
| Findings | GET /findings?state=current\|history&limit=100 plus filters/cursor | {findings:Finding[],next_cursor,state,coverage}. coverage may be null. Keep the entire returned page; filtering can return a variable row count. No total count or sort parameter. |
| Review annotation | POST /findings/:id/annotation {state:"unreviewed"\|"reviewed"\|"dismissed"} | Annotation object; do not change engine evidence state. |
| Vault status | GET /vault/status | {created,unlocked}, independent of observations. |
| Create/unlock vault | POST /vault/create or /unlock {passphrase} | Vault status. No keyring unlock. |
| Lock vault | POST /vault/lock {} | {locked:true}. Backend control pipe may independently lock it; next status invalidates all UI reveal state. |
| List vault | GET /vault/entries | {entries:CredentialMetadata[]}. Metadata is id,title,location,finding_id,created_at,updated_at only. |
| Save credential | POST /vault/entries {title,secret,username?,location?,notes?,finding_id?} | Credential metadata, never secret-bearing row. title <=256, secret/notes <=65,536, username <=2048, location <=4096. |
| Edit credential | PATCH /vault/entries/:id {title,secret?,username?,location?,notes?,finding_id?} | Credential metadata. Omit untouched sensitive fields; explicit clear sets username/notes empty. finding_id:null unlinks. Do not reveal just to edit title. |
| Reveal/copy | POST /vault/entries/:id/reveal or /copy {} | Full entry including secret,username,notes. Fetch only for explicit click; discard transient payload after native clipboard write or reveal timeout. |
| Delete credential | DELETE /vault/entries/:id {} | {deleted:true}; explicit confirmation names the selected entry without revealing its secret. |
| Backup | POST /vault/backup {passphrase} | {filename,backup_base64}, max decoded 16 MiB. Explicit native save dialog; no scan-state backup claim. |
| Restore | POST /vault/restore {backup,backup_passphrase,new_passphrase,replace?:boolean} | Vault status; decoded <=16 MiB. Restore while locked/uncreated works. Set replace:true only after existing-vault confirmation. A failed restore may leave vault locked; refetch status. |
| Plugin list | GET /plugins | {plugins,active_profile}; entries id,kind,version,api_version,profiles,sha256,has_conformance,enabled. enabled means enabled in active profile, not installed globally. |
| Install plugin | POST /plugins/install {filename,wheel,reviewed:true} | Plugin object; base64 reviewed .whl, raw <=48,000,000 bytes, basename validated. Install does not enable. |
| Plugin controls | POST /plugins/conformance {id}; /plugins/enable or /disable {id,profile} | Existing registry result. Conformance failure stays visible. Profiles explicit; list refresh after completion. No marketplace. |
| Git guards | GET /hooks/status?repository=... | {repository,hooks_directory,managed,profile,effective_config_path,worker_policy,base_config_path}. managed lists hook names. Empty != error. |
| Install/remove guards | POST /hooks/install {repository,profile}; /hooks/uninstall {repository} | Install includes installed hook names/profile/effective_config_path/worker_policy; remove includes uninstalled hook names. Recheck status after acknowledgement. |
| Settings | GET /settings; POST /settings {active_profile?,scan_workers?} | GET includes active_profile,profiles,worker_policy,scan_workers,max_file_bytes,scan_timeout_seconds. POST returns {settings,observations_locked,host_restarted}. Editable profile credentials/sensitive/firm and workers 1/2 only. |

Source fields: id,label,root,kind,exclusions,schedule_seconds,enabled,last_success_at,next_run_at,root_identity,mount_marker. Do not expose internal identity arrays as user content.

Job fields: id,source_id,state,created_at,updated_at,next_retry_at,attempts,slices,files_scanned,pending_files,pending_directories,coverage,last_error,report_id,policy_resets. State may be queued/running/paused/backoff/completed/cancelled/failed. Null pending counts mean unknown. Files checked is not a known denominator.

Finding filters: state, profile, rule (case-insensitive contains), severity (block/review/info), source (path contains), category (credentials/contact/financial-identifier/organization-identifier/firm/other), annotation, cursor, limit. When any filter changes, discard cursor stack/selection; Apply starts a new query. Cache previous pages/cursors only in memory; refresh starts at page one. If a filtered page is empty but next_cursor exists, show Next page.

Finding row optional fields: id,rule,severity,source.path,source_id,start_line,end_line,part_id,category,state,classification,last_verified,annotation.state,coverage. Unknown fields must not be invented. Coverage is latest source-job coverage attached by Buddy; absent is Unknown. Inspector uses the row, not a fetch that can omit late-page IDs. React text nodes render untrusted paths/rule names; never HTML.

## Renderer/preload boundary

Luna declares the following interface locally under `apps/buddy-ui/src/desktop.d.ts`. Sol implements it in preload; neither lane imports source from the other's directory. Availability is detected through `window.buddyDesktop`; browser mode keeps working without it.

```ts
interface BuddyDesktop {
  getInfo(): Promise<DesktopInfo>;
  bootstrapSession(): Promise<{ token: string }>;
  chooseDirectory(): Promise<{ canceled: boolean; path?: string }>;
  saveEncryptedBackup(input: { filename: string; base64: string }):
    Promise<{ canceled: boolean; saved: boolean }>;
  copySecret(input: { text: string }): Promise<{ copied: boolean }>;
  getPreferences(): Promise<DesktopPreferences>;
  setPreferences(patch: Partial<DesktopPreferences>): Promise<DesktopPreferences>;
  onEvent(callback: (event: DesktopEvent) => void): () => void;
}
type DesktopPreferences = {
  theme: "system" | "light" | "dark";
  startAtLogin: boolean;
};
type DesktopInfo = {
  protocolVersion: 1;
  appVersion: string;
  platform: "darwin" | "win32" | "linux";
  packaged: boolean;
  profileKind: "desktop";
  capabilities: {
    directoryPicker: boolean;
    encryptedBackupSave: boolean;
    nativeClipboard: boolean;
    startAtLogin: boolean;
    sessionLockEvents: boolean;
  };
};
type DesktopEvent =
  | { type: "navigate"; page: "overview" | "sources" | "findings" | "vault" | "plugins" | "settings" }
  | { type: "clear-sensitive"; reason: "hide" | "blur" | "idle" | "os-lock" | "suspend" | "disconnect" | "quit" }
  | { type: "vault-locked" }
  | { type: "backend-state"; state: "ready" | "unavailable" | "stopping"; code?: string };
```

All IPC validates sender webContents and top-frame exact origin, arguments, lengths and allowed keys. Never expose ipcRenderer, a raw event object, file read/write, arbitrary path open, shell, process, generic fetch or credential/session details through getInfo. copySecret accepts <=65,536 characters and only writes/conditionally clears; it cannot read clipboard to the renderer. Backup accepts only fixed safe filename and strict bounded base64, and writes solely to the user-chosen Save dialog path. DOM file inputs handle restore/plugin wheel selection; native IPC has no generic file reader.

Header native picker can select an exact root, but server browse still enforces the selected root. In browser fallback use existing /roots and /browse, download encrypted backup via explicit Blob link, and report clipboard unsupported/failure honestly. Do not load a test fixture in normal mode when an API call fails.

Native startup/recovery uses a shell-owned local error page before auth; it exposes Retry/Quit through a separate tightly scoped preload context, never the ordinary bootstrap IPC to an unvalidated about:blank/file URL. Simpler alternative: a native message box with Retry/Quit, then construct the BrowserWindow only after backend readiness. **Choose the native message box approach for v0**; it avoids a second renderer origin. First runtime preparation can show a native progress/status window without privileged web content, or delay main window with a clear native startup indication. No fake ready screen.

## UI build and dependency baseline

Exact versions verified from npm registry on 2026-10-26: react/react-dom 19.3.1; @mui/material/@mui/icons-material 9.5.0; @emotion/react 11.14.0; @emotion/styled 11.14.1; ag-grid-community/ag-grid-react 36.2.0; vite 8.3.5; @vitejs/plugin-react 6.1.2; typescript 7.0.2. Pin direct packages with no ranges and commit each lane's own lockfile. Include a pinned compatible @emotion/cache for nonce injection and matching React type packages. No monorepo root package lock/shared package edit required.

Luna owns `apps/buddy-ui/package.json`, lock, build script and generated flat static files. Build/typecheck output is produced on devbox. Production build must contain no prototype scenario toolbar, synthetic fixture rows, CDN references or sourcemaps. Hash routes (#sources etc.) avoid a Python SPA path fallback. Static nonce sentinel remains unexpanded in the wheel and is replaced only at request time.

Accessible MUI + AG Grid, truthful coverage, independent locks and explicit save/reveal/backup are acceptance requirements. Charts, docking, arbitrary source edits, global schedule pause, SSH GUI, service registration, automatic updates, existing-state migration and broad settings editors are deliberate v0 cuts.
