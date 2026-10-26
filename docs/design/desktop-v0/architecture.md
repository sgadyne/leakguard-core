# Desktop v0 — architecture freeze

Decision: 2026-10-26. Phase 1 is accepted at `5c1eca1`. This is the phase-2 dispatch contract, not another approval gate. Build on devbox, integrate in the coordinator's worktree, then perform native Mac acceptance in an isolated profile. Product behavior is specified in [README.md](README.md), UI boundaries in [contracts.md](contracts.md), and ownership/checkpoints in [tasks.md](tasks.md).

## Runtime shape

Electron owns one main window, tray/menu-bar item, single-instance control, native dialogs, clipboard lifetime, login preference and the process it launches. Python Buddy owns authentication, sources, jobs, scan storage, credential vault, plugin installation and Git guards. React is an ordinary same-origin client of Buddy's HTTP API. No business logic moves into Electron.

The app uses a new, separate **Password Buddy desktop workspace**. It never discovers, attaches to, stops, copies or migrates a running legacy LeakGuard/Buddy installation. First run says: “This desktop workspace is separate from your existing LeakGuard installation. You can explicitly restore a credential backup here.” No automatic observations migration. Legacy files and completed runs remain untouched.

Default data root is `app.getPath("appData")/Password Buddy`, set as Electron userData before single-instance acquisition. Typical paths are macOS `~/Library/Application Support/Password Buddy`, Windows `%APPDATA%/Password Buddy`, Linux `$XDG_CONFIG_HOME/Password Buddy` (usual fallback `~/.config`). Native acceptance uses an explicit absolute `--buddy-data-dir PATH` override under the coordinator's temporary acceptance directory. The override selects the entire desktop profile, never the old LeakGuard state directory. Resolve/canonicalize and reject symlinked profile roots. No UI “open arbitrary old state directory” in v0.

```text
<desktop-data>/
  desktop-preferences.json            # theme/login/first-close only; no secrets
  profile/
    desktop-runtime.json              # manifest identity; no auth material
    state/
      config.json                     # installer-owned base config, preserved on reuse
      observations.lgo                # existing encrypted observation format
      credentials.lgv                 # existing encrypted credential format
      .buddy-owner.lock               # held OS lock, not a PID-file assertion
      buddy-config.json, buddy-active-config.json, extensions/, hook-profiles/
  runtimes/<runtimeId>/
    python/                           # stable private copy of bundled base interpreter
    engine/
      active.json                     # existing installer layout/name is authoritative
      releases/<backendRelease>/venv/  # writable private venv for reviewed plugins
      releases/<backendRelease>/...    # wheelhouse, backend, manifests, deploy/support
```

The exact existing installer receipt/active filename must be read from installer output; shell must not reconstruct internal installer filenames. The conceptual `active.json` above is not a new file-format requirement. No profile encryption key/passphrase/session cookie/CSRF token/credential reveal goes in desktop preferences, process arguments, environment, URLs or logs.

Use Electron's single-instance lock after choosing userData. A second launch shows the first window and never starts a second backend. Also add a backend-wide nonblocking OS ownership lock acquired before Buddy config/registry writes; it remains held for the lifetime of each new Buddy process, including locked stores. Reuse the repository's cross-platform lock primitive or a similarly narrow stdlib implementation. Profile-in-use is a visible error, not stale-lock-file deletion. No attachment fallback.

## Immutable bundle and private runtime

Package the app as `Password Buddy`, Electron version `0.1.0-alpha.1`, app id `org.leakguard.passwordbuddy`. Use Electron 45.0.0 and @electron/packager 20.3.0. Node 22.23.2 on devbox meets their >=22.12 requirement. No updater in v0.

```text
<resources>/
  app.asar                            # compiled main/preload and their assets
  buddy/
    desktop-manifest.json             # schema below
    bootstrap.py                      # stdlib-only runtime preparer
    python/                           # target-specific relocatable CPython tree
    backend/LeakGuard/
      release.json
      deploy/{installer.py,default-config.json,release-manifest.json,...}
      wheelhouse/*.whl
      backends/<target>/gitleaks[.exe]
      support/...
```

`process.resourcesPath/buddy` is the only packaged resource root. All native Python and Gitleaks files live outside ASAR. In un-packaged development only, `BUDDY_DESKTOP_RESOURCES` may select a staged resource directory with the same manifest/layout. No implicit developer checkout, system Python, global venv or Miniconda fallback.

The release agent owns `bootstrap.py`. The shell launches the manifest-selected bundled interpreter with argument array, never a shell:

```text
<resources>/buddy/<pythonExecutable> -I -X utf8
  <resources>/buddy/bootstrap.py
  --resources <resources>/buddy
  --data-dir <desktop-data>
```

Manifest schema 1 uses camelCase, exact target labels `macos-arm64`, `windows-x86_64`, `linux-x86_64`:

```json
{
  "schemaVersion": 1,
  "desktopVersion": "0.1.0-alpha.1",
  "protocolVersion": 1,
  "target": "macos-arm64",
  "pythonVersion": "3.13.13",
  "pythonExecutable": "python/bin/python3",
  "backendBundle": "backend/LeakGuard",
  "backendRelease": "desktop-0.1.0-alpha.1",
  "runtimeId": "<sha256-of-runtime-and-backend-inputs>",
  "sourceCommit": "<integrated-commit>",
  "files": [{"path": "<relative-path>", "sha256": "<hash>", "mode": 493}]
}
```

Use each target's real interpreter-relative path (`python.exe` for the Windows tree); no guessed POSIX path on Windows. Manifest entries cover immutable payload files; preserve validated in-tree symlinks for the Python distribution and reject escaping symlinks. Record the original upstream runtime/archive hashes and backend-wheel provenance separately. The build does not overwrite historical alpha manifests.

Preparation verifies the bundled closure, copies base Python into the stable `runtimes/<runtimeId>/python` location, and invokes the existing offline installer **with that copied interpreter**, explicit root `runtimes/<runtimeId>/engine` and explicit state `profile/state`. Use the existing installer to create its private venv and install exact wheels. The base interpreter alone is insufficient: ExtensionRegistry requires `sys.prefix != sys.base_prefix`, and reviewed wheel installation needs writable venv site-packages and pip. Stable userData paths also keep installed Git hooks independent of where the .app is moved.

The preparer must use native `venv/ensurepip` and bundled wheel closure without discovering or depending on uv/system Python; constrain installer environment so an unrelated PATH uv cannot select another runtime. Git can remain an OS prerequisite for Git-only features. No service registration, global shortcut, mount, login setting or user shell/PATH change occurs during preparation. Existing installer private launchers under the explicitly selected root are acceptable. Repair only owned incomplete staging; never delete profile state or an active runtime.

Preparation emits bounded JSON lines: `{"type":"progress","stage":"copying-runtime"|"installing-backend"|"checking-runtime"}`, then exactly one `{"type":"runtime-ready","protocol":1,"runtimeId":"...","python":"<absolute venv interpreter>","stateDir":".../profile/state","config":".../profile/state/config.json"}`. Errors are `{"type":"error","code":"stable-code"}`; capture/sanitize installer output instead of forwarding arbitrary subprocess output. Main validates response paths remain within its selected data root. Allow up to 10 minutes for first installation with progress and explicit failure, then reuse the validated receipt without reinstalling or erasing user plugins.

New Buddy code is built as **leakguard-buddy 0.1.0a2**, including the generated React static files. Sol shell owns that version bump. Release agent replaces the old Buddy wheel and regenerates desktop release metadata; no source overlay over an old wheel's RECORD. Preserve existing core/host/vault wheel bytes and hashes unless the coordinator explicitly integrates an engine fix. Original alpha.5 files are immutable inputs.

No automatic runtime upgrade/migration is part of v0. Reusing the same manifest keeps the same private venv and plugin installs. If an existing desktop profile records a different runtimeId, refuse silent migration/reinstallation and show a retained-data diagnostic; a future explicit migration must handle registry/plugin compatibility. Do not copy an old registry into a fresh venv and pretend its enabled plugins exist.

Inputs already prepared on devbox:
- `/home/dev/projects/leakguard-desktop-v0-20261026/runtime-inputs/cpython-3.13.13-macos-aarch64-none`
- Equivalent `cpython-3.11.16-windows-x86_64-none` and `cpython-3.11.16-linux-x86_64-gnu`.
- `/home/dev/projects/leakguard-desktop-v0-20261026/bundle-inputs/<target>/LeakGuard`; coordinator's `bundle-inputs.json` records alpha ZIP hashes.
- Source ZIPs: `/home/dev/projects/leakguard-alpha-20261026T001800Z/artifacts/LeakGuard-alpha5-FINAL-attempt2/bundles/`.

Confirm actual directories before use; do not download replacements unnecessarily. ZIP extraction may discard executable modes. Restore Python/Gitleaks/launcher executable bits from the source archive/manifest. Coordinator has natively verified relocated Mac Python, SQLite serialize, private venv creation and pip. This is feasibility evidence, not final app acceptance.

## Backend process and private control channel

After runtime-ready, shell spawns:

```text
<venv-python> -I -X utf8 -m leakguard_buddy.desktop
  --state-dir <receipt.stateDir> --config <receipt.config>
```

Explicitly set LEAKGUARD_STATE_DIR/LEAKGUARD_CONFIG to the same values. Remove inherited PYTHONHOME/PYTHONPATH and developer injection variables; no passphrase/token in env. Working directory is the private profile, not a scanned folder. Inherit only required OS/home/temp/locale/PATH state; backend code controls subprocess commands without shell execution.

Add `leakguard_buddy/desktop.py`, owned by shell agent. It constructs BuddyBackend and LocalBuddy with **no browser launch file**, binds an ephemeral IPv4 127.0.0.1 port, and keeps stdin/stdout as an inherited parent-only control pipe. It does not modify CLI/browser entry behavior except shared ownership/error fixes.

JSONL protocol version 1, max 16 KiB per line. Ready: `{"type":"ready","protocol":1,"origin":"http://127.0.0.1:<port>","pid":123,"apiVersion":1}`. The ready line contains no token. Requests: `{"id":1,"op":"bootstrap"|"status"|"lock-credentials"|"shutdown"}`. Responses: `{"id":1,"ok":true,"result":{...}}` or `{"id":1,"ok":false,"error":"stable-code"}`. Reject unknown op/fields; no arbitrary method execution. Serialize control mutations with backend's existing lock.

- bootstrap rotates LocalBuddy's bootstrap token/digest under session_lock and returns `{"token":"..."}`. This response is private, transient and never logged.
- status returns only scan/vault created/unlocked flags, scheduler state, pending job count, background readiness and stable error codes. No finding/credential/source content.
- lock-credentials invokes credential_lock; acknowledges confirmed locked state.
- shutdown performs the safe sequence below and exits only after success.
- stdin EOF (parent death) initiates the same safe shutdown. Do not promote the process into a persistent external service.

Do not log raw stdout, requests, responses, stderr or exceptions. Protocol parsing errors yield stable generic diagnostics. No generic “execute”, API proxy or shell command in the control channel.

## Authentication and serving

Renderer loads exactly the child's validated `http://127.0.0.1:<port>/`. It does not load file:// UI, Vite dev server, remote content or a token-bearing URL in desktop mode. Main validates the ready origin using URL parsing: scheme http, hostname exactly 127.0.0.1, integer port, no credentials/path/query/fragment.

Preload `bootstrapSession()` asks the owned child for a fresh single-use token, and returns it only to this main window's top frame at the exact assigned origin. React POSTs `/__bootstrap` with `{token}` and receives the existing HttpOnly SameSite=Strict cookie and JSON CSRF value. CSRF is memory-only. Mutations use JSON, exact same origin and X-Buddy-CSRF; credentials stay in same-origin cookies. Keep existing Host/Origin/Sec-Fetch-Site/body validation.

Add authenticated `GET /api/session` returning `{"csrf":"...","api_version":1}` for reload/session recovery in both desktop and browser modes. No unauthenticated CSRF/bootstrap disclosure. Desktop 401 session-required/expired triggers one rebootstrap and fresh GET reload; do not automatically replay a mutation. Browser compatibility consumes its existing #bootstrap fragment once, immediately removes it with replaceState, then uses this same client. No auth tokens in localStorage/sessionStorage.

Vite output is exactly `index.html`, `app.js`, `app.css` in existing `apps/buddy/src/leakguard_buddy/static/`. One JS entry/chunk, no dynamic chunks, no external fonts, no sourcemaps in release. Inline bundled SVG/data assets where needed. Build fails if extra served assets appear. Keep the Python flat static whitelist; do not add arbitrary directory serving or path resolution. Luna owns static output and contains `<meta name="buddy-style-nonce" content="__BUDDY_STYLE_NONCE__">` exactly once in the HTML template.

Python generates a fresh nonce on each index response, replaces that exact sentinel, and sets:
```text
default-src 'none'; script-src 'self'; style-src 'self';
style-src-elem 'self' 'nonce-<nonce>'; style-src-attr 'unsafe-inline';
connect-src 'self'; img-src 'self' data:; font-src 'self';
object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
```
Retain no-store, nosniff, no-referrer and frame denial headers. React passes the meta nonce to Emotion createCache and AG Grid styleNonce. No inline script/InitColorSchemeScript, eval, string-expression grid functions, CDN or Google-font loader. Inline style attributes are permitted specifically for MUI/grid dynamic positioning; script restrictions stay strict.

Electron: contextIsolation=true, sandbox=true, nodeIntegration=false, webSecurity=true, no webview. Deny all permission requests/checks, popups and remote navigation. Same-document fragment routing is allowed; external links do not open automatically. Constrain session requests to the assigned origin and required data images; disable downloads except the narrow explicit backup-save path. Use an ephemeral session partition so cookies do not persist across app restarts. Disable devtools in packaged normal mode. No remote-debugging port in normal release.

## Native behavior and safe shutdown

Close hides the window and locks the credential vault; scan storage and scheduler continue. First close shows one short explanation. Tray menu: Open Password Buddy, sanitized status, Open Sources, Lock credential vault (enabled only when unlocked), Settings, Quit. No global schedule pause, remote deploy or background scan-all shortcut.

On window hide, suspend, and macOS/Windows lock-screen events, main immediately tells the renderer to clear sensitive state and independently sends lock-credentials to the owned backend. Also lock after 5 minutes OS idle; do not unlock automatically. On Linux, advertise only supported idle/suspend behavior, not unverified session-lock events. Lock acknowledgements determine UI status; a pending/failing lock must not be displayed as success. Revealed UI values hide after 30 seconds, navigation, blur, lock or disconnect. Async generation fencing prevents a late reveal response from repopulating cleared state.

Explicit Copy writes through narrow native IPC, then clears after 30 seconds **only if the clipboard still contains that exact copied value**; never clobber a later clipboard value. Clear owned clipboard on lock/quit under the same condition. Browser mode uses its existing clipboard capability/failure handling and makes no false guarantee.

Start at login is an explicit opt-in, default off, shown only on packaged macOS/Windows where Electron login-item APIs are supported. Save via setLoginItemSettings, read back via getLoginItemSettings, expose failure truthfully. Launch with --background; if setup/unlock is needed, show the window instead of claiming unattended readiness. Moving the app can require re-enabling login. Linux start-at-login and automatic updates are out of v0. Capability presence and native test evidence are different fields in release documentation.

Quit first clears renderer secrets, marks backend quiescing to reject new mutations/reveals, waits for in-flight operations, and invokes backend.close while retaining HTTP/control availability for a retryable failure. Only after host.stop confirms no worker owns the observation store may the store close; then stop/drain HTTP and release ownership lock. Do not hold the backend lock while server_close joins request threads. Return/exit after success. Main waits for the owned ChildProcess exit, then quits Electron. If worker-still-running, retain the process/store/lock and show “Waiting for the current scan to stop” with Retry; never call app.exit or SIGKILL on a timer. A bounded normal timeout is a reported failure, not permission to discard ownership. No kill-by-port, PID-file kill, taskkill tree or external-service stop. Use the same behavior for OS quit where the OS permits; forced OS termination can only recover the last durable checkpoint on next launch.

## Verification and distribution truth

Mac deliverable: self-contained arm64 .app ZIP, payload manifest, SHA256, separate native acceptance receipt, and launch/install instructions. Root may apply ad-hoc signing as a final Mac packaging step and must record it; no claim of Developer ID signing/notarization without an identity. Runtime copying must preserve signatures/execute modes for native files. Verify from a relocated app path on Simon's Mac without developer checkout, uv, system Python or legacy Miniconda paths.

Windows: self-contained win32-x64 app-directory ZIP with Python 3.11 and native dependency closure. Build and inspect on devbox; label **native Windows unverified** until actually executed on Windows. No installer/service/keychain claim from cross-compilation alone. Linux may ship a corresponding x64 directory/tar artifact if the closure is built and smoke-tested; native desktop/tray capability depends on the target session.

Official references checked 2026-10-26: [Electron security](https://www.electronjs.org/docs/latest/tutorial/security), [powerMonitor events](https://www.electronjs.org/docs/latest/api/power-monitor), [login item APIs](https://www.electronjs.org/docs/latest/api/app#appsetloginitemsettingssettings-macos-windows), [MUI CSP/nonces](https://mui.com/material-ui/guides/content-security-policy/), [AG Grid CSP/styleNonce](https://www.ag-grid.com/react-data-grid/security/). Existing repository APIs remain the authority for engine semantics.
