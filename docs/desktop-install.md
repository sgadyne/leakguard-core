# Password Buddy desktop v0

The desktop release contains Electron, its target CPython distribution, the
LeakGuard engine, reviewed dependency wheels and Gitleaks. End users do not need
Python, uv, Miniconda, npm or a developer checkout. Git is an OS prerequisite for
the optional per-repository Git guard workflow.

On macOS, expand the arm64 ZIP with Finder or `ditto -x -k`, move **Password
Buddy.app** to the desired location, then open it. The final artifact receipt
states its signing and native acceptance status. An ad-hoc signed build has no
Developer ID or Apple notarization claim.

On Windows x64, expand the whole application-directory ZIP and launch **Password
Buddy.exe** inside that directory. Keep its resources and other DLLs alongside
the executable. A cross-built artifact is **native Windows unverified** until a
Windows machine has actually run it. No Windows installer or service is created.

Linux x64 uses the complete application directory and its **Password Buddy**
executable. A runtime/API smoke check does not establish native tray or desktop
session behavior.

The desktop workspace is separate from an existing LeakGuard installation:

| Platform | Default desktop workspace |
| --- | --- |
| macOS | `~/Library/Application Support/Password Buddy` |
| Windows | `%APPDATA%/Password Buddy` |
| Linux | `$XDG_CONFIG_HOME/Password Buddy`, normally `~/.config/Password Buddy` |

First launch verifies the bundled payload, copies CPython into the workspace and
installs the exact offline wheel closure into a writable private venv. This can
take several minutes. App resources are never installation destinations. Moving
the application later keeps the same workspace and stable private runtime, so
its Git guard interpreter path remains stable.

Create encrypted scan storage to add sources and scan. The credential vault has
its own passphrase and can be created separately. Existing encrypted stores are
offered for unlock. Existing legacy state is neither copied nor migrated;
credential backup restore is an explicit workflow.

Closing the main window hides it while the owned backend continues. Reopen from
the menu bar/tray. Quit requests safe shutdown. A pending scanner shutdown stays
visible and retains its store ownership until it can finish.

Preparation failure preserves profile state. A different runtime identity is
reported as `runtime-migration-required`; v0 does not silently replace a runtime
or copy a plugin registry into a new venv. Keep the existing profile and receipt
for diagnosis. Do not delete encrypted stores or an active runtime as a repair.

For isolated acceptance, launch with an absolute, canonical, new profile path:

```sh
"/path/Password Buddy.app/Contents/MacOS/Password Buddy" \
  --buddy-data-dir /absolute/isolated/desktop-profile
```

The application rejects a symlinked profile root. An already owned profile is a
visible error; it is never attached to a legacy process. Start at login is off by
default and is offered only where the native implementation supports it.

## Build and validation

Build only from the clean integrated commit, after the UI and shell have been
committed. The builder invokes each project's locked npm build by default and
checks that `apps/buddy-ui/dist` is byte-identical to the three generated static
files entering the new Buddy 0.1.0a2 wheel.

```sh
python3 deploy/desktop/build.py \
  --target macos-arm64 \
  --runtime-input /prepared/cpython-3.13.13-macos-aarch64-none \
  --backend-input /prepared/macos-arm64/LeakGuard \
  --provenance /prepared/runtime-downloads.json \
  --output /new/empty/output
```

Other targets are `windows-x86_64` and `linux-x86_64`. `--stage-only` assembles the
same verified payload without Electron download/packaging. `--skip-js-build`
consumes already built integrated output; byte equality remains mandatory.
Release tooling is pinned to Node 22.23.2 and @electron/packager 20.3.0, with
Electron 45.0.0. Build-time npm downloads are distinct from offline first launch.

The output includes `artifact-receipt.json`, the resource
`desktop-manifest.json`, input provenance and (for a packaged artifact)
`artifact-files.json` and the application ZIP. The original alpha wheelhouse and
historical manifests are read-only inputs. All wheels except Buddy retain their
original bytes. The new Buddy wheel has newly generated metadata and RECORD.
Runtime archive URLs may be recorded without upstream archive hashes where
those hashes were not independently obtained; tree hashes identify the actual
prepared input bytes.

Run the small preparer checks and the exact built runtime journey:

```sh
python3 tools/check_desktop_bootstrap.py -v
python3 tools/check_desktop_runtime.py \
  --resources /built/resources/buddy \
  --work /new/isolated/runtime-check \
  --receipt /receipts/runtime-check.json \
  --browser-inputs /prepared/native-browser-inputs.json
```

The optional Chromium step uses the production static assets and real installed
API with a test-only bridge. It does not establish Electron IPC, native tray,
clipboard, login, macOS lock events or signing acceptance. The harness cleans
only directories it created after confirming its owned children exited. With
`--keep-profile`, encrypted fixture state remains for explicit inspection. A
failed safe stop retains that profile; the harness never kills by port or kills
a process tree.

## Mac signing order

The coordinator performs signing and native acceptance on a Mac. Preserve valid
upstream native signatures where possible. If native CPython/Gitleaks bytes must
be signed, sign them before sealing the payload, then run:

```sh
python3 deploy/desktop/seal.py \
  --resources "/path/Password Buddy.app/Contents/Resources/buddy" \
  --signing-label ad-hoc
```

The helper accepts only modifications to existing Mach-O payload files, updates
the Gitleaks backend hash when needed, records the changed native hashes in
provenance, and recomputes the closure and runtime identity. It does not sign or
claim notarization. Sign the outer app afterward, then regenerate the final ZIP,
application-file manifest and artifact SHA receipt. Accept the signed candidate
in a fresh profile because resealing changes its runtime identity. Never edit a
sealed payload after outer signing.

Native Mac acceptance must launch a relocated app without checkout/system
Python/uv, test restart with encrypted state retained, exercise hide/reopen/quit
and confirm owned-process exit. Record OS-lock receipt separately from simulated
handler tests. The coordinator does not lock the user's OS session without
coordinating the exact action.
