# LeakGuard alpha install

LeakGuard alpha installs under the current user's account. It needs Python 3.11
or newer. Install does not require administrator rights, enable Git hooks, or
remove user data. The runtime uses a private virtual environment and each
version remains in its own release directory.

## Build an offline bundle

Build one wheelhouse per target OS, CPU architecture, and Python ABI. Native
packages such as cryptography and psutil need wheels compatible with that target.
The release manifest pins the direct distribution versions; the builder records
the complete wheel closure and SHA-256 for each wheel.

From the reviewed integrated source checkout, build the local package wheels into
an empty revision-specific wheelhouse (the example path must not already exist),
then download the pinned public dependencies and the transitive closure declared
by those local wheel metadata files:

```sh
mkdir -p artifacts
mkdir artifacts/wheelhouse
python -m build --wheel --outdir artifacts/wheelhouse .
python -m build --wheel --outdir artifacts/wheelhouse packages/leakguard_host
python -m build --wheel --outdir artifacts/wheelhouse packages/leakguard_vault
python -m build --wheel --outdir artifacts/wheelhouse apps/buddy
python -m build --wheel --outdir artifacts/wheelhouse plugins/sensitive_basics
python -m build --wheel --outdir artifacts/wheelhouse templates/firm_plugin
python -m pip download --only-binary=:all: --dest artifacts/wheelhouse \
  pip==26.2.2 cryptography==50.0.2 keyring==25.7.0 psutil==7.2.2 cachetools==7.2.5 \
  pypdf==6.21.2 olefile==0.47 'packaging>=24,<27'
python -m pip download --only-binary=:all: --no-index \
  --find-links artifacts/wheelhouse --dest artifacts/wheelhouse \
  'leakguard-core[documents]==0.2.1a3' leakguard-host==0.2.0 leakguard-vault==0.1.0 \
  leakguard-buddy==0.1.0a1 leakguard-sensitive-basics==0.1.0 \
  leakguard-firm-example==0.1.0
```

The complete Buddy bundle pins the optional document parsers separately from
the core package: `pypdf==6.21.2` and `olefile==0.47`. This keeps the documents
extra optional for standalone core installs while preserving PDF and Outlook
MSG extraction in the offline alpha runtime. The builder records each parser
wheel's SHA-256 and the installer doctor checks both installed versions.

The two plugin wheels are included as reviewed code but remain disabled until
the user explicitly installs or enables a profile. Keep plugin artifacts in
the same wheelhouse so their metadata and hashes are recorded in the bundle.

The release needs the native Gitleaks executable for each complete target. The
builder records its SHA-256 and exact version. The installer runs the backend's
version command before activation and pins its absolute path in private config,
so it never depends on an ambient `PATH`. Use `--partial` only when that target
backend is unavailable; doctor reports the release as partial and Gitleaks as
unavailable. Labels use `linux-x86_64`, `macos-arm64`, or `windows-x86_64`
(also `macos-x86_64` where needed). Build and hash the release archive with:

```sh
python deploy/build_bundle.py \
  --wheelhouse artifacts/wheelhouse \
  --output artifacts/LeakGuard-0.2.0-alpha.2-linux-x86_64.zip \
  --source-commit "$(git rev-parse HEAD)" \
  --target-platform linux-x86_64 \
  --target-python 3.11 \
  --backend-artifact linux-x86_64/gitleaks=/path/to/pinned/gitleaks
```

Build the wheelhouse and run `build_bundle.py` under the exact target Python
minor version, and pass it with `--target-python`. The archive records that
version. Installation rejects a different Python minor before it creates the
versioned runtime; a CPython 3.11 wheelhouse therefore cannot be selected with
Python 3.13 just because both satisfy the package's minimum requirement.

The command prints the bundle SHA-256. Keep that digest with the archive when
transferring it through an offline corporate channel. The builder refuses a
missing or mismatched pinned distribution. Its manifest contains every wheel
and backend hash and verifies package name and version from wheel metadata
before install. It also includes a hash-indexed `support/` tree with the install
guide, alpha limits, worker policy, firm setup instructions, script example,
and reviewed firm-plugin starter/promotion fixtures. The installer copies that
tree to the immutable release beside `wheelhouse/`; it is not installed as
executable code. A complete install creates its private venv at the final
immutable release path, verifies pip for reviewed local extension installs,
and runs installed console-script help plus a short loopback Buddy startup
check before activating the release.

## Linux and macOS

Extract the archive and run the platform bootstrap from its `LeakGuard` folder:

```sh
unzip LeakGuard-0.2.0-alpha.2-linux-x86_64.zip
cd LeakGuard
./deploy/install.sh
```

The script uses `python3`. If Python's `venv` module has no `ensurepip`, install
`uv` for the current user or use a Python build that includes `ensurepip`. The
runtime is created directly at its final versioned path and all wheel
installation runs offline. The selected interpreter's minor version must match
the bundle metadata; if `python3` selects a different minor, choose one
explicitly with `PYTHON=/path/to/python3.11 ./deploy/install.sh` (use the
version recorded in that bundle). On Linux, add `~/.local/bin` to `PATH` if
needed.
The Buddy shortcut is also written to the user's application menu.

For a native macOS alpha install, new configs use the explicit
`supervised-alpha` worker policy. When migrating an existing macOS config, the
installer adds that policy only if `worker_policy` is absent. It preserves an
existing valid `strict` or `supervised-alpha` choice during updates and
rollback, and rejects an invalid value instead of silently replacing it.
Doctor reports the selected policy. On every platform, the installer preserves
other existing settings while selecting the encrypted observation backend at
`state/observations.lgo`; an unavailable key keeps observations ephemeral
rather than falling back to a plaintext database.

## Windows

Extract the archive, then run PowerShell as the current user:

```powershell
Expand-Archive .\LeakGuard-0.2.0-alpha.2-windows-x86_64.zip .\LeakGuardBundle
& .\LeakGuardBundle\LeakGuard\deploy\install.ps1 `
  -BundleDirectory .\LeakGuardBundle\LeakGuard
```

The bootstrap reads the bundle's target Python version and uses the matching
Python launcher selector (for example `py -3.11`); it installs under
`%LOCALAPPDATA%\LeakGuard`. It adds Buddy, Buddy Open, Doctor, and Manage
commands to the user's Start Menu. From PowerShell, service actions are also
available through
`& "$env:LOCALAPPDATA\LeakGuard\bin\leakguard-install.cmd" service enable`.
Windows scripts are supplied with the alpha bundle; Windows is unverified until
a native install journey completes. If a Windows Gitleaks binary is not in the
bundle, the release must be explicitly marked partial and doctor will report
that backend as unavailable.

## First launch and local checks

Run `leakguard-buddy` from the user's bin directory or use the installed Buddy
shortcut. The `leakguard` command launches the CLI with the same private config
and state paths. Run `leakguard-doctor` for the exact package versions,
SQLiteScanStore's actual in-memory serialize/deserialize path, selected
Gitleaks executable and hash, native execution capability map, and verified
observation-keyring status from the installed runtime. Doctor does not unlock
credentials or write a keyring probe.

To run Buddy after login without opening a browser, enable its per-user service:

```sh
leakguard-install service enable
leakguard-install service status
```

Use **LeakGuard Buddy Open** from the user's app menu (or
`leakguard-buddy-open`) to consume the one-time browser bootstrap URL written by
the service. Disable the service with `leakguard-install service disable`.
When a verified observation key is unavailable, the service can remain locked;
unattended scanning stays unavailable until the encrypted observation store
reports a usable native key. Credentials still require their own passphrase and
foreground unlock.

## Manual update, rollback, and uninstall

If the optional background service is enabled, stop it before switching
releases, then start it again to register the selected version:

```sh
leakguard-install service disable
leakguard-install install /path/to/LeakGuard-0.2.0-alpha.3.zip
leakguard-install service enable
```

Rollback follows the same service sequence:

```sh
leakguard-install service disable
leakguard-install rollback
leakguard-install service enable
leakguard-doctor
```

Prior release directories remain available for rollback. To remove app files and
shortcuts while retaining the vault, observations, and config:

```sh
leakguard-install uninstall
```

Only use `leakguard-install uninstall --purge-data` when the user explicitly
wants to delete the private state directory too.

The alpha does not auto-update or publish telemetry. Check the release receipts
for exact native installation, service, and keyring results. A complete offline
bundle or a static script check does not establish native execution. Bundle
compatibility is checked at install time, but the bundle SHA-256 is an integrity
value, not a signature.
