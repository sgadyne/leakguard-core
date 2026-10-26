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

From an integrated source checkout, build the local package wheels into a clean
wheelhouse, then download the pinned public dependencies and the transitive
closure declared by those local wheel metadata files:

```sh
mkdir -p artifacts/wheelhouse
python -m build --wheel --no-deps --outdir artifacts/wheelhouse .
python -m build --wheel --no-deps --outdir artifacts/wheelhouse packages/leakguard_host
python -m build --wheel --no-deps --outdir artifacts/wheelhouse packages/leakguard_vault
python -m build --wheel --no-deps --outdir artifacts/wheelhouse apps/buddy
python -m pip download --only-binary=:all: --dest artifacts/wheelhouse \
  cryptography==50.0.2 keyring==25.7.0 psutil==7.2.2
python -m pip download --only-binary=:all: --no-index \
  --find-links artifacts/wheelhouse --dest artifacts/wheelhouse \
  leakguard-core==0.2.0 leakguard-host==0.2.0 leakguard-vault==0.1.0 \
  leakguard-buddy==0.1.0a1
```

If a separately verified backend executable is part of the release, include it
with `--backend-artifact PLATFORM/NAME=PATH`; the bundle manifest records its
platform, file name, and hash. Build and hash the release archive with:

```sh
python deploy/build_bundle.py \
  --wheelhouse artifacts/wheelhouse \
  --output artifacts/LeakGuard-0.2.0-alpha.1-linux-x86_64.zip \
  --source-commit "$(git rev-parse HEAD)"
```

The command prints the bundle SHA-256. Keep that digest with the archive when
transferring it through an offline corporate channel. The builder refuses a
missing or mismatched pinned distribution. Its manifest contains every wheel
hash and verifies package name and version from wheel metadata before install.

## Linux and macOS

Extract the archive and run the platform bootstrap from its `LeakGuard` folder:

```sh
unzip LeakGuard-0.2.0-alpha.1-linux-x86_64.zip
cd LeakGuard
./deploy/install.sh
```

The script uses `python3`. If Python's `venv` module has no `ensurepip`, install
`uv` for the current user or use a Python build that includes `ensurepip`. The
runtime is still created under LeakGuard's private release directory, and wheel
installation runs offline. On Linux, add `~/.local/bin` to `PATH` if needed.
The Buddy shortcut is also written to the user's application menu.

For a native macOS alpha install, the new default config selects the explicit
`supervised-alpha` worker policy. The installer also selects that policy in an
existing macOS config, and doctor reports the choice. On every platform, the
installer preserves other existing settings while selecting the encrypted
observation backend at `state/observations.lgo`; an unavailable key keeps
observations ephemeral rather than falling back to a plaintext database.

## Windows

Extract the archive, then run PowerShell as the current user:

```powershell
Expand-Archive .\LeakGuard-0.2.0-alpha.1-windows-x64.zip .\LeakGuardBundle
& .\LeakGuardBundle\LeakGuard\deploy\install.ps1
```

The bootstrap uses the Python launcher (`py -3`) and installs under
`%LOCALAPPDATA%\LeakGuard`. It adds Buddy, Buddy Open, Doctor, and Manage
commands to the user's Start Menu. From PowerShell, service actions are also
available through
`& "$env:LOCALAPPDATA\LeakGuard\bin\leakguard-install.cmd" service enable`.
Windows scripts are supplied with the alpha bundle; Windows is unverified until
a native install journey completes.

## First launch and local checks

Run `leakguard-buddy` from the user's bin directory or use the installed Buddy
shortcut. The `leakguard` command launches the CLI with the same private config
and state paths. Run `leakguard-doctor` for the exact package versions,
SQLite serialization, native execution capability map, and verified
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
leakguard-install install /path/to/LeakGuard-0.2.0-alpha.2.zip
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

The alpha does not auto-update or publish telemetry. Native macOS is available
for the documented Python 3.13 bridge run; Windows has no runner yet and must
remain marked unverified. Bundle compatibility is checked at install time, but
the bundle SHA-256 is an integrity value, not a signature.
