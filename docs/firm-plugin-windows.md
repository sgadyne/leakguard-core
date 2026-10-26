# Windows firm-plugin development checkpoint

Use the scanner and extension CLI to develop firm-specific sensitive-data rules.
Core is `0.2.0`, the reviewed firm starter is `0.1.0`, and its detector API is v2.
The starter lives in `templates/firm_plugin`; Sensitive Basics is in
`plugins/sensitive_basics`. Custom desktop work and Bitwarden deployment are
paused. Existing credentials and scanner profiles stay separate from this work.

This is a pre-alpha authoring checkpoint. Linux plugin conformance and bounded
Mac/Linux scans have been exercised. Native Windows execution remains unverified;
complete the synthetic smoke below on the corporate machine before scanning firm
data. Plugins run as trusted code with the current account's permissions.

## Get the source

The handoff receipt supplies the exact commit, branch, bundle filename and SHA-256.
Verify the SHA-256 with `Get-FileHash`, then either clone the bundle into a new
directory or fetch its branch into an existing clean clone:

```powershell
Get-FileHash C:\Handoff\leakguard-firm-plugins-20261026.bundle -Algorithm SHA256
git bundle list-heads C:\Handoff\leakguard-firm-plugins-20261026.bundle
git clone -b checkpoint/firm-plugins-20261026 `
  C:\Handoff\leakguard-firm-plugins-20261026.bundle C:\Work\leakguard-plugin-dev
Set-Location C:\Work\leakguard-plugin-dev
git bundle verify C:\Handoff\leakguard-firm-plugins-20261026.bundle
git status --short
git log -1 --oneline
```

For an existing clone, use `git fetch <bundle> checkpoint/firm-plugins-20261026`
and inspect `FETCH_HEAD` before creating a work branch. No remote push is required.

## Create an isolated Windows runtime

Use an approved, complete **Windows x64 / CPython 3.11** LeakGuard alpha bundle.
The Git bundle contains source, not Python, dependency wheels or Gitleaks. Keep
the extracted release directory and its `release.json` together. Set `$BUNDLE`
to that directory, and use a new development workspace under your user profile:

```powershell
$ErrorActionPreference = 'Stop'
$BUNDLE = (Resolve-Path 'C:\Approved\LeakGuard').Path
$WORK = Join-Path $env:LOCALAPPDATA 'LeakGuardFirmPluginDev-20261026'
if (Test-Path -LiteralPath $WORK) { throw 'Choose a new isolated workspace.' }
New-Item -ItemType Directory -Path $WORK | Out-Null
$manifest = Get-Content (Join-Path $BUNDLE 'release.json') -Raw | ConvertFrom-Json
if ($manifest.target_platform -ne 'windows-x86_64') { throw 'Wrong bundle target.' }
if ($manifest.target_python -ne '3.11') { throw 'This example requires a 3.11 bundle.' }
$WH = Join-Path $BUNDLE 'wheelhouse'
$GL = Join-Path $BUNDLE 'backends\windows-x86_64\gitleaks.exe'
if (-not (Test-Path -LiteralPath $GL -PathType Leaf)) { throw 'Bundled Gitleaks is missing.' }
& $GL version
if ($LASTEXITCODE -ne 0) { throw 'Gitleaks cannot execute.' }

py -3.11 -m venv (Join-Path $WORK 'runtime')
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 venv creation failed.' }
$PY = Join-Path $WORK 'runtime\Scripts\python.exe'
& $PY -m pip install --no-index --find-links $WH `
  'pip==26.2.2' 'leakguard-core[documents]==0.2.0'
if ($LASTEXITCODE -ne 0) { throw 'Offline runtime installation failed.' }
$EXT = Join-Path $WORK 'runtime\Scripts\leakguard-extensions.exe'
$CLI = Join-Path $WORK 'runtime\Scripts\leakguard.exe'
$REG = Join-Path $WORK 'extensions-firm'
$STATE = Join-Path $WORK 'scan-state'
$BASE = Join-Path $WORK 'base.json'
$CONFIG = Join-Path $WORK 'firm.json'
$UTF8 = [System.Text.UTF8Encoding]::new($false)
$baseConfig = @{
  gitleaks_executable = $GL
  worker_policy = 'strict'
  scan_workers = 1
  max_file_bytes = 4194304
  scan_timeout_seconds = 30
  credential_store = $null
  observation_backend = 'legacy'
  observation_path = (Join-Path $STATE 'observations.sqlite3')
  exclude_components = @('.git','node_modules','.venv','__pycache__','build','dist')
}
[System.IO.File]::WriteAllText($BASE, ($baseConfig | ConvertTo-Json -Depth 5), $UTF8)
```

The explicit absolute `gitleaks_executable` is required here. An isolated config
must not assume that `LEAKGUARD_INSTALL_ROOT` or an ambient `PATH` resolves the
bundled backend. A Linux evaluation initially returned required `detector-failed`
for every input until this path was supplied; incomplete coverage is a failure,
not a clean result. This workspace uses a private plaintext **metadata/cache**
store, contains no credential vault and does not enable keyring access.

Windows PowerShell 5.1's usual UTF-8 file writer adds a BOM. The explicit no-BOM
writer above produces JSON accepted by the scanner's UTF-8 config parser.

## Inspect, install, check and explicitly enable the starter

Begin with the approved starter wheel included in the release. Installation is
offline into the new venv and leaves the extension disabled:

```powershell
$WHEEL = Join-Path $WH 'leakguard_firm_example-0.1.0-py3-none-any.whl'
& $EXT --registry $REG inspect $WHEEL
if ($LASTEXITCODE -ne 0) { throw 'Wheel inspection failed.' }
& $EXT --registry $REG install $WHEEL
if ($LASTEXITCODE -ne 0) { throw 'Wheel installation failed.' }
& $EXT --registry $REG --worker-policy strict check firm-example
if ($LASTEXITCODE -ne 0) { throw 'Conformance failed; do not enable.' }
& $EXT --registry $REG --worker-policy strict enable firm-example --profile firm
if ($LASTEXITCODE -ne 0) { throw 'Activation failed.' }
& $EXT --registry $REG export-profile --profile firm --base-config $BASE --output $CONFIG
if ($LASTEXITCODE -ne 0) { throw 'Profile export failed.' }
```

The default bundled cases cover two positives and two controls. Run a small
synthetic scan and inspect its JSON coverage as well as the process exit code:

```powershell
$DEMO = Join-Path $WORK 'synthetic-demo.txt'
[System.IO.File]::WriteAllText($DEMO, "customer_id: ACME-CUST-004812`nCONFIDENTIAL - synthetic demo record`n", $UTF8)
& $CLI scan --config $CONFIG --state-dir $STATE --format json `
  --budget-seconds 30 --max-files 1 $DEMO
if ($LASTEXITCODE -ne 0) { throw 'Synthetic scan did not complete successfully.' }
```

Expect `firm-customer-number` and `firm-confidentiality-marker`, both `review`,
with line locations, complete required coverage and no matched values/snippets.
CLI exit 2 means incomplete/setup failure. A blocking verdict changes the process
exit code to 1 only when `--fail-on block` is supplied; always inspect the JSON.

## Author a firm-specific wheel

Copy `templates/firm_plugin` into a separate private working directory. Change
the distribution/module/component IDs and version together; update the static
manifest, `PluginManifest`, rule IDs, options and independent conformance cases.
Keep positives and negative controls synthetic. Start with review severity.

Build with a separate Python build venv using the corporate-approved package
index or build wheelhouse (the declared build requirements are
`setuptools>=77` and `wheel>=0.45`):

```powershell
py -3.11 -m venv (Join-Path $WORK 'build-runtime')
$BUILD = Join-Path $WORK 'build-runtime\Scripts\python.exe'
& $BUILD -m pip wheel --no-deps --wheel-dir (Join-Path $WORK 'wheels') `
  'C:\Private\MyFirmPlugin'
if ($LASTEXITCODE -ne 0) { throw 'Plugin wheel build failed.' }
```

For an offline build, add `--no-index --find-links C:\Approved\BuildWheelhouse`
with the reviewed build dependencies present. Point `$WHEEL` at the newly built
wheel and repeat inspect/install/check/enable with its new component ID. Review
and provision any runtime dependency closure separately; extension installation
uses `--no-index --no-deps` and will not fetch it. Options that alter expected
findings require matching reviewed `--cases` JSON. See
[firm-plugin-setup.md](firm-plugin-setup.md) for option-specific cases and the
optional fixed-argv script check.

## Evidence and limits

Bounded real filesystem evaluations on the Mac (161 files / 6.63 MB) and Linux
(180 files / 3.12 MB) completed after harness/config corrections, with unchanged
source hashes. The Mac profiles returned no findings; Linux returned one likely
false positive on a URL-password guard. These corpora have no complete ground
truth, so they provide no recall claim. Prior frozen synthetic labels and the
invalid AWS specimen caveat remain in the evaluation receipts.

Plugin-enabled scans currently bypass semantic reuse; repeat rescanning is
expected. The existing literal-password blocker noise needs separate detector
quality work. Windows Job Objects, packaging and this PowerShell workflow still
need native execution. Keep real firm data local, review redacted findings and
coverage, and leave Git-hook activation as a separate explicit decision.

For automation, drain subprocess output concurrently or redirect it to private
files while the process runs. Polling a child with undrained JSON output pipes
can deadlock; track and clean up only the invocation's recorded owned processes.
