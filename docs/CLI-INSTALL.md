# Integrated CLI install, upgrade and rollback

This is the CLI-first internal alpha. Obtain the integrated source revision,
artifact manifest and platform receipts through the approved release channel.
Compare the full `git rev-parse HEAD` with the receipt before building. Use the
receipt's SHA-256 values to verify every wheel before installing. The package
versions below are checkpoint versions, not unique revision identifiers: do not
mix wheels from earlier builds with identical names. Build into an empty
per-revision wheelhouse and install into a new, unused environment. A digest
verifies integrity against a trusted receipt; it is not a signature.

Python 3.11 is required for the optional Presidio and JOSE wheels. Use an
approved Python installation with working `venv` and `pip` support. Use approved
Python, Git and Gitleaks 8.30.1 appropriate to each platform. Gitleaks is a
separate executable. No NER model, Java, Tika server, private firm rules or
credentials are included. Tika is optional; see the [Tika guide](../plugins/tika_extractor/README.md).
An offline wheelhouse must contain wheels for the target OS, architecture and
CPython 3.11 ABI. Build and verify separately on each native target or approved
target-matched staging host; a Mac wheelhouse is not a Windows wheelhouse.

## Prepare the reviewed wheelhouse

On a connected, approved Python 3.11 staging host of the target platform, in
an integrated checkout, use a new build environment and an empty output
directory. These commands build only the CLI, adapter, JOSE and synthetic firm
example wheels; add the Tika wheel if explicitly needed. The lock contains
hashes for the Presidio dependency closure. The second download collects core
and local-wheel dependencies, which must also be checked against the approved
artifact manifest. Build tooling and package index access are staging inputs;
review their provenance. Never use `--extra-index-url` to mix a private firm
package with public names.

```sh
# macOS or Linux; replace paths with private, unused paths.
python3.11 -m venv /private/lg-build
/private/lg-build/bin/python -m pip install --upgrade pip
WH=/private/lg-wheels-REVISION
mkdir "$WH"                       # must not already exist
PY=/private/lg-build/bin/python
"$PY" -m pip wheel --no-deps --wheel-dir "$WH" . \
  plugins/presidio_detector plugins/jose_recognizers \
  plugins/presidio_detector/examples/firm_presidio_recognizer
"$PY" -m pip download --only-binary=:all: --require-hashes \
  --dest "$WH" -r plugins/presidio_detector/requirements-py311.lock
"$PY" -m pip download --only-binary=:all: --dest "$WH" \
  "$WH/leakguard_core-0.2.1a2-py3-none-any.whl" \
  "$WH/leakguard_presidio_detector-0.1.0a2-py3-none-any.whl" \
  "$WH/leakguard_jose_recognizers-0.1.0a2-py3-none-any.whl" \
  "$WH/example_firm_presidio_recognizer-0.1.0-py3-none-any.whl"
# Record full source commit and hashes in the receipt; compare with reviewed artifacts.
git rev-parse HEAD
shasum -a 256 "$WH"/*.whl
```

On Windows PowerShell, from the reviewed checkout:

```powershell
py -3.11 -m venv C:\Work\lg-build
$BUILD = 'C:\Work\lg-build\Scripts\python.exe'
& $BUILD -m pip install --upgrade pip
$WH = 'C:\Approved\lg-wheels-REVISION'
New-Item -ItemType Directory -Path $WH -ErrorAction Stop
& $BUILD -m pip wheel --no-deps --wheel-dir $WH . `
  plugins\presidio_detector plugins\jose_recognizers `
  plugins\presidio_detector\examples\firm_presidio_recognizer
if ($LASTEXITCODE -ne 0) { throw 'Project wheel build failed' }
& $BUILD -m pip download --only-binary=:all: --require-hashes `
  --dest $WH -r plugins\presidio_detector\requirements-py311.lock
if ($LASTEXITCODE -ne 0) { throw 'Locked dependency download failed' }
& $BUILD -m pip download --only-binary=:all: --dest $WH `
  (Join-Path $WH 'leakguard_core-0.2.1a2-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_presidio_detector-0.1.0a2-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_jose_recognizers-0.1.0a2-py3-none-any.whl') `
  (Join-Path $WH 'example_firm_presidio_recognizer-0.1.0-py3-none-any.whl')
if ($LASTEXITCODE -ne 0) { throw 'Wheel preparation failed' }
git rev-parse HEAD
Get-ChildItem $WH -Filter *.whl | Get-FileHash -Algorithm SHA256
```

Stop if any command fails or any hash differs from the reviewed manifest.
Transfer the wheelhouse, the Presidio lock, source revision and receipt through
the approved channel. For the Linux broker and an optional Mac client, build
`packages/leakguard_vault` and `packages/leakguard_broker` from the same revision
and prepare their target-compatible dependency closure separately; the broker's
[Python 3.11 lock](../packages/leakguard_broker/requirements-py311.lock) records
its exercised Linux dependencies. That lock includes the three local project
wheels, so verify their revision and hashes as well. See the broker's own guide
for trusted-host setup and the agent CLI. The Windows instructions here cover
core and plugins, not a native Windows broker.

## Install on macOS

Verify the received hashes and use an unused private environment. The commands
below run from the matching reviewed checkout, which supplies the dependency
lock and synthetic fixtures; the runtime itself uses installed wheels.

```sh
WH=/private/lg-wheels-REVISION
python3.11 -m venv /private/lg-runtime-REVISION
PY=/private/lg-runtime-REVISION/bin/python
"$PY" -m pip install --no-index --find-links "$WH" --require-hashes \
  -r plugins/presidio_detector/requirements-py311.lock
"$PY" -m pip install --no-index --find-links "$WH" \
  "$WH/leakguard_core-0.2.1a2-py3-none-any.whl" \
  "$WH/leakguard_presidio_detector-0.1.0a2-py3-none-any.whl" \
  "$WH/leakguard_jose_recognizers-0.1.0a2-py3-none-any.whl" \
  "$WH/example_firm_presidio_recognizer-0.1.0-py3-none-any.whl"
"$PY" -m pip check
/private/lg-runtime-REVISION/bin/leakguard --help
/private/lg-runtime-REVISION/bin/leakguard-recognizer-profile --help
```

Set the reviewed absolute Gitleaks path in a private base config. On macOS,
select `"worker_policy": "supervised-alpha"` explicitly and give the worker a
suitable bounded memory budget; this is sampled RSS supervision, not a hard
memory limit. The installed `leakguard-recognizer-profile` can compose a new
credentials, sensitive or firm profile from that base. Then run the synthetic
positive and negative checks in [recognizer coverage](recognizer-coverage.md)
and inspect coverage and findings before firm data. The local follow-through
receipt records what was actually exercised on the target Mac.

## Additional wheels for Mac qualification and Linux broker

For the synthetic Mac qualification, the host, vault, broker client, Sensitive
Basics and generic firm-example packages also need target-compatible wheels.
While preparing the same clean wheelhouse on the target-matched staging host,
build these wheels from the reviewed revision and resolve their dependencies.
Run these after the earlier wheelhouse preparation commands and before recording
and reviewing its hashes:

```sh
"$PY" -m pip wheel --no-deps --wheel-dir "$WH" \
  packages/leakguard_host packages/leakguard_vault packages/leakguard_broker \
  plugins/sensitive_basics templates/firm_plugin
"$PY" -m pip download --only-binary=:all: --find-links "$WH" --dest "$WH" \
  "$WH/leakguard_core-0.2.1a2-py3-none-any.whl" \
  "$WH/leakguard_host-0.2.0-py3-none-any.whl" \
  "$WH/leakguard_vault-0.1.0-py3-none-any.whl" \
  "$WH/leakguard_broker-0.1.0a2-py3-none-any.whl" \
  "$WH/leakguard_sensitive_basics-0.1.0-py3-none-any.whl" \
  "$WH/leakguard_firm_example-0.1.0-py3-none-any.whl"
```

After verifying the complete wheelhouse against its receipt and installing the
base wheels on the target as above, install the additional wheels offline into
that same new runtime:

```sh
"$PY" -m pip install --no-index --find-links "$WH" \
  "$WH/leakguard_host-0.2.0-py3-none-any.whl" \
  "$WH/leakguard_vault-0.1.0-py3-none-any.whl" \
  "$WH/leakguard_broker-0.1.0a2-py3-none-any.whl" \
  "$WH/leakguard_sensitive_basics-0.1.0-py3-none-any.whl" \
  "$WH/leakguard_firm_example-0.1.0-py3-none-any.whl"
"$PY" -m pip check
```

Here `$PY` means the build interpreter in the staging step and the runtime
interpreter in the install step. The Mac client is tested against the Linux
broker in the [Mac qualification recipe](MAC-CLI-QUALIFICATION.md); use the
[broker guide](../packages/leakguard_broker/README.md) for Linux host setup.
Installing the Sensitive Basics wheel does not enable it or mean it should be
combined with the overlapping Presidio profile.

## Install on corporate Windows

Verify the hashes and use an unused environment, approved Gitleaks executable
and a private config/state directory. In PowerShell, from the matching checkout:

```powershell
$WH = 'C:\Approved\lg-wheels-REVISION'
py -3.11 -m venv C:\Work\lg-runtime-REVISION
$PY = 'C:\Work\lg-runtime-REVISION\Scripts\python.exe'
& $PY -m pip install --no-index --find-links $WH --require-hashes `
  -r plugins\presidio_detector\requirements-py311.lock
if ($LASTEXITCODE -ne 0) { throw 'Locked dependency install failed' }
& $PY -m pip install --no-index --find-links $WH `
  (Join-Path $WH 'leakguard_core-0.2.1a2-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_presidio_detector-0.1.0a2-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_jose_recognizers-0.1.0a2-py3-none-any.whl') `
  (Join-Path $WH 'example_firm_presidio_recognizer-0.1.0-py3-none-any.whl')
if ($LASTEXITCODE -ne 0) { throw 'Project wheel install failed' }
& $PY -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Dependency check failed' }
& C:\Work\lg-runtime-REVISION\Scripts\leakguard.exe --help
& C:\Work\lg-runtime-REVISION\Scripts\leakguard-recognizer-profile.exe --help
```

Use `strict` worker policy on Windows and run the synthetic checks from the
[recognizer coverage guide](recognizer-coverage.md). A cross-platform CI result
is evidence for its stated core/plugin tests, not a native broker qualification
or an acceptance of a corporate environment. Review that release's actual
Windows receipts before firm-data use.

## Firm seam, upgrade and rollback

A firm-owned package is a separate private wheel in the same environment. Name
its `module:build_recognizers` factory explicitly in the Presidio adapter's
`recognizer-modules` and include desired entity IDs; installation alone does not
register it. Keep options, rule data and labeled positive/negative tests in the
firm's private project. See the [adapter guide](../plugins/presidio_detector/README.md)
and its synthetic example. Confidence thresholds and `block-entities` are
separate policy decisions. Generic JOSE findings default to review; structure
alone does not validate credentials. The published synthetic evaluation found
identity-profile false alerts for ITIN-shaped negatives; it does not establish
broad PII precision or recall.

For an upgrade, retain the old environment, wheelhouse, source receipt and
private config; build and install the new revision in another environment and
run the same synthetic checks before selecting it. Reinstall any explicitly
managed Git hooks with the new runtime so their interpreter paths point to the
new version. Roll back by selecting the retained old environment and config,
then reinstall the hooks with its `leakguard-install-hooks` command and verify
status and synthetic behavior. Do not overwrite or migrate existing vaults,
master-password files, services or keychains during this process. Real vault
migration and broker isolation remain human-operated. For the separate optional
Buddy bundle, use its own [versioned installer and rollback instructions](INSTALL.md).
