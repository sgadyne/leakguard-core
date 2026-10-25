# Native platform acceptance handoff

## Scope and current status

Run the source and clean-wheel acceptance on native macOS and Windows with
Python 3.11 and 3.13. Each platform/version pair has four separate checks:
source/base, source/`.[documents]`, wheel/base, and wheel/`.[documents]`.
The commands below use only the synthetic fixtures in this source tree, an
empty private configuration, disposable state/repositories, and the pinned
Gitleaks installer. They do not scan user data, modify global Git or Python
configuration, install hooks globally, or publish artifacts.

The source identity for native follow-up is the final implementation-validation
commit `9111c9caa7426148d2412244be00542ac2989bde`, tree
`0474c80494fddb24a833adbd1481d55612d415df`. Its production package subtree
`9d3597b34f0471645869b77c396d3136dfd5dc1a` is unchanged from the earlier
`ce1ea500` four-cell Linux matrix. The later changes add corpus/tool validation.
The Linux Gitleaks 8.30.1 executable used for reference acceptance has SHA-256
`88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509`. This is
not an expected macOS/Windows binary hash: the native installer verifies the
official release archive checksum and each native run must record the hash of
its privately installed executable. The acceptance config must contain only
`{}`. Use a new private run root and unique receipt paths for every Python
version.

All native rows are currently **UNVERIFIED**. The existing CI declaration is
not execution evidence, and the Linux receipts below do not establish native
macOS or Windows behavior.

| Native runner | Source base/docs | Wheel base/docs | Status |
|---|---|---|---|
| macOS, Python 3.11 | Not run | Not run | UNVERIFIED |
| macOS, Python 3.13 | Not run | Not run | UNVERIFIED |
| Windows, Python 3.11 | Not run | Not run | UNVERIFIED |
| Windows, Python 3.13 | Not run | Not run | UNVERIFIED |

## Frozen Linux reference artifacts and receipts

These hashes identify reference builds from the earlier production freeze
`ce1ea500fd832ea7c15a0a3558918fbf674f0eb4`; they are
Linux results, not native macOS/Windows evidence. The Python 3.13 wheel rows ran
their installed tests on Python 3.13.15 (the receipt's `python` field is the
Python 3.11.2 builder; see `target_python_version`). `run_acceptance.py
--mode wheel` rebuilds artifacts on the native host; record actual native
artifact hashes rather than assuming byte-for-byte reproducibility. Receipts
preserve member hashes, source identity, test totals, skip IDs, installation
origin and private work directory.

| Check | Receipt | Core wheel SHA-256 | Detector wheel SHA-256 | Extractor wheel SHA-256 | sdist SHA-256 | Test summary |
|---|---|---|---|---|---|---|
| Linux/Python 3.11 wheel/base | `evidence-wheel-py311-base-ce1ea50.json` | `c4d2040ab3cc33ed0dc0b3ebbc4941fe74a86e22033fe890c4ecefbc10362f9c` | `cc0efe34f2c064d6cc66d83905139904ac4e1ed65710fe0d6cf8ada8e8d96099` | `63738770955e5634760e7be1c5ba42d18a3eaac585ebd5a127299a32844639bd` | `6e2bbecf1f0b69504134c7a1904ec260bf62e925f22fa30ea05d777c62ad359a` | 249 total; 243 passed, 6 skipped (2 Job Object + 4 optional-document tests). |
| Linux/Python 3.11 wheel/docs | `evidence-wheel-py311-docs-ce1ea50.json` | `0070f4e7144c4eba81bed5b7c38b35c57c0946e8b0e202be39f9ba3cc7d2525d` | `0f4ba8dc08f9b56b7bbacea9554582889afc2799cb4338e6bc59b43dd5d09bdb` | `80676c1455b1d940ab6ac9d383c08a21fa8fbdc745da17cd03b036559effd30b` | `1589f203be95e1155236be3cbab132eb2b3a7e55e1ac5e87d8a7f1fa700f58b5` | 249 total; 247 passed, 2 skipped (Windows Job Object tests). |
| Linux/Python 3.13 wheel/base | `evidence-wheel-py313-base-ce1ea50.json` | `443b87ea390af7715c55b3e047ba701632e1fa9430d8353fa82e497e34bcedc0` | `aa88cbcd89130a17f994d1e2ef4968cbb84f6ed124848deae3c8364de55f268e` | `8fa89436854bbe631b39a36047490a26f00944ff3241d0fb8c007e21075e9fe9` | `292d2724e4d24dc4d3a8a8c8b863a7efcdbf936df195fadab92394d544f6bc6f` | 249 total; 243 passed, 6 skipped (2 Job Object + 4 optional-document tests). |
| Linux/Python 3.13 wheel/docs | `evidence-wheel-py313-docs-ce1ea50.json` | `3bb489fa0e59ebd9cf259fd1111a0c02fedeec39f6a4520bf7acc3225768c67e` | `5310a38c64a06bd722ba7f77dd232f3b768d2cee794a5887886e56057f225a51` | `baee0db37bf0ea0092b6a6b8196f481c355f2474a534e230d279f9158731a627` | `e1a6773a6f0d527d742a0f17405016d681abdca23a203d90c8b06ba580fda017` | 249 total; 247 passed, 2 skipped (Windows Job Object tests). |

Linux source references from that earlier commit are `evidence-source-py311-base-ce1ea50.json`
(Python 3.11.2, 249 total, 243 passed, 6 skipped) and
`lead-source-ce1ea50-docs-summary.json` (Python 3.11.2 with `pypdf` 6.21.2 and
`olefile` 0.47, 249 total, 247 passed, 2 Windows Job Object skips). The base
skips are the two Windows-only tests plus four optional-document tests; docs
runs skip only those two Windows-only tests. These references are not native
platform evidence.

The source and docs-wheel receipts also use source commit
`ce1ea500fd832ea7c15a0a3558918fbf674f0eb4`. Keep the full JSON receipts and
their work directories. Do not reduce results to “all passed”: preserve
`test_summary.total`, `passed`, `skipped`, `failures`, `errors`, and
`skip_test_ids`. For each native wheel receipt, additionally hash the generated
core and example wheels under its `work_directory` and record those hashes next
to the receipt.

The final `9111c9c` Linux Python 3.11 document source suite and Python 3.13
document wheel suite each execute 251 tests: 249 passed, two Windows-only skips.
See [final installed acceptance](evidence-wheel-py313-docs-final-9111c9c.json)
for exact artifact hashes and [final source acceptance](lead-source-9111c9c-py311-docs-summary.json).
These additional Linux receipts do not establish native platform behavior.

## macOS commands

Run this block from a checkout containing the frozen commit, once with
`PY=python3.11` and `TAG=macos-py311`, then again with `PY=python3.13` and
`TAG=macos-py313`. It creates a detached worktree at the exact source commit
and a new temporary root outside it. `run_acceptance.py` creates its private
state, Git config, installed environment, and output under the receipt tree.

```sh
set -euo pipefail
PY=python3.11                 # Repeat with python3.13
TAG=macos-py311               # Use macos-py313 for Python 3.13
EXPECTED=9111c9caa7426148d2412244be00542ac2989bde
EXPECTED_TREE=0474c80494fddb24a833adbd1481d55612d415df
test -z "$(git status --porcelain)"
CHECKOUT="$PWD"
RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/leakguard-${TAG}-XXXXXX")"
chmod 700 "$RUN_ROOT"
mkdir -m 700 "$RUN_ROOT/receipts" "$RUN_ROOT/gitleaks"
git cat-file -e "$EXPECTED^{commit}"
SRC="$RUN_ROOT/source"
git worktree add --detach "$SRC" "$EXPECTED"
cd "$SRC"
test "$(git rev-parse HEAD)" = "$EXPECTED"
test "$(git rev-parse 'HEAD^{tree}')" = "$EXPECTED_TREE"
test -z "$(git status --porcelain)"
printf '{}\n' > "$RUN_ROOT/config.json"
chmod 600 "$RUN_ROOT/config.json"
"$PY" tools/install_gitleaks.py "$RUN_ROOT/gitleaks"
GITLEAKS="$RUN_ROOT/gitleaks/gitleaks"
test -x "$GITLEAKS"
shasum -a 256 "$GITLEAKS"
RETURNCODES="$RUN_ROOT/return-codes.txt"
failed=0
run_acceptance() {
  label=$1; shift
  code=0
  "$@" || code=$?
  printf '%s=%s\n' "$label" "$code" | tee -a "$RETURNCODES"
  if [ "$code" -ne 0 ]; then failed=1; fi
}

"$PY" -m venv "$RUN_ROOT/source-base"
PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.org/simple PIP_CACHE_DIR="$RUN_ROOT/pip-base" \
  "$RUN_ROOT/source-base/bin/python" -m pip install 'packaging>=24,<27'
run_acceptance source-base "$RUN_ROOT/source-base/bin/python" tools/run_acceptance.py --mode source \
  --output "$RUN_ROOT/receipts/${TAG}-source-base.json" --gitleaks "$GITLEAKS" --config "$RUN_ROOT/config.json"

"$PY" -m venv "$RUN_ROOT/source-docs"
PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.org/simple PIP_CACHE_DIR="$RUN_ROOT/pip-docs" \
  "$RUN_ROOT/source-docs/bin/python" -m pip install 'packaging>=24,<27' 'pypdf>=6,<7' 'olefile>=0.47,<1'
run_acceptance source-docs "$RUN_ROOT/source-docs/bin/python" tools/run_acceptance.py --mode source --documents-extra \
  --output "$RUN_ROOT/receipts/${TAG}-source-docs.json" --gitleaks "$GITLEAKS" --config "$RUN_ROOT/config.json"

run_acceptance wheel-base "$PY" tools/run_acceptance.py --mode wheel \
  --output "$RUN_ROOT/receipts/${TAG}-wheel-base.json" --gitleaks "$GITLEAKS" --config "$RUN_ROOT/config.json"
run_acceptance wheel-docs "$PY" tools/run_acceptance.py --mode wheel --documents-extra \
  --output "$RUN_ROOT/receipts/${TAG}-wheel-docs.json" --gitleaks "$GITLEAKS" --config "$RUN_ROOT/config.json"

find "$RUN_ROOT/receipts" -type f \( -name '*.whl' -o -name '*.tar.gz' \) -print0 | xargs -0 shasum -a 256
test "$(git -C "$SRC" rev-parse HEAD)" = "$EXPECTED"
test "$(git -C "$SRC" rev-parse 'HEAD^{tree}')" = "$EXPECTED_TREE"
test -z "$(git -C "$SRC" status --porcelain)"
test "$failed" -eq 0
cd "$CHECKOUT"
git -C "$CHECKOUT" worktree remove --force "$SRC"
```

`--documents-extra` on source mode records the matrix variant; the separate
source-docs venv above installs the optional parsers before the suite runs. The
wheel mode creates a new installed venv and installs the optional parsers when
the flag is present. The tool sets a private empty config/state context and
removes ambient `PYTHONPATH` for the test process.

## Windows PowerShell commands

Run in a fresh PowerShell process from a checkout containing the frozen
commit, once with `$PyVersion = '3.11'` and `$Tag = 'windows-py311'`, then
again with `3.13` and `windows-py313`. The commands create a detached worktree
at the exact source commit. The Windows temporary directory is private to the
current account; no `HOME`, global Git configuration, or global hook path is
changed.

```powershell
$ErrorActionPreference = 'Stop'
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw ("command-failed:{0}:{1}" -f $Executable, $LASTEXITCODE) }
}
function Invoke-Acceptance {
    param([string]$Name, [string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    $Code = [int]$LASTEXITCODE
    [IO.File]::AppendAllText($ReturnCodes, "$Name=$Code`n", [Text.Encoding]::ASCII)
    if ($Code -ne 0) { throw ("acceptance-failed:{0}:{1}" -f $Name, $Code) }
}
$PyVersion = '3.11'             # Repeat with 3.13
$Tag = 'windows-py311'          # Use windows-py313 for Python 3.13
$Expected = '9111c9caa7426148d2412244be00542ac2989bde'
$ExpectedTree = '0474c80494fddb24a833adbd1481d55612d415df'
if ((git status --porcelain)) { throw 'source-tree-not-clean' }
$Checkout = (Get-Location).Path
$RunRoot = Join-Path ([IO.Path]::GetTempPath()) ("leakguard-$Tag-" + [guid]::NewGuid().ToString('N'))
$Receipts = Join-Path $RunRoot 'receipts'
$GitleaksDir = Join-Path $RunRoot 'gitleaks'
New-Item -ItemType Directory -Path $RunRoot | Out-Null
New-Item -ItemType Directory -Path $Receipts, $GitleaksDir | Out-Null
$Source = Join-Path $RunRoot 'source'
Invoke-Checked 'git' @('cat-file', '-e', "$Expected^{commit}")
Invoke-Checked 'git' @('worktree', 'add', '--detach', $Source, $Expected)
Set-Location $Source
if ((git rev-parse HEAD).Trim() -ne $Expected) { throw 'source-commit-mismatch' }
if ((git rev-parse 'HEAD^{tree}').Trim() -ne $ExpectedTree) { throw 'source-tree-mismatch' }
if ((git status --porcelain)) { throw 'source-tree-not-clean' }
$Config = Join-Path $RunRoot 'config.json'
[IO.File]::WriteAllText($Config, "{}`n", [System.Text.UTF8Encoding]::new($false))
$ReturnCodes = Join-Path $Receipts 'return-codes.txt'
Set-Content -LiteralPath $ReturnCodes -Value '' -Encoding ascii
Invoke-Checked 'py' @("-$PyVersion", 'tools/install_gitleaks.py', $GitleaksDir)
$Gitleaks = Join-Path $GitleaksDir 'gitleaks.exe'
if (!(Test-Path -LiteralPath $Gitleaks -PathType Leaf)) { throw 'gitleaks-not-installed' }
Get-FileHash -Algorithm SHA256 -LiteralPath $Gitleaks

$env:PIP_CONFIG_FILE = 'NUL'
$env:PIP_INDEX_URL = 'https://pypi.org/simple'
$env:PIP_CACHE_DIR = Join-Path $RunRoot 'pip-cache'
$SourceBase = Join-Path $RunRoot 'source-base'
$SourceDocs = Join-Path $RunRoot 'source-docs'
Invoke-Checked 'py' @("-$PyVersion", '-m', 'venv', $SourceBase)
$BasePython = Join-Path $SourceBase 'Scripts/python.exe'
Invoke-Checked $BasePython @('-m', 'pip', 'install', 'packaging>=24,<27')
Invoke-Acceptance 'source-base' $BasePython @('tools/run_acceptance.py', '--mode', 'source',
    '--output', (Join-Path $Receipts "$Tag-source-base.json"), '--gitleaks', $Gitleaks,
    '--config', $Config)
Invoke-Checked 'py' @("-$PyVersion", '-m', 'venv', $SourceDocs)
$DocsPython = Join-Path $SourceDocs 'Scripts/python.exe'
Invoke-Checked $DocsPython @('-m', 'pip', 'install', 'packaging>=24,<27', 'pypdf>=6,<7', 'olefile>=0.47,<1')
Invoke-Acceptance 'source-docs' $DocsPython @('tools/run_acceptance.py', '--mode', 'source', '--documents-extra',
    '--output', (Join-Path $Receipts "$Tag-source-docs.json"), '--gitleaks', $Gitleaks,
    '--config', $Config)
Invoke-Acceptance 'wheel-base' 'py' @("-$PyVersion", 'tools/run_acceptance.py', '--mode', 'wheel',
    '--output', (Join-Path $Receipts "$Tag-wheel-base.json"), '--gitleaks', $Gitleaks,
    '--config', $Config)
Invoke-Acceptance 'wheel-docs' 'py' @("-$PyVersion", 'tools/run_acceptance.py', '--mode', 'wheel', '--documents-extra',
    '--output', (Join-Path $Receipts "$Tag-wheel-docs.json"), '--gitleaks', $Gitleaks,
    '--config', $Config)
Get-ChildItem -LiteralPath $Receipts -File -Recurse |
    Where-Object { $_.Name -match '\.(whl|tar\.gz)$' } | Get-FileHash -Algorithm SHA256
if ((git rev-parse HEAD).Trim() -ne $Expected) { throw 'source-commit-changed' }
if ((git rev-parse 'HEAD^{tree}').Trim() -ne $ExpectedTree) { throw 'source-tree-changed' }
if ((git status --porcelain)) { throw 'source-tree-changed' }
Set-Location $Checkout
Invoke-Checked 'git' @('-C', $Checkout, 'worktree', 'remove', '--force', $Source)
```

After each command, retain its exit code and receipt. A nonzero runner status,
`outcome != passed`, a changed source identity, or nonzero test failures/errors
is not a pass. Verify that the source commit before/after equals the frozen hash,
then record the exact skip count and IDs from each `test_summary`. Native wheel
receipt `work_directory` values contain the rebuilt artifacts; compute their
wheel hashes there if the final `Get-ChildItem` glob does not include those
nested directories.

## Native-only gates and receipt interpretation

- **Windows Job Objects:** Both `test_windows_job_enforces_a_hard_memory_limit`
  and `test_windows_job_kills_descendant_after_parent_success` must execute and
  pass in source and installed-wheel base/docs runs on both Python versions.
  They must not appear in a Windows `skip_test_ids` list. macOS skips of these
  Windows-only tests are expected and do not constitute Job Object evidence.
  With optional parsers installed, macOS may skip only these two native-Windows
  cases. Without optional parsers, the four document-specific tests listed in
  the Linux base reference may also skip. Investigate and record every other
  skipped test; Windows' POSIX executable-bit assertion is platform-specific,
  but the Windows hook invocation test below must execute.
- **Git hook launch:** Require the real disposable-repository hook tests to run
  and pass, including
  `FinalGitAcceptanceTests.test_installed_pre_commit_ignores_repository_core_package_spoof`,
  `FinalGitAcceptanceTests.test_installed_pre_commit_ignores_future_pythonpath_spoof`,
  `FinalGitAcceptanceTests.test_installed_hook_preserves_fixed_unicode_extension_path`,
  and `IntegrationTests.test_staged_secret_is_blocked_even_when_working_tree_is_clean`.
  On native POSIX, also require
  `IntegrationTests.test_installed_pre_commit_hook_has_execute_bit` to pass.
  Windows may skip POSIX mode-bit assertions; that skip alone is not evidence
  that Git executed a Windows hook. The real commit-blocking test must pass on
  Windows as well.
- Keep the allowlisted acceptance receipts, their private work directories,
  exact exit codes, test/skip totals and IDs, source-before/after identity,
  Gitleaks executable hash, installed import origin, and actual artifact hashes.
  Do not claim a skipped test as a platform pass or infer execution from CI
  configuration alone.
- A native run is accepted only when all four commands return zero, each receipt
  says `outcome: passed`, `source_stable: true` at the frozen commit, and has zero
  failures/errors. Preserve each command's exact process return code alongside
  its receipt; a passing wheel/base row cannot substitute for source/docs or
  wheel/docs.
- `<private-run-root>/heavy.py` is a Linux-local
  admission wrapper and is not the native macOS/Windows runner. Before starting
  a full native `run_acceptance.py` job, coordinate with the lead to reserve one
  of the two shared heavy slots. Never run more than two CPU-heavy matrix jobs
  concurrently across the shared project. Record the host, Python version,
  receipt IDs and slots used; leave this file's native row UNVERIFIED until the
  native receipt has been inspected.

No native macOS or Windows source/wheel receipt is attached to this handoff yet.
