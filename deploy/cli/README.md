# LeakGuard CLI internal alpha 0.2.1a3

This offline deployment kit contains core 0.2.1a3, credential detector 0.1.0a2
with six alias resources, Presidio adapter 0.1.0a2, JOSE recognizers 0.1.0a2,
the complete pinned CPython 3.11 dependency wheelhouse, a native Gitleaks 8.30.1
executable, explicit profile composition, and install/verify/smoke/scan tooling.
No checkout or network is needed to install or run it. Installation does not
activate services, alter global launchers, or install Git hooks.

Obtain the archive hash from the trusted release receipt and check it before
extracting into a fresh private directory. Each zip has `kit.py` at its root.
The manifest is an integrity/provenance inventory, not a digital signature.
The exact identity is the archive SHA-256 + manifest SHA-256 + full source commit
and tree, recorded in the release receipt. Version strings alone are insufficient.
Keep the extracted kit at its final absolute path: runtime configuration binds to
its native backend. Do not combine backend binaries or target wheelhouses.

## External prerequisites

Use an approved **CPython 3.11** installation with `venv`, `ensurepip`, working
standard library (including SQLite serialization), and sufficient private disk
space (allow 2 GiB). No Python interpreter or OS libraries are bundled. Linux
x86_64 needs glibc 2.28 or newer; macOS arm64 needs macOS 14 or newer; Windows
needs native x86_64 CPython, supported Windows and any Microsoft runtime required
by that approved Python/native dependencies. Target selection does not establish
native qualification: consult the separate exact-artifact platform receipts.
Git is additionally needed for explicitly installed Git guards. No NLP model,
Java, Tika, private firm rules, real credentials, broker, vault or GUI is included.
Gitleaks executable provenance/checksums/license are in `backend/`; Python wheel
license texts and metadata are in `licenses/inventory.json`. Core/local projects
use the included MIT license. Third-party licenses remain their own.

## Install, verify, smoke

On macOS/Linux, from the extracted kit directory (substitute a new absolute
private runtime path; it must be outside this kit):

```sh
python3.11 kit.py install --env /private/leakguard-0.2.1a3
python3.11 kit.py verify --env /private/leakguard-0.2.1a3
python3.11 kit.py smoke --env /private/leakguard-0.2.1a3
python3.11 kit.py smoke --env /private/leakguard-0.2.1a3
python3.11 kit.py scan --env /private/leakguard-0.2.1a3 -- /absolute/selected-file.txt
```

On Windows PowerShell, from the extracted **windows-x86_64** kit:

```powershell
py -3.11 kit.py install --env C:\Work\leakguard-0.2.1a3
if ($LASTEXITCODE -ne 0) { throw 'Install failed' }
py -3.11 kit.py verify --env C:\Work\leakguard-0.2.1a3
if ($LASTEXITCODE -ne 0) { throw 'Verification failed' }
py -3.11 kit.py smoke --env C:\Work\leakguard-0.2.1a3
if ($LASTEXITCODE -ne 0) { throw 'Smoke failed' }
py -3.11 kit.py scan --env C:\Work\leakguard-0.2.1a3 -- C:\Work\selected-file.txt
if ($LASTEXITCODE -ne 0) { throw 'Scan incomplete or failed' }
```

`install` requires an unused environment and installs only local hashed wheels.
The default **credentials** profile explicitly enables the credential plugin and
pattern-only JOSE/Presidio factory as well as native Gitleaks. An installed core
by itself remains Gitleaks-only. For optional broader presets, add
`--profile sensitive` or `--profile firm` to **install**. Firm here is the generic
preset, containing no organization rules. The immutable managed profile rejects
later configuration edits. Custom firm configurations/extensions belong in a
separate, explicitly managed environment; see the optional examples archive.
The optional presets inherit known identity/ITIN-shaped false alerts and have no
production accuracy qualification. macOS uses explicit `supervised-alpha` with
sampled RSS, not a hard allocation boundary; Linux/Windows use `strict`.

`verify` checks kit member/hash inventory, target/Python, exact installed
package set/versions and installed wheel bytes (including six resources and
native dependencies), configuration/profile, runtime interpreter digest,
Gitleaks digest/version, imports outside source, `pip check`, and runtime doctor.
A missing/corrupt dependency, plugin, resource, backend or config fails before
scan. It invokes modules with isolated Python; generated entry-point wrappers
and bytecode are outside the wheel byte comparison. Retain trusted Python/OS and
private filesystem control. Direct CLI invocations bypass this kit verifier.
`smoke` creates and removes fresh synthetic files/state every time, requiring a
credential block, JOSE review and clean reference negative; exit 0 and
`{"status":"passed",...}` mean success. `scan` prints the value-free public JSON
report; exit 2 indicates failure/incomplete coverage. Exit 0 means completed
inventory, including any findings: inspect counts, severity and decision.

## Upgrade and rollback

Retain the previous kit archive/hash/receipt, extracted kit, environment, config
and state snapshot. Install this kit into a second unused environment, run verify
and smoke twice, then select its absolute command path in your task-local caller.
Do not overwrite the old environment or restore newer state into an old runtime.
For rollback select the retained old command/environment and its matching old
config/state snapshot, then repeat its smoke. This release performs no state or
vault migration. Failed partial installations can be retained for diagnosis;
retry into another new path.

For explicitly managed **disposable/test** repository hooks, use the selected
runtime's `leakguard-install-hooks` with `--help` for its repository/config/state
arguments; record its existing-hook backup. On upgrade or rollback reinstall
from the selected environment and matching private config/state, then verify
both a synthetic rejecting commit and a clean commit. Installation alone does
not repoint hooks. Real user hooks need separate explicit authorization.

## Coverage and limits

See `COVERAGE.md`. The base detects 32 flat aliases in six groups/five roles,
literal Authorization Basic/Bearer and ten lexical connection URL spellings;
JOSE structure remains review, not credential validity. Nested records, JDBC,
ODBC, additional protocols and Phase 2 remain outside scope. Unmatched prose
quotes can suppress later fields on a line. URL public location guarantees are
original line only; raw multiline/CRLF columns remain unqualified. Unknown plugin
external state deliberately disables persistent result reuse and audit progress
across slices: choose a budget that completes one invocation and preserve
incomplete reports. No broad whole-machine scan, production precision/recall,
corporate Windows deployment, daemon, GUI or real vault migration is certified.
