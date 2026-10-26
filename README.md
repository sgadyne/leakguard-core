# LeakGuard Core

## Install the current plugin-development checkpoint

Start with the [Presidio/Tika setup and Windows corporate guide](docs/presidio-tika-checkpoint.md).
Core `0.2.1a1` uses maintained Presidio recognizers plus explicitly registered
[firm recognizer packages](plugins/presidio_detector/README.md#a-firm-owned-recognizer-package),
with Gitleaks retained for credentials. Presidio defaults to **pattern-only**;
no NER model is bundled. Tika is an **opt-in** local document parser requiring
Java 17+ and the pinned Tika 4.1.0 archive. Native Windows execution remains
unverified; this is a developer checkpoint with explicit prerequisites, not a
self-contained all-platform installer.

For an existing clone, use a new Python 3.11 environment and the approved
target-specific wheelhouse prepared as described in the guide:

```powershell
git fetch origin feature/presidio-tika-checkpoint-20261026
git switch -c review/presidio-tika FETCH_HEAD
py -3.11 -m venv C:\Work\LeakGuardFrameworkTest\runtime
$PY = 'C:\Work\LeakGuardFrameworkTest\runtime\Scripts\python.exe'
$WH = 'C:\Approved\LeakGuardWheelhouse'
& $PY -m pip install --no-index --find-links $WH --require-hashes `
  -r plugins\presidio_detector\requirements-py311.lock
& $PY -m pip install --no-index --find-links $WH `
  (Join-Path $WH 'leakguard_core-0.2.1a1-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_presidio_detector-0.1.0a1-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_tika_extractor-0.1.0a1-py3-none-any.whl') `
  (Join-Path $WH 'example_firm_presidio_recognizer-0.1.0-py3-none-any.whl')
& $PY -m pip check
```

Then follow the guide's explicit private config, capability doctor and synthetic
scan before firm files. The firm example returns native Presidio recognizers;
the [adapter guide](plugins/presidio_detector/README.md) explains registration,
entity allowlists, confidence thresholds and independent severity policy.
Python traversal remains the default and needs no Rust compiler.

## Plugin guide

Author firm recognizers as a **separate private wheel**, using native Presidio
`PatternRecognizer` or `EntityRecognizer` objects. Start with the
[shipped firm example](plugins/presidio_detector/examples/firm_presidio_recognizer),
then keep actual firm rules, configuration and data in your private project.
Its `build_recognizers(options)` factory returns recognizers for explicit
registration; installed packages are not discovered automatically.

Build on your approved development/staging machine and install the reviewed
wheel into the isolated Python 3.11 runtime from the setup guide:

```powershell
& $PY -m pip wheel --no-deps --wheel-dir .\dist `
  .\plugins\presidio_detector\examples\firm_presidio_recognizer
& $PY -m pip install --no-deps `
  .\dist\example_firm_presidio_recognizer-0.1.0-py3-none-any.whl
```

Add this adapter entry to your private scan config's `plugins` list:

```json
{
  "module": "presidio_detector.plugin",
  "options": {
    "entities": ["EMAIL_ADDRESS", "FIRM_ACCOUNT_ID"],
    "ner-mode": "pattern-only",
    "score-threshold": "0.35",
    "block-entities": [],
    "recognizer-modules": ["firm_presidio_recognizer.plugin:build_recognizers"],
    "recognizer-options": "{\"firm_presidio_recognizer.plugin:build_recognizers\":{\"prefix\":\"FIRM-DEMO\"}}"
  }
}
```

The entity allowlist selects what is analyzed. Confidence filters matches;
`block-entities` is a separate severity policy, so a high score alone does not
block. Pattern-only is the default; NER requires a separately approved installed
model and its explicit checksum. Findings use offsets relative to each extracted
part, not arbitrary original-document page positions, and contain no match text.

From the repository root, check the adapter's bundled conformance cases, then
scan the example's synthetic positive/negative fixtures with your private config:

```powershell
& $PY -m leakguard_core.conformance --kind detector --module presidio_detector.plugin `
  --cases plugins\presidio_detector\src\presidio_detector\cases.json
& $PY -m leakguard_core scan --config C:\Work\LeakGuardFrameworkTest\firm.json `
  --state-dir C:\Work\LeakGuardFrameworkTest\firm-state --format json `
  --budget-seconds 30 --max-files 2 `
  plugins\presidio_detector\examples\firm_presidio_recognizer\fixtures
```

The firm fixtures expect one `FIRM_ACCOUNT_ID` review finding in the positive
file and none in the negative. Add your own labeled positive/negative cases
before using firm data. On macOS, select the documented `supervised-alpha` worker
policy explicitly; the commands above use the Windows strict default. See the
[adapter authoring details](plugins/presidio_detector/README.md) and
[versioned plugin contract](PLUGIN_API.md) for options, conformance case schemas,
span metadata, worker lifetimes and compatibility.

The integrated Password Buddy alpha adds a private local UI, encrypted vault and observations, host jobs, and offline deployment. Start with [the alpha guide](docs/ALPHA.md) and [installation instructions](docs/INSTALL.md). Exact native platform claims live in each release’s receipts.

Offline secret scanning, Git guards and local file inventory. The engine uses Gitleaks as a subprocess and supports explicitly configured detector/extractor plugins. Configured module-backed plugins run in supervised workers. Source files are never moved or changed by a scan. Reports contain locations, rules and evidence classifications, never matched values or source snippets.

This is an initial public core, not a claim that every file type or credential can be detected. Every encountered regular file receives a scan/skip/error result; an unfinished crawl is explicitly reported as unfinished. No folders or shares are scanned until configured or passed on the command line.

## Install and run

Python 3.11+ and Git are required. Install Gitleaks 8.30.1 separately from its official releases and put it on PATH, or set `LEAKGUARD_GITLEAKS` to its executable. No scanner binary, local configuration, runtime database or real finding is shipped here.

```sh
python -m pip install -e '.[documents]'
leakguard scan ./my-project --budget-seconds 120 --max-files 1000
leakguard-manage status
leakguard-manage explain --repo ./my-project
```

`leakguard scan` is inventory by default. A completed inventory returns 0 even
when it contains findings; `--fail-on block` returns 1 for a blocking finding.
Required incomplete coverage, errors and bounded unfinished work return 2. Use
`--format json` for one redacted schema object on stdout. See
[compatibility notes](COMPATIBILITY.md) for the 0.2 exit contract and API
migration.

The CLI defaults to 120 seconds/1,000 files for `scan`, 600 seconds/3,000 files
for `audit`, and 45 seconds/150 files for `drain`. Override the time and file
bounds with `--budget-seconds` and `--max-files`. `--no-cache` disables semantic
reuse; `drain` starts with reuse disabled and accepts `--use-cache` to opt in.
The selected config's `max_file_bytes` and `scan_timeout_seconds` also bound CLI
input and detector execution. Python callers supply these limits explicitly in
`ScanLimits`.

`LEAKGUARD_CONFIG` optionally names an external JSON configuration. Start with `examples/config.json`. Set `LEAKGUARD_STATE_DIR` to a private writable runtime directory; otherwise the per-user OS state directory is used. `LEAKGUARD_GITLEAKS` can select a separately installed binary. Runtime state is automatically excluded from traversal. Set restrictive filesystem permissions on configuration and runtime state, especially when using shared directories.

```json
{
  "audit_scopes": {"workspace": "/path/to/workspace"},
  "profiles": {"general": {"sources": ["workspace"]}, "companion": {"sources": []}},
  "exclude_components": [".git"],
  "plugins": []
}
```

Advance a persistent crawl with `leakguard audit workspace --budget-seconds 120 --max-files 1000`. Queues survive interruption. A bounded one-off `scan` reports remaining work but does not persist its pending paths; use `audit` for a full resumable baseline. Directory enumeration is bounded per step. A directory that is larger than the enumeration bound or keeps changing may remain pending indefinitely; its audit cycle stays incomplete. Reports expose skipped/error paths and cycle completion, not a false "clean drive" claim. Excluded directories are policy omissions: their contents are not enumerated. Review configured exclusions when assessing coverage.

Directory audits use sequential traversal plus bounded post-scan directory-signature
checks; they are not an atomic filesystem snapshot. If a checked directory changes
or its identity is unavailable, work is requeued and the cycle remains incomplete
until validation succeeds. New directory work invalidates earlier checks. Changes
after the final check or changes hidden by coarse filesystem metadata can still be
observed only on a later audit. A full `ScanStore` queue implementation must
provide these directory-page and signature-check methods; otherwise audit/drain
returns incomplete. The full store protocol and bounded directory signature are
documented in [compatibility notes](COMPATIBILITY.md).

## Git guards and inventory

`leakguard-install-hooks install /path/to/repository --config /private/profile.json --state-dir /private/state` installs pre-commit and pre-push hooks for that selected repository and preserves/chains existing hooks. Use `status` or `uninstall` with the same repository path to inspect or restore them. It leaves global Git templates unchanged. Installation is explicit and opt-in. Git guards scan staged content and outgoing history, including bounded document blobs. They block on credentials and incomplete required scans. They never push or authenticate discovered credentials.


Managed hook launchers pin the installed core and use isolated Python startup so
the repository working directory and later `PYTHONPATH` values cannot replace
the hook or scanner core. Hook installation records bounded absolute Python
search paths for explicitly configured extensions, excluding the target
repository and installer working directory. Bounded absolute operator
`PYTHONPATH` roots may also supply a plugin that the configuration names; the
plugin worker searches for it after pinned core and interpreter paths. This does
not discover unconfigured plugins. Reinstall managed hooks after upgrading to
refresh existing launchers. Built-in parser and extension workers also pin
their core imports; ordinary console commands and Python API callers still use
their selected interpreter environment. Plugins remain explicitly configured
trusted code with the scanner account's permissions; worker isolation is not
an OS sandbox.

`leakguard-manage explain` prints the current repository's latest redacted typed report; `--format json` supplies its schema object to CLI consumers. To read an archived schema-0 report or a saved schema-1 report explicitly, use `explain --report PATH`. Explicit report input is capped at 64 MB and rejects malformed or unsupported schemas with a fixed redacted error. Findings retain commit and line so historical Git content is not confused with the working tree.

`leakguard-manage report general` and `report companion` show current active and unknown findings with first/last-seen and verification times. Add `--state history` to inspect prior observations, or `--format json` for the closed redacted findings-page envelope (schema version 2, independent of ScanReport schema 1). Pages default to 1,000 findings and accept `--limit` from 1 to 10,000. When `has_more` is true, pass the returned opaque `next_cursor` to `--cursor` to continue; the envelope includes `page_count`, `has_more` and `next_cursor`, never a total count. A cursor continues the indexed order and is not a snapshot across concurrent scans. `report all` includes both profiles. These commands query the indexed store directly and do not initialize detectors. Other commands include `locate`, `history`, `copies`, `where`, `register-material` and `plan-location`. Existing companion findings are inventory; Git guards remain blocking. Suggested locations never trigger moves.

The Python API uses the same service and result schema as the CLI and Git guards:

```python
from pathlib import Path

from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.models import FileInput, ScanLimits, ScanPolicy

with Scanner.open(config=ScanConfig.from_mapping({})) as scanner:
    report = scanner.scan(
        [FileInput(Path("./sample.txt"))],
        policy=ScanPolicy.inventory(),
        limits=ScanLimits(deadline_seconds=30, max_files=100),
    )
    print(report.to_json())
```

Importing `leakguard_core.api` or `leakguard_core.models` does not read the
operator configuration or create state. Select a config with
`ScanConfig.from_mapping()` or `ScanConfig.from_file()` and open the scanner
explicitly. For durable observations, inject a `ScanStore`; otherwise an API
scanner uses private temporary work without a persistent catalog or cache.
Injected stores are trusted application code and must honor the service's
monotonic deadline contract; see [compatibility notes](COMPATIBILITY.md) for the
`set_deadline()` and empty-Git-report repository requirements.
Public source paths, repository identities and `BytesInput.logical_path` values
are limited to 4,096 Unicode code points and reject NUL. POSIX surrogateescaped
path characters are preserved and escaped safely in JSON.

## Detection policy

Gitleaks provider-specific rules are extended with explicit client-secret/password assignment rules and XML password settings. Bare `secret` variable names, folder names, high entropy alone, file extensions and generic hash shapes do not justify suppressing or declaring credentials. Generic engine matches remain blocking in Git unless a narrow evidence check proves metadata.

The backend runs Gitleaks with a private working directory, so a caller
repository's `.gitleaksignore` cannot waive a required scan. LeakGuard reads the
explicit top-level rule file and up to two inherited files, each bounded to
1 MB. It stages the admitted top-level file as private `rules.toml` and stages
relative inherited files in a layout that preserves their reference paths.
Absolute inherited files remain at their configured external paths; those bytes
are inspected for runtime identity but are not copied into staging, and an
absolute reference is not an immutable worker snapshot if it changes concurrently.
Any inherited rule reference currently disables persistent cache reuse,
including a bounded relative file. Scanned source stays on stdin and is not
written into the staging area. Missing, malformed or over-bound rules fail
closed with a fixed configuration error.
See [compatibility notes](COMPATIBILITY.md) for relative-path and inheritance
bounds.

There is no blanket pre-scan hash masking and no filename-wide hash exception. AST fingerprints are informational only when the digest matches the sibling function in the same commit/index version. `source_fingerprints` file hashes require matching file bytes from that version. Wrong/missing/ambiguous source, duplicate JSON keys and mixed values on one line do not grant exemptions. Real credentials alongside hashes still block.

Explicit password fields do not need high entropy to be sensitive: weak literal passwords are detected too. Placeholder exceptions are limited to exact documented markers/environment references rather than broad `example-*` or `your-*` prefixes. Provider rules are independently evaluated. Duplicate Git/plugin observations retain the most restrictive severity.

The legacy `review_only_rules` setting applies only to built-in Gitleaks findings
in inventory mode. It cannot downgrade a plugin's declared blocking rule or any
Git-mode finding. Reports retain the detector's native value in
`detector_severity`; the final `severity` can be `review` for inventory display
or `info` for verified metadata. Earlier releases applied this inventory setting
to Git scans too; that was corrected because inventory configuration cannot
weaken Git protection. Configurations that relied on Git findings being
downgraded must no longer expect that behavior. See
[compatibility notes](COMPATIBILITY.md) for migration details.

## Plugins

See [the plugin API](PLUGIN_API.md). Plugins are optional trusted Python code explicitly named by module in external configuration. Nothing is downloaded/discovered automatically. Detector results have a narrow schema without matched values. Plugins cannot waive unrelated findings. V2 detector and extractor examples are separate installable packages; the v1 example remains for source compatibility. Host-specific rules, scopes, material references and firm checks belong in separately distributed extension packages.

## Supported content and limits

UTF-8/UTF-16-BOM text is scanned regardless of filename extension. Optional document adapters cover modern Office XML, text PDFs and Outlook message bodies. Parsers run in supervised workers with input, output and time bounds; a hard memory bound is reported only where the platform mechanism is available, and required scans fail with `resource-bound-unavailable` otherwise. Input defaults to 20 MiB and Office/PDF extracted text is bounded. The strict report byte cap defaults to 64 MB and accepts values from 2,048 bytes upward. Unknown binary formats receive named omissions. Encrypted or no-text content on a required surface makes coverage incomplete, and Git guards fail closed; neither case is reported as clean. There is no OCR, legacy Office parser, recursive archive support, full executable analysis or credential validation. Configured v1/v2 extractor plugins use supervised workers but remain trusted code with the scanner account's permissions; worker supervision is not an OS sandbox. Only deprecated in-memory fixtures used by internal tests execute in-process and are not a supported deployment model.

The core has resumable audits and a queue/event consumer; Windows watcher scripts are in `scripts/windows`. The integrated alpha supplies per-user service installers described in [the install guide](docs/INSTALL.md); native validation varies by platform and is recorded in the release receipts. Fleet coordination and server-side DLP remain outside the alpha. An observed delete/rename event moves prior findings to unknown; the event alone never resolves them. Notifications can be lost, so periodic audits remain necessary. Partial or failed enumeration leaves affected evidence unknown, including known-material observations. An internal bounded confirmation can resolve prior evidence as `source-absent` only after validating the stored directory identity chain; that reason differs from a successful clean content scan, and there is no CLI or public `Scanner` action for this check. Use history and `last_verified` when assessing old observations. Local known-material matching stores source references and keyed fingerprints, while file copy detection uses exact-content hashes. These are sensitive metadata even when values are redacted.

## Development

Known-material references supplement filesystem scans. Git protection uses the detection engine and explicitly configured plugins; registering a filesystem material reference does not itself add a native Gitleaks rule.

```sh
python -m pip install -e '.[documents]'
python -m unittest discover -s tests -v
python -m compileall -q src
```

Tests use synthetic values and disposable repositories. They never authenticate credentials. Set an isolated `LEAKGUARD_STATE_DIR` while running tests. See [release validation](RELEASING.md), [contributing](CONTRIBUTING.md) and [third-party notices](THIRD_PARTY_NOTICES.md). License: MIT.
