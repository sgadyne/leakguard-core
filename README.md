# LeakGuard Core

Offline secret scanning, Git guards and local file inventory. The engine uses Gitleaks as a subprocess and supports explicitly configured detector/extractor plugins. Source files are never moved or changed by a scan. Reports contain locations, rules and evidence classifications, never matched values or source snippets.

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

`LEAKGUARD_CONFIG` optionally names an external JSON configuration. Start with `examples/config.json`. Set `LEAKGUARD_STATE_DIR` to a private writable runtime directory; otherwise the per-user OS state directory is used. `LEAKGUARD_GITLEAKS` can select a separately installed binary. Runtime state is automatically excluded from traversal. Set restrictive filesystem permissions on configuration and runtime state, especially when using shared directories.

```json
{
  "audit_scopes": {"workspace": "/path/to/workspace"},
  "profiles": {"general": {"sources": ["workspace"]}, "companion": {"sources": []}},
  "exclude_components": [".git"],
  "plugins": []
}
```

Advance a persistent crawl with `leakguard audit workspace --budget-seconds 120 --max-files 1000`. Queues survive interruption. A bounded one-off `scan` reports remaining work but does not persist its pending paths; use `audit` for a full resumable baseline. Reports expose skipped/error paths and cycle completion, not a false "clean drive" claim. Excluded directories are policy omissions: their contents are not enumerated. Review configured exclusions when assessing coverage.

## Git guards and inventory

`leakguard-install-hooks /path/to/checkouts` installs pre-commit and pre-push hooks and preserves/chains existing hooks. It also sets up the Git template for future repositories. Installation is explicit and opt-in. Git guards scan staged content and outgoing history, including bounded document blobs. They block on credentials and incomplete required scans. They never push or authenticate discovered credentials.

`leakguard-manage explain` prints the current repository's latest redacted typed report; `--format json` supplies its schema object to CLI consumers. To read an older schema-0 JSON report explicitly, use `explain --report PATH`. Findings retain commit, part and line so historical Git content is not confused with the working tree.

`leakguard-manage report general` and `report companion` show current active and unknown findings with first/last-seen and verification times. Add `--state history` to inspect prior observations, or `--format json` for a closed redacted JSON shape. `report all` includes both profiles. These commands query the indexed store directly and do not initialize detectors. Other commands include `locate`, `history`, `copies`, `where`, `register-material` and `plan-location`. Existing companion findings are inventory; Git guards remain blocking. Suggested locations never trigger moves.

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

## Detection policy

Gitleaks provider-specific rules are extended with explicit client-secret/password assignment rules and XML password settings. Bare `secret` variable names, folder names, high entropy alone, file extensions and generic hash shapes do not justify suppressing or declaring credentials. Generic engine matches remain blocking in Git unless a narrow evidence check proves metadata.

There is no blanket pre-scan hash masking and no filename-wide hash exception. AST fingerprints are informational only when the digest matches the sibling function in the same commit/index version. `source_fingerprints` file hashes require matching file bytes from that version. Wrong/missing/ambiguous source, duplicate JSON keys and mixed values on one line do not grant exemptions. Real credentials alongside hashes still block.

Explicit password fields do not need high entropy to be sensitive: weak literal passwords are detected too. Placeholder exceptions are limited to exact documented markers/environment references rather than broad `example-*` or `your-*` prefixes. Provider rules are independently evaluated. Duplicate Git/plugin observations retain the most restrictive severity.

## Plugins

See [the plugin API](PLUGIN_API.md). Plugins are optional trusted Python code explicitly named by module in external configuration. Nothing is downloaded/discovered automatically. Detector results have a narrow schema without matched values. Plugins cannot waive unrelated findings. V2 detector and extractor examples are separate installable packages; the v1 example remains for source compatibility. Host-specific rules, scopes, material references and firm checks belong in separately distributed extension packages.

## Supported content and limits

UTF-8/UTF-16-BOM text is scanned regardless of filename extension. Optional document adapters cover modern Office XML, text PDFs and Outlook message bodies. Parsers run in bounded subprocesses. Input defaults to 20 MiB, Office/PDF extracted text is bounded, and extraction/scanning failures are reported. Other binary/encrypted/no-text content is explicitly skipped; there is no OCR, legacy Office parser, recursive archive support, full executable analysis or credential validation. Trusted extractor plugins execute in-process and are not a security sandbox.

The core has resumable audits and a queue/event consumer; Windows watcher scripts are in `scripts/windows`. Cross-platform service installers, fleet coordination and server-side DLP are outside this release. Polling/watch notifications can be lost; periodic complete audits remain necessary. Local known-material matching stores source references and keyed fingerprints, while file copy detection uses exact-content hashes. These are sensitive metadata even when values are redacted.

## Development

Known-material references supplement filesystem scans. Git protection uses the detection engine and explicitly configured plugins; registering a filesystem material reference does not itself add a native Gitleaks rule.

```sh
python -m pip install -e '.[documents]'
python -m unittest discover -s tests -v
python -m compileall -q src
```

Tests use synthetic values and disposable repositories. They never authenticate credentials. Set an isolated `LEAKGUARD_STATE_DIR` while running tests. See [release validation](RELEASING.md), [contributing](CONTRIBUTING.md) and [third-party notices](THIRD_PARTY_NOTICES.md). License: MIT.
