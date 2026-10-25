# Compatibility and migration

LeakGuard 0.2 introduces one typed scan report for Python callers, the CLI and
Git adapters. The report schema version is `1`; it is independent of the package
version and plugin API major. Reports contain source locations, rule identifiers,
severity and evidence classifications. They never include matched values or
source snippets.

## Python callers

New integrations should use `leakguard_core.api.Scanner` and the immutable types
from `leakguard_core.models`:

```python
from pathlib import Path

from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.models import FileInput, ScanLimits, ScanPolicy

config = ScanConfig.from_mapping({})
with Scanner.open(config=config, state_dir=Path("/private/leakguard-state")) as scanner:
    report = scanner.scan(
        [FileInput(Path("./sample.txt"))],
        policy=ScanPolicy.inventory(),
        limits=ScanLimits(deadline_seconds=30, max_files=100),
    )
    print(report.to_json())
```

`ScanConfig.from_mapping()` validates and copies an explicit mapping. Use
`ScanConfig.from_file(path)` only when the caller intentionally selects a config
file. Importing `leakguard_core.api` or `leakguard_core.models` does not read
environment configuration, create state, load extensions or start a process.
Without `state_dir` or an injected store, the API uses private temporary work and
does not persist a catalog or semantic cache. `Scanner.scan()` accepts one
`FileInput` per file or bounded `BytesInput`; `Scanner.scan_paths()` delegates
directory expansion and enumeration coverage to the shared service.
Audit directory enumeration is bounded per step. An unusually large or
continuously changing directory may remain pending indefinitely, in which case
the audit cycle remains incomplete and does not establish a complete inventory.

The temporary `engine.scan_file()` and `engine.scan_blob()` compatibility wrappers
remain for existing internal callers. Their legacy return shapes are not the new
contract. Legacy cache status `unchanged` maps to the typed `reused` outcome only
inside that adapter. New code should read `ScanResult.outcome`, preserve its
finding tuple on reuse and inspect coverage before drawing conclusions.

`plugins.Finding`, `API_VERSION = 1`, `create_plugin(options)` and the v1 detector
signature remain supported. V1 plugins without a complete declared runtime
closure can execute but cannot authorize semantic cache reuse. See
[PLUGIN_API.md](PLUGIN_API.md) for the distinct v2 detector and extractor API.

## CLI behavior

For `leakguard scan` and one audit/drain batch, a completed inventory returns 0
even when it reports findings. Add `--fail-on block` to return 1 for a blocking
finding. Required coverage failures, errors, invalid configuration or bounded
unfinished work return 2. JSON mode writes exactly one report object to stdout;
human progress and sanitized setup errors go to stderr.
CLI bounds can be set with `--budget-seconds` and `--max-files`; validated
configuration supplies the maximum input size and per-detector timeout. Python
callers choose those values explicitly through `ScanLimits`.

Git hooks use the same report schema and policy decision. Allow or allow-with-
omissions returns 0, a blocking finding returns 1, and required incomplete work
returns 2. A chained hook's nonzero status remains authoritative. `manage explain`
renders the indexed latest typed report for the selected/current repository;
`manage explain --report PATH` explicitly reads a bounded schema-0 archive or
schema-1 report file.
`manage report PROFILE` defaults to indexed current active and unknown findings,
with `--state history` for prior observations. Both current/history views include
timestamps and use a closed redacted JSON schema with `--format json`. Successful
reads return 0 even when reports contain blocking findings; read or state failures
return 2. The query path opens the store without initializing detectors.

This differs from 0.1 callers that treated a zero scan exit as evidence of a clean
scan. A zero means the requested inventory completed under its declared policy;
review the report's decision and coverage. An incomplete or omitted report is
never described as clean.

## Password Buddy boundary

The 0.2 engine release provides redacted observations and an injectable
`ScanStore` seam. It does not implement a credential vault or accept actual
secret values in scan reports, plugins, normal logs or JSON exports. Password
Buddy's separate milestone will provide an encrypted observation store and a
distinct user-approved credential vault flow with source revalidation. Saving a
credential will not resolve or alter the source finding.
