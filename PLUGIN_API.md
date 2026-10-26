# Plugin API v1 and v2

Plugins live in separate installed packages or explicitly supplied PYTHONPATH locations. No import occurs unless external configuration names the module:

```json
{"plugins": [{"module": "example_plugin", "options": {}}]}
```

The module exports `API_VERSION = 1` and `create_plugin(options)`. The returned object implements `detect(text, path, part)` and yields `leakguard_core.plugins.Finding(rule, line, severity)`. Rule IDs match `[a-z][a-z0-9-]{0,79}`, lines are positive integers within the supplied text, and severity is `block` or `review`. Do not return values, snippets, fingerprints or free-form messages. `examples/example_plugin.py` is a synthetic implementation.

The optional `extract(data, path)` method returns `None` when unsupported, or `(part_name, text)` pairs. Core limits are 1,000 parts and 12 MB extracted UTF-8 text. Part labels are location metadata; use fixed, non-sensitive names. An empty extraction is reported as no extractable text. Extracted parts pass through both Gitleaks and detector plugins. Never execute document code/macros or validate credentials.

Invalid output, API mismatch or plugin failure produces a sanitized error. Git fails closed. Underlying exception text is discarded because it can contain input data. Plugins do not receive permission to downgrade findings from other detectors; core evidence classifiers control proven metadata exceptions.

Plugins are trusted executable code with the scanner's account permissions, not sandboxed regex definitions. Configured module-backed v1 and v2 detectors and extractors run in supervised workers with bounded input, output and time; the worker does not remove account permissions or provide an OS sandbox. Only deprecated in-memory instances used by internal tests execute in-process and they are not a supported deployment mechanism. Extensions can read files or use the network if their author writes such behavior. Only install reviewed extensions. The built-in engine makes no credential-validation or telemetry requests. Dependency/network policy for extensions remains the operator's responsibility.

Plugin options and known-material references remain in the external local configuration/runtime database. Publishing a plugin SDK does not require publishing those configurations, business rules, actual documents or scan results.

## API v2: separate detector and extractor components

API v2 gives independently installed packages distinct detector and extractor
contracts. Install an extension explicitly and name its module and component in
the external configuration. LeakGuard does not discover entry points, import
every installed extension or download code automatically.

```python
from collections.abc import Iterable, Mapping

from leakguard_core.plugins import (
    DetectionContext,
    Finding,
    OptionSchema,
    PluginManifest,
    RuleSpec,
)

API_VERSION = 2
MANIFEST = PluginManifest(
    id="example-firm-marker",
    implementation_version="1.0.0",
    kind="detector",
    rules=(RuleSpec(id="example-firm-marker", minimum_severity="review"),),
    formats=("text",),
    part_kinds=("text",),
    options_schema=OptionSchema(fields=()),
    dependencies=(),
    deterministic=True,
    external_state="none",
)

class Detector:
    def detect(self, text: str, context: DetectionContext) -> Iterable[Finding]:
        ...

def create_plugin(options: Mapping[str, object]) -> Detector:
    ...
```

`Finding` remains the closed `{rule, line, severity}` value. A detector declares
its rule IDs and minimum severities in the manifest, then returns only those
rule IDs with a 1-based line and `block` or `review` severity. It receives the
core-generated logical path, part ID and format ID through `DetectionContext`;
it cannot change policy or waive findings from another detector.

An extractor declares supported format IDs and static part kinds. It receives
bounded bytes, the logical path, format ID and immutable extraction limits, then
returns a fixed disposition and declared parts:

```python
from leakguard_core.extraction import Extraction, ExtractedPart, ExtractionContext

class Extractor:
    def extract(self, data: bytes, context: ExtractionContext) -> Extraction:
        if not data.startswith(b"LGNOTE\\n"):
            return Extraction(disposition="unsupported", parts=())
        text = data[7:].decode("utf-8", errors="strict")
        return Extraction(
            disposition="extracted",
            parts=(ExtractedPart(kind="note", ordinal=1, text=text),),
        )
```

Valid dispositions are `extracted`, `unsupported`, `encrypted` and `no-text`.
Part kinds must be declared static tokens; ordinals are positive and unique.
Archive member names, document titles and arbitrary plugin output are not report
labels. The standard core routes one extractor for each format. A selected
required extractor that returns unsupported is a coverage issue. Extractor
failures never mean that the content is clean.

The manifest contains a stable component ID and implementation version, API
major/minor requirements, component kind, declared rules/formats/part kinds,
bounded option schema, dependency distribution names, determinism and external
state declaration. The core validates options and resolves installed dependency
versions and content identity. Unknown or incomplete runtime closure can disable
cache reuse even when the extension continues to run. Declared versions alone
do not establish identity.

If the OS cannot apply the configured hard worker memory limit, a required
operation returns `resource-bound-unavailable`; a wall timeout is not treated as
a memory cap. Platform-specific memory enforcement must be validated on that
platform before it is claimed.

Installable examples live in [`examples/v2_detector`](examples/v2_detector) and
[`examples/v2_extractor`](examples/v2_extractor). The original
[`examples/example_plugin.py`](examples/example_plugin.py) remains the v1
compatibility example. Where available, run the reusable conformance interface
`leakguard_core.conformance.check_detector()` or `check_extractor()` against an
explicitly installed module before deployment.

## Fixed-argv firm checks

The optional `script_checks` adapter implements the same DetectorV2 result
contract for organizations that distribute a fixed command rather than a Python
package. Configuration provides an absolute executable, fixed argv, static rule
IDs/severities and an implementation version. LeakGuard sends one bounded JSON
request on stdin per independently extracted part and accepts exactly one
bounded JSON response containing `schema_version: 1` and
`findings: [{rule, line, severity}]`. Requests contain `schema_version: 1`,
`logical_path`, the core-generated `part_id` and `format_id`, and the part's
`text`. An empty list with exit 0 means that part was checked. Extra fields,
invalid lines, nonzero exits, malformed output,
timeouts, crashes and output over the configured limit are sanitized failures.

The script example is in [`examples/script_checks`](examples/script_checks).
The adapter uses core supervision and identity checks. It does not interpolate
source text into a shell command, pass values in command arguments or environment
variables, forward stderr, or grant the check a credential-vault capability.
Script checks receive source text and remain trusted local code; process
supervision does not create an OS sandbox or guarantee network denial.

## Compatibility and trust

### Core 0.2.1a1: warm sessions and result schema 2

Legacy `Finding(rule, line, severity)` and request workers remain unchanged.
An opt-in v2 manifest may set `worker_lifetime="session"` and `result_schema=2`.
Session inspection uses static metadata; the actual factory is constructed once
in an owned bounded worker and reused across serialized requests. A session is
recycled after 1,000 requests, on failure, resource-policy change or scanner close.
`close()` on the plugin is called on normal shutdown; owned process/job cleanup
also covers parser children and a private session temporary/cache directory.
Direct registry callers must call `plugins.close(handles)`; `Scanner` and
conformance/extension checks own that cleanup automatically.

Schema 2 detectors may return `NewFinding(..., analysis=AnalysisMetadata(...))`.
The closed metadata schema has `schema_version=1`, `start`, `end`, `entity_type`,
`score`, `recognizer_id`, `analyzer_id`, `analyzer_version` and `model_id`.
Offsets are Unicode codepoints relative to the independently extracted part;
`end` is exclusive. The core validates offsets/line agreement and preserves
distinct spans on the same line. Score is finite in [0,1] or absent and does not
determine severity. Entity/provenance labels are bounded static identifiers;
matched text, explanations, arbitrary dictionaries and document titles are not
accepted. Public finding JSON includes `analysis` only when present; old stored
reports and their closed three-field plugin findings remain readable.

Schema 2 also makes format dispatch explicit: nonempty `formats`/`part_kinds`
allowlists are enforced before execution; an empty detector list means all
extracted text formats/part kinds. Existing schema-1 compatibility behavior is
preserved. New adapters declare their complete intended document-text coverage.
Extractor format/part declarations remain enforced.

Framework dependencies and operator-selected model/artifact identities belong
in explicit configuration. Unknown dependency closure still disables plugin
semantic caching. Required models are not automatically downloaded or silently
substituted. `worker_memory_bytes` config controls the CLI's explicit worker
budget; SDK callers supply the same limit through `ScanLimits`. Mac supervised
RSS policy remains an explicit watchdog rather than a hard memory cap.

V1 `API_VERSION = 1`, `create_plugin(options)` and the `detect(text, path, part)`
signature remain supported. V1 plugins without a verifiable runtime manifest can
execute but are not eligible for semantic cache reuse. V1 extensions do not gain
the v2 manifest's static part/rule declarations.

V1 and v2 Python extensions execute trusted code with the scanner account's
permissions. A worker can bound time, validate output and contain parser crashes;
it does not prevent extension code from reading local files or using the network.
Only install reviewed extensions. Findings carry no matched values or free-form
exception text, and no extension may waive another detector's result.
