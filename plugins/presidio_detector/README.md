# LeakGuard Presidio detector

This package adapts the Presidio Analyzer Python API to LeakGuard's detector
contract. It creates one `AnalyzerEngine` for each owned session worker and reuses
it for successive parts. Presidio receives the text in memory; findings expose
only a static rule ID, line, character offsets, entity type, confidence score,
and analyzer/model identifiers. They never include the matched value or source
snippet.
The adapter accepts LeakGuard text, PDF text, Word, spreadsheet, slide, and
Outlook MSG text formats. It analyzes each extracted text part separately so
its offsets remain relative to that part; parser/extraction choices stay with
the core runtime.

The base runtime is pinned to Python 3.11 and `presidio-analyzer==2.2.365`;
`requirements-py311.lock` records the complete 52-package dependency closure
and wheel hashes. The adapter does not bundle an NER model. Its default is
`pattern-only`, which uses Presidio's `NoOpNlpEngine` and does not claim
person/location recognition. Required NER is available only after an operator
installs an approved model into the private runtime. Add NER-backed types such
as `PERSON` or `LOCATION` to the entity allowlist when selecting `required`.
The adapter checks the model distribution and language before analysis.
Required NER also requires the expected SHA-256 of the installed model
distribution. It hashes sorted relative file labels and per-file SHA-256
digests, excluding bytecode and `__pycache__`, with a 512 MiB total bound. The
identity is checked before and after analyzer construction, then reused for all
parts in the worker session; model files are not rehashed per part. Presidio's
spaCy engine can download missing models automatically, so this preflight
deliberately fails before that path is reached. Model files must follow the deployment's
licensing and distribution review; they are outside this package.
The built-in email recognizer keeps Presidio's regex and context rules, but
uses an AnalyzerEngine-owned `tldextract` configured with no suffix-list URLs,
no cache directory, and its packaged snapshot. Email validation therefore
does not fetch or cache public-suffix data.

## Explicit configuration

```json
{
  "entities": ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IBAN_CODE", "IP_ADDRESS"],
  "language": "en",
  "score-threshold": "0.35",
  "ner-mode": "pattern-only",
  "model-name": "en_core_web_sm",
  "model-sha256": "",
  "block-entities": [],
  "recognizer-modules": [],
  "recognizer-options": "{}"
}
```

`score-threshold` filters analyzer matches. `block-entities` independently maps
the listed entity types to LeakGuard's `block` severity; every other result is
`review`. A high Presidio score does not promote a finding to `block` by itself.
The plugin declares the static rule `presidio-entity`; the specific Presidio
entity type is stored in structured analysis metadata.

The options accept one language and an explicit entity allowlist. The model name
must already be installed in the private Python runtime. The adapter never
silently falls back to a different model. `capabilities()` reports whether NER
is active and the configured model identity without exposing recognizer patterns.

## A firm-owned recognizer package

`examples/firm_presidio_recognizer` shows a separate package returning native
Presidio `PatternRecognizer` instances. Install it into the same reviewed
private runtime, then explicitly configure its factory:

```json
{
  "entities": ["EMAIL_ADDRESS", "FIRM_ACCOUNT_ID"],
  "recognizer-modules": ["firm_presidio_recognizer.plugin:build_recognizers"],
  "recognizer-options": "{\"firm_presidio_recognizer.plugin:build_recognizers\":{\"prefix\":\"FIRM-DEMO\"}}"
}
```

The adapter does not scan installed entry points or discover packages. It imports
only reviewed module factories named in the profile, checks the returned objects
are Presidio `EntityRecognizer` instances, and registers them through
`RecognizerRegistry.add_recognizer`. The fixtures use synthetic identifiers only.

## Installation and focused checks

Create an isolated Python 3.11 environment and install the locked runtime
dependencies before installing this package and any reviewed firm recognizer
wheel. For example, from this package directory:

```sh
python -m pip install --require-hashes -r requirements-py311.lock
python -m pip install --no-deps .
```

To enable NER, first install an operator-approved model into that same private
runtime, then set `ner-mode` to `required`, `model-name` to its installed
package name, and `model-sha256` to its distribution identity. Calculate that
identity with `installed_model_sha256()` in the private runtime, then review
and store the value alongside the model package version in the profile. The
adapter does not download or substitute a model. Its focused
development checks cover both the real `en_core_web_sm==3.8.0` NER path and
the default NoOp path; that model was used only in a private test environment
and is not included in this package or lock.

```sh
python -c "from presidio_detector.plugin import installed_model_sha256; print(installed_model_sha256('en_core_web_sm'))"
```

For an author-side conformance run, install the package and invoke the core's
supervised conformance CLI with its bundled cases:

```sh
python -m leakguard_core.conformance \
  --kind detector \
  --module presidio_detector.plugin \
  --cases src/presidio_detector/cases.json
```

The installed-package CI smoke uses Python 3.11 on Linux, macOS and Windows:

```sh
# From the repository root, after installing core, adapter, locked dependencies
# and the synthetic firm example into the selected Python 3.11 environment:
python tools/check_presidio_smoke.py
```

It checks built-in email and firm pattern positives, a negative control,
value-free results, two requests in one owned worker session, and cleanup.
The direct analyzer probe denies socket connections. No NER model is installed
or downloaded. The worker smoke explicitly uses a 2 GiB memory budget; macOS
selects `supervised-alpha` (RSS supervision), while Linux and Windows retain
`strict` allocation/Job Object limits. This lane does not establish NER, Tika,
or production corporate-recognizer acceptance. The adapter and example remain
pinned to Python 3.11 until their dependency stack is separately qualified.
