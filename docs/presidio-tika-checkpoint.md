# Presidio and Tika developer checkpoint

Core `0.2.1a2` retains Gitleaks, Git guards, legacy v2/script extensions,
navigation, source validation and coverage accounting. New sensitive-data
profiles use `leakguard-presidio-detector==0.1.0a2`, backed by
`presidio-analyzer==2.2.365`, with native Presidio custom recognizer packages.
Do not also enable the overlapping Sensitive Basics compatibility detector.
Tika is an explicit extractor override, not a silent parser replacement.

The base Presidio adapter targets Python **3.11**. Its hashed dependency lock is
[`../plugins/presidio_detector/requirements-py311.lock`](../plugins/presidio_detector/requirements-py311.lock).
The default is **pattern-only**, including an offline public-suffix snapshot for
email validation. It does not provide NER person/location coverage. Required NER
needs a separately approved installed model and explicit `model-sha256`; no model
wheel or weights are included, downloaded, or licensed by this handoff.

Tika requires an approved **Java 17+** runtime and the complete official
`tika-server-standard-4.1.0.zip` with the pinned SHA-512 in
[`../plugins/tika_extractor/README.md`](../plugins/tika_extractor/README.md).
The package verifies/copies the archive into a private owned runtime and warms
one loopback-only service. It does not download Java/Tika, use cloud OCR or return
arbitrary metadata. Tika locations are aggregate `body-1` text lines and Unicode
offsets, not PDF page/sheet/slide positions; original source references remain.
Legacy positioned parsers remain available without an explicit override.

## Isolated Windows setup

Use the [current integrated CLI install guide](CLI-INSTALL.md) and its release
receipt to select the revision and wheel set. Historical recognizer results do
not by themselves qualify this integrated revision on Windows. Use a new workspace/runtime and
synthetic inputs before firm data. Preserve your existing profiles and credentials.
The source/bundle is not a complete Windows interpreter, Java or backend package.
Use an approved Python 3.11, Java 17+ and Gitleaks 8.30.1 distribution. Python
navigation remains the default; the optional Rust FD bridge is POSIX-only.

```powershell
# Start in the reviewed integrated checkout identified by the release receipt.
# Confirm git rev-parse HEAD matches that receipt before building any wheels.
py -3.11 -m venv C:\Work\LeakGuardFrameworkTest\runtime
$PY = 'C:\Work\LeakGuardFrameworkTest\runtime\Scripts\python.exe'
```

On an approved connected staging machine, prepare target-compatible wheels from
the hashed lock. For offline Windows staging, select the Windows x64/CPython 3.11
platform when downloading; do not copy Mac native wheels. The pinned models are
excluded. Then install into the new runtime using the staged wheelhouse:

```powershell
# $WH contains the reviewed target-specific dependency closure and project wheels.
& $PY -m pip install --no-index --find-links $WH --require-hashes `
  -r plugins\presidio_detector\requirements-py311.lock
& $PY -m pip install --no-index --find-links $WH `
  (Join-Path $WH 'leakguard_core-0.2.1a2-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_presidio_detector-0.1.0a2-py3-none-any.whl') `
  (Join-Path $WH 'leakguard_tika_extractor-0.1.0a1-py3-none-any.whl') `
  (Join-Path $WH 'example_firm_presidio_recognizer-0.1.0-py3-none-any.whl')
& $PY -m pip check
```

Build these wheels from the reviewed source on the staging machine when a handoff
does not include them. Core also needs its pinned psutil/cachetools/packaging
dependencies. Add pinned pypdf/olefile wheels for the legacy document fallback.
No Rust compiler is needed for the Python traversal path.

Use a separate UTF-8 config with explicit absolute Gitleaks/Tika/Java paths,
`credential_store: null`, a new state directory and reviewed plugin modules:

```json
{
  "gitleaks_executable": "C:\\Approved\\gitleaks.exe",
  "worker_policy": "strict",
  "worker_memory_bytes": 1073741824,
  "scan_workers": 1,
  "detection_profile": "sensitive",
  "plugins": [
    {"module": "presidio_detector.plugin", "options": {
      "entities": ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IBAN_CODE", "IP_ADDRESS", "FIRM_ACCOUNT_ID"],
      "ner-mode": "pattern-only",
      "recognizer-modules": ["firm_presidio_recognizer.plugin:build_recognizers"]
    }},
    {"module": "leakguard_tika_extractor.plugin", "options": {
      "artifact-path": "C:\\Approved\\tika-server-standard-4.1.0.zip",
      "artifact-sha512": "c932f84c569fb02df4f72ab060d6f2cf77b6797417040202401bc256e18a8f6f0ebc25d12d6dce222cb9328abfcb388cfa6511d7382c765a45687240a8a4bd7e",
      "java-path": "C:\\Approved\\Java17\\bin\\java.exe"
    }}
  ],
  "extractor_overrides": {".pdf": "tika-extractor", ".docx": "tika-extractor", ".xlsx": "tika-extractor", ".xlsm": "tika-extractor", ".pptx": "tika-extractor", ".msg": "tika-extractor"}
}
```

The synthetic firm package is a recognizer example, not coverage for your actual
business identifiers. Replace its reviewed package/options as needed.

```powershell
& $PY -m leakguard_core doctor --config C:\Work\LeakGuardFrameworkTest\config.json --format json
# Scan only an invented fixture first; inspect JSON coverage, not just exit status.
& $PY -m leakguard_core scan --config C:\Work\LeakGuardFrameworkTest\config.json `
  --state-dir C:\Work\LeakGuardFrameworkTest\state --format json `
  --budget-seconds 60 --max-files 10 C:\Work\LeakGuardFrameworkTest\synthetic
```

Framework presence alone does not establish production detection quality. Missing
models/runtimes, encrypted/no-text inputs, unsupported formats, limits and errors
remain explicit gaps. Confidence is analyzer evidence; severity is separate policy.

## Local acceptance

The installed Mac/Python 3.11 runtime passed actual Presidio+firm+Gitleaks text,
Tika PDF/DOCX, negative controls, encrypted/malformed/unsupported coverage,
redacted span/report roundtrip, runtime-setting invalidation and owned cleanup.
Four positive/negative inputs took 9.757s cold and .994s warm: one analyzer worker
served eight requests and one Tika worker four, with zero descendants after close.
This is a small invented fixture, not a broad-filesystem throughput forecast.

The original 512MiB combined Tika worker budget failed closed in integration.
The tested profile uses an explicit 1GiB worker budget. RSS enforcement on Mac
is sampled supervised policy, not a hard cap. Broader scans have separate global
memory/disk/time controls and keep baseline versus new-runtime coverage distinct.
No GUI, credential import, Bitwarden deployment or old-profile migration occurs.
