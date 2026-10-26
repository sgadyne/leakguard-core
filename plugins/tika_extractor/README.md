# LeakGuard Apache Tika extractor

This is an opt-in v2 extractor backed by a local Apache Tika 4.1.0
`tika-server-standard` process. See the official [Tika downloads](https://tika.apache.org/download.html)
and [Tika 4.1 server documentation](https://tika.apache.org/docs/4.1.x/using-tika/server/index.html).
It keeps one Tika server warm for the owning
LeakGuard session worker. The server binds to an ephemeral loopback port; the
adapter sends only document bytes and a fixed media type, then returns one
fixed `body-1` text part using Tika's `body` handler. It discards all Tika metadata and error text, so
document titles, source names, attachment names, and archive member names do
not become public labels.

Tika 4.1.0 requires Java 17 or later. Provide the full official server zip
archive and an explicit Java executable path in local plugin options. The
adapter verifies the archive against the pinned Apache SHA-512 before
extracting it to a private temporary directory. It does not download, install,
or update Java or Tika. Do not point `artifact-path` at a thin jar: Tika 4.x
requires the adjacent `lib/` closure shipped in the official archive.

Pinned runtime:

- Apache Tika `tika-server-standard-4.1.0.zip`
- SHA-512 `c932f84c569fb02df4f72ab060d6f2cf77b6797417040202401bc256e18a8f6f0ebc25d12d6dce222cb9328abfcb388cfa6511d7382c765a45687240a8a4bd7e`
- Java 17 or later; the selected runtime is recorded by version in the runtime identity

The archive contains Apache's `LICENSE` and `NOTICE`; retain both with any
offline distribution. A small plugin wheel alone is not a self-contained Tika
bundle. For air-gapped use, stage the official archive and a supported Java
runtime through the organization's existing software distribution process.
The runtime gate was executed on macOS with Java 17; Windows process cleanup
and runtime behavior have not yet been verified.

## Example configuration

Install this wheel alongside LeakGuard Core `0.2.1a1` or later in the same
`0.2.x` line. The archive is a separately staged local file; no registry or
runtime downloads are performed by the extractor.

```json
{
  "plugins": [
    {
      "module": "leakguard_tika_extractor.plugin",
      "component": "tika-extractor",
      "options": {
        "artifact-path": "/opt/leakguard/tika-server-standard-4.1.0.zip",
        "artifact-sha512": "c932f84c569fb02df4f72ab060d6f2cf77b6797417040202401bc256e18a8f6f0ebc25d12d6dce222cb9328abfcb388cfa6511d7382c765a45687240a8a4bd7e",
        "java-path": "/opt/java/bin/java",
        "max-file-bytes": 20971520,
        "max-text-bytes": 12000000,
        "startup-timeout-ms": 30000,
        "request-timeout-ms": 25000
      }
    }
  ],
  "extractor_overrides": {
    ".pdf": "tika-extractor",
    ".docx": "tika-extractor",
    ".xlsx": "tika-extractor",
    ".xlsm": "tika-extractor",
    ".pptx": "tika-extractor",
    ".msg": "tika-extractor"
  }
}
```

Only suffixes explicitly routed in `extractor_overrides` use this parser. The
core UTF-8/UTF-16 text fast path stays in place, and existing PDF, OOXML, and
MSG extractors remain the default until an operator selects this component.
Tika returns a single aggregated body part, so the adapter does not claim PDF
page, slide, sheet, or attachment position precision.

The server exposes only `/tika` and `/version`, disables per-request parser
configuration, pipes, OCR text recognizers, and inference engines, and limits
input, output, XML/package depth, parser time, and the Java heaps (128 MiB for
the server parent and 256 MiB for the parser fork). It is not an
authentication boundary: it binds only to loopback on an ephemeral port and
should run on a trusted local machine. The temporary config, archive copy,
extracted jars, and parser temp files live in a mode-0700 directory that is
removed when the session closes.

An unsupported or mismatched file, encrypted PDF, parse exception, missing
runtime, timeout, or output limit produces an explicit coverage issue. Tika
metadata and server error bodies are never included in findings or logs. An
empty document returns `no-text`; callers must not treat that as proof that a
binary file was inspected successfully.

Synthetic PDF and OOXML integration checks are in `tests/test_tika_integration.py`.
They require the exact local archive and Java runtime configured through the
test environment and create all inputs in memory.
