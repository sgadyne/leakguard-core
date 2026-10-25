# Extension conformance command

The installed package provides a supervised conformance command for one
explicitly named extension. It imports neither arbitrary plugin discovery nor
case modules. The author supplies a bounded JSON case file and an optional JSON
options file; only a redacted JSON report is written to standard output.

```sh
python -m leakguard_core.conformance \
  --kind detector \
  --module example_detector.plugin \
  --cases detector-cases.json \
  --options detector-options.json
```

`--options` may be omitted, in which case the component receives `{}`. The
detector case file has one top-level `cases` array. Each case has a static
`case_id`, `text`, `logical_path`, `format_id`, and `part_id`. Optional
`expected_findings` entries contain exactly `rule`, inclusive `start_line`,
inclusive `end_line`, and `severity` (`block` or `review`). For example:

```json
{
  "cases": [
    {
      "case_id": "marker-present",
      "text": "ordinary text\nFIRM-DEMO-MARKER\n",
      "logical_path": "notes.txt",
      "format_id": "text",
      "part_id": "text",
      "expected_findings": [
        {"rule": "example-firm-marker", "start_line": 2, "end_line": 2, "severity": "review"}
      ]
    }
  ]
}
```

Extractor cases use `data_base64` rather than `text`, and require
`expected_format` and `expected_disposition` (`extracted`, `unsupported`,
`encrypted`, or `no-text`). An extracted case may declare `expected_parts`;
each entry contains the core-generated `part_id`, the SHA-256 digest of UTF-8
text, and its logical `line_count`. `expected_issues` is an optional list of
closed extraction issue codes. The CLI bounds the total case file to 64 MiB and
rejects duplicate JSON keys, unknown fields, dynamic labels, and malformed
values before starting the component.

The report contains static component/case identifiers, counts, pass state, and
closed issue codes. It excludes case contents, input bytes, options, extension
output, exception messages, and tracebacks. Exit status is `0` when all cases
pass, `1` for a component or case conformance failure, and `2` for invalid case
or CLI setup, unavailable capabilities, component load failure, or missing
extractor API. A malformed invocation still emits one safe report object.

The harness tests the declared examples and the core test suite exercises
malformed output, out-of-range lines, foreign rules/part kinds, severity
downgrades, duplicate parts, excessive parts, exceptions, hangs, crashes, and
redaction. Passing author cases is evidence for those samples, not a guarantee
about arbitrary future inputs or an OS sandbox for trusted Python extensions.
