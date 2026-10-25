# LeakGuard v2 extractor example

This independently installable package demonstrates a declared synthetic
`demo-note` format. The bytes begin with `LGNOTE\n`; the remainder is UTF-8
text. The extractor returns one fixed part kind and ordinal. It does not return
archive member names, titles or source-derived labels.

Install alongside LeakGuard Core from this directory with `python -m pip
install .`, then explicitly select this component in the external configuration:

```json
{
  "plugins": [
    {
      "module": "example_extractor.plugin",
      "component": "example-demo-note",
      "options": {}
    }
  ],
  "extractor_overrides": {
    "demo-note": "example-demo-note"
  },
  "required_formats": ["demo-note"]
}
```

This is an illustration only. Parser and extension code run with the scanner's
account permissions; worker supervision does not turn Python code into a
security sandbox.
