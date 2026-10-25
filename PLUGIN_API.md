# Plugin API v1

Plugins live in separate installed packages or explicitly supplied PYTHONPATH locations. No import occurs unless external configuration names the module:

```json
{"plugins": [{"module": "example_plugin", "options": {}}]}
```

The module exports `API_VERSION = 1` and `create_plugin(options)`. The returned object implements `detect(text, path, part)` and yields `leakguard_core.plugins.Finding(rule, line, severity)`. Rule IDs match `[a-z][a-z0-9-]{0,79}`, lines are positive integers within the supplied text, and severity is `block` or `review`. Do not return values, snippets, fingerprints or free-form messages. `examples/example_plugin.py` is a synthetic implementation.

The optional `extract(data, path)` method returns `None` when unsupported, or `(part_name, text)` pairs. Core limits are 1,000 parts and 12 MB extracted UTF-8 text. Part labels are location metadata; use fixed, non-sensitive names. An empty extraction is reported as no extractable text. Extracted parts pass through both Gitleaks and detector plugins. Never execute document code/macros or validate credentials.

Invalid output, API mismatch or plugin failure produces a sanitized error. Git fails closed. Underlying exception text is discarded because it can contain input data. Plugins do not receive permission to downgrade findings from other detectors; core evidence classifiers control proven metadata exceptions.

Plugins are trusted executable code with the scanner's account permissions, not sandboxed regex definitions. They can read files/network if their author writes such behavior. Only install reviewed extensions. The built-in engine makes no credential-validation or telemetry requests. Dependency/network policy for extensions remains the operator's responsibility.

Plugin options and known-material references remain in the external local configuration/runtime database. Publishing a plugin SDK does not require publishing those configurations, business rules, actual documents or scan results.
