# Fixed-argv firm check example

`check.py` demonstrates the LeakGuard script-check protocol v1 using only the
synthetic marker `FIRM-DEMO-MARKER`. The configured check must use a fixed argv
with an absolute executable and no shell interpolation:

```json
{
  "script_checks": [
    {
      "id": "firm-demo-check",
      "argv": ["/usr/bin/python3", "/absolute/path/to/check.py"],
      "implementation_version": "1",
      "rules": [{"id": "firm-demo-marker", "minimum_severity": "review"}]
    }
  ]
}
```

For each independently extracted part, the adapter sends one bounded JSON
request on stdin with `protocol_version`, `logical_path`, core-generated
`part_id`, `format_id` and `text`. The script writes exactly one JSON object to
stdout: `{"schema_version":1,"findings":[{"rule":"...","line":1,"severity":"review"}]}`.
Exit 0 with an empty list means the part was checked and no rule matched. Extra
fields, malformed output, nonzero exit, invalid line/rule/severity, timeout or
excessive output are sanitized failures; stderr and exception text are discarded.

The script receives source text and runs as trusted local code under the scanner
account. Fixed argv and process supervision do not make it an OS sandbox. It
cannot access a credential vault through the scanner API, and its output cannot
waive another detector's finding. Do not put actual secrets in command arguments,
environment variables, stdout/stderr or reports.
