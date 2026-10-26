# Private firm plugin starter

This standalone wheel demonstrates the existing LeakGuard v2 detector API.
The synthetic component detects a structured customer identifier only when it
appears under a `customer_id` or `customer_number` field, plus an explicit
`CONFIDENTIAL` marker. It reports fixed rule IDs and line numbers; it does not
return values or source snippets. Both rules default to review. A firm can
promote selected IDs only by supplying the `promote-rules` option in its firm
profile after reviewing the policy impact.

Build and inspect the wheel from this directory with the private runtime:

```sh
python -m pip wheel --no-deps --wheel-dir dist .
```

The wheel contains a static `leakguard-plugin.json` discovery record and four
independent synthetic detector cases. Installing the wheel does not enable it.
Use `leakguard-extensions install` for the `firm` profile, then explicitly
enable the `firm-example` component and run `leakguard-extensions check` before
using it in scans or selected Git hooks. The registry reads the static record
without importing the package; execution happens only after explicit enable.
The default bundled cases expect review-only severity. If promoting
`firm-customer-number`, distribute `fixtures/cases-promoted.json` beside the
wheel and pass it as `--cases` together with the promotion `--options` during
install. A custom customer prefix also needs a reviewed case file with matching
positive values.

`script-check.json` and `scripts/firm_check.py` show a second, fixed-argv path
for firms that distribute a command instead of a Python wheel. The command
accepts one JSON request on stdin and emits only the fixed rule ID, line and
severity. Its separate positive and negative fixtures are in `fixtures/`.
Replace both absolute paths in the config with the private runtime interpreter
and script locations; keep `argv` fixed and never add shell interpolation.

Use the profile-specific config written by the registry so the private rule and
script run only in the selected `firm` profile. The default `credentials`
profile remains core-only, and no Git hook is changed until an operator
explicitly installs one for a repository.

Extensions are trusted code running with the scanner account's permissions.
Process supervision validates inputs and outputs and bounds execution; it is
not an operating-system sandbox. Review the wheel source and its dependencies
before installing it.
