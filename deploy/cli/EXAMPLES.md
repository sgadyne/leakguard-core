# Optional synthetic extension examples

These wheels are separate from every base deployment kit:

- `leakguard_private_credential_example-0.1.0-py3-none-any.whl`: synthetic private alias wrapper.
- `example_firm_presidio_recognizer-0.1.0-py3-none-any.whl`: synthetic firm Presidio recognizer.

They contain no real firm rules or credentials. Installation does not activate
plugins. Verify this archive hash and each manifest file hash against the release
receipt first. Use a **separate custom runtime**, initialized from a verified kit's
`requirements.lock` and `wheelhouse`, with the same approved CPython 3.11. After
extracting both archives, use absolute paths (Unix example; Windows uses
`Scripts/python.exe` instead of `bin/python`):

```sh
python3.11 -m venv /private/new-lg-custom
/private/new-lg-custom/bin/python -m pip install --no-index --require-hashes \
  --find-links /absolute/extracted-kit/wheelhouse -r /absolute/extracted-kit/requirements.lock
/private/new-lg-custom/bin/python -m pip install --no-index --no-deps \
  /absolute/extracted-examples/leakguard_private_credential_example-0.1.0-py3-none-any.whl \
  /absolute/extracted-examples/example_firm_presidio_recognizer-0.1.0-py3-none-any.whl
/private/new-lg-custom/bin/python -m pip check
```

 This custom runtime is outside the base kit's exact
package-set guarantee. Do not add wheels to the managed kit environment.

Compose a new private config with `leakguard-recognizer-profile`, preserving the
base native Gitleaks path and worker policy. Explicitly add
`{"module":"private_credential_pack.plugin","options":{}}` to `plugins` for the
private alias example. For the firm example, add
`firm_presidio_recognizer.plugin:build_recognizers` to the Presidio option
`recognizer-modules` and `FIRM_ACCOUNT_ID` to `entities`; preserve the JOSE
factory/entities. Set `recognizer-options` as a JSON string mapping that factory
to `{"prefix":"FIRM-DEMO"}` if selecting that synthetic prefix.

Use only synthetic fixtures, validate positives/negative controls and effective
installed config, then invoke the installed CLI with explicit config/state.
Firm factories/options remain explicit; there is no discovery from file paths.
No custom extension is certified merely because these examples pass. Both public
and private alias plugins retain unknown external state and disabled result reuse
and continuation. Retain separate old runtime/config/state for rollback.
