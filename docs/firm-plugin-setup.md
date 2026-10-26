# Corporate private-plugin setup

This workflow installs a reviewed firm detector and optional fixed-argv check
from local files. It uses the per-user Python runtime from the LeakGuard release
bundle. It does not change a Git hook until a user selects a repository and
enables that hook.

The examples use POSIX paths. On Windows, use the private runtime's
`Scripts\\leakguard-extensions.exe` and `Scripts\\leakguard.exe`, with the
same arguments. Keep the registry, config and script under a user-private
directory with access limited to that account.

## 1. Install the local bundle

Install LeakGuard from the approved offline bundle with its platform installer.
The runtime and all dependencies stay under the user's private installation.
For the remaining commands, set these paths to the actual installation and
local bundle locations:

```sh
PY=/absolute/path/to/leakguard/runtime/bin/python
EXT=/absolute/path/to/leakguard/runtime/bin/leakguard-extensions
CLI=/absolute/path/to/leakguard/runtime/bin/leakguard
STATE=/absolute/path/to/user-private/leakguard
CORE_CONFIG=/absolute/path/to/user-private/leakguard/sources.json
SENSITIVE_WHEEL=/absolute/path/to/release/plugins/leakguard_sensitive_basics-0.1.0-py3-none-any.whl
FIRM_WHEEL=/absolute/path/to/reviewed/leakguard_firm_example-0.1.0-py3-none-any.whl
WORKER_POLICY="" # On macOS, set to: --worker-policy supervised-alpha
```

`sources.json` is the local source configuration already used by the firm. Keep
the chosen roots and exclusions there; do not store passwords or personal
records in the config. Registry files are separate from the scan report store
and credential vault.

## 2. Install Sensitive Basics for review

Use a separate registry for the unpromoted sensitive profile. Static inspection
reads the wheel manifest without importing its code. Installation uses the
current private runtime and is disabled until explicitly enabled:

```sh
SENSITIVE_REGISTRY="$STATE/extensions-sensitive"
"$EXT" --registry "$SENSITIVE_REGISTRY" inspect "$SENSITIVE_WHEEL"
"$EXT" --registry "$SENSITIVE_REGISTRY" install "$SENSITIVE_WHEEL"
"$EXT" --registry "$SENSITIVE_REGISTRY" $WORKER_POLICY check sensitive-basics
"$EXT" --registry "$SENSITIVE_REGISTRY" $WORKER_POLICY enable sensitive-basics --profile sensitive
"$EXT" --registry "$SENSITIVE_REGISTRY" $WORKER_POLICY export-profile --profile sensitive --base-config "$CORE_CONFIG" --output "$STATE/sensitive.json"
```

`check` runs the wheel's bundled independent cases. The `sensitive` profile
reports all nine built-in rules as review findings. Their IDs begin with
`pii-contact-`, `pii-financial-` or `pii-identifier-`. The category is encoded
in the rule ID; results contain only IDs, locations and severity.

## 3. Install the reviewed firm wheel

The starter at [`../templates/firm_plugin`](../templates/firm_plugin) contains a
standalone wheel project, a structured customer-number rule, a confidentiality
marker, conformance cases and a fixed-argv script example. The firm team should
review and build its private wheel in its own build pipeline, pin all
dependencies in the offline bundle, and publish the wheel only to its approved
internal distribution. Do not edit the engine to add firm-specific rules.

Create an options file in the private configuration directory. Leave
`promote-rules` empty for review-only behavior, or list only rule IDs that the
firm has explicitly approved to block:

```json
{
  "customer-prefix": "ACME-CUST",
  "promote-rules": []
}
```

Install and verify the wheel. `enable` re-runs its conformance check and
records it only in the `firm` profile:

```sh
FIRM_REGISTRY="$STATE/extensions-firm"
"$EXT" --registry "$FIRM_REGISTRY" inspect "$FIRM_WHEEL"
"$EXT" --registry "$FIRM_REGISTRY" install "$FIRM_WHEEL" --options "$STATE/firm-options.json"
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY check firm-example
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY enable firm-example --profile firm
```

To promote a Sensitive Basics rule for firm scans, install the wheel into the
firm registry with an options file such as `{"promote-rules":["pii-identifier-employee"]}`
and enable it only there. Keep the sensitive registry unpromoted. Registry
options belong to an installed extension entry, so use separate registries when
the same wheel needs different options in different profiles.

## 4. Register a fixed-argv firm check (optional)

Copy `templates/firm_plugin/scripts/firm_check.py` and its `script-cases.json`
into a user-private extension directory. Update `script-check.json` so `argv`
contains the absolute private-runtime interpreter and absolute script path. The
command receives one bounded JSON request on stdin; it does not receive source
text in its arguments or environment.

```sh
"$EXT" --registry "$FIRM_REGISTRY" register-script \
  /absolute/path/to/script-check.json \
  --cases /absolute/path/to/script-cases.json
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY check firm-demo-check
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY enable firm-demo-check --profile firm
```

The sample cases include a positive synthetic marker and a negative control.
Exit 0 with an empty findings list means the input part was checked. The script
returns only `firm-script-marker`, its line and review severity. It never emits
matched text or exception details.

## 5. Select sources and run the demo

Use the selected roots and exclusions in `sources.json`, then export a
profile-specific config. The registry reference remains in that file, so
disabling an extension changes future scans without editing engine code:

```sh
"$EXT" --registry "$FIRM_REGISTRY" export-profile \
  --profile firm --base-config "$CORE_CONFIG" --output "$STATE/firm.json"
```

Run the bundled synthetic sample against the firm profile before scheduling
scans. For example, write these synthetic lines to a temporary file inside a
private test directory and scan only that file:

```text
customer_id: ACME-CUST-004812
CONFIDENTIAL - synthetic demo record
FIRM-SCRIPT-REVIEW-MARKER
```

```sh
"$CLI" scan --config "$STATE/firm.json" /absolute/path/to/private-demo.txt
```

Confirm the three expected rule IDs appear with line locations and review
severity. Confirm the report contains no source snippets or matched values.
Then choose real roots and exclusions in Buddy, run a bounded scan, review the
findings and coverage, and set an opt-in schedule if wanted. Install Git hooks
only for the selected repositories after checking the firm profile and
conformance results.

## Trust and scope

Private Python wheels and fixed-argv checks run as trusted local code with the
scanner account's filesystem and network permissions. Process supervision
bounds execution and validates output; it is not an operating-system sandbox.
Review extension code and dependencies before installation. The examples use
synthetic identifiers and do not claim broad medical, legal or document-level
understanding.
