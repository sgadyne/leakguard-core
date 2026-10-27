# Corporate private-plugin setup

For a self-contained PowerShell workflow with an isolated runtime and an explicit
bundled Gitleaks path, use [firm-plugin-windows.md](firm-plugin-windows.md).

This workflow installs a reviewed firm detector and optional fixed-argv check
from local files. It uses the per-user Python runtime from the LeakGuard release
bundle. It does not change a Git hook until a user selects a repository and
enables that hook.

The examples use POSIX shell syntax. Windows has not been validated in this
release; its private runtime command paths are
`venv\Scripts\leakguard-extensions.exe`, `venv\Scripts\leakguard.exe` and
`venv\Scripts\python.exe`. Keep the registry, config and script under a
user-private directory with access limited to that account.

## 1. Install the local bundle

Install LeakGuard from the approved offline bundle with its platform installer.
The installer prints JSON containing `installed` (the absolute versioned
release directory) and `runtime_python`; retain that install receipt. Set
`RELEASE` to its `installed` path, so the wheelhouse and extension tool come
from the same immutable release. The installed release wheelhouse is
`$RELEASE/wheelhouse`. Set `SIDECARS` to a private folder containing any
reviewed option-specific case JSON files; these sidecars are delivered
separately from the wheelhouse, which contains only hash-pinned wheels.

```sh
RELEASE=/absolute/path/from-install-receipt/releases/REVISION
RELEASE_WHEELHOUSE="$RELEASE/wheelhouse"
PY="$RELEASE/venv/bin/python"
EXT="$RELEASE/venv/bin/leakguard-extensions"
CLI="$RELEASE/venv/bin/leakguard"
STATE=/absolute/path/to/user-private/leakguard
CORE_CONFIG=/absolute/path/to/user-private/leakguard/sources.json
SIDECARS=/absolute/path/to/reviewed-sidecars
SENSITIVE_WHEEL="$RELEASE_WHEELHOUSE/leakguard_sensitive_basics-0.1.0-py3-none-any.whl"
FIRM_WHEEL="$RELEASE_WHEELHOUSE/leakguard_firm_example-0.1.0-py3-none-any.whl" # replace with your reviewed firm wheel
SENSITIVE_PROMOTED_CASES="$SIDECARS/sensitive-basics-cases-promoted.json"
FIRM_PROMOTED_CASES="$SIDECARS/firm-cases-promoted.json"
WORKER_POLICY="" # On macOS, set to: --worker-policy supervised-alpha
```

If you just installed the bundle, copy `RELEASE` from the install receipt's
`installed` value. To install an extension after an update or rollback, point
it at the release selected by that operation. Keep option-specific case files
in the approved offline handoff beside the bundle, outside `wheelhouse` so they
do not alter the installer's hash-pinned wheel set. The wheel's default
conformance cases cover its default options; a promotion or custom identifier
prefix needs a matching reviewed `--cases` file because it changes expected
findings.

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
`promote-rules` empty for review-only behavior:

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
firm registry with an options file such as
`{"promote-rules":["pii-identifier-employee"]}` and its matching reviewed
case file. Enable it only in `firm`; keep the sensitive registry unpromoted:

```sh
cat > "$STATE/sensitive-firm-options.json" <<'EOF'
{"promote-rules":["pii-identifier-employee"]}
EOF
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY install "$SENSITIVE_WHEEL" \
  --options "$STATE/sensitive-firm-options.json" --cases "$SENSITIVE_PROMOTED_CASES"
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY check sensitive-basics
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY enable sensitive-basics --profile firm
```

To promote `firm-customer-number`, use this instead of the review-only install
above and make the choice before first activation:

```sh
cat > "$STATE/firm-promoted-options.json" <<'EOF'
{"promote-rules":["firm-customer-number"]}
EOF
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY install "$FIRM_WHEEL" \
  --options "$STATE/firm-promoted-options.json" --cases "$FIRM_PROMOTED_CASES"
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY check firm-example
"$EXT" --registry "$FIRM_REGISTRY" $WORKER_POLICY enable firm-example --profile firm
```

Registry options belong to an installed extension entry, so use separate
registries when the same wheel needs different options in different profiles.
When changing a prefix, supply a reviewed case file whose positive values use
that prefix.

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
