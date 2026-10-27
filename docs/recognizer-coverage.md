# Optional native recognizer profiles

LeakGuard's core-only configuration runs Gitleaks. It does **not** provide the
general compact JWE coverage described here. Python 3.13 core installations do
not acquire Presidio or an NLP model through this change. Installing a recognizer
wheel also does not enable it in a scanner configuration.

The optional native path uses Python 3.11, the existing Presidio adapter and its
public `build_recognizers(options)` factory seam. Gitleaks remains enabled for
provider credentials and private keys. The JOSE package performs bounded local
structure checks; it never authenticates a token, decrypts a payload, fetches a
key, or identifies a provider from public algorithm names.

| Configuration | General compact JOSE coverage | Other native entities |
| --- | --- | --- |
| Unmodified core defaults | Unavailable | None |
| Composed `credentials` | JWE, JWS candidates, unverified JOSE | None added |
| Composed `sensitive` | Same | Default PII plus financial and identity presets |
| Composed `firm` | Same | Same presets; retains supplied firm recognizer factories |

Generic JOSE findings have review severity. Git guards allow a completed scan
containing only review findings. An operator can explicitly set
`block-entities`, but structural confidence alone does not establish credential
validity or justify automatically blocking every JWE. A missing enabled factory
or dependency fails the scan or makes coverage incomplete; it is never a clean
negative. The core-only coverage limitation above is an explicit deployment
choice, not an unavailable enabled detector being ignored.

## Compose and use a configuration

Build the core, Presidio adapter and JOSE recognizer wheels from the same task
branch. Use a new, unused private Python 3.11 environment and install the
coordinated wheel set. These local feature artifacts retain checkpoint
prerelease versions; wheel digests and the installed-origin gate identify the
tested build. Reusing an existing environment can retain a same-version wheel.
Install the adapter's pinned
dependencies and those wheels. No language model is required for pattern-only
mode. For offline installation, prepare and review the complete wheelhouse
beforehand and use `pip install --no-index --find-links <wheelhouse>`.

```sh
python3.11 -m venv /private/leakguard-native
/private/leakguard-native/bin/python -m pip install \
  -r plugins/presidio_detector/requirements-py311.lock
/private/leakguard-native/bin/python -m pip install \
  /reviewed-wheels/leakguard_core-0.2.1a2-py3-none-any.whl \
  /reviewed-wheels/leakguard_presidio_detector-0.1.0a2-py3-none-any.whl \
  /reviewed-wheels/leakguard_jose_recognizers-0.1.0a2-py3-none-any.whl

/private/leakguard-native/bin/leakguard-recognizer-profile \
  --profile credentials --output /private/credentials-native.json
/private/leakguard-native/bin/leakguard \
  scan /selected/synthetic-fixtures --config /private/credentials-native.json \
  --state-dir /private/scan-state --format json
```

Use the platform's environment executable paths on Windows (`Scripts\python.exe`
and `Scripts\leakguard-recognizer-profile.exe`). Keep the deployment's chosen
worker policy. The composer preserves that choice when `--base-config` is used;
without a base it uses the core's strict policy. Platform policy availability is
a separate preflight from recognizer availability.

`--output` creates a new private file and refuses to replace an existing one.
The composer does not install dependencies or verify runtime availability. Scan
fresh synthetic fixtures through the actual target runtime before using a
profile. A successful composer command is not an enabled-runtime receipt.

For an existing firm configuration, retain its custom modules and options:

```sh
leakguard-recognizer-profile --profile firm \
  --base-config /private/existing-firm.json --output /private/firm-native.json
```

The command merges all three JOSE entity IDs and the factory
`jose_recognizers.plugin:build_recognizers` into one configured Presidio adapter.
It preserves existing custom entities, factory options, thresholds, block policy
and unrelated extractors. Multiple Presidio adapter specs are ambiguous and are
rejected. New sensitive and firm profiles select `financial` and `identity`;
`--healthcare` adds the optional healthcare preset. See the
[adapter guide](../plugins/presidio_detector/README.md) for exact preset members
and local-context limits. URL, UUID, MAC address and date recognition are not
added as secrets by these profiles.

The existing host accepts the resulting mapping through `ScanConfig`. Git hooks
accept the same external file:

```sh
leakguard-install-hooks install /selected/repository \
  --config /private/credentials-native.json --state-dir /private/hook-state
```

Use the same private runtime for scans, host and hook installation. A hook keeps
its explicit configuration path. Changing only `detection_profile` in a JSON
file does not replace its explicit plugin options; compose a new configuration
when changing coverage. Extension-registry enablement remains a separate,
explicit operation for registered extension plugins.

## Context and result interpretation

The public `DetectionContext` contains `logical_path`, `part_id`, and `format_id`.
It has no field name or column-header member. Paths and ordinary part identifiers
are not semantic field context. The adapter uses bounded text around each match
for recognizer context; a term elsewhere in a document cannot boost every match.
An application requiring explicit semantic column context must provide a
separately designed API; this change does not invent that information.

Offsets are Unicode codepoints in the original extracted part, with an exclusive
end. Findings contain entity IDs, scores and offsets, with no matched values.
For document formats, offsets refer to extracted parts, not byte positions or
visual coordinates in the original container. Extraction failures and omitted
parts remain coverage failures rather than true negatives.

`JOSE_COMPACT_JWE` means the supported bounded structural checks passed.
`JOSE_COMPACT_JWS_CANDIDATE` means a signed or JWT-shaped candidate passed those
checks. `JOSE_COMPACT_UNVERIFIED` keeps bounded unsupported JOSE structures
visible for review. None of these proves current cryptographic validity,
provider attribution, an active session, or actionable exposure. Corrupting a
real credential would not automatically make it harmless.

The [JOSE package guide](../plugins/jose_recognizers/README.md) defines supported
algorithms, header constraints and resource limits. The
[independent evaluation tools](../tools/recognizer_eval/README.md) separate
format-positive and actionable-exposure labels. Their synthetic measurements
are not production precision/recall or calibrated probabilities.

## Installed integration gate

Run `tools/check_recognizer_profiles.py` from a directory outside the checkout
with fresh installed wheels. It requires the optional host/vault packages,
the shipped firm recognizer example, and their dependencies as well as the
native detector packages. Supply the reviewed
Gitleaks executable, an unused output directory, and the source root to exclude
from import origins:

```sh
python /checkout/tools/check_recognizer_profiles.py \
  --gitleaks /reviewed/bin/gitleaks --output-dir /owned/new-profile-gate \
  --source-root /checkout
```

The gate generates disposable cryptographic JWE fixtures, checks exact spans
and redacted reports through all three profiles, runs the real encrypted host,
and exercises local Git commit/push hooks. It checks default review behavior,
explicit block policy, and unavailable enabled factories. It uses a local bare
Git remote and never contacts a credential provider.
