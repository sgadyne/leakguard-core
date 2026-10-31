# Credential detector

`leakguard-credential-detector` is a separately installed, offline DetectorV2
plugin. Configure `credential_detector.plugin` explicitly; the profile
composition and installation procedure are described in the repository CLI
installation documentation. Its wheel depends on a compatible `leakguard-core`.
A missing plugin, dependency, or invalid resource is an error, not a clean scan.
The separate `examples/private_credential_pack` distribution illustrates an
explicitly configured organization-specific pack without modifying this wheel.

The detector covers flat credential fields from six bundled alias groups and
literal HTTP `Authorization: Basic` and `Authorization: Bearer` headers. Field
aliases map to password, API key, client secret, access token, and private key
rules. It descends JSON-style containers and recognizes bounded plist dictionary values;
it does not infer arbitrary record semantics, validate credentials against
services, or cover every credential format. Rules are `block`; findings carry
rule, line, and bounded analysis offsets into the original input, not values.
Keys are ASCII case-insensitive with `_`, `-`, and `.` removed; matching is for
the complete key. A quoted scalar is literal, including a quoted `$NAME`;
unquoted environment references and pure placeholder forms are excluded. Empty
values and unquoted null/boolean atoms are excluded. The lexer uses bounded declaration/reference grammar selected by syntax and
source language, without evaluating code. It also supports explicit contextual
password disclosures. For unrelated quoted scalars, an unmatched quote or apostrophe
earlier on a line can suppress a later assignment on that line. Inputs and
resources are bounded; exceeding bounds fails the operation instead of silently reporting a
clean result. See the implementation and coverage document for exact syntax,
limits, controls, and the supported profile wiring. The [alias resource
inventory and provenance](src/credential_detector/resources/README.md) lists
the bundled data.

### Representations and bounds

| Input | Supported representation and limits |
| --- | --- |
| Flat fields | A complete alias key followed by `:` or `=` and a single-line quoted or unquoted scalar. A comma, semicolon, closing brace, or line ending terminates an unquoted scalar. Literal values are 1–4,096 Unicode codepoints; unknown scalar fields are consumed without the credential-value bound. The scanner accepts at most 10,000,000 input codepoints, 100,000 fields, and 10,000 field spans. |
| HTTP Authorization | Complete Basic or Bearer header lines; at most 10,000,000 input codepoints, 8,192 codepoints per line, 4,096 per token, and 10,000 HTTP spans. Basic accepts canonical Base64 for printable UTF-8 `username:password`, including an empty username and requiring a nonempty password. It does not recursively scan decoded content. |

The field scanner excludes supported unquoted environment references and pure
`${NAME}`, `{{NAME}}`, or `<NAME>` placeholders, including when quoted. A quoted
`$NAME` is a literal. Limits fail required work rather than silently truncating
it or returning a clean result.

Alias resources are packaged JSON files loaded with `importlib.resources`. The
installed runtime identity follows explicitly declared distributions and hashes
their installed files, including JSON; a version string alone is not resource
identity. The bundled public plugin declares `external_state="none"` and uses explicitly
packaged resources. Unknown external-state extensions remain a conservative
fence: persistent result reuse and continuation cannot rely on their identity. Installed acceptance
must demonstrate that fence; a wheel hash receipt alone is not that proof.
An audit using an unknown-state plugin must finish within one bounded slice;
it cannot resume an earlier slice as though its external state were fixed.

## Offline installed-wheel qualification

Use a clean checkout of the exact reviewed commit, a target-specific wheelhouse,
a local Python 3.11 interpreter, and `uv` 0.12.12. The Linux lane used CPython
3.11.2, setuptools 80.9.0 and wheel 0.45.1. The input wheelhouse contains only
those two build wheels plus packaging 26.3, psutil 7.2.2 and cachetools 7.2.5.
Use a native compatible psutil wheel for each target and record its hash. A
Python 3.13 run and native Windows/macOS runs provide separate platform
coverage; do not infer those results from Linux. The Python and uv binary hashes,
input wheel hashes, commit, pinned build/runtime versions, built wheel hashes,
and source/wheel/installed file hashes are recorded in the receipt. Preserve
and verify the input hashes against the approved artifact source before use.

For example, on a Unix target with an approved Python and uv already available,
prepare an isolated bootstrap environment and target-specific input wheelhouse
when online (paths are examples outside the checkout):

```sh
uv venv --seed --python /approved/python3.11 /private/credential-bootstrap
/private/credential-bootstrap/bin/python -m pip download --only-binary=:all: \
  --dest /private/credential-input-wheels \
  setuptools==80.9.0 wheel==0.45.1 packaging==26.3 psutil==7.2.2 cachetools==7.2.5
```

Then qualify without network access, using a new, nonexistent artifact
location. In the coordinated Linux run, invoke the command through its
`run-heavy.py` wrapper. On Windows, use the venv's `Scripts/python.exe` and
native paths; no shell-specific commands are required by the smoke script.

```sh
python3 scripts/credential_install_smoke.py \
  --python /approved/python3.11 --uv /approved/uv \
  --wheelhouse /private/credential-input-wheels \
  --artifacts /private/new-credential-gate
```

The script builds the core, detector and private example wheels from a tracked commit archive with pinned build constraints and no index or cache. It first tries
to install the private wheel into an empty environment with core and its runtime
dependencies available but the credential engine absent, and requires resolution
to fail specifically for that engine. A second fresh environment installs
the private wheel through its metadata, using only the supplied inputs and
newly built wheels; it checks dependency closure and compares every package
Python, JSON and TOML file across source, wheel and installed distribution.
It verifies required JSON resources, rejects editable or checkout imports, runs
the inspection using isolated Python, and emits `receipt.json`. This packaging
check does not replace the synthetic installed CLI, Git, host, cache and native
platform acceptance gates. It installs no NLP models and enables no services.


## Alpha refinement grammar and schema checks

Core 0.2.1a4 and credential detector 0.1.0a3 share `credential_syntax` for typed
booleans, null/default punctuation, comparisons, code references, declaration
parameters, format placeholders, and bounded multiword credential prompts.
Quoted null/boolean/type/format words remain literal candidates. Unquoted
`.env` strings (including `true`/`false`), dotted opaque values and short
passwords stay visible. Type declarations can be followed by real assignments;
the parser resumes after the type instead of swallowing the remaining body.
The existing explicit placeholder and native XML/HTTP/provider rule grammars
remain separate validators; unknown or unsupported forms keep their normal
candidate/error behavior rather than gaining a path exclusion.

`artifact_context` interprets narrow schemas independently of aliases: a
validated RSA SubjectPublicKeyInfo in an extension manifest's public `key`,
JSON `localizationKey` metadata, plist dictionary tags, and exact identity
labels in Apple string tables. Sibling credential fields remain visible.
Typed plist credential values retain raw source spans, including bounded data
values up to 524,288 characters. Base64 decoding is bounded to 262,144 bytes per
payload and 1,048,576 bytes total. Relevant native findings on lines wholly
inside recognized binary data remain review findings; mixed lines and textual
data receive no reduction. This neither authenticates keys nor decrypts data.

Long anchored signatures in a validated hash/regex catalogue retain AWS-shaped
observations as review only when every AWS lexical candidate on that source
line lies in approved signature values. An unknown/literal sibling on the same
minified line prevents reclassification. The bundled AWS rule and source
classifier share the pinned 8.30.1 grammar, enforced by regression tests.
Native chunk columns are never promoted to absolute source offsets. Native
line-only deduplication remains a documented limitation; no new cross-detector
grouping is performed without trustworthy source spans.

Native preparation applies only to the exact bundled rule closure bytes.
Different caller-supplied policies receive admitted input bytes unchanged.


The inherited Gitleaks8.30.1 global allowlist contains the ungrouped expression
`(?i)^true|false|null$`; its `false` alternative can suppress a native finding
containing that word. This upstream provider-policy behavior is unchanged here.
The bundled credential alias detector retains explicit quoted literals and
unquoted environment strings such as `password=false`, with precise spans, so
the combined credentials profile keeps these fields visible. Native-only
provider candidates containing that substring remain an upstream limitation;
this candidate makes no whole-machine false-negative-rate claim.
