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
rules. It does not infer nested record semantics, validate credentials against
services, or cover every credential format. Rules are `block`; findings carry
rule, line, and bounded analysis offsets into the original input, not values.
Keys are ASCII case-insensitive with `_`, `-`, and `.` removed; matching is for
the complete key. A quoted scalar is literal, including a quoted `$NAME`;
unquoted environment references and pure placeholder forms are excluded. Empty
values and unquoted null/boolean atoms are excluded. Inputs and resources are
bounded; exceeding bounds fails the operation instead of silently reporting a
clean result. See the implementation and coverage document for exact syntax,
limits, controls, and the supported profile wiring.

Alias resources are packaged JSON files loaded with `importlib.resources`. The
installed runtime identity follows explicitly declared distributions and hashes
their installed files, including JSON; a version string alone is not resource
identity. Both the public and example plugin manifests declare
`external_state="unknown"` as a conservative fence: persistent result reuse and
continuation cannot rely on their identity in this phase. Installed acceptance
must demonstrate that fence; a wheel hash receipt alone is not that proof.

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

The script builds the core, detector and private example wheels from a copied
source tree with pinned build constraints and no index or cache. It first tries
to install the private wheel into an empty environment with no dependency
wheelhouse and requires resolution to fail. A second fresh environment installs
the private wheel through its metadata, using only the supplied inputs and
newly built wheels; it checks dependency closure and compares every package
Python, JSON and TOML file across source, wheel and installed distribution.
It verifies required JSON resources, rejects editable or checkout imports, runs
the inspection using isolated Python, and emits `receipt.json`. This packaging
check does not replace the synthetic installed CLI, Git, host, cache and native
platform acceptance gates. It installs no NLP models and enables no services.
