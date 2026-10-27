# Private credential pack example

This separate MIT-licensed example distribution contributes one synthetic
organization-specific field label, `acme_deploy_key`, using the existing
DetectorV2 interface and the shared credential engine. The original alias data
is in `src/private_credential_pack/resources/aliases.json`; its role is `api-key` and the
resource is loaded explicitly from this package. The example doesn't discover
packages or load arbitrary files. The alias matches complete normalized field
keys assigned literal values and uses the engine's reference and bounds rules.
It does not recognize unlabelled keys or validate them externally.

Install the core and `leakguard-credential-detector` distributions along with
this wheel, then explicitly configure module `private_credential_pack.plugin` as a v2
detector in the existing plugin configuration. The bounded dependency is
required both by wheel metadata and the plugin manifest. Missing engine or
resource fails initialization; it cannot silently fall back to an empty pack.
The manifest declares `external_state="unknown"` as a conservative additional
cache and continuation fence; installed distribution identity also covers packaged files. The separate synthetic conformance cases
are packaged as `private_credential_pack/cases.json`.
