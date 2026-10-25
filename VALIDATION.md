# Release validation — 0.1.0

Validated on 25 October 2026.

- 33 synthetic unit/integration checks passed on Windows with Python 3.11 and Gitleaks 8.30.1.
- The built wheel installed and passed the full suite in a clean environment with no private plugin package or source-path injection. Default source scopes and default plugin lists were empty.
- Coverage includes staged/index isolation, outgoing/history credentials, document parts, engine/plugin failure handling, value redaction, verified source/AST fingerprints, real credentials alongside metadata, weak literal passwords, exact placeholder handling, nonstandard text extensions, explicit binary skip accounting, local catalog events and actual Git invocation of an opt-in plugin.
- All generic Windows runner/installer scripts passed PowerShell syntax parsing. Task registration/service operation was not exercised as part of the clean package test.
- Source files and decompressed wheel/source-archive members were checked for deployment-specific identifiers and excluded runtime material. No matches were found. The identifier list and operational evidence remain outside this project.
- The fresh repository history was scanned with the public detection profile. Release artifacts contain no operational state, private extension, credential store, bundled scanner executable or inherited deployment history.

These checks are regression and publication checks, not measured real-world precision/recall or proof that every filesystem format is scanned. Linux CI is configured but was not executed on this Windows workstation. Full OCR/archive/executable coverage and fleet services are outside this release.
