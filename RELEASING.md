# Release validation

1. Work from this standalone repository. Never attach a deployment folder, runtime database, local configuration, upstream fork or existing operational Git history.
2. Run the synthetic tests with an isolated state directory and separately installed Gitleaks. Verify build/install on supported hosts; the included CI workflow exercises Windows and Linux.
3. Build a source archive and wheel with `python -m build`. Inspect their full member lists and scan their actual contents for sensitive data and organization-specific identifiers. The private deployment owner should supply the identifier denylist outside this public repository.
4. Validate notices, license, plugin examples, public documentation and synthetic fixtures. Keep release checksums and test results, while keeping workstation paths and private audit reports out of the artifacts.
5. Confirm publication rights and repository destination, then publish the reviewed artifacts. This repository does not upload releases or create remotes automatically.

Version 0.1.0 is an extensible initial core. Binary/OCR/archive completeness, fleet services and real-world detector precision/recall are not asserted by the synthetic suite.
