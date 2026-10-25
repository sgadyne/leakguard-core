# Contributing

Start with a synthetic regression case for a false positive, missed credential or coverage error. Keep real credentials, internal hostnames, private paths, customer documents and production findings out of issues, fixtures and pull requests. Use reserved example domains and disposable repositories.

Detection changes need positive cases, plausible benign negatives, mixed credential/metadata cases and malformed/ambiguous inputs. Test staged-versus-working content and historical commit behavior when changing Git integration. Exemptions must cite verifiable evidence and stay scoped to the relevant detector. Never weaken all rules because a value looks hexadecimal or a filename looks generated.

Run the unit/integration suite, compile sources and inspect the built wheel/source archive. Keep runtime state outside the checkout. Plugins must follow API v1 and remain optional. Preserve upstream licenses and attribution. Report security issues using SECURITY.md.
