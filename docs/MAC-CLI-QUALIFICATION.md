# Native Mac CLI kit qualification

Use the exact candidate commit/tree and archive/manifest hashes supplied by the
coordinator. Qualification can start while independent remote lanes continue.
All results remain provisional until exact-candidate CI and independent review
are complete. No broker, vault, GUI, Tika or service deployment is part of this
CLI alpha kit.

Verify the `leakguard-cli-0.2.1a3-macos-arm64-cp311.zip` hash against the trusted
receipt before extracting into a new private directory outside source. Record
macOS version, architecture, approved CPython 3.11 patch version and binary hash,
archive/manifest/source identity, commands, exits and actual outcomes in private
evidence. Consult [the shipped kit README](../deploy/cli/README.md) for external
prerequisites and exact install/verify/smoke commands. Keep the final extracted
kit path stable. Use an unused runtime outside it, install offline, verify, and
repeat the smoke twice. Invoke from outside any checkout; installed modules and
resource bytes must match the immutable wheels. The default profile must enable
credential DetectorV2 plus JOSE/Presidio and the exact native Gitleaks backend.
A core-only installation remains Gitleaks-only.

Check missing/corrupt dependencies, credential JSON resource, backend and
configuration fail before scan. Test each control in its own disposable copy,
restore it or discard it afterwards, and preserve value-free receipts. Test the
optional sensitive and firm preset by installing each into another unused
environment with the corresponding `--profile` option. The synthetic extension
archive has its own explicit custom-runtime instructions; those environments
are separate from the managed kit's exact package-set guarantee. Preserve firm
factory/options in those custom configurations. Actual Git guard tests require
Git and a newly generated disposable repository/remote with private config and
state. Never install hooks in a real user checkout as part of qualification.

For upgrade/rollback retain old environment, matching config and an old-state
snapshot. Select a new unused runtime for the new release; run synthetic clean
and rejected commit/push controls, then reinstall disposable hooks from the old
environment with its old-state snapshot. Verify the original hook chain and
backup. Never give new state to old code or assume forward schema compatibility.
No real credential or vault migration is performed.

For the monitored synthetic workload, generate at most 2,000 files and 128 MiB
of admitted input under the run's fixtures directory. Run one heavy scenario at
a time, at most 600 seconds per scenario, with a supervisory process-tree RSS
cap and at most 32 MiB of reports. Measure cold, repeated and changed-input wall
time, files/bytes throughput, process-tree RSS, completion/coverage and owned
worker cleanup. Stop only owned processes if a cap is reached and mark the gate
incomplete. Mac `supervised-alpha` samples RSS and is not a hard allocation
boundary. Unknown plugin external state deliberately disables persistent result
reuse and continuation across audit slices; repeated scans must not claim cache
speedup or accumulated certified progress. Synthetic performance is not a
production throughput promise or accuracy estimate.

The prior Phase 1 receipts remain historical evidence for their original
commit/platform/artifact; they do not qualify this final kit. Report all native
and enterprise gaps explicitly. A bounded read-only pilot on a user-selected
repository can be recommended after the kit gates pass; a whole-machine scan or
real repository pilot is not part of this synthetic qualification.
