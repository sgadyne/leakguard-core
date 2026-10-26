# macOS alpha acceptance — 2026-10-26

Resumed after the overnight run and completed native macOS arm64 acceptance of
the exact `0.2.0-alpha.5` package. Production commit:
`d6ab851908e77665a7585573ef34ee642d5920a7`. Mac bundle SHA-256:
`8a88e14312b7d1f43f45f41b74e8766b7aa9bfa7955dd48a949df9f5dbcd0cdd`.
Production package bytes were unchanged.

The local working repository now contains the integrated monorepo. Its six
previous untracked handoff/planning/probe files were preserved under
`../../../.leakguard-runs/alpha-resume-20261026/original-working-documents/`
(relative to this document's directory) before the fast-forward.

## Evidence

- Installed core: 353 cases, 349 passed, four explicit skips, no failures/errors.
  Two skips require Windows; two require invalid UTF-8 filenames that this Mac
  filesystem rejects. Separate Unicode/newline filename and root tests passed.
- Installed v1 detector, v2 detector and v2 extractor conformance: three passed.
- Encrypted observation storage: 18 checks passed; encrypted resumable scan
  cycle: 12 passed; installed HTTP/vault/Git journey: 32 passed.
- Normal per-user installation and doctor passed using Python 3.13.13 and the
  19 pinned package wheels. Safari authenticated and displayed both first-run
  storage setup and credential vault setup.

Test-only commit `af4694c6ba50509955f2c27d46259e7ac9ffb5ed` makes native
fixtures select the approved Mac `supervised-alpha` policy and express the
filesystem limitations above. Strict-policy refusal tests remain intact.
The first rerun also omitted the original harness's canonical temporary
directory; restoring that isolated environment fixed its three path/race
fixture failures. Failed attempts remain in the evidence directory.

Local evidence is in
`../../../.leakguard-runs/alpha-resume-20261026/` relative to this directory:
`native-final-core-suite.json`, `native-validation/storage.json`,
`native-validation/cycle.json`, `native-validation/http-journey/journey.json`,
`personal-install.json`, `personal-doctor.json`, and `resume-completion.json`.

## Installed app

Installation: `~/Library/Application Support/LeakGuard`.
Commands: `~/.local/bin/leakguard`, `leakguard-buddy`, `leakguard-buddy-open`,
`leakguard-doctor`, and `leakguard-install`.

Buddy is running locally and open in Safari. To reopen the running app:

```sh
~/.local/bin/leakguard-buddy-open
```

If it has stopped, start it with `~/.local/bin/leakguard-buddy`.
Choose your own passphrase in **Vault → Create vault**, and separately create
encrypted scan storage under **Sources**. Then add selected folders to scan.
No personal secret was entered, no personal drive scan was started, and no
hooks or OS service were activated during this follow-up. Only explicit Save
stores an actual credential.

## Remaining acceptance limits

Windows has an offline bundle but no native runner result. Real SMB/NFS/UNC
disconnects, external SSH scans, keychain opt-in and OS service registration
remain unverified. Earlier loopback SSH and update/rollback receipts retain
their original scope. Native Safari verification here covered first-run
navigation; the full interactive browser journey was previously run on Linux.

Mac workers use an RSS watchdog, not a hard memory cap. Plugins execute as
trusted code with the current account's access. Observation state remains
bounded at 64 MiB and directory continuation at 100,000 entries. These are
internal-alpha limits, not claims of production readiness or company-wide
detection accuracy.

The expired overnight waiver was not renewed and no agents were restarted.
This foreground follow-up supersedes the old handback's unverified Mac
installation status; it does not rewrite historical receipts.
