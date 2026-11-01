# Password Buddy: supervised Mac alpha pilot

This pilot combines automatic footprint discovery/freshness fixes with scan
profiles, configurable alias packs and the Settings preview/apply workflow.
The release notes and checksums identify the exact packaged commit and runtime.
Only Apple Silicon macOS is qualified in this release. It is ad-hoc signed,
not Developer ID signed or notarized. Use only where the Mac's and organization's
software policy permits this build. If policy blocks it, use the signing or
managed-distribution route; do not disable protections to install it.

## Start and test

1. Download the app ZIP, SHA256SUMS.txt and pilot validation receipt from the
   same prerelease. Verify the ZIP digest with `shasum -a 256` before extracting.
2. Quit the prior Password Buddy instance. Retain the old app and profile backup.
   Copy the extracted app to an approved application location.
3. For a first pilot, use a separate profile. For example, with the app in
   your Applications folder:

   ```sh
   open -n "$HOME/Applications/Password Buddy Alpha.app" --args --buddy-data-dir "$HOME/Library/Application Support/Password Buddy Pilot"
   ```

   This does not import credentials from another profile. For an existing-profile
   upgrade, review the app's migration/backup prompt. Never run two versions
   against the same profile. Rollback must use the retained matching app/profile
   backup, rather than pointing an older binary at migrated state.
4. In Settings, preview/apply the standard credential profile or a reviewed custom
   pack. Automatic This Mac scope is independent of profile selection. Existing
   source-specific schedule overrides remain in force.
5. Review schedule and exclusions. A fresh profile defaults to hourly polling;
   the bounded automatic qualification used one-minute recurrence. Neither is a
   real-time file/read monitor. The app and unlocked scan store must remain
   available for background work.
6. Create/unlock encrypted scan storage privately. The credential vault is a
   separate gate. Review findings and move credentials deliberately; a finding
   is not proof that a credential is valid or that its original copy was removed.
7. Check a disposable credential fixture through create, edit, rename, delete
   and restart, then review the app's pending/inaccessible/unsupported/error
   states. Use synthetic values in bug reports; never attach a private profile,
   plaintext credential, or an unreviewed scan export.

## Pilot boundaries

- Broad automatic discovery and content inspection are separate progress states.
  The prior bounded whole-machine trial did not finish its entire backfill.
- One generic failed slice recovered in prior qualification; its underlying cause
  remains unconfirmed. Treat recurring failures or stalled queues as a pilot issue.
- User aliases, presets, DetectorV2/ExtractorV2 and Presidio factories are explicit
  extension points. Profiles do not install arbitrary code or grant permissions.
- General recursive archives/OCR/obfuscation search, native event/read monitoring,
  arbitrary transport/job plugins and fleet administration are not provided.
- Windows/Linux and remote-source evidence from earlier builds is not fresh
  platform qualification for this Mac release.

## Next work, driven by evidence

1. Preserve bounded, redacted exception type/stage diagnostics for recovered
   `scan-failed` slices, then reproduce recurring failures before changing logic.
2. Show queue-age buckets, last successful inspection and oldest completed work;
   report excluded, deferred, unsupported and failed content separately.
3. Consolidate the legacy profile selector and new scan-profile card. Add a concise
   field-by-field change summary before the advanced JSON/provenance details.
4. Target new alias/protocol rules with labelled positive, negative and boundary
   controls from actual misses. Deduplicate overlapping findings without hiding
   detector attribution. No speculative expansion to hundreds of custom rules.
5. Measure parsing/traversal/cache costs on the integrated pilot. Use fair bounded
   work shares and per-format budgets; retain event-loss reconciliation when a
   future native change-feed provider is added.
6. Separate future modes explicitly: ordinary backfill/polling, bounded deep
   inspection, and OS access auditing. Keep scope, inspection depth, cadence,
   content omissions and alert suppression independently configurable.
