# Responding to an exposure in the personal beta

Use the native app with a new private beta profile. Monitor only the sources you
have explicitly selected. Treat each finding as a lead for review; a detector
may report an example or a dynamic reference rather than a secret. Do not paste
suspected values into reports or messages.

1. **Triage.** Inspect the location privately and decide whether it is a real
   credential, a benign example, a dynamic reference, a public identifier, or
   uncertain. Keep uncertain cases open for review. Grouped findings retain
   their individual observations and rules.
2. **Store or link if useful.** Manually create or link a vault entry using the
   intended service and a safe name. A link is metadata: it does not establish
   that the entry and finding contain the same value, remove any source copy,
   or resolve the exposure. Use the credential only through the intended
   service workflow. Never authenticate an arbitrary discovered value to test it.
3. **Rotate or revoke with the provider.** For a real exposed credential, the
   operator uses that provider's supported interface to issue a replacement and
   separately verify that the old authority is revoked. Update authorized uses
   and verify the new credential works. The app has no provider integration and
   cannot attest to revocation or successful use.
4. **Remove source copies and rescan.** Clean each authorized copy, including
   relevant history or deployment copies where separately approved. Run a
   complete scan of the selected source and check its result. A scan interrupted
   by sleep, permission loss, missing/offline storage, failure or lock does not
   establish absence. A successful clean source scan establishes only what that
   scan covered; it does not prove provider revocation or the absence of copies
   outside its scope.
5. **Keep separate records.** Record the operator's provider verification and
   the complete source scan evidence separately without values. Continue
   tracking any unknown source, unverified provider action, or remaining copy.

Before real onboarding, complete a synthetic backup and restore into a separate
profile and retain an independent recovery route. Use a new backup filename for
each saved backup; the desktop shell refuses to replace an existing file. A
failed backup publication is not a successful backup, even if a file appears.
