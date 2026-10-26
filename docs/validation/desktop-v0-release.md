# Desktop v0 release checks

This is the release tooling receipt; final artifact hashes and native Mac
acceptance belong to the coordinator's frozen-candidate receipt.

2026-10-26, devbox release lane:

- `python3 -m py_compile deploy/desktop/bootstrap.py deploy/desktop/build.py`
  passed for the first tooling slice.
- `python3 tools/check_desktop_bootstrap.py -v` passed eight focused checks:
  tamper/unlisted-file rejection, relative versus escaping symlinks, unsafe and
  duplicate manifest paths, exclusive preparation lock, unclaimed state refusal,
  runtime mismatch retaining existing ciphertext, the shared backend ownership
  lock, and an installer environment that hides uv and unset profile config.
- Exact release npm lock generated with Node 22.23.2 and
  @electron/packager 20.3.0. No external publishing occurred.

The runtime/API harness uses the actual built target interpreter, then the
installer-returned private venv. It checks owned-process control, auth headers,
session recovery, source scan/review, manual credential operations, offline
reviewed plugin installation/conformance/explicit enabling, disposable Git
guards, identity reuse and mismatch preservation, restart, encrypted state and
safe owned cleanup. Its optional production Chromium check is explicitly a
test-only native bridge simulation.

## Actual installed Linux boundary

The complete integrated product at `96d13884f0075605c3364e34f74323e725857fb3`
was cloned into a disposable clean snapshot. A harness-reporting-only commit
produced proof source `2832c57be2005be50026c2715310e94d07a91dbd`. The UI and shell
were rebuilt in that snapshot. The resulting Linux payload was assembled with
the prepared CPython 3.11.16 tree and verified alpha.5 wheelhouse, replacing only
Buddy with the fresh 0.1.0a2 wheel.

The full installed runtime/API and production Chromium check passed on
2026-10-26 in 17.483 seconds, using the corrected route-heading harness selector
at release commit `24d1cf7ecd0bfbe7d526ecf026504b49f345e99f`.

| Evidence | Value |
| --- | --- |
| Resource manifest SHA-256 | `7c46596b63a68ac89b3e3f696ac537225f2d4545dde0fc7f747fcd9500e71dce` |
| Runtime identity | `32b97de68cefa3fa91ef080a9f70aba27f4e0e68a9450a1a728276dee6056016` |
| Receipt on devbox | `/home/dev/projects/leakguard-desktop-v0-20261026/proof-full-linux/runtime-check2.json` |
| Checks | 15 passed |
| Owned children | All stopped through safe shutdown |
| Synthetic profile/source/repository | Cleaned by their owning harness |
| Production browser | Six routes and the actual installed scan finding grid |
| Script/CSP errors | 0 / 0 |
| Dynamic style nonce | All 34 style elements correctly nonced |
| Resource mutation | Full closure reverified after preparation and API/browser journey |

The passing checks include true private venv/pip readiness, auth Host/Origin/CSRF
and session recovery, exclusive backend ownership with both stores locked,
bounded source scan and review, explicit credential save/edit/reveal/lock and
encrypted backup/restore, offline reviewed plugin installation/conformance and
explicit profile enabling, stable-runtime disposable Git guards, same-identity
runtime/plugin reuse, mismatch retaining existing state, encrypted stores
retained locked after restart, and no synthetic secret in plaintext state,
stderr or unclassified API responses.

Earlier failed receipts remain preserved alongside the proof. Their failures
were the preparer's Linux terminfo case-collision handling, selecting a
not-yet-created config for the installer's core-help smoke, and a browser harness
selector matching both the toolbar and page headings. Each has a concrete fix;
the final passing check used real integrated product sources throughout.

Pending coordinator evidence: final Mac/Windows/Linux packaged artifacts and
hashes, relocated native Mac launch/lifecycle, signing status, and any Windows
native validation. No Windows native pass is inferred from cross-packaging or
static closure checks. The Linux proof establishes installed runtime and browser
behavior, not native Electron tray/session behavior.
