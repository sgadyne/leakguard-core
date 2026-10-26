# Desktop v0 release checks

This is the release tooling receipt; final artifact hashes and native Mac
acceptance belong to the coordinator's frozen-candidate receipt.

2026-10-26, devbox release lane:

- `python3 -m py_compile deploy/desktop/bootstrap.py deploy/desktop/build.py`
  passed for the first tooling slice.
- `python3 tools/check_desktop_bootstrap.py -v` passed six focused checks:
  tamper/unlisted-file rejection, relative versus escaping symlinks, unsafe and
  duplicate manifest paths, exclusive preparation lock, unclaimed state refusal,
  and runtime mismatch retaining existing ciphertext.
- Exact release npm lock generated with Node 22.23.2 and
  @electron/packager 20.3.0. No external publishing occurred.

The runtime/API harness uses the actual built target interpreter, then the
installer-returned private venv. It checks owned-process control, auth headers,
session recovery, source scan/review, manual credential operations, offline
reviewed plugin installation/conformance/explicit enabling, disposable Git
guards, identity reuse and mismatch preservation, restart, encrypted state and
safe owned cleanup. Its optional production Chromium check is explicitly a
test-only native bridge simulation.

Pending until a real integrated candidate is supplied: standalone staged/runtime
journey, final Mac/Windows/Linux packaging receipts and hashes, relocated native
Mac launch/lifecycle, signing status, and any Windows native validation. No
Windows native pass is inferred from cross-packaging or static closure checks.
