# LeakGuard and Password Buddy alpha

The alpha combines the existing scanner and Git guards with a local browser
app, encrypted observations, a separately unlocked credential vault, host jobs,
and reviewed private extensions. Use the release's exact install bundle and
consult its platform receipts and known issues before piloting it with a team.

## Install and first scan

Follow [INSTALL.md](INSTALL.md) for a private per-user installation from the
hashed offline bundle. Keep the install JSON receipt: its `installed` field
locates the immutable release, runtime, and `wheelhouse/`. Installation does not
activate Git hooks or register a background service automatically.

1. Launch the installed Password Buddy command/shortcut. A running service can
   open a new local browser session with `leakguard-buddy open --state-dir STATE`.
2. Create encrypted scan storage with its own passphrase. Add an explicitly
   selected folder, mounted share, or supported native UNC source. Review the
   root and exclusions, then start a scan.
3. Review findings, file/part/line provenance, verification time, and coverage.
   Permission failures, disconnections, parser failures, and exhausted budgets
   are incomplete work. An empty finding list is not a clean-drive claim.
4. To retain a credential, separately create/unlock the credential vault. Add to
   vault fills only a title and location. Enter/paste the value and choose Save.
   Saving, reviewing, or dismissing does not resolve an exposure or weaken Git.
5. Lock the credential vault and encrypted scan storage independently. A portable
   encrypted backup requires a backup passphrase; recovery does not depend on
   the original machine's keyring.

Buddy serves bundled assets only on IPv4 loopback. Its one-use bootstrap URL
uses a fragment; authenticated API mutations require exact Origin and CSRF.
The app uses no third-party browser scripts and logs no request bodies.

## Scanning and background operation

CLI, Buddy, and selected Git hooks use the same core service and configured
worker policy. The library remains usable independently of the product.
The installed profile selects `observation_backend: encrypted`. CLI/Git open a
verified observation keyring session when available; otherwise they enforce
using memory only and report `observations-ephemeral`. They never fall back to
plaintext observation files. Durable findings queries report unavailable when
that encrypted session cannot be opened.

Buddy's foreground passphrase session supports scans and persisted bounded job
slices. Unattended scans require explicit enablement and verified native keyring
storage of the **observation** key. Background jobs never unlock credentials.
Restarted interrupted jobs pause for an explicit resume. One active job per
source and one store owner coordinate encrypted checkpoints. Separate processes
may contend for a profile; ephemeral Git enforcement does not update Buddy's
history while another owner holds the encrypted store.

A source's encrypted SQLite checkpoint is initially capped at 64 MiB. Directory
slices admit at most `max_directory_entries` new entries and can replay up to
100,000 earlier entries to verify a resumable prefix. Changed directory identity,
signature, or ordering invalidates progress conservatively. Directories above
the hard replay/admission cap remain incomplete. This is a bounded local alpha,
not large-fleet storage.

Selected source descendants are not followed through symlinks. POSIX scoped
reads/enumeration use descriptor-relative nofollow opens; stable ancestor aliases
above an explicitly selected root (such as macOS `/var`) remain supported.
Native Windows behavior must be assessed from its own receipt, not Linux tests.

## Policy and extensions

Read [alpha-worker-policy.md](alpha-worker-policy.md) for execution capabilities.
Strict remains the standalone default. macOS alpha installation explicitly uses
`supervised-alpha`: bounded I/O, timeout, owned process cleanup, and sampled RSS.
An RSS watchdog can overshoot and is not a hard allocation limit. Run installed
`leakguard doctor --config CONFIG --format json` and the installation manager's
doctor to inspect the exact runtime and unattended-storage availability.

Credentials are the default Git blocker. Sensitive Basics supplies modest
contextual contact, financial, and organization-identifier candidates. These
are review-only unless a firm explicitly promotes named rules. It does not
provide broad semantic, medical, legal, OCR, or legacy Office understanding.

Use [firm-plugin-setup.md](firm-plugin-setup.md) for a reviewed wheel/fixed-argv
script, a separate firm profile, and independent conformance cases. Merely
installing a wheel leaves it disabled. Registry discovery reads static metadata
without importing arbitrary installed modules. Plugins are trusted account-level
code; supervision is not a sandbox. Startup-hook wheels are rejected to preserve
explicit activation.

Install selected repository hooks explicitly through Buddy or
`leakguard-install-hooks install REPO --config CONFIG --state-dir STATE`.
Use `status REPO` and `uninstall REPO` to inspect and restore preserved hooks.
An external shared hooks directory is rejected to keep the operation scoped.
The staged/outgoing Git checks block on credentials and incomplete required work.

Mounted shares use the current user's existing access; the alpha does not mount
shares or store share credentials. Explicit SSH deployment/scanning uses strict
host keys, a chosen artifact/root, and redacted results. Source bytes stay remote;
no remote credential-vault capability is provided. Loopback SSH evidence does
not establish behavior on an external host or a real SMB/NFS share.

## Python integration

`ScanConfig.from_mapping` validates an immutable configuration snapshot.
`Scanner.open(config=..., store=...)` accepts an injected ScanStore as its sole
observation sink; the caller owns an injected store's checkpoint/close lifecycle.
`Scanner.capabilities()` probes the selected worker primitive.
`Scanner.work_identity(policy=..., limits=...)` identifies resumable work using
the effective configuration and runtime. Its policy digest excludes slice-only
budgets and worker count, so it differs from the full per-report `policy_id`.
Changes to detection, acquisition, extraction, or worker policy restart persisted
work conservatively rather than combining results from different policies.
`parse_report(str_or_bytes)` validates the strict value-free report wire schema,
including counts and coverage, and rejects unknown fields and duplicate keys.

Host code receives only the encrypted observation adapter. Credential create,
unlock, Save, reveal, edit, delete, and backup operate through a separate explicit
CredentialSession. See the package READMEs for the small shared Python contracts.
