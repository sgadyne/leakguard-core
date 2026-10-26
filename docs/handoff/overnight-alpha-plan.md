# LeakGuard and Password Buddy overnight alpha plan

Draft for Simon's review. Target: a useful internal team alpha after one
10-hour execution window with 4 Sol xhigh and 4 Luna xhigh agents. Implementation
starts only after Simon reviews this plan, supplies addenda, and dispatches it.
This replaces the earlier multi-day release-candidate proposal for this run.

The morning deliverable is one monorepo and a downloadable install bundle:
install Buddy, navigate local folders and mounted drives, select scan scopes,
run or schedule scans, review findings, save credentials explicitly into an
encrypted local vault, enable Git hooks, and install a private firm plugin.
CLI and remote SSH scanning use the same engine. This is an internal alpha;
platforms are marked tested only when their native installation actually ran.

## Starting point

Start implementation from integrated commit
`c0c2c0ced88b90620c8d5b3d41f462bc348b6af0`, not the older local 0.1 checkout.
Its verified bundle is available in the local pilot directory and on devbox.
Preserve the original checkout and its untracked handoff documents. Bring this
plan and subsequent user addenda into the new integration branch explicitly.

Existing assets include the typed engine, CLI, Git hooks, file audit queue,
SQLite/Memory ScanStore, v1/v2 detector and extractor interfaces, script checks,
document parsers, conformance tools, packaging, and 251 integration/unit tests.
Reuse these rather than creating another scanner.

Known work to address first:

- Linux reference: 249 passes, two Windows-only skips.
- Mac installed diagnostic: 251 tests, 37 failures, 13 errors, two skips.
  Rejected RLIMIT_AS enforcement is one confirmed cause; other failures still
  need classification, including path and directory-identity behavior.
- Independently labelled text pilot: 2 TP, 4 TN, 0 FP, 6 FN. Six short literal
  credentials were missed; the old corpus wrongly treated these as negatives
  for the intended product behavior.
- Buddy UI, credential vault, scheduler, and installation flows are new work.

## Product scope for the morning

| Surface | Required alpha behavior |
| --- | --- |
| Buddy UI | Local browser UI launched by an installed shortcut/command. Sources, scan progress, findings, vault, plugins, settings. Clear scan/cancel/resume controls and last successful scan time. |
| System navigation | Paginated directory browser; home/common locations, macOS volumes, Linux mounts, Windows drive letters and supplied UNC paths. Show permission-denied, offline and unreadable locations. Add explicit roots and exclusions; do not follow symlinks outside a selected root by default. Reveal a finding in the OS file manager where supported; otherwise copy its path. |
| Findings | Filter by source, rule, category and state; show file/part/line, last verification and coverage. Review/dismiss annotations are separate from engine evidence and never weaken Git enforcement. |
| Credential vault | Create, unlock, lock, list, add/edit, explicitly reveal/copy, delete and encrypted backup/restore. Store actual secrets only after an explicit Save action. Link an entry to a finding without resolving the exposure. |
| Periodic scans | Opt-in per-source schedule, bounded work slices, one active job per scope, persisted progress, retry/backoff for offline shares, pause/resume, service status. Resume after restart conservatively. |
| Git | Explicit install/uninstall for selected repositories; staged/outgoing-history checks and existing-hook chaining. No global hook activation during installation. |
| Fileshares | Scan mounted SMB/NFS volumes and Windows UNC paths using the current user's access. Disconnection is incomplete coverage. Alpha does not manage share credentials or mount shares. |
| SSH | Deploy an explicitly selected artifact to a chosen host and run a bounded scan against a chosen remote root. Source bytes stay remote; return redacted results over SSH. No remote credential-vault access. |
| Firm extensions | Install a reviewed private wheel or fixed-argv script, configure it in a separate firm profile, run its sample conformance cases, and use it from UI/CLI/Git without editing core. |
| Installation | Per-user macOS/Linux bootstrap and Windows PowerShell bootstrap; private runtime, pinned dependencies, versioned release directory, launcher, doctor, service enable/disable, update and rollback. Supply an offline wheelhouse option for corporate installation. |

The first vault flow uses manual entry/paste, including an Add to vault action
that pre-fills the finding's title/location. Automatic secret extraction from a
source file is a later extension; it must not introduce values into scan reports.
Clipboard clearing is best effort and must not erase newer clipboard content.

## Monorepo and shared contracts

Keep the existing core source layout and distribution name during this run.
Add separately installable packages around it; a cosmetic move of the engine
would consume integration time without improving the alpha.

```text
leakguard/
  src/leakguard_core/          existing engine and CLI
  apps/buddy/                 local service, browser assets and launcher
  packages/leakguard_vault/   credential and encrypted observation storage
  packages/leakguard_host/    navigation, scheduling, OS service and SSH adapters
  plugins/sensitive_basics/   small first-party PII and identifier rule pack
  templates/firm_plugin/     standalone private wheel, config and labelled cases
  examples/script_checks/   existing fixed-argv interface
  deploy/                    platform bootstraps and offline bundle builder
  tests/integration/         whole-product acceptance scenarios
  docs/                      install, architecture, firm guide and alpha limits
```

One release manifest pins compatible package/plugin versions, dependency hashes,
backend executable hashes and platform artifacts. All user-specific roots,
private plugins, vaults, rules and observations live outside the checkout.

Core keeps ScanService/ScanStore and the current v2 plugin contract. Host adapters
provide root listing, bounded directory listing, job submission/cancellation,
service installation and explicit remote execution. Buddy consumes those APIs;
it does not parse arbitrary command output or duplicate scan policy. Freeze the
small shared interfaces during the first 45 minutes; the integration lead owns
later changes.

Buddy serves bundled static assets on loopback only. Use a per-install session
bootstrap, authenticated requests, exact Host/Origin checks, CSRF protection and
no third-party scripts. Values and unlock requests never enter URLs or logs.
The credential worker has a separate unlock capability; scan jobs and plugins
do not receive it. Treat plugins as trusted account-level code, not a sandbox.

## Storage and platform choices

Use maintained cryptography primitives and a versioned authenticated format.
The proposed alpha uses `cryptography` AEAD encryption with fresh nonces and
Argon2id passphrase key derivation with recorded, bounded parameters. Random
data keys, separate credential/observation keys, authenticated format metadata,
atomic replacement and encrypted backups are required. Keep library versions
pinned in the artifact; do not implement encryption primitives.

Credential unlock requires a user action and passphrase. Background scanning
must never unlock that vault. The observation key may use a verified native OS
keyring so scheduled scans can continue while credentials remain locked. If a
usable keyring is unavailable, offer a foreground passphrase-unlocked session;
report unattended scanning unavailable instead of storing a plaintext key.
Backup recovery must work without the original machine's keyring.

For the alpha observation store, reuse SQLiteScanStore's semantics with an
in-memory SQLite connection and encrypted serialized checkpoints. This avoids a
new platform-specific SQLCipher build dependency overnight. Keep SQLite temp
storage in memory, disable plaintext journal/report mirrors, and serialize
through the store owner. Only encrypted bytes reach disk. Verify serialization
support during preflight; reject unsupported runtimes in doctor.

Bound each observation profile's serialized state to 64 MiB initially. Checkpoint
after a bounded job slice and before acknowledging durable progress. A crash can
replay the last unacknowledged slice; it cannot resolve a finding on missing work.
Apply backpressure and show a capacity limit before the store fills. Benchmark
checkpoint cost at integration; large-fleet storage is outside this alpha.

On macOS, adopt an explicit **supervised alpha worker policy** if a hard memory
cap is unavailable: bounded input/output, wall timeout, descendant cleanup and
an RSS watchdog. An RSS watchdog is not a hard allocation limit. Expose that
capability in doctor and reports. Preserve the existing strict policy, which
rejects required work when the hard bound is unavailable. Changing this policy
must change runtime/cache identity. This is an explicit proposed alpha policy
change for review, not a silent weakening of the old contract.

A successfully completed document scan can be accepted under the selected
supervised policy; parser failure, timeout, missing required dependencies and
incomplete acquisition still block Git. CLI, Buddy and hooks must select the
same configured policy. Native Windows Job Objects and Linux limits remain in
use where actually supported.

Library references: [authenticated encryption](https://cryptography.io/en/latest/hazmat/primitives/aead/),
[key derivation](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/),
[OS keyring backends](https://keyring.readthedocs.io/en/stable/),
and [SQLite serialization](https://sqlite.org/c3ref/serialize.html). These document
the building blocks; the integrated storage behavior still needs the checkpoint
acceptance below.

## Detection depth and firm plugins

Ship three named profiles: credentials, sensitive information, and firm.
Credentials remain the default Git blocker. Sensitive-information rules default
to review until a firm explicitly promotes specific rules; adding a PII profile
must not make every email address a Git blocker.

Required first-night depth:

- Repair short quoted password/client-secret detection and cover common field
  aliases and unquoted assignments with benign controls. Labels express product
  expectations independently of existing regex thresholds.
- Retain supported text, UTF-16, Office XML, text PDF and MSG extraction, with
  explicit limits and omissions. Fix platform execution before adding formats.
- Add a modest rule pack: contextual email/phone/address-like records, financial
  identifier candidates with checksums where applicable, and configurable
  employee/customer/account identifiers. Record entity category and rule ID,
  not matched values. Do not claim broad medical/legal document understanding.
- The firm template demonstrates a structured identifier, a confidentiality
  marker and a custom script check, with independent positive/negative fixtures.
- ZIP traversal is stretch work only: fixed member/byte/depth budgets, no writes
  outside private scratch, and no following links. OCR and legacy Office wait.

The private extension seam is the already implemented v2 manifest/options API
and fixed-argv JSON script adapter. Supply install/enable/disable/list/check
commands and a configuration template. Inspect a manifest without importing
arbitrary installed packages; execute only explicitly enabled extensions.
Unknown dependency closure disables semantic reuse. Core upgrades must retain
working v1/v2 compatibility or reject the incompatible plugin explicitly.

The corporate workflow should be: download the release bundle, install into a
private per-user runtime, install the firm's reviewed wheel from a local path,
select the firm profile and sources, run its labelled demo, then enable scans
and selected Git hooks. Uninstalling the app retains the vault unless the user
explicitly requests data deletion. No auto-update or telemetry service is needed.

## Backend execution work

Optimize the existing scan path after the first integrated slice works:

1. Remove repeated per-file configuration/runtime/dependency setup within one
   bounded scan job, while validating the immutable inputs used for identity.
2. Add bounded parallel file work with one durable store writer; preserve
   cancellation, result ordering/provenance and total byte admission. Start at
   two workers; measure before increasing on a laptop or network share.
3. Preserve content-validated positive cache replay, resumable enumeration and
   incremental observations. Coalesce queued changes and back off offline roots.
4. Attempt backend batching only if per-part/file/commit boundaries survive the
   integration comparison. Do not concatenate unrelated text for a speed win.

Measure same-host cold/warm scans at 50 and 500 small files, a mixed-document
sample, installed-hook latency, worker count, backend launches and memory.
Target a useful cold-throughput improvement and responsive cancellation, but
do not promise a multiplier before measuring. Keep an optimization only if
the reference path and optimized path agree on findings, provenance and coverage.

## Agent ownership

Use exactly eight execution agents; four Sol xhigh and four Luna xhigh. Every
agent owns one branch/worktree. The integration lead counts among the eight.
No unbounded additional reviewers or nested worker teams.

| Agent | Ownership | Required handback |
| --- | --- | --- |
| Sol 1 | Integration lead; core platform failures, policy and shared API changes | Integrated branch, policy capabilities, passing release checkpoint and honest platform matrix |
| Sol 2 | Vault/storage and credential capability boundary | Encrypted observation adapter, credential CRUD/lock/backup and persistence integration |
| Sol 3 | Host adapters, scheduler and SSH execution | Navigation API, resumable service jobs, remote execution and disconnection semantics |
| Sol 4 | Engine execution performance and extension integration review | Bounded execution improvements, reference equivalence and stable plugin seam |
| Luna 1 | Buddy UI and launcher | Complete usable sources/findings/vault/plugins/settings flows |
| Luna 2 | Platform installation and release artifacts | Bootstraps, shortcuts, per-user service adapters, offline bundle, rollback and doctor |
| Luna 3 | Sensitive-information rules and firm template | Installable rule pack, private-plugin template, examples and corporate setup guide |
| Luna 4 | Integration scenarios and evaluation | Independently labelled corpus, native receipts, install journey and benchmark summaries |

Where the coordinator only supports four concurrent chats, dispatch two
persistent four-agent squads on devbox, each 2 Sol + 2 Luna, sharing immutable
contract notes and handing commits to Sol 1. Sol 1 is the only integration-branch
writer. Reserve at most two simultaneous heavy jobs across both squads; expand
only after checking shared host capacity. Native Mac/Windows runs count toward
that budget. Routine coding and lightweight imports do not consume a heavy slot.

## Ten hour execution schedule

| Time after dispatch | Outcome |
| --- | --- |
| 0 to 45 minutes | Prepare the integrated baseline and isolated worktrees; confirm Mac/Linux and locate a Windows runner; freeze interfaces; check crypto/keyring/SQLite/package availability; publish artifact and branch ownership. |
| 45 minutes to hour 4 | Build parallel vertical slices. Fix platform launcher and short literals; land vault/storage, sources/job APIs, Buddy shell, first installers and firm example. |
| Hour 4 checkpoint | Integrate once. Install locally, add a folder, scan synthetic text/document content, show a finding, explicitly save a credential, lock/restart/unlock, and load the firm example. Run the shared suite once and assign failures. |
| Hours 4 to 8 | Finish scheduling, mounted shares/SSH, system navigation and update/uninstall flows. Add the sensitive-information pack and bounded execution improvements. Fix integration failures. |
| Hour 8 checkpoint | Freeze features. Run native installed acceptance, complete product journeys, labelled evaluation, secret-leak/tamper/crash checks and the short benchmark/equivalence set. |
| Hours 8 to 10 | Repair checkpoint blockers, remove or disable incomplete stretch features, rebuild affected artifacts and rerun affected acceptance. Publish the exact build, install commands, platform matrix, alpha limits and morning demo. |

The clock is elapsed wall time for the whole team. No extra soak period is a
prerequisite for this internal alpha. If Windows execution is unavailable,
deliver its artifact/scripts with Windows marked unverified; do not let a
missing runner consume the entire night or call it verified cross-platform.

## Testing policy

Be light during implementation: imports, build/start smoke checks, and a focused
reproducer when needed to diagnose a failure. Do not run the full suite after
every patch, build a large new matrix, or spend a lane on repetitive reviews.
Use the three major integration checkpoints above. Add only compact regression
cases for new behavior or discovered defects; reuse existing coverage.

The final checkpoint concentrates on:

- Fresh install/start/stop, navigation and a scan on each available native OS;
  explicit record of unavailable platforms. One selected Python runtime per OS
  for this alpha, not every Python version.
- End-to-end local, mounted-share and SSH jobs, including cancellation, restart
  and one offline/reconnect scenario. A local test double does not establish
  real SMB/NFS/SSH behavior; label the available host evidence.
- Credential save/reveal/lock/restart/backup/restore; wrong password, tampered
  ciphertext and interrupted write. Scan/plugin code cannot access vault unlock
  capabilities. Inspect the app's persisted state and logs for synthetic values
  outside the encrypted vault and intentional explicit reveal response.
- Actual installed pre-commit/pre-push invocation, chaining, positive cache replay,
  required document failure, and private-plugin installation from its wheel.
- Independent TP/FP/TN/FN for labelled synthetic rule cases, plus a separate
  extraction/omission table. Unlabelled user files do not become true negatives.
- Optimized/reference equivalence and small same-host throughput measurements.

Only rerun the checks affected by final fixes, followed by a short whole-product
smoke on the frozen artifact. Record observed failures rather than counting
skips as passes or manufacturing a clean-drive claim.

## Scope cuts and completion

If the schedule tightens, cut in this order: ZIP support, UI cosmetics/tray
integration, advanced PII/NLP, backend batching, then update automation. Keep
manual update/rollback. Browser autofill, cloud sync, shared/team credential
vaults, fleet management, recursive OCR, active credential validation and signed
public-store distribution are outside this overnight alpha.

Do not cut the installable local journey, encrypted persistence, explicit vault
approval/lock, native failure visibility, Git correctness or the firm-plugin
example. If one of these cannot land, identify the precise incomplete surface
in the handback and disable misleading entry points. Never deliver plaintext
credential storage as a shortcut.

The handback contains one integrated commit and verified source bundle, hashed
platform artifacts/offline dependencies, a short install-and-first-scan guide,
private-plugin starter, exact platform results, the labelled matrix, measured
performance, and a concise known-issues list. Retain only owned artifacts and
useful receipts; stop owned jobs and do not clean shared host resources.

## Items for Simon's addenda

The proposed defaults are eight agents, ten hours, a local browser UI, manual
credential entry, encrypted bounded observation checkpoints, and the explicit
supervised alpha policy on platforms without hard memory limits.

Useful dispatch details are the Windows runner or CI target, the first SSH
host:path and mounted-share targets, and two or three firm-specific data classes
to use in the starter profile. Missing real-data targets do not block building
the alpha with synthetic fixtures; they remain explicit pilot follow-ups.
