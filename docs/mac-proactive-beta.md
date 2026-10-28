# Local Mac proactive beta

Onboarding enables **This Mac** after encrypted scan storage is created or
unlocked. It discovers the accessible local root and home footprint without a
folder list. Hidden configuration and history are included. Initial metadata
inventory and content inspection are separate queues; neither current scheduled
work nor an inspected version means that a machine is clean.

Settings persist automatic coverage, interval or daily scheduling, IANA time
zone, global pause, exclusions, new-content admission, notifications, storage
paths, and configured locations. Locations can inherit the global schedule or
save an interval/daily override. One overdue run catches up after downtime.
Daily schedules choose the first repeated local time and advance a skipped time
to the next valid minute. UTC wall-clock deadlines survive restart; a backward
clock adjustment delays an interval run until its saved deadline. User pauses
survive restart. Interrupted automatic work resumes after scan-storage unlock.
Native key access and start at login remain separate explicit opt-ins.

The local beta is packaged with `--local-beta`, using the distinct macOS bundle
identity `org.leakguard.passwordbuddy.beta` so qualification can run beside the
previous app. Disposable testing also uses `--buddy-data-dir` with a private
profile. A distinct bundle identity does not select a different default profile;
live cutover still requires the explicit verified upgrade and store unlock.

The inventory preserves enumerated metadata, pending/changed content, inspected
versions, inspection errors, inaccessible paths, placeholders, encrypted stores,
unsupported formats, exclusions, aliases, and paths not seen again. Unreadable or
excluded directories have unknown descendants. Symlinks and special files are
not opened. Cloud placeholders are not deliberately hydrated. Protected stores
are inventoried without decryption. Archives, logical databases, image/OCR
content, Git object/history decoding and inaccessible content retain gaps rather
than a clean result. Priority admission reserves regular turns for the rest of
the queue. Reconciliation can discover new content during an initial content
backlog. No automatic deletion, quarantine, credential authentication or vault
migration is performed.

## Additional locations

External drives and OS-mounted shares use their selected path. Mount metadata
rejects an unmounted local fallback. Local Mac volume UUIDs and mounted endpoint
markers support reconnect. No mounting, VPN setup, network discovery or sharing
service is performed.

SSH locations use an explicit existing SSH alias/account and absolute VM path.
The beta's tested remote targets are Linux hosts with `/usr/bin/python3`.
OpenSSH uses batch authentication, strict existing host trust and no host-key
updates. Configured alias ports are respected; an explicit per-location port is
optional. A bounded fixed stdlib helper runs with isolated imports and no
bytecode writes. It does not execute repository code or install remote software.
Metadata and bounded file snapshots travel over SSH. Detection runs on the Mac;
only encrypted metadata and redacted observations persist. Every imported
snapshot carries its SHA-256, remote version, VM/root identity and a post-scan
version check. `ssh://` locations remain distinct from Mac paths and other VMs.
SSH private-key stores and other protected formats remain inventory-only.
Scans stay within the selected root/device, with explicit mount-boundary gaps.
Unavailable locations back off while other locations continue. A replaced VM or
root identity requires review. SSH scope is the selected directory, not a claim
to cover all disks or inaccessible accounts on the VM.

A private `pending-locations.json` preference file can stage validated SSH
locations before scan storage is unlocked. It contains only location preferences,
never file inventory or secrets. After each location is durably registered in
encrypted host state, the pending file is removed. Interrupted imports deduplicate
by the location URI.

## Persistence and recovery

The original bounded encrypted catalog remains the single-writer owner.
Inventory/evidence use bounded in-memory SQLite partitions, immutable encrypted
bases and bounded encrypted journals behind that owner. Standard compression is
inside the existing authenticated AES-GCM envelope. No plaintext SQLite file,
sort file or inventory journal is written. Partition files are published before
an atomic encrypted catalog commit; superseded uncommitted objects are reclaimed
without deleting the last committed generation. A durable user-control checkpoint
can publish while a scan transaction remains unpublished. Missing or corrupt
partitions fail explicitly; they are never replaced with empty state.

Credential-vault storage and encrypted scan storage are separately configurable.
Relocation quiesces writers, verifies encrypted copies, exercises atomic replace
on the destination and switches configuration atomically. The original copy is
retained. Supported destinations are private owned directories on supported
local filesystems; network storage for encrypted stores is not qualified here.
An offline configured store is unavailable rather than a new empty vault.
Credential-vault backups remain portable. A partitioned observation profile must
be backed up as the complete encrypted profile, including `.lgo.parts`; the old
single-file observation-backup command explicitly refuses to omit partitions.

The desktop runtime requires explicit upgrade. It holds preparation and profile
ownership locks, verifies a profile backup before switching runtime identity,
and rolls back a failed preparation without replacing the ownership lock inode.
An interrupted upgrade resumes against the retained backup. To restore that
backup while the app is stopped:

```text
<bundled-python> -I -B <resources>/bootstrap.py --resources <resources> \
  --data-dir <profile-root> --rollback-migration
```

Rollback restores the profile as of its backup; preserve any newer encrypted
profile separately before an intentional rollback. The original runtime and app
must remain available. Ad-hoc local signing is not Developer ID/notarization.
