# LeakGuard host adapters

Install beside the matching `leakguard-core==0.2.0`. Importing the package does
not scan, launch processes, create state, or unlock credentials.

```python
from leakguard_host import HostService
host = HostService(config=config, scan_store=unlocked_observations)
source = host.add_source("/explicit/selected/root", exclusions=["build"])
job = host.submit(source["id"])
host.start()
# UI polls host.jobs(), host.sources(), and host.status().
host.stop()  # Must succeed before observations.close()/lock().
```

The observation adapter must supply `load_host_state() -> dict` and
`save_host_state(dict) -> None`. The latter atomically checkpoints the same core
ScanStore and the host state in encrypted storage before durable progress is
acknowledged. There is no plaintext fallback. Checkpoint failures stop work.
Running/queued/backoff jobs restart paused, with `interrupted-restart`; the user
can resume them. Completed evidence remains in the core store. Pause, cancel,
and offline roots retain incomplete coverage. One worker serializes slices and
one active job is admitted for each source. Schedules are opt-in, at least 60
seconds apart. Offline retry grows from 5 seconds to one hour.
Three unchanged budget-only slices without file or directory progress pause the
job with `scan-progress-stalled` and incomplete coverage. Successful directory
enumeration and durable cursor advancement count as progress even when a slice
contains no scanned files. Unexpected worker failures are visible in status and
pause admitted work before shutdown.

Each job persists the core's public `Scanner.work_identity(policy=...,limits=...)`
before acknowledging a slice. A changed policy, plugin registry, or runtime
identity restarts that job's work cycle and makes prior evidence unknown until
it is verified under the new identity. A matching identity preserves resumable
work. This requires the matching alpha core API; an older core fails visibly
with `work-identity-unavailable` before source scanning.
The continuation identity excludes slice scheduling and output budgets; the
per-report policy identity still records that report's complete configuration.
Cancelling a job can return while its bounded slice is unwinding. Removing the
source returns `source-busy` until that slice has released store ownership.

`roots()` lists home/common folders and native mount metadata. `browse(path,
root=selected_root, cursor=..., limit=100)` pages at most 500 rows and inspects
at most 20,000 entries per request. A changed directory invalidates its cursor.
Symlinks are shown without being followed; resolved navigation cannot leave a
selected root. POSIX directory enumeration holds directory handles and opens
descendants without following links, so an ancestor substituted during browsing
cannot redirect enumeration outside that root. Changed listings discard their
rows and require a refresh. The engine handles no-follow scan acquisition. OS filesystem
calls can still wait for a stalled network filesystem; `stop()` reports
`worker-still-running` when it cannot safely release store ownership. Do not
close the store after that result. Mounted-share credentials and mount actions
are outside this adapter. UNC access requires native Windows; other platforms
report it unavailable. Native capability presence is not a validation receipt.

`service_spec(command, state_dir, platform=None)` returns a pure dictionary:
`platform`, `supported`, `filename`, `path`, `content` (UTF-8 text), `encoding`,
`reload_argv`, `enable_argv`, `disable_argv`, `status_argv`. Paths and argument
vectors are final, with no placeholders. The installer writes the private file
and registers it; host rendering changes no OS state. A service launches Buddy
and can schedule unattended work only with a verified observation-key backend.
The credential vault stays locked.

The macOS mount reader uses the no-argument command documented in Apple's
[mount source](https://github.com/apple-oss-distributions/diskdev_cmds/blob/main/mount.tproj/mount.c).
Windows task XML binds the current user's logon trigger and principal using
[UserId with InteractiveToken](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-logontype-principaltype-element).
Windows specifications remain unverified until a native runner executes them.

`SSHRunner.run(target, root, python=absolute_runtime_python, config_path=None,
max_seconds=30, max_files=100)` executes an installed remote host package with
an ephemeral memory ScanStore. It returns only a validated redacted core report.
The remote root and runtime are explicit; source bytes remain remote. Limits
are 120 seconds/1,000 files with an additional remote supervisor wall bound.
Incomplete bounded scans are reported incomplete and have no persistent remote
resume state. Existing SSH keys/agent and strict known-host verification are
required. Passwords and credential-vault access are never accepted.

`SSHRunner.upload(target, artifact, remote_directory, sha256=...)` transfers a
chosen release ZIP into a **new** private remote directory and verifies its hash.
Uploading does not install or execute it. `SSHRunner.deploy(...)` is the explicit
upload-and-install action: it verifies the ZIP hash again, rejects traversal,
symlinks, duplicate/encrypted members and oversized archives, extracts into a new
private directory, then invokes the bundled offline installer with an explicit
private prefix and state directory. It returns a validated install receipt with
`runtime_python` for a subsequent `run` call. Deployment requires a POSIX remote
host with the exact Python minor declared by the offline release's
`target_python` and its supported dependencies. Installation
does not enable services, mounts, hooks, or credential-vault access. SSH process
output is bounded; stderr and arbitrary command output never enter the response.

The embedded remote installer and process-group supervisor require a POSIX
target. Their tests execute those target scripts locally on POSIX runners;
Windows CI retains client, host, service-specification and credential/profile
checks but does not execute these three POSIX-target fixtures locally. This
does not qualify a native Windows remote deployment or supervisor.

For one explicit deploy-and-scan journey, pass `--scan-root /chosen/remote/root`
to `leakguard-host ssh-deploy TARGET bundle.zip /new/private/deployment --sha256
HASH`. The scan uses the installed receipt's runtime and configuration, including
the pinned bundled backend. Python callers pass `scan_root=...` to `deploy`.
If installation succeeds but the scan fails, its install receipt is retained and
scan coverage is incomplete. SSH CLI commands return exit2 for incomplete work.
