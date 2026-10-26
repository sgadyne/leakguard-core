# Password Buddy

Password Buddy is the local browser companion shipped with LeakGuard. The
installed `leakguard-buddy` command starts a private service on IPv4 loopback
and opens its browser session. The service chooses an available port and
prints a readiness line such as `Password Buddy listening at http://127.0.0.1:54321`.

Installers can run it in the background with:

```text
leakguard-buddy --no-browser --state-dir STATE --config CONFIG
leakguard-buddy open --state-dir STATE
```

The first command starts the service. The second consumes the private, one-use
browser launch file and opens a fresh session. Buddy rotates that file after a
successful exchange, so the installed shortcut can be used again while the
service is running. `--config` points to the shared LeakGuard config. Buddy
keeps its own selected detection profile and worker count in `buddy-config.json`
under the private state directory; worker policy remains shared with the CLI
and Git hooks.

Buddy stores encrypted scan observations and actual credentials separately in
`observations.lgo` and `credentials.lgv`. Unlock sessions are independent.
Source scans and plugins cannot access the credential session. Findings and
reports omit matched values. A user can explicitly add a credential with Save,
reveal or copy it, and create or restore an encrypted vault backup. Adding a
finding to the vault pre-fills only its rule title and source location.

Git hooks are opt-in per selected repository. Buddy snapshots the effective
profile configuration for that repository, reports its path and shared worker
policy, and does not enable global hooks. The default credentials profile
remains separate from the selected Sensitive or Firm profile.

For an explicitly selected SSH target, use the installed host CLI; Buddy does
not connect to remote hosts or expose its vault to them:

```text
leakguard-host ssh-deploy TARGET ARTIFACT.zip /private/remote/dir --sha256 HASH
leakguard-host ssh-scan TARGET /explicit/remote/root --python /receipt/runtime_python
```

The remote source stays on the remote host. Review deployment receipts and
scan limits before using real targets.
