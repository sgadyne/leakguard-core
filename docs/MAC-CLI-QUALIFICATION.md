# Mac CLI synthetic qualification

Run only after the supervisor reports `lanes_stopped`, the candidate is
`ready_for_local`, and the integrated bundle SHA-256 matches candidate.json.
Record the integrated commit, wheel hashes, OS/Python/Git/Gitleaks versions,
commands, exit codes and completed/deferred gates in a local private report.
Never read an existing user vault, auth file or master-password file. Do not
activate a service or modify Keychain. This recipe uses only synthetic data.

1. Verify the retained bundle with `git bundle verify` in a repository with
   its prerequisites, check out candidate `commit` into a new private directory,
   and ensure `git rev-parse HEAD` equals that 40-character commit and the tree
   is clean. Follow `docs/CLI-INSTALL.md` for a **new** Python 3.11 venv and
   target-specific wheels; verify the artifact manifest and wheel/source/
   installed identities rather than trusting versions alone. Set `LG_SOURCE`,
   `LG_VENV`, `LG_WHEELHOUSE`, `LG_PRIVATE`, and `LG_GITLEAKS` to absolute paths;
   `LG_PRIVATE` must be a fresh mode-700 directory outside the source tree.
   Install the
   synthetic firm Presidio recognizer, firm example, sensitive basics, host and
   vault wheels too. Install the pinned Gitleaks binary specified in the guide;
   validate its version and hash. Use supervised-alpha on Mac, which does not
   claim a hard worker memory bound.
2. From the private directory outside the checkout, verify the installed
   project modules and shipped rules/plugin data against the matching source
   and each uniquely selected wheel. Create a second unused core-only venv for
   the optional-factory checks, using the verified target wheelhouse:

   ```sh
   cd "$LG_PRIVATE"
   "$LG_VENV/bin/python" -I "$LG_SOURCE/tools/verify_project_identity.py" \
     --source "$LG_SOURCE" --wheelhouse "$LG_WHEELHOUSE" > "$LG_PRIVATE/project-identity.json"
   python3.11 -m venv "$LG_PRIVATE/core-only"
   LG_CORE_VENV="$LG_PRIVATE/core-only"
   "$LG_CORE_VENV/bin/python" -m pip install --no-index --find-links "$LG_WHEELHOUSE" \
     "$LG_WHEELHOUSE/leakguard_core-0.2.1a3-py3-none-any.whl"
   "$LG_CORE_VENV/bin/python" -m pip check
   ```

   Stop if the identity command or `pip check` fails. Record the identity
   receipt and core-only wheel hash. Run the installed profile journey. This exercises synthetic JWE/JWS positive exact spans, a selected
   firm factory, CLI scans, encrypted host, local Git commit/push and explicit
   policy blocking. The optional core-only venv covers absent factories:

   ```sh
   "$LG_VENV/bin/python" -I "$LG_SOURCE/tools/check_recognizer_profiles.py" \
     --source-root "$LG_SOURCE" --gitleaks "$LG_GITLEAKS" \
     --output-dir "$LG_PRIVATE/profile-journey" --core-only-python "$LG_CORE_VENV/bin/python"
   "$LG_VENV/bin/python" -I "$LG_SOURCE/tools/synthetic_vault_check.py"
   ```

   The profile journey's `output-dir` must not exist. Confirm its receipt and
   process exit, plus vault output and exit. It creates disposable data only;
   vault testing here uses the installed Python API because this release does
   not ship a standalone local vault CLI. It does not test the optional Mac
   daemon. It is not a claim of clinical recall, general PII quality, production
   false-positive rate, or actual token validity; see `docs/recognizer-evaluation.md`.
3. Run the bounded synthetic benchmark against the checked-out source using
   the same installed Python and pinned Gitleaks (the benchmark explicitly
   loads source, so label it as a source measurement, not installed-release
   latency). It runs only newly created fixtures; cold/warm/one-file-mutated
   cached results are compared to uncached results for both worker counts.
   Create a fresh private config containing `{"worker_policy":"supervised-alpha"}`.
   The state and output paths must be unused:

   ```sh
   "$LG_VENV/bin/python" "$LG_SOURCE/tools/run_bounded.py" --seconds 900 -- \
     "$LG_VENV/bin/python" "$LG_SOURCE/tools/benchmark_scan.py" \
     --config "$LG_PRIVATE/benchmark-config.json" --gitleaks "$LG_GITLEAKS" \
     --state "$LG_PRIVATE/benchmark-state" --output "$LG_PRIVATE/benchmark.json" \
     --file-counts 50 200 --repetitions 1 --hook-repetitions 1
   ```

   Record fixture counts, bytes, cold/warm/mutated timings and equivalence,
   completion, worker launches and memory availability. Mac process-tree RSS
   sampling and SQLite lock time may be unavailable; report null as unmeasured.
   An exit code of 124 means the deadline stopped the owned process tree and
   the benchmark is incomplete, even if a partial file exists.
   Scan duration is not lock time. Do not launch a broad real filesystem crawl.

## Mac client to disposable Linux broker

This requires an accessible Linux test host and SSH. If unavailable, report
this gate deferred with that reason. Use a fresh Linux checkout of the **same**
verified integrated revision and a fresh installed broker/core/vault venv.
No real PKI, vault, credential, config or platform authentication file is used.
The fixture creates its own CA, synthetic client key and upstream; it listens
on Linux loopback only. Keep its terminal open (EOF revokes the grant). The
export directory must be a new private directory outside the checkout:

```sh
"$LG_LINUX_VENV/bin/python" -I "$LG_LINUX_SOURCE/tools/synthetic_broker_bridge.py" \
  --export-dir "$LG_LINUX_PRIVATE/bridge-client" --ttl 900
```

Read the printed `linux_loopback_port` and synthetic `grant`. The broker
certificate includes `127.0.0.1`. Copy only the three disposable files
`ca.pem`, `client.pem`, `client-key.pem` from `bridge-client` to a fresh
mode-700 Mac test directory using the existing authenticated SSH channel;
keep the synthetic key mode 600. Do not copy the CA private key, vault, admin
socket, or any real data. In another Mac terminal, forward a free local port:

```sh
ssh -N -L 127.0.0.1:LOCAL_PORT:127.0.0.1:LINUX_PORT LINUX_HOST
```

Run the following using the installed Mac agent and values from the synthetic
fixture (replace placeholders; the grant is short-lived synthetic test data):

Use the `--grant=VALUE` form: a generated grant may begin with a hyphen.

```sh
"$LG_VENV/bin/leakguard-agent" --url https://127.0.0.1:LOCAL_PORT \
  --ca "$LG_PRIVATE/bridge-client/ca.pem" --cert "$LG_PRIVATE/bridge-client/client.pem" \
  --key "$LG_PRIVATE/bridge-client/client-key.pem" \
  inventory --grant=SYNTHETIC_GRANT --label "Synthetic test service" --limit 20
"$LG_VENV/bin/leakguard-agent" --url https://127.0.0.1:LOCAL_PORT \
  --ca "$LG_PRIVATE/bridge-client/ca.pem" --cert "$LG_PRIVATE/bridge-client/client.pem" \
  --key "$LG_PRIVATE/bridge-client/client-key.pem" \
  request --grant=SYNTHETIC_GRANT --binding synthetic-binding --method GET --path /fixture-health
```

Verify inventory contains the synthetic binding, the request returns its
fixture response, and neither output exposes the synthetic bearer. Press Enter
in the Linux fixture terminal: its final JSON must report
`synthetic_upstream_received_expected_authorization: true` and exit 0. Close
only the SSH forward and fixture processes started for this test. The fixture
removes its private CA, upstream and vault; remove the explicitly created
client export directories after retaining the redacted result. It expires at
TTL even if forgotten. Do not interpret this as hostile-admin isolation: the
Linux host/account/CA and operator channel are trusted.

Only after all required local gates pass may the local agent update CLI wrappers;
record previous wrapper paths and a rollback procedure first. Real broker
account isolation and any master-passphrase migration remain human-operated;
no real vault migration is performed by this recipe.
