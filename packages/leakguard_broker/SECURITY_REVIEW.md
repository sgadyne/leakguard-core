# LeakGuard broker v0 independent security review

**APPROVE for a scoped synthetic internal alpha.** All four blocking review
findings are fixed and verified in the integrated implementation. The final
installed gates pass with no failures, errors or skips. Trusted broker-host and
operator assumptions apply; hostile host-administrator isolation is unqualified.

Assignment: security v1. Run: `leakguard-broker-20261026T214330Z`.
Reviewed source: `2e8bfdaf12150dfe9f0066296adba18f7b1384b1`.
Production `src` tree: `b37b883145206fc5f3b4da82dfdc978a08e4df89`.
Baseline: `e9310a5454e39fa0111bdacbb21e17dfe001d57f`.
Contract: `control/interfaces/contract.json`, version 1, with stricter
unreserved-ASCII paths and connection limits implemented during review.

## Scope and independence

This review covers credential custody, administrator-owned session lifetime,
mTLS delegation and destination/policy enforcement. A malicious agent may use
all its granted permissions. The broker and its human administrator must be
outside that agent's administrative reach. A dedicated OS account protects only
against less-privileged agents; this shared devbox cannot establish resistance
to its administrator. Agent root on a different host/VM is compatible with the
stated boundary.

The reviewer owned separate `tests/test_security_*.py` and this report. Production
fixes were implemented by the lead/client owners. The independent TLS witness
uses asyncio/ssl, separate from the harness's upstream server. It observes real
request targets, Host, SNI and credential arrival; forbidden-sink checks assert
no credential arrives, not just a client denial. Scheduling probes use delayed
or in-memory providers; the installed harness additionally exercises the existing
encrypted CredentialVault and actual terminal/getpass interaction. All PKI,
vaults, credentials and upstreams are synthetic.

## Findings and disposition

| ID | Observed failure | Verified fix |
| --- | --- | --- |
| S1 | Repeated unlock cancellation could cancel its asyncio wrapper while its thread continued, allowing a delayed provider to finish unlocked after cleanup. The real vault's mutex limits that demonstration and can instead block synchronous cleanup. | Shield-drain workers and lock finalizers despite repeated cancellation; serialize vault access and reserve admin ownership through teardown. State races and connection-claim probes pass. |
| S2 | The initial request counter excluded accepted TLS connections with incomplete headers: 80 remained open while the HTTP counter was zero. | Acquire before accept: at most 64 accepted sockets across TLS/HTTP, 5-second TLS handshake, lifecycle slot release and 1-second TLS shutdown. Pre-TLS, partial-header and slot-recovery probes pass. A nonreading 8 MiB response receiver also releases its slot through idle/shutdown deadlines. |
| S3 | `xn--fa-hia.review.test` became Unicode for TLS; Python's IDNA mapping verified `fass.review.test`. A certificate for that different name accepted a credential-bearing request. | Use canonical ASCII `origin.raw_host` for SNI and verification. Wrong-name denial and correct A-label positive tests pass with matching Host/SNI. |
| S4 | Ctrl-D at `credential put` secret input returned to an already-unlocked shell; its existing grant still returned HTTP 200. Earlier prompt-EOF coverage started locked and missed active authority. | Exit the shell and close its owning Unix connection on cancelled/unavailable secret input or terminal loss. The new regression passes; independent installed PTY shows exit 0, vault locked, grants zero, old grant HTTP 423. The full harness confirms no extra upstream request. |

Historical failures and fixed counterparts are retained in `RUN_ROOT/logs/`:
`security-initial-regressions.log`, `security-idna-before-fix.log`,
`security-secret-eof-before-fix.log`, `security-prompt-eof.log`,
`security-secret-eof-source-fixed.log` and `security-prompt-eof-fixed.log`.
Their synthetic reproducers/source snapshots remain under `RUN_ROOT/artifacts/`.

Qualification issue Q1 exposed stale installed `admin_cli.py`, `client.py` and
`server.py` despite current wheel contents and matching version numbers. The
first installed failures were retained and superseded. Final runs install explicit
local wheel files without cache reuse and compare every project Python file
across source, wheel and installed site-packages. Version pins alone were
insufficient provenance; the byte comparisons now pass for all 56 files.

## Final integrated evidence

| Gate | Result | Receipt under RUN_ROOT |
| --- | --- | --- |
| Independent installed review | 127 passed in 39.24 seconds; zero failures/errors/skips | `artifacts/security-final-installed-s4-2e8bfda/receipt.json` and `results.xml` |
| Complete installed new-package suite | 192 passed in 58.01 seconds; zero failures/errors/skips | `artifacts/final-installed-suite-2e8bfda/receipt.json` and `results.xml` |
| Public CLI, getpass PTY and daemon | 23 assertions true, including active secret-prompt EOF, locked startup, SIGTERM, restart and no grant resurrection | `control/receipts/testing-installed-acceptance.json` |
| Independent actual EOF confirmation | Grant HTTP 200 before Ctrl-D; exit 0, locked, zero grants and HTTP 423 afterward | `logs/security-prompt-eof-fixed.log` |
| Artifact identity | All 56 project Python files source = wheel = installed; all 19 runtime pins match | Both final suite receipts and the installed acceptance receipt |

The independent suite covers changed DNS answers, mixed candidates, mapped IPv6,
IPv4/IPv6 literals, canonical path/origin/header attacks, wrong IDNA TLS identity,
live grant/principal separation, certificate expiry on an existing TLS connection,
admin EOF/cancellation/teardown races, response reflection/compression/overflow,
no cookie replay, exactly one POST/PUT/DELETE after a dropped upstream reply,
encoded/decoded body caps, slow input, outbound queue deadlines and connection
slot recovery. The complete harness adds the three auth modes, budget and policy
revocation, wrong CA/hostname, CONNECT/upgrade, restart and encrypted-vault CLI
qualification.

All builds/installations/tests used the run's heavy admission wrapper. Final tests
were copied outside source and executed with `python -I`, cleared `PYTHONPATH`,
installed project modules in site-packages and explicit archived local wheels.
The reviewed source remained clean. No whole-core CI rerun was needed because
core/vault implementation and CI files were unchanged.

Platform: Linux x86_64/glibc 2.36, Python 3.11.2, OpenSSL 3.0.20.
Runtime lock SHA256:
`ccaa3424afd44ce7439f56ba6fefea3563addc27243e306bcb84f6709b0598cb`.
Exact wheel hashes, commands, module paths, versions and test hashes are in the
receipts. Retained tested wheels are in each final suite's `wheels/` directory.
The independent runner is `artifacts/security_installed_review.py`; its log is
`logs/security-final-installed-s4.log`.

The grant response's `expires_at` is an administrative upper bound for a
principal. Effective authority is the minimum of that deadline, the admin
session deadline and the presented certificate's NotAfter. Each request and
in-flight deadline enforces the earlier value, including keepalive requests.
This meets the approved effective-expiry claim and is not a blocker.

## Residual limits and deployment conditions

* The broker host, OS, runtime, CA issuance and interactive operator are trusted.
  Broker/admin interaction must be beyond the agent's administrative reach.
* Authorized upstream operations can create tokens, export data or relay it.
  Method/path rules do not interpret GraphQL or body semantics. Real bindings
  need service-scoped credentials and operator review.
* Literal reflection checks are defense in depth. Transformed, split, encoded
  or newly issued authority can evade generic checks; upstream behavior remains
  part of the trust model.
* Revocation cannot undo a request or credential already transmitted upstream.
* Python plaintext and keys have no guaranteed zeroization. The reused vault
  holds decrypted entries during its unlocked session.
* Runtime enrollment and policy edits are ephemeral. Durable removal requires
  updating the operator's daemon configuration; restart reloads that configuration
  and never restores old grants.
* Tests cover synthetic loopback services on one Linux/Python platform. They do
  not qualify production routing/DNS/firewalls, routing-layer translations,
  native Windows/macOS behavior or real service semantics. Local caps do not
  establish volumetric denial-of-service resistance.

Approval applies to this implementation tree and exercised synthetic policies.
The historical S4 BLOCK is superseded by the verified fix and final receipts.
Report-only integration commits do not change the reviewed production tree.
