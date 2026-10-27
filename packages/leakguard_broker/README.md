# LeakGuard broker v0

LeakGuard Broker holds an operator-created credential vault behind a small
policy controlled HTTPS service. Agents authenticate with mTLS and a grant ID.
They can find only curated binding metadata and make bounded requests through
an explicitly configured binding. Agent private keys are delegated authority;
they are not vault keys and do not prove that an agent is benevolent.

The broker protects credential custody and destination scope. Policy rules do
not understand every upstream API's meaning, so a permitted API can still
create or export data. Use service-scoped credentials and narrow method/path
rules. Literal response reflection checks cannot prevent every transformed or
newly issued authority from reaching an agent. A broker host administrator can
access the broker's files and process.

## Install

From a checkout with Python 3.11 or newer:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install . ./packages/leakguard_vault ./packages/leakguard_broker
```

The package pins the exercised HTTP dependency. Install the broker on a
dedicated trusted host account, with its vault and configuration outside agent
accounts. That account boundary protects only against agents with fewer OS
privileges; it does not protect against an agent running as the broker account
or with administrator/root access. The approved synthetic devbox is controlled
by its administrator, so a test there demonstrates behavior, not protection
from that administrator. The admin shell is a local Unix socket client for the
broker host.

## Operator setup

Create an operator PKI outside agent reach. The broker certificate needs a SAN
for the hostname agents use, and the broker must trust the client CA. Do not
copy the CA signing key to agents. Set the config file's `policy`, dedicated
`vault_path`, protected `admin_socket`, listen address, and certificate paths;
the daemon config contains no passphrase or credential value. The initial
policy can enroll mTLS certificate fingerprints and define bindings. Each
binding names one vault entry, exact HTTPS origin, authentication placement,
allowed methods and paths, allowed request headers, and size/time limits. See
`examples/policy.template.json` for a metadata-only starting point.

For a loopback-only synthetic example, run the following as a trusted operator
using OpenSSL 1.1.1 or newer. `umask` keeps generated private keys private;
OpenSSL prompts to encrypt the CA signing key. Keep this operator-only
directory outside agent reach. This one test CA signs both identities for
convenience; use the deployment's separately managed trust roots for real
services.

```sh
umask 077
PKI="$HOME/leakguard-synthetic-pki"
mkdir -m 700 "$PKI"

# Operator-only CA. OpenSSL prompts for a CA-key passphrase.
openssl req -x509 -newkey rsa:3072 -sha256 -days 365 \
  -keyout "$PKI/ca.key" -out "$PKI/ca.pem" \
  -subj "/CN=LeakGuard synthetic test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Broker identity for https://localhost:8443.
openssl req -new -newkey rsa:3072 -nodes \
  -keyout "$PKI/broker.key" -out "$PKI/broker.csr" \
  -subj "/CN=localhost"
cat > "$PKI/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "$PKI/broker.csr" \
  -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial \
  -out "$PKI/broker.pem" -days 90 -sha256 -extfile "$PKI/server.ext"

# Synthetic agent identity. Its unencrypted key is delegated authority for
# that agent; keep it readable only by the agent account that needs it.
openssl req -new -newkey rsa:3072 -nodes \
  -keyout "$PKI/worker-demo.key" -out "$PKI/worker-demo.csr" \
  -subj "/CN=worker-demo"
cat > "$PKI/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in "$PKI/worker-demo.csr" \
  -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial \
  -out "$PKI/worker-demo.pem" -days 90 -sha256 -extfile "$PKI/client.ext"

# Enroll this lowercase SHA-256 fingerprint through the admin shell.
openssl x509 -in "$PKI/worker-demo.pem" -outform DER | sha256sum
```

Install `broker.pem` and `broker.key` for the daemon, and configure `ca.pem`
as its client CA. Provision the agent with only `ca.pem`, `worker-demo.pem`,
and `worker-demo.key`; never copy `ca.key` to an agent. The client key is
delegated authority and must be protected by the agent account's file
permissions.

Run the daemon in the foreground under its dedicated account:

```sh
leakguard-broker --config /etc/leakguard-broker/config.json
```

On that trusted host, open the one long-lived admin connection:

```sh
leakguard-admin shell --socket /run/leakguard-broker/admin.sock
```

The `init` and `unlock` commands prompt with `getpass`; passphrases are not
accepted in command arguments, environment variables, or files. `init` asks
for confirmation. The admin connection itself owns the unlocked session and
grants. EOF, `quit`, disconnect, lock, the configured deadline, or daemon
restart locks the vault and revokes grants. A later unlock does not restore
old grants.

Useful shell commands:

```text
status
init
credential put "Synthetic example" --username demo
principal enroll <lowercase SHA256 fingerprint of client DER> worker-demo
grant create worker-demo 300 50 synthetic-binding
credential get <entry-id>
lock
quit
```

`credential put` prompts for the credential value without echo and reports its
entry ID for use as a binding's `credential_ref`. `credential get` is the only
command that reveals a value, and it writes the raw value only to an
interactive terminal. The admin CLI keeps one socket connection for the
whole shell and never reconnects after it closes. `policy replace FILE` reads
a complete, validated policy document without embedding any secret values in
that policy. Principal enroll/revoke and `policy replace` change live in-memory
state only; they are not written back to the daemon configuration. For a
durable principal removal, an operator must remove its fingerprint from the
daemon policy configuration and restart the daemon. A restart reloads that
configuration, revokes all current grants, and later unlocks never restore old
grants. A live `policy replace` also revokes every grant immediately.

A grant result's `expires_at` is its administrative deadline. The presented
certificate's NotAfter and the active admin session can end its effective
authority earlier. The broker checks those bounds on each HTTP request,
including requests on an existing TLS connection, and bounds in-flight work
by the earliest deadline.

## Agent CLI

Provision each agent with its own client certificate/key and the broker CA
certificate. The key file stays local to that agent. The CLI accepts paths,
never key contents, and does not print those paths or read key material into
model-facing output.

Use the `--grant=VALUE` form: a generated grant may begin with a hyphen.

```sh
leakguard-agent \
  --url https://broker.example:8443 \
  --ca /etc/leakguard-agent/broker-ca.pem \
  --cert /etc/leakguard-agent/agent.pem \
  --key /etc/leakguard-agent/agent-key.pem \
  inventory --grant=GRANT_ID --label "Synthetic test service" --limit 20
```

An inventory result contains only permitted binding IDs, labels, tags, and
environment. Request through one of those IDs; the broker chooses the origin
and credential from policy:

```sh
leakguard-agent \
  --url https://broker.example:8443 \
  --ca /etc/leakguard-agent/broker-ca.pem \
  --cert /etc/leakguard-agent/agent.pem \
  --key /etc/leakguard-agent/agent-key.pem \
  request --grant=GRANT_ID --binding synthetic-binding \
  --method GET --path /fixture-health --query format=json
```

No redirect following, cookies, environment proxies, automatic retries, or
response decompression are enabled. Request bodies can be supplied with
`--body-file FILE` or `--body-file -` (stdin). The broker's 1 MiB inbound cap
is for the entire JSON wire body, including the base64-encoded `body_b64` and
the other request fields. Since base64 expands binary data by about one third,
the effective binary body limit is less than 768 KiB even when the binding's
decoded-body limit is 1 MiB; smaller binding limits apply as well.
The CLI writes the approved upstream response body to stdout and its HTTP
status to stderr. Treat the response as data returned by the permitted API;
generic path/method rules cannot determine every API's semantics.

## Python SDK

The async SDK uses the same verified mTLS transport and exposes only inventory
and scoped requests. It has no vault lookup or credential reveal operation.

```python
import asyncio
from leakguard_broker.client import BrokerClient


async def main():
    async with BrokerClient(
        "https://broker.example:8443",
        ca_file="broker-ca.pem",
        cert_file="agent.pem",
        key_file="agent-key.pem",
    ) as broker:
        page = await broker.inventory_find(
            "GRANT_ID", label="Synthetic test service", limit=20,
        )
        for binding in page["items"]:
            print(binding["id"], binding["label"])

        response = await broker.request(
            "GRANT_ID", "synthetic-binding", "GET", "/fixture-health",
            query=[("format", "json")],
        )
        print(response["status"])
        print(response["body_b64"])


asyncio.run(main())
```

The SDK returns the bounded response in the wire DTO (`body_b64`). It does not
retry requests or follow redirects, since a retry could repeat an upstream
mutation. Always check the operation's application semantics before granting
it, especially for APIs that support exports, token creation, or relays.

## Synthetic example

`examples/synthetic_client.py` demonstrates metadata lookup and one request to
a local synthetic binding. It contains no credentials or production endpoint;
the matching loopback TLS upstream and certificates are created by the
installed acceptance harness. Use the harness policy only with its synthetic
fixture. Loopback access should not be added to a real binding's allowed CIDRs.
