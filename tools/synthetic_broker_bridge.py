#!/usr/bin/env python3
"""Disposable Linux loopback broker for a Mac CLI over an SSH local forward.

Run from the integrated checkout with the installed Python, never against a
real vault. Only exported synthetic client material is suitable for copying.
The server expires automatically; stdin EOF also closes its admin session.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages/leakguard_broker/tests"))
from tls_fixtures import SyntheticPKI, SyntheticHttpsWitness, SYNTHETIC_MARKER

MASTER = "synthetic-bridge-master-only-5a87"


async def serve(export: Path, ttl: int) -> int:
    import leakguard_broker
    from leakguard_broker.provider import VaultProvider
    from leakguard_broker.server import Broker, server_tls

    module = Path(leakguard_broker.__file__).resolve()
    if module.is_relative_to(ROOT) or "site-packages" not in module.parts:
        raise RuntimeError("broker-must-be-wheel-installed")
    export.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(export, 0o700)
    with tempfile.TemporaryDirectory(prefix="lg-bridge-", dir="/tmp") as temp:
        private = Path(temp)
        os.chmod(private, 0o700)
        pki = SyntheticPKI(private / "pki")
        for src, name in ((pki.inbound_ca.ca_cert, "ca.pem"),
                          (pki.client.cert, "client.pem"), (pki.client.key, "client-key.pem")):
            shutil.copyfile(src, export / name)
            os.chmod(export / name, 0o600)
        with SyntheticHttpsWitness(pki.upstream_server) as witness:
            vault = private / "synthetic.lgv"
            provider = VaultProvider(vault)
            provider.create(MASTER)
            entry = provider.put(title="synthetic bridge", secret=SYNTHETIC_MARKER)
            provider.lock()
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pki.client.cert.read_text())).hexdigest()
            policy = {"schema": 1, "principals": {fingerprint: "synthetic-mac"},
                      "max_unlock_seconds": ttl, "bindings": [{
                          "id": "synthetic-binding", "label": "Synthetic test service",
                          "tags": ["synthetic"], "environment": "test", "credential_ref": entry["id"],
                          "origin": witness.origin, "auth": {"kind": "bearer"},
                          "rules": [{"method": "GET", "path": "/fixture-health"}],
                          "allowed_cidrs": ["127.0.0.0/8"], "max_body_bytes": 1024,
                          "max_response_bytes": 1024, "timeout_seconds": 5,
                          "ca_file": str(pki.upstream_ca.ca_cert)}]}
            broker = Broker(policy, vault)
            admin_writer = None
            try:
                await broker.start(admin_socket=private / "admin.sock", host="127.0.0.1", port=0,
                                   tls=server_tls(str(pki.broker_server.cert), str(pki.broker_server.key),
                                                  str(pki.inbound_ca.ca_cert)))
                reader, admin_writer = await asyncio.open_unix_connection(str(private / "admin.sock"))
                async def admin(request):
                    admin_writer.write(json.dumps(request).encode() + b"\n")
                    await admin_writer.drain()
                    return json.loads(await asyncio.wait_for(reader.readline(), 5))
                if (await admin({"op": "unlock", "passphrase": MASTER, "ttl": ttl})).get("ok") is not True:
                    raise RuntimeError("unlock-failed")
                grant = await admin({"op": "grant.create", "principal": "synthetic-mac",
                                     "bindings": ["synthetic-binding"], "ttl": ttl, "max_requests": 10})
                if grant.get("ok") is not True:
                    raise RuntimeError("grant-failed")
                print(json.dumps({"ready": True, "linux_loopback_port": broker.port,
                                  "grant": grant["result"]["grant_id"],
                                  "ttl_seconds": ttl, "installed_broker": str(module)}), flush=True)
                loop = asyncio.get_running_loop()
                done = loop.create_future()
                def stdin_ready():
                    # Read available bytes only; readline could block on a
                    # partial pipe write and prevent the TTL from firing.
                    os.read(sys.stdin.fileno(), 4096)
                    if not done.done():
                        done.set_result(None)
                loop.add_reader(sys.stdin.fileno(), stdin_ready)
                try:
                    await asyncio.wait_for(done, timeout=ttl)
                except asyncio.TimeoutError:
                    pass
                finally:
                    loop.remove_reader(sys.stdin.fileno())
                requests = witness.snapshot()
                valid = any(r["method"] == "GET" and r["path"] == "/fixture-health"
                            and r["headers"].get("authorization") == "Bearer " + SYNTHETIC_MARKER
                            for r in requests)
                print(json.dumps({"synthetic_upstream_received_expected_authorization": valid,
                                  "upstream_request_count": len(requests)}), flush=True)
                return 0 if valid else 1
            finally:
                if admin_writer is not None:
                    admin_writer.close()
                    await admin_writer.wait_closed()
                await broker.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", required=True, type=Path, help="new private directory for synthetic client files")
    parser.add_argument("--ttl", type=int, default=600, choices=range(60, 1801), metavar="60..1800")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        return asyncio.run(serve(args.export_dir.absolute(), args.ttl))
    except Exception as error:
        print(json.dumps({"ready": False, "error_type": type(error).__name__}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
