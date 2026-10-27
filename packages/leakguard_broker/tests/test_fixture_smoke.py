from __future__ import annotations

import ssl
import subprocess
import urllib.error
import urllib.request

from .tls_fixtures import SyntheticHttpsWitness


def test_independent_pki_and_tls_upstream(synthetic_pki, upstream_witness):
    """Prove fixture trust and destination witness work before using them as oracles."""
    ok = subprocess.run(
        ["openssl", "verify", "-CAfile", str(synthetic_pki.inbound_ca.ca_cert),
         "-purpose", "sslclient", str(synthetic_pki.client.cert)],
        capture_output=True, text=True, check=False,
    )
    assert ok.returncode == 0, ok.stderr
    assert subprocess.run(
        ["openssl", "verify", "-CAfile", str(synthetic_pki.inbound_ca.ca_cert),
         "-purpose", "sslclient", str(synthetic_pki.expired_client.cert)],
        capture_output=True, text=True, check=False,
    ).returncode != 0
    assert subprocess.run(
        ["openssl", "verify", "-CAfile", str(synthetic_pki.inbound_ca.ca_cert),
         "-purpose", "sslclient", str(synthetic_pki.untrusted_client.cert)],
        capture_output=True, text=True, check=False,
    ).returncode != 0

    context = ssl.create_default_context(cafile=str(synthetic_pki.upstream_ca.ca_cert))
    with urllib.request.urlopen(upstream_witness.origin + "/fixture-health", context=context, timeout=3) as response:
        assert response.status == 200
        assert b"fixture-health" in response.read()
    assert upstream_witness.snapshot()[0]["path"] == "/fixture-health"

    wrong_name = SyntheticHttpsWitness(synthetic_pki.wrong_name_upstream)
    try:
        try:
            urllib.request.urlopen(wrong_name.origin + "/must-not-arrive", context=context, timeout=3)
        except urllib.error.URLError as exc:
            assert isinstance(exc.reason, ssl.SSLCertVerificationError)
        else:
            raise AssertionError("TLS accepted an upstream certificate with the wrong IP SAN")
        assert wrong_name.snapshot() == []
    finally:
        wrong_name.close()
