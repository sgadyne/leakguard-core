from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import warnings

import pytest

from leakguard_broker import admin_cli, cli
from leakguard_broker.client import (
    BrokerClient,
    BrokerClientError,
    _validate_headers,
    _validate_path,
    _validate_query,
)
from .tls_fixtures import SYNTHETIC_MARKER


def test_client_identity_errors_and_repr_do_not_disclose_paths(synthetic_pki, tmp_path, capsys):
    cert_path = tmp_path / "private-client-cert-file.pem"
    key_path = tmp_path / "private-client-key-file.pem"
    result = cli.main([
        "--url", "https://broker.test", "--ca", str(synthetic_pki.inbound_ca.ca_cert),
        "--cert", str(cert_path), "--key", str(key_path),
        "inventory", "--grant", "synthetic-grant",
    ])
    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert str(cert_path) not in captured.err
    assert str(key_path) not in captured.err
    assert captured.err.strip() == "leakguard-agent: client-identity-invalid"

    client = BrokerClient(
        "https://broker.test", ca_file=synthetic_pki.inbound_ca.ca_cert,
        cert_file=synthetic_pki.client.cert, key_file=synthetic_pki.client.key,
    )
    assert str(synthetic_pki.client.cert) not in repr(client)
    assert str(synthetic_pki.client.key) not in repr(client)


def test_client_path_cap():
    assert _validate_path("/" + "x" * 4095) == "/" + "x" * 4095
    with pytest.raises(BrokerClientError):
        _validate_path("/" + "x" * 4096)
    with pytest.raises(BrokerClientError):
        _validate_path("//attacker.test/path")


def test_client_query_caps_and_controls():
    assert _validate_query([["q", "x" * 8192]]) == [["q", "x" * 8192]]
    with pytest.raises(BrokerClientError):
        _validate_query([["q", "x" * 8193]])
    with pytest.raises(BrokerClientError):
        _validate_query([["q", "x" * 8192], ["q", "x" * 8192], ["q", "x" * 8192], ["q", "x" * 8193]])
    with pytest.raises(BrokerClientError):
        _validate_query([["q", "control\nvalue"]])


def test_client_header_value_cap():
    assert _validate_headers({"x-test": "x" * 8192}) == {"x-test": "x" * 8192}
    with pytest.raises(BrokerClientError):
        _validate_headers({"x-test": "x" * 8193})


@pytest.mark.asyncio
async def test_oversize_request_body_is_rejected_before_transport(synthetic_pki):
    client = BrokerClient(
        "https://broker.test", ca_file=synthetic_pki.inbound_ca.ca_cert,
        cert_file=synthetic_pki.client.cert, key_file=synthetic_pki.client.key,
    )
    with pytest.raises(BrokerClientError) as exc:
        await client.request("grant", "binding", "POST", "/path", body=b"x" * (1024 * 1024 + 1))
    assert exc.value.code == "request-invalid"


class _FakeContent:
    def __init__(self, body: bytes):
        self.body = body

    async def iter_chunked(self, _size):
        yield self.body


class _FakeResponse:
    status = 403

    def __init__(self, body: bytes):
        self.content = _FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class _FakeSession:
    closed = False

    def __init__(self, body: bytes):
        self.response = _FakeResponse(body)

    def post(self, *_args, **_kwargs):
        return self.response

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_error_body_is_not_logged_or_included_in_client_exception(synthetic_pki):
    client = BrokerClient(
        "https://broker.test", ca_file=synthetic_pki.inbound_ca.ca_cert,
        cert_file=synthetic_pki.client.cert, key_file=synthetic_pki.client.key,
    )
    body = json.dumps({"error": "fixed-denial", "detail": SYNTHETIC_MARKER}).encode()
    client._session = _FakeSession(body)
    with pytest.raises(BrokerClientError) as exc:
        await client._post("/v1/request", {})
    assert exc.value.code == "fixed-denial"
    assert str(exc.value) == "fixed-denial"
    assert SYNTHETIC_MARKER not in str(exc.value)


class _TtyStringIO(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_admin_shell_uses_one_uds_session_prompts_out_of_band_and_closes_on_eof(monkeypatch, tmp_path):
    with tempfile.TemporaryDirectory(prefix="lgadmin-", dir="/tmp") as directory:
        socket_path = Path(directory) / "admin.sock"
        requests = []
        disconnected = asyncio.Event()

        async def handle(reader, writer):
            try:
                while line := await reader.readline():
                    requests.append(json.loads(line))
                    writer.write(b'{"ok":true,"result":{"updated":true}}\n')
                    await writer.drain()
            finally:
                disconnected.set()
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_unix_server(handle, path=str(socket_path))
        os.chmod(socket_path, 0o600)
        saved_argv = list(sys.argv)
        saved_env = dict(os.environ)
        output = io.StringIO()
        inputs = iter(["credential put synthetic-title", "quit"])

        def input_fn(_prompt):
            return next(inputs)

        monkeypatch.setattr(admin_cli.sys, "stdin", _TtyStringIO())
        monkeypatch.setattr(admin_cli.sys, "stderr", _TtyStringIO())
        monkeypatch.setattr(admin_cli.getpass, "getpass", lambda _prompt: SYNTHETIC_MARKER)
        try:
            result = await admin_cli._shell(socket_path, input_fn=input_fn, out=output)
            await asyncio.wait_for(disconnected.wait(), timeout=3)
            assert result == 0
            assert len(requests) == 2
            assert requests[0]["op"] == "credential.put"
            assert requests[0]["secret"] == SYNTHETIC_MARKER
            assert requests[1]["op"] == "quit"
            assert SYNTHETIC_MARKER not in output.getvalue()
            assert SYNTHETIC_MARKER not in saved_argv
            assert all(SYNTHETIC_MARKER not in value for value in saved_env.values())
            for item in Path(directory).iterdir():
                if item.is_file():
                    assert SYNTHETIC_MARKER not in item.read_text(errors="ignore")
        finally:
            server.close()
            await server.wait_closed()


def test_raw_reveal_requires_explicit_tty_output():
    hidden = io.StringIO()
    admin_cli._display("status", {"ok": True, "result": {"secret": SYNTHETIC_MARKER}}, hidden)
    assert SYNTHETIC_MARKER not in hidden.getvalue()

    non_tty = io.StringIO()
    admin_cli._display("raw-secret", {"ok": True, "result": {"secret": SYNTHETIC_MARKER}}, non_tty)
    assert "reveal-requires-terminal" in non_tty.getvalue()
    assert SYNTHETIC_MARKER not in non_tty.getvalue()

    tty = _TtyStringIO()
    admin_cli._display("raw-secret", {"ok": True, "result": {"secret": SYNTHETIC_MARKER}}, tty)
    assert tty.getvalue() == SYNTHETIC_MARKER + "\n"
    assert admin_cli._command(shlex.split("credential get synthetic-id")) == (
        {"op": "credential.get", "entry_id": "synthetic-id"}, "raw-secret"
    )


def test_getpass_echo_warning_fails_closed(monkeypatch):
    monkeypatch.setattr(admin_cli.sys, "stdin", _TtyStringIO())
    monkeypatch.setattr(admin_cli.sys, "stderr", _TtyStringIO())

    def unsafe_getpass(_prompt):
        warnings.warn("synthetic no-echo failure", admin_cli.getpass.GetPassWarning)
        return SYNTHETIC_MARKER

    monkeypatch.setattr(admin_cli.getpass, "getpass", unsafe_getpass)
    with pytest.raises(admin_cli.AdminCLIError) as exc:
        admin_cli._prompt_secret("Synthetic prompt: ")
    assert exc.value.code in {"secret-input-unavailable", "secret-input-cancelled"}
