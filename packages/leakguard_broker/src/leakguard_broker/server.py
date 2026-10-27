"""mTLS agent HTTP server and connection-owned local operator channel."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import ssl
import stat
import time

from aiohttp import web
from cryptography import x509

from .admission import BoundedSite
from .errors import BrokerError
from .policy import Policy
from .provider import VaultProvider
from .state import State, drain_worker
from .transport import Transport, prepare_request

MAX_JSON = 1048576
MAX_ADMIN_LINE = 131072
_LOG = logging.getLogger("leakguard_broker.private")
_LOG.handlers = [logging.NullHandler()]
_LOG.propagate = False


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def decode_json(raw):
    try:
        data = json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(data) is not dict:
            raise ValueError()
        return data
    except (ValueError, UnicodeError, RecursionError):
        raise BrokerError("json-invalid", 400) from None


def server_tls(cert_path, key_path, ca_path):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_cert_chain(str(cert_path), str(key_path))
    context.load_verify_locations(cafile=str(ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["http/1.1"])
    return context


def peer_identity(request):
    transport = request.transport
    ssl_object = transport.get_extra_info("ssl_object") if transport is not None else None
    if ssl_object is None:
        raise BrokerError("identity-invalid", 403)
    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        raise BrokerError("identity-invalid", 403)
    try:
        certificate = x509.load_der_x509_certificate(der)
        not_after = certificate.not_valid_after_utc.timestamp()
        not_before = certificate.not_valid_before_utc.timestamp()
    except ValueError:
        raise BrokerError("identity-invalid", 403) from None
    if not not_before <= time.time() < not_after:
        raise BrokerError("identity-expired", 403)
    return hashlib.sha256(der).hexdigest(), not_after


class Broker:
    def __init__(self, policy: dict, vault_path: Path):
        self.state = State(Policy.parse(policy), VaultProvider(vault_path))
        self.transport = Transport()
        self.port = None
        self._runner = None
        self._site = None
        self._admin_server = None
        self._socket_path = None
        self._socket_identity = None
        self._admin_tasks = set()
        self._writers = set()
        self._http_count = 0
        self._admin_claimed = False

    @web.middleware
    async def _boundary(self, request, handler):
        if self._http_count >= 32:
            return web.json_response({"error": "broker-busy"}, status=503)
        self._http_count += 1
        try:
            if request.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise BrokerError("encoding-denied", 400)
            if request.headers.get("Upgrade") or request.method == "CONNECT":
                raise BrokerError("request-denied", 403)
            return await handler(request)
        except BrokerError as error:
            return web.json_response({"error": error.code}, status=error.status)
        except web.HTTPException:
            return web.json_response({"error": "route-invalid"}, status=404)
        except Exception:
            # No exception repr, request dumps, access logs or traceback can carry
            # injected headers, vault values or upstream response fragments.
            return web.json_response({"error": "broker-failed"}, status=500)
        finally:
            self._http_count -= 1

    async def _read(self, request):
        if request.content_type != "application/json":
            raise BrokerError("content-type-invalid", 400)
        if request.content_length is not None and request.content_length > MAX_JSON:
            raise BrokerError("body-too-large", 413)
        chunks, size = [], 0
        try:
            async with asyncio.timeout(5):
                async for chunk in request.content.iter_chunked(65536):
                    size += len(chunk)
                    if size > MAX_JSON:
                        raise BrokerError("body-too-large", 413)
                    chunks.append(chunk)
        except TimeoutError:
            raise BrokerError("input-timeout", 408) from None
        return decode_json(b"".join(chunks))

    async def _inventory(self, request):
        fingerprint, expiry = peer_identity(request)
        self.state.require_active()
        data = await self._read(request)
        if set(data) - {"grant_id", "label", "tags", "environment", "cursor", "limit"}:
            raise BrokerError("request-invalid", 400)
        grant = self.state.check(fingerprint, expiry, data.get("grant_id"), consume=True)
        limit, cursor = data.get("limit", 20), data.get("cursor", "0")
        if type(limit) is not int or not 1 <= limit <= 100 or type(cursor) is not str or not cursor.isascii() or not cursor.isdecimal() or len(cursor) > 6:
            raise BrokerError("filter-invalid", 400)
        for key in ("label", "environment"):
            if key in data and (type(data[key]) is not str or len(data[key]) > 256):
                raise BrokerError("filter-invalid", 400)
        tags = data.get("tags", [])
        if type(tags) is not list or len(tags) > 32 or any(type(t) is not str or len(t) > 128 for t in tags):
            raise BrokerError("filter-invalid", 400)
        values = []
        for bid in sorted(grant.bindings):
            binding = self.state.policy.bindings[bid]
            if ("label" in data and binding.label != data["label"] or
                    "environment" in data and binding.environment != data["environment"] or
                    not set(tags) <= set(binding.tags)):
                continue
            values.append(binding.metadata())
        offset = int(cursor)
        end = offset + limit
        return web.json_response({"policy_version": self.state.policy.version,
                                  "items": values[offset:end],
                                  "next_cursor": str(end) if end < len(values) else None})

    async def _request(self, request):
        fingerprint, expiry = peer_identity(request)
        self.state.require_active()
        data = await self._read(request)
        if set(data) - {"grant_id", "binding_id", "method", "path", "query", "headers", "body_b64"}:
            raise BrokerError("request-invalid", 400)
        gid, bid = data.get("grant_id"), data.get("binding_id")
        if type(bid) is not str:
            raise BrokerError("binding-denied", 403)
        grant = self.state.check(fingerprint, expiry, gid, consume=True, binding_id=bid)
        request_deadline = min(grant.expires_mono, self.state.deadline,
                               time.monotonic() + max(0, expiry - time.time()))
        binding = self.state.policy.bindings.get(bid)
        if binding is None:
            raise BrokerError("binding-denied", 403)
        prepared = prepare_request(binding, data)

        def live():
            self.state.check(fingerprint, expiry, gid, binding_id=bid)

        async def get_entry():
            async with self.state._vault_mutex:
                live()
                return self.state.provider.get(binding.credential_ref)

        task = asyncio.create_task(self.transport.execute(
            binding, prepared, get_entry, live))
        self.state.inflight[task] = gid
        try:
            async with asyncio.timeout_at(request_deadline):
                result = await task
                live()
                return web.json_response(result)
        except TimeoutError:
            raise BrokerError("request-expired", 403) from None
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                raise
            raise BrokerError("request-revoked", 403) from None
        finally:
            self.state.inflight.pop(task, None)

    async def start(self, admin_socket: Path, host: str, port: int, tls: ssl.SSLContext):
        if tls.verify_mode != ssl.CERT_REQUIRED or tls.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise BrokerError("tls-config-invalid", 400)
        path = Path(admin_socket)
        if not path.is_absolute():
            raise BrokerError("admin-socket-invalid", 400)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = path.parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            raise BrokerError("admin-directory-insecure", 400)
        if path.exists() or path.is_symlink():
            raise BrokerError("admin-socket-exists", 409)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.bind(str(path))
            os.chmod(path, 0o600)
            sock.listen(1)
            sock.setblocking(False)
            self._socket_path = path
            st = path.lstat()
            self._socket_identity = (st.st_dev, st.st_ino)
            self._admin_server = await asyncio.start_unix_server(self._admin_connection, sock=sock, limit=MAX_ADMIN_LINE)
            app = web.Application(middlewares=[self._boundary], client_max_size=MAX_JSON, logger=_LOG)
            app.router.add_post("/v1/inventory.find", self._inventory)
            app.router.add_post("/v1/request", self._request)
            self._runner = web.AppRunner(app, access_log=None, logger=_LOG,
                                         auto_decompress=False, shutdown_timeout=1,
                                         max_line_size=8192, max_field_size=8192,
                                         keepalive_timeout=15)
            await self._runner.setup()
            self._site = BoundedSite(self._runner.server, tls)
            await self._site.start(host, port)
            self.port = self._site.port
        except BaseException:
            sock.close()
            await self.close()
            raise

    async def close(self):
        if self._admin_server is not None:
            self._admin_server.close()
            await self._admin_server.wait_closed()
            self._admin_server = None
        self.state.owner = None
        await self.state.lock()
        if self._site is not None:
            await self._site.close()
            self._site = None
        for writer in list(self._writers):
            writer.close()
        if self._admin_tasks:
            await asyncio.gather(*list(self._admin_tasks), return_exceptions=True)
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        if self._socket_path is not None:
            try:
                st = self._socket_path.lstat()
                if (st.st_dev, st.st_ino) == self._socket_identity and stat.S_ISSOCK(st.st_mode):
                    self._socket_path.unlink()
            except FileNotFoundError:
                pass
            self._socket_path = None

    async def _send(self, writer, response):
        writer.write(json.dumps(response, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n")
        async with asyncio.timeout(2):
            await writer.drain()

    async def _admin_connection(self, reader, writer):
        task = asyncio.current_task()
        self._admin_tasks.add(task)
        self._writers.add(writer)
        owner = object()
        claimed = False
        pump = None
        pump_finishing = asyncio.Event()
        try:
            if self._admin_claimed:
                await self._send(writer, {"ok": False, "error": "admin-busy"})
                return
            self._admin_claimed = True
            claimed = True
            self.state.owner = owner
            queue = asyncio.Queue(maxsize=16)

            async def read_commands():
                try:
                    while True:
                        line = await reader.readline()
                        if not line or len(line) > MAX_ADMIN_LINE or not line.endswith(b"\n"):
                            break
                        queue.put_nowait(line)
                except (ValueError, ConnectionError, asyncio.QueueFull):
                    pass
                finally:
                    # Dedicated reader observes EOF even during vault KDF work.
                    pump_finishing.set()
                    await self.state.disconnect(owner)
                    try:
                        queue.put_nowait(None)
                    except asyncio.QueueFull:
                        pass

            pump = asyncio.create_task(read_commands())
            while self.state.owner is owner:
                line = await queue.get()
                if line is None:
                    break
                try:
                    data = decode_json(line)
                    result = await self._admin_op(owner, data)
                    self.state.owned(owner)
                    await self._send(writer, {"ok": True, "result": result})
                    if data.get("op") == "quit":
                        break
                except BrokerError as error:
                    await self._send(writer, {"ok": False, "error": error.code})
                except (TypeError, ValueError, KeyError):
                    await self._send(writer, {"ok": False, "error": "admin-input-invalid"})
                except Exception:
                    await self._send(writer, {"ok": False, "error": "admin-failed"})
        except (ConnectionError, TimeoutError, BrokenPipeError):
            pass
        finally:
            # Do not cancel an EOF reader while it is waiting to close the vault.
            # If we initiate shutdown, complete our own lock before cancelling it.
            if pump is not None and pump_finishing.is_set():
                await asyncio.gather(pump, return_exceptions=True)
            else:
                await self.state.disconnect(owner)
                if pump is not None:
                    pump.cancel()
                    await asyncio.gather(pump, return_exceptions=True)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, BrokenPipeError):
                pass
            if claimed:
                self._admin_claimed = False
            self._writers.discard(writer)
            self._admin_tasks.discard(task)

    async def _admin_op(self, owner, data):
        self.state.owned(owner)
        op = data.get("op")
        shapes = {
            "status": ({"op"}, set()), "init": ({"op", "passphrase"}, {"ttl"}),
            "unlock": ({"op", "passphrase"}, {"ttl"}), "lock": ({"op"}, set()),
            "quit": ({"op"}, set()), "credential.put": ({"op", "title", "secret"}, {"username", "entry_id"}),
            "credential.get": ({"op", "entry_id"}, set()),
            "principal.enroll": ({"op", "fingerprint", "principal"}, set()),
            "principal.revoke": ({"op", "fingerprint"}, set()),
            "grant.create": ({"op", "principal", "bindings", "ttl", "max_requests"}, set()),
            "grant.revoke": ({"op", "grant_id"}, set()), "policy.replace": ({"op", "policy"}, set()),
        }
        if type(op) is not str or op not in shapes:
            raise BrokerError("admin-op-invalid", 400)
        required, optional = shapes[op]
        if not required <= set(data) or set(data) - required - optional:
            raise BrokerError("admin-input-invalid", 400)
        if op == "status":
            return self.state.status()
        if op in {"unlock", "init"}:
            return await self.state.unlock(owner, data["passphrase"], data.get("ttl"), create=op == "init")
        if op in {"lock", "quit"}:
            await self.state.lock()
            return self.state.status()
        self.state.require_active()
        if op == "credential.put":
            async with self.state._vault_mutex:
                self.state.owned(owner)
                self.state.require_active()
                # Persistence is bounded by the underlying vault (16MiB).
                # Serialize against disconnect; never release its mutex while
                # a worker may still be writing decrypted state.
                worker = asyncio.create_task(asyncio.to_thread(self.state.provider.put,
                    **{key: value for key, value in data.items() if key != "op"}))
                try:
                    return await drain_worker(worker)
                except asyncio.CancelledError:
                    self.state.active = False
                    self.state.grants.clear()
                    self.state.provider.lock()
                    raise
        if op == "credential.get":
            return self.state.provider.get(data["entry_id"])
        if op == "principal.enroll":
            await self.state.enroll(owner, data["fingerprint"], data["principal"])
            return {}
        if op == "principal.revoke":
            await self.state.enroll(owner, data["fingerprint"])
            return {}
        if op == "grant.create":
            return self.state.create_grant(owner, data["principal"], data["bindings"], data["ttl"], data["max_requests"])
        if op == "grant.revoke":
            await self.state.revoke(owner, data["grant_id"])
            return {}
        if op == "policy.replace":
            await self.state.replace_policy(owner, data["policy"])
            return {"policy_version": self.state.policy.version}
