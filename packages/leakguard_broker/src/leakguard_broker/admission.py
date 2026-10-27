"""Bound accepted sockets while delegating TLS to asyncio and HTTP to aiohttp."""
from __future__ import annotations

import asyncio
import socket


class _Lifecycle(asyncio.Protocol):
    """Only observe transport lifetime; all HTTP bytes go directly to aiohttp."""
    def __init__(self, delegate, closed):
        self.delegate = delegate
        self.closed = closed

    def connection_made(self, transport):
        self.delegate.connection_made(transport)

    def data_received(self, data):
        self.delegate.data_received(data)

    def eof_received(self):
        return self.delegate.eof_received()

    def pause_writing(self):
        self.delegate.pause_writing()

    def resume_writing(self):
        self.delegate.resume_writing()

    def connection_lost(self, exc):
        try:
            self.delegate.connection_lost(exc)
        finally:
            if not self.closed.done():
                self.closed.set_result(None)


class BoundedSite:
    def __init__(self, protocol_factory, tls, *, connections=64):
        self._factory = protocol_factory
        self._tls = tls
        self._slots = asyncio.Semaphore(connections)
        self._listener = None
        self._accept_task = None
        self._tasks = set()
        self._transports = set()
        self.port = None

    async def start(self, host, port):
        self._listener = socket.create_server((host, port),
            family=socket.AF_INET6 if ":" in host else socket.AF_INET, backlog=32)
        self._listener.setblocking(False)
        self.port = self._listener.getsockname()[1]
        self._accept_task = asyncio.create_task(self._accept())

    async def _accept(self):
        loop = asyncio.get_running_loop()
        while True:
            # Acquire BEFORE accepting, so even incomplete TLS handshakes count.
            await self._slots.acquire()
            try:
                connection, _ = await loop.sock_accept(self._listener)
            except BaseException:
                self._slots.release()
                raise
            task = asyncio.create_task(self._serve(connection))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _serve(self, connection):
        transport = None
        try:
            loop = asyncio.get_running_loop()
            closed = loop.create_future()
            protocol = _Lifecycle(self._factory(), closed)
            transport, _ = await loop.connect_accepted_socket(
                lambda: protocol, connection, ssl=self._tls,
                ssl_handshake_timeout=5, ssl_shutdown_timeout=1)
            self._transports.add(transport)
            await closed
        except asyncio.CancelledError:
            raise
        except Exception:
            # TLS/parser diagnostics may contain attacker-provided data.
            pass
        finally:
            if transport is not None:
                self._transports.discard(transport)
                transport.close()
            else:
                connection.close()
            self._slots.release()

    async def close(self):
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self._accept_task is not None:
            self._accept_task.cancel()
            await asyncio.gather(self._accept_task, return_exceptions=True)
            self._accept_task = None
        for transport in list(self._transports):
            transport.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
