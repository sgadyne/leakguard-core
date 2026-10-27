"""Deterministic state races with no real credential or vault decryption."""
from __future__ import annotations

import asyncio
import threading
import time

from leakguard_broker.policy import Policy
from leakguard_broker.state import State


class DelayedProvider:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.unlocked = False

    def unlock(self, passphrase):
        self.started.set()
        if not self.release.wait(5):
            raise RuntimeError("synthetic review barrier timed out")
        self.unlocked = True
        self.finished.set()

    create = unlock

    def lock(self):
        self.unlocked = False


def test_security_repeated_unlock_cancellation_does_not_resurrect_provider():
    async def scenario():
        provider = DelayedProvider()
        state = State(Policy.parse({"schema": 1, "bindings": []}), provider)
        owner = object()
        state.owner = owner
        task = asyncio.create_task(state.unlock(owner, "synthetic review passphrase"))
        assert await asyncio.to_thread(provider.started.wait, 1)
        try:
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            disconnect = asyncio.create_task(state.disconnect(owner))
            await asyncio.sleep(.02)
            provider.release.set()
            await asyncio.gather(task, disconnect, return_exceptions=True)
            assert await asyncio.to_thread(provider.finished.wait, 1)
            # Let the worker future's completion callback run after a second cancel.
            await asyncio.sleep(.01)
            assert state.owner is None
            assert not state.active
            assert not state.grants
            assert not provider.unlocked, "worker completed unlock after cancellation had already locked provider"
        finally:
            provider.release.set()
            await state.lock()

    asyncio.run(scenario())


def test_security_old_owner_cannot_unlock_after_disconnect_during_kdf():
    async def scenario():
        provider = DelayedProvider()
        state = State(Policy.parse({"schema": 1, "bindings": []}), provider)
        owner = object()
        state.owner = owner
        task = asyncio.create_task(state.unlock(owner, "synthetic review passphrase"))
        assert await asyncio.to_thread(provider.started.wait, 1)
        try:
            disconnect = asyncio.create_task(state.disconnect(owner))
            await asyncio.sleep(0)
            provider.release.set()
            await asyncio.gather(task, disconnect, return_exceptions=True)
            assert state.owner is None
            assert not state.active
            assert not provider.unlocked
        finally:
            provider.release.set()
            await state.lock()

    asyncio.run(scenario())


def test_security_lock_cleanup_survives_repeated_cancel_and_rejects_unlock():
    async def scenario():
        from leakguard_broker.errors import BrokerError
        import pytest

        provider = DelayedProvider()
        provider.unlocked = True
        state = State(Policy.parse({"schema": 1, "bindings": []}), provider)
        owner = object()
        state.owner = owner
        state.active = True
        state.deadline = time.monotonic() + 30
        await state._vault_mutex.acquire()
        try:
            locking = asyncio.create_task(state.lock())
            await asyncio.sleep(0)
            locking.cancel()
            await asyncio.sleep(0)
            locking.cancel()
            with pytest.raises(BrokerError) as error:
                await state.unlock(owner, "synthetic review password")
            assert error.value.code == "lock-in-progress"
            assert not state.active
            assert not state.grants
            state._vault_mutex.release()
            await asyncio.gather(locking, return_exceptions=True)
            assert not provider.unlocked
            assert not state._locking
        finally:
            if state._vault_mutex.locked():
                state._vault_mutex.release()
            await state.lock()

    asyncio.run(scenario())
