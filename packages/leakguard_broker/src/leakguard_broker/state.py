"""Ephemeral grants bound to an active human connection and policy epoch."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import secrets
import time

from .errors import BrokerError
from .policy import FINGERPRINT, Policy, identity, number


async def drain_worker(worker):
    """Drain a thread-backed task despite any number of cancellation requests.

    Cancelling an asyncio wrapper does not stop its thread. Keep shielding until
    completion so callers can close the provider before releasing their mutex.
    """
    interrupted = False
    result = None
    while True:
        try:
            result = await asyncio.shield(worker)
            break
        except asyncio.CancelledError:
            interrupted = True
            if worker.done():
                break
        except Exception:
            if interrupted:
                raise asyncio.CancelledError() from None
            raise
    if interrupted:
        # Consume a worker exception without ever exposing its text.
        if worker.done() and not worker.cancelled():
            worker.exception()
        raise asyncio.CancelledError()
    return result


@dataclass
class Grant:
    id: str
    principal: str
    bindings: frozenset[str]
    expires_at: float
    remaining: int
    generation: int
    expires_mono: float


class State:
    def __init__(self, policy: Policy, provider):
        self.policy = policy
        self.provider = provider
        self.principals = dict(policy.principals)
        self.owner = None
        self.active = False
        self.deadline = 0.0
        self.wall_deadline = 0.0
        self.generation = 0
        self.grants: dict[str, Grant] = {}
        self.inflight: dict[asyncio.Task, str] = {}
        self._vault_mutex = asyncio.Lock()
        self._deadline_task = None
        self._lock_completion = None
        self._locking = False

    def owned(self, owner):
        if owner is not self.owner or owner is None:
            raise BrokerError("admin-session-invalid", 403)

    def require_active(self):
        if not self.active or time.monotonic() >= self.deadline:
            raise BrokerError("locked", 423)

    def status(self):
        live = self.active and time.monotonic() < self.deadline
        return {"unlocked": live, "deadline": self.wall_deadline if live else None,
                "policy_version": self.policy.version, "grants": len(self.grants) if live else 0}

    async def unlock(self, owner, passphrase, ttl=None, *, create=False):
        self.owned(owner)
        if self._locking:
            raise BrokerError("lock-in-progress", 409)
        if self.active:
            raise BrokerError("already-unlocked", 409)
        ttl = self.policy.max_unlock_seconds if ttl is None else number(ttl, 1, self.policy.max_unlock_seconds, integer=False)
        if type(passphrase) is not str or not 1 <= len(passphrase) <= 4096:
            raise BrokerError("admin-input-invalid", 400)
        epoch = self.generation
        async with self._vault_mutex:
            # Shield the worker so cancellation cannot release the mutex while
            # decryption is still running and subsequently resurrect the vault.
            worker = asyncio.create_task(asyncio.to_thread(self.provider.create if create else self.provider.unlock, passphrase))
            try:
                await drain_worker(worker)
            except BaseException:
                self.provider.lock()
                raise
            if owner is not self.owner or epoch != self.generation:
                self.provider.lock()
                raise BrokerError("admin-session-invalid", 403)
            self.grants.clear()
            self.generation += 1
            self.deadline = time.monotonic() + ttl
            self.wall_deadline = time.time() + ttl
            self.active = True
            generation = self.generation
            self._deadline_task = asyncio.create_task(self._expire(generation, ttl))
        return self.status()

    async def _expire(self, generation, ttl):
        await asyncio.sleep(ttl)
        if generation == self.generation:
            await self.lock()

    async def cancel_tasks(self, grant_id=None):
        tasks = [t for t, gid in list(self.inflight.items()) if grant_id is None or gid == grant_id]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def lock(self):
        # Revoke synchronously before any await, including while a KDF is running.
        self.active = False
        self.grants.clear()
        self.deadline = self.wall_deadline = 0.0
        self.generation += 1
        deadline_task, self._deadline_task = self._deadline_task, None
        if deadline_task is not None and deadline_task is not asyncio.current_task():
            deadline_task.cancel()
        self._locking = True
        if self._lock_completion is None or self._lock_completion.done():
            self._lock_completion = asyncio.create_task(self._finish_lock())
        await drain_worker(self._lock_completion)

    async def _finish_lock(self):
        try:
            await self.cancel_tasks()
            async with self._vault_mutex:
                self.provider.lock()
        finally:
            self._locking = False

    async def disconnect(self, owner):
        if self.owner is owner:
            self.owner = None
            await self.lock()

    def create_grant(self, owner, principal, bindings, ttl, max_requests):
        self.owned(owner)
        self.require_active()
        identity(principal)
        if principal not in self.principals.values() or type(bindings) is not list or not bindings or len(bindings) > 256 or any(type(b) is not str or b not in self.policy.bindings for b in bindings):
            raise BrokerError("grant-invalid", 400)
        number(ttl, .05, self.policy.max_unlock_seconds, integer=False)
        number(max_requests, 1, 100000)
        if len(self.grants) >= 1024:
            raise BrokerError("grant-limit", 429)
        gid = secrets.token_urlsafe(24)
        expiry = min(time.time() + ttl, self.wall_deadline)
        self.grants[gid] = Grant(gid, principal, frozenset(bindings), expiry, max_requests, self.generation, min(time.monotonic() + ttl, self.deadline))
        return {"grant_id": gid, "expires_at": expiry}

    def check(self, fingerprint, cert_not_after, grant_id, *, consume=False, binding_id=None):
        self.require_active()
        if type(grant_id) is not str or len(grant_id) > 128 or type(fingerprint) is not str:
            raise BrokerError("grant-invalid", 403)
        grant = self.grants.get(grant_id)
        if (grant is None or grant.generation != self.generation or
                time.monotonic() >= grant.expires_mono or
                self.principals.get(fingerprint) != grant.principal or
                time.time() >= min(grant.expires_at, cert_not_after, self.wall_deadline)):
            raise BrokerError("grant-invalid", 403)
        # Effective grant validity is always bounded by the presented certificate,
        # including an already-established TLS connection after certificate expiry.
        if binding_id is not None and binding_id not in grant.bindings:
            raise BrokerError("binding-denied", 403)
        if consume:
            if grant.remaining <= 0:
                raise BrokerError("budget-exhausted", 429)
            grant.remaining -= 1
        return grant

    async def revoke(self, owner, grant_id):
        self.owned(owner)
        self.require_active()
        if type(grant_id) is not str:
            raise BrokerError("grant-invalid", 400)
        self.grants.pop(grant_id, None)
        await self.cancel_tasks(grant_id)

    async def enroll(self, owner, fingerprint, principal=None):
        self.owned(owner)
        self.require_active()
        if type(fingerprint) is not str or not FINGERPRINT.fullmatch(fingerprint):
            raise BrokerError("principal-invalid", 400)
        if principal is not None:
            identity(principal)
            if len(self.principals) >= 1024 and fingerprint not in self.principals:
                raise BrokerError("principal-limit", 429)
            self.principals[fingerprint] = principal
        else:
            self.principals.pop(fingerprint, None)
        self.grants.clear()
        await self.cancel_tasks()

    async def replace_policy(self, owner, raw):
        self.owned(owner)
        self.require_active()
        policy = Policy.parse(raw)
        self.grants.clear()
        await self.cancel_tasks()
        self.policy = policy
        self.principals = dict(policy.principals)
        # Shorter policy deadlines take effect immediately; never extend unlock.
        ttl = min(self.deadline - time.monotonic(), policy.max_unlock_seconds)
        self.deadline = time.monotonic() + max(0, ttl)
        self.wall_deadline = time.time() + max(0, ttl)
        self.generation += 1
        if self._deadline_task is not None:
            self._deadline_task.cancel()
        self._deadline_task = asyncio.create_task(self._expire(self.generation, max(0, ttl)))
