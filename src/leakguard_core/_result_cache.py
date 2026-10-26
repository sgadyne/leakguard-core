"""Process-wide, owner-scoped LRU of redacted native detector observations.

This is not a source/extraction cache or a durable scan-result cache. Values
contain only validated rule IDs and line ranges. Callers supply content/runtime
digests and still perform source, proof, plugin and final publication checks.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
import sys
import threading

from cachetools import LRUCache


@dataclass(frozen=True, slots=True)
class _Entry:
    rows: tuple
    weight: int


class CacheScope:
    """Opaque service/profile lifetime. Closing fences late producers."""
    __slots__ = ('token', 'closed', 'generation')

    def __init__(self):
        self.token = secrets.token_hex(16)
        self.closed = False
        self.generation = 0


class ObservationCache:
    def __init__(self, *, max_bytes=8 * 1024 * 1024, max_entries=2048, max_flights=64):
        if min(max_bytes, max_entries, max_flights) <= 0:
            raise ValueError('cache-budget')
        self._cache = LRUCache(max_bytes, getsizeof=lambda entry: entry.weight)
        self._max_entries = max_entries
        self._max_flights = max_flights
        self._lock = threading.RLock()
        self._flights = {}
        self._epoch = 0
        self._counts = dict(hits=0, misses=0, waits=0, evictions=0, bypasses=0)

    @staticmethod
    def _entry(key, rows):
        # Accept a narrow immutable schema, never arbitrary detector JSON,
        # source bytes/text, exceptions, callbacks or final findings.
        if type(rows) is not tuple or len(rows) > 100_000:
            return None
        # Include conservative per-entry dict/LRU bookkeeping in addition to
        # the actual immutable keys/values. This remains an estimate, not RSS.
        weight = 256 + sys.getsizeof(key) + sum(sys.getsizeof(item) for item in key)
        weight += sys.getsizeof(rows) + sys.getsizeof(_Entry((), 0)) + sys.getsizeof(0)
        for row in rows:
            if (type(row) is not tuple or len(row) != 4
                    or type(row[0]) is not str or not re.fullmatch('[a-z][a-z0-9-]{0,79}', row[0])
                    or type(row[1]) is not int or type(row[2]) is not int
                    or not 1 <= row[1] <= row[2]
                    or type(row[3]) is not str or row[3] not in {'block', 'review', 'info'}):
                return None
            weight += sys.getsizeof(row) + sum(sys.getsizeof(item) for item in row)
        return _Entry(rows, weight)

    def get_or_compute(self, scope, digest, *, domain, check, compute):
        """Coalesce only within a caller's cancellation/deadline domain.

        A cancelled waiter never cancels its producer. Failures are not shared
        or retained; a waiter can retry under its own remaining budget. No
        producer callback, text or exception is placed in the flight table.
        """
        if (type(scope) is not CacheScope or type(digest) is not str
                or re.fullmatch('[0-9a-f]{64}', digest) is None):
            raise ValueError('cache-identity')
        key = (scope.token, digest)
        flight_key = (key, domain)
        while True:
            check()
            with self._lock:
                if scope.closed:
                    self._counts['bypasses'] += 1
                    bypass = True
                else:
                    bypass = False
                    entry = self._cache.get(key)
                    if entry is not None:
                        self._counts['hits'] += 1
                        return entry.rows
                    flight = self._flights.get(flight_key) if domain is not None else None
                    if flight is not None:
                        self._counts['waits'] += 1
                    else:
                        self._counts['misses'] += 1
                        epoch, generation = self._epoch, scope.generation
                        if domain is not None and len(self._flights) < self._max_flights:
                            flight = threading.Event()
                            self._flights[flight_key] = flight
                        else:
                            flight = None
                        break
            if bypass:
                return compute()
            # A bounded polling wait lets each caller enforce its own budget.
            flight.wait(0.025)
        try:
            rows = compute()
            check()
            entry = self._entry(key, rows)
            with self._lock:
                if (entry is not None and not scope.closed and scope.generation == generation
                        and self._epoch == epoch and entry.weight <= self._cache.maxsize):
                    self._cache.pop(key, None)
                    while (len(self._cache) >= self._max_entries and key not in self._cache
                           or self._cache.currsize + entry.weight > self._cache.maxsize):
                        self._cache.popitem()
                        self._counts['evictions'] += 1
                    self._cache[key] = entry
            return rows
        finally:
            if flight is not None:
                with self._lock:
                    if self._flights.get(flight_key) is flight:
                        del self._flights[flight_key]
                    flight.set()

    def close_scope(self, scope):
        with self._lock:
            scope.closed = True
            self.clear_scope(scope)

    def clear_scope(self, scope):
        with self._lock:
            scope.generation += 1
            for key in tuple(self._cache):
                if key[0] == scope.token:
                    del self._cache[key]

    def reset(self):
        """Drop observations and fence in-flight writes without cancellation."""
        with self._lock:
            self._epoch += 1
            self._cache.clear()
            for name in self._counts:
                self._counts[name] = 0

    def metrics(self):
        with self._lock:
            return dict(self._counts, entries=len(self._cache), bytes=self._cache.currsize,
                        max_entries=self._max_entries, max_bytes=self._cache.maxsize,
                        flights=len(self._flights))


OBSERVATIONS = ObservationCache()
