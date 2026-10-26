"""Bounded ordered execution; input preparation stays on the store owner's thread."""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
import threading


class InputFailure(RuntimeError):
    def __init__(self, code, source=None):
        self.code = code
        self.source = source
        super().__init__(code)


class Cancellation:
    """Serialize caller callbacks and share one latched stop signal with workers."""
    def __init__(self, callback=None):
        self._callback = callback
        self._stopped = threading.Event()
        self._lock = threading.Lock()

    def __call__(self):
        if self._stopped.is_set():
            return True
        if self._callback is not None:
            with self._lock:
                if self._callback():
                    self._stopped.set()
        return self._stopped.is_set()

    def stop(self):
        self._stopped.set()


def ordered_work(inputs, *, prepare, execute, workers, max_items, stop):
    """Keep at most ``workers`` admitted inputs and consume results in input order.

    A terminal enumeration/preparation error is raised after earlier admitted
    work has been delivered. Closing the iterator stops and joins its workers
    before releasing private backend setup. No task can touch the durable store.
    """
    iterator = iter(inputs)
    pending = deque()
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='leakguard-scan') if workers > 1 else None
    count = 0
    exhausted = False
    terminal = None
    try:
        while True:
            while not exhausted and terminal is None and len(pending) < workers:
                try:
                    item = next(iterator)
                    if count >= max_items:
                        raise InputFailure('budget-exhausted')
                    work = prepare(item)
                    count += 1
                    # The serial reference path runs in the caller thread.
                    pending.append(pool.submit(execute, work) if pool else execute(work))
                except StopIteration:
                    exhausted = True
                except Exception as error:
                    terminal = error
            if pending:
                value = pending.popleft()
                completed = value.result() if pool else value
                value = None
                try:
                    yield completed
                finally:
                    # Release the delivered future/result before preparing the
                    # next input; a completed Future otherwise retains raw bytes
                    # while the next full window is being admitted.
                    completed = None
            elif terminal is not None:
                raise terminal
            else:
                break
    finally:
        stop()
        if pool is not None:
            for future in pending:
                future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
        if hasattr(iterator, 'close'):
            iterator.close()
