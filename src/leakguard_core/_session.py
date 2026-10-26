"""Owned bounded framed worker lifetime; no shared server or retained payloads."""
from __future__ import annotations

import os
import math
import signal
import struct
import subprocess
import sys
import threading
import tempfile
import time

from ._supervision import (WorkerError, WORKER_POLICIES, _POSIX_LAUNCH,
                           _RSSWatchdog, worker_environment)


class FramedWorker:
    """One serialized request at a time, with process/job and idle RSS ownership."""
    def __init__(self, argv, *, memory_bytes=512 * 1024 * 1024, worker_policy='strict'):
        if (worker_policy not in WORKER_POLICIES or type(memory_bytes) is not int
                or memory_bytes <= 0 or os.name not in {'posix', 'nt'}):
            raise WorkerError('worker-input-invalid')
        if sys.platform == 'darwin' and worker_policy == 'strict':
            raise WorkerError('resource-bound-unavailable')
        self._lock = threading.Lock()
        self._lifecycle = threading.RLock()
        self._closed = threading.Event()
        self._failure = None
        self._job = None
        self._monitor = None
        self._temporary = tempfile.TemporaryDirectory(prefix='leakguard-session-')
        self._watchdog = (_RSSWatchdog(memory_bytes) if worker_policy == 'supervised-alpha'
                          and sys.platform == 'darwin' else None)
        hard = 0 if self._watchdog is not None else memory_bytes
        if os.name == 'nt':
            try:
                from ._windows_jobs import WindowsJob
                self._job = WindowsJob(memory_bytes)
            except Exception:
                raise WorkerError('resource-bound-unavailable') from None
        command = ([sys.executable, '-I', '-S', '-c', _POSIX_LAUNCH,
                    str(hard), *argv] if os.name == 'posix' else argv)
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=worker_environment({
                    'TMPDIR': self._temporary.name, 'TEMP': self._temporary.name,
                    'TMP': self._temporary.name, 'HOME': self._temporary.name,
                    'XDG_CACHE_HOME': self._temporary.name + '/cache',
                    'XDG_CONFIG_HOME': self._temporary.name + '/config'}),
                start_new_session=os.name == 'posix',
                creationflags=(0x00000004 | 0x00000200) if os.name == 'nt' else 0)
            if self._job is not None:
                self._job.attach_and_resume(self.process)
            if self._watchdog is not None:
                self._watchdog.attach(self.process.pid)
        except Exception:
            if hasattr(self, 'process'):
                self.close()
            elif self._job is not None:
                self._job.close()
                self._temporary.cleanup()
            else:
                self._temporary.cleanup()
            raise WorkerError('resource-bound-unavailable') from None
        if self._watchdog is not None:
            self._monitor = threading.Thread(target=self._watch, daemon=True,
                                              name='leakguard-session-rss')
            self._monitor.start()

    def _watch(self):
        while not self._closed.wait(.05):
            try:
                self._watchdog.check()
            except WorkerError as error:
                self._failure = error.code
                self.close()
                return

    def request(self, data, *, timeout, maximum=80_000_000, cancel=None):
        if (type(data) is not bytes or type(maximum) is not int or len(data) > maximum or not 0 < maximum <= 80_000_000
                or not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not math.isfinite(timeout) or timeout <= 0):
            raise WorkerError('worker-input-invalid')
        deadline = time.monotonic() + timeout
        while not self._lock.acquire(timeout=.025):
            if cancel is not None and cancel():
                raise WorkerError('cancelled')
            if time.monotonic() >= deadline:
                raise WorkerError('worker-timeout')
        try:
            if self._closed.is_set():
                raise WorkerError(self._failure or 'worker-start-failed')
            if cancel is not None and cancel():
                raise WorkerError('cancelled')
            done = threading.Event()
            written = threading.Event()
            result = []
            failure = []
            def read_exact(count):
                output = bytearray()
                while len(output) < count:
                    chunk = self.process.stdout.read(min(65536, count - len(output)))
                    if not chunk:
                        raise EOFError
                    output.extend(chunk)
                return bytes(output)
            def read():
                try:
                    count = struct.unpack('!I', read_exact(4))[0]
                    if count > maximum:
                        failure.append('worker-output-limit')
                    else:
                        result.append(read_exact(count))
                except (OSError, ValueError, EOFError):
                    failure.append('worker-start-failed')
                finally:
                    done.set()
            def write():
                try:
                    self.process.stdin.write(struct.pack('!I', len(data)))
                    for start in range(0, len(data), 65536):
                        self.process.stdin.write(data[start:start + 65536])
                    self.process.stdin.flush()
                except (OSError, ValueError):
                    failure.append('worker-start-failed')
                finally:
                    written.set()
            reader = threading.Thread(target=read, daemon=True, name='leakguard-session-output')
            writer = threading.Thread(target=write, daemon=True, name='leakguard-session-input')
            reader.start(); writer.start()
            try:
                while not (done.is_set() and written.is_set()):
                    if self._failure:
                        raise WorkerError(self._failure)
                    if self._closed.is_set() or cancel is not None and cancel():
                        raise WorkerError('cancelled')
                    if time.monotonic() >= deadline:
                        raise WorkerError('worker-timeout')
                    if failure or self.process.poll() is not None:
                        raise WorkerError(failure[0] if failure else 'worker-start-failed')
                    done.wait(.005)
                if failure:
                    raise WorkerError(failure[0])
                if time.monotonic() >= deadline:
                    raise WorkerError('worker-timeout')
                return result[0]
            except BaseException:
                self.close()
                raise
            finally:
                reader.join(timeout=2)
                writer.join(timeout=2)
        finally:
            self._lock.release()

    def close(self):
        self._closed.set()
        with self._lifecycle:
            if not hasattr(self, 'process'):
                return
            if os.name == 'posix':
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            elif self._job is not None:
                self._job.terminate()
            elif self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            if self._watchdog is not None:
                self._watchdog.cleanup()
            if self._job is not None:
                self._job.close(); self._job = None
            for pipe in (self.process.stdin, self.process.stdout):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass
            if self._temporary is not None:
                self._temporary.cleanup()
                self._temporary = None
        if self._monitor is not None and self._monitor is not threading.current_thread():
            self._monitor.join(timeout=1)
        if self._watchdog is not None:
            self._watchdog.cleanup()
