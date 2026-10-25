"""Bounded private subprocess transport shared by parsers and trusted extensions.

This contains crashes and resource exhaustion; it is not a code/network sandbox.
Input and output are transient sensitive bytes and must never appear in errors.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
import signal
import subprocess
import threading
import time
from typing import Callable, Mapping, Sequence


class WorkerError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class WorkerResult:
    stdout: bytes
    returncode: int


def worker_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    # Do not forward operator secrets to explicitly configured script checks.
    keep = ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL')
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env.update(PYTHONIOENCODING='utf-8', PYTHONUTF8='1', PYTHONNOUSERSITE='1',
               OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1')
    if extra:
        env.update(extra)
    return env


def _resource_setup(memory_bytes: int | None):
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if memory_bytes is not None:
        # RLIMIT_AS is available and exercised on supported POSIX parser workers.
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    # Parser/extension stdout is capped in the parent; don't permit large files.
    resource.setrlimit(resource.RLIMIT_FSIZE, (80_000_000, 80_000_000))


def run_worker(argv: Sequence[str], data: bytes, *, timeout: float,
               max_output_bytes: int = 80_000_000,
               memory_bytes: int | None = 512 * 1024 * 1024,
               max_input_bytes: int = 80_000_000,
               env: Mapping[str, str] | None = None,
               cwd: str | os.PathLike | None = None,
               cancel: Callable[[], bool] | None = None) -> WorkerResult:
    """Execute fixed argv with bounded output, timeout, and owned group cleanup."""
    if (isinstance(argv, (str, bytes)) or not argv or any(type(x) is not str or not x or '\x00' in x for x in argv)
            or type(data) is not bytes or type(max_input_bytes) is not int or max_input_bytes <= 0 or len(data) > max_input_bytes
            or not isinstance(timeout, (float, int)) or isinstance(timeout, bool)
            or not math.isfinite(timeout) or timeout <= 0
            or type(max_output_bytes) is not int or max_output_bytes <= 0):
        raise WorkerError('worker-input-invalid')
    if memory_bytes is not None and (type(memory_bytes) is not int or memory_bytes <= 0):
        raise WorkerError('worker-input-invalid')
    if memory_bytes is not None and os.name != 'posix':
        # Do not silently substitute a wall timer for a Windows hard memory bound.
        raise WorkerError('resource-bound-unavailable')
    try:
        process = subprocess.Popen(
            list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=cwd, env=dict(env) if env is not None else worker_environment(),
            start_new_session=os.name == 'posix',
            preexec_fn=(lambda: _resource_setup(memory_bytes)) if os.name == 'posix' else None,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        raise WorkerError('worker-start-failed') from None

    output = bytearray()
    overflow = threading.Event()
    reader_done = threading.Event()
    writer_done = threading.Event()

    def read_output():
        try:
            while True:
                chunk = process.stdout.read(65_536)
                if not chunk:
                    break
                remaining = max_output_bytes - len(output)
                output.extend(chunk[:max(0, remaining)])
                if len(chunk) > remaining:
                    overflow.set()
                    break
        except (OSError, ValueError):
            pass
        finally:
            reader_done.set()

    def write_input():
        try:
            view = memoryview(data)
            for offset in range(0, len(view), 65_536):
                process.stdin.write(view[offset:offset + 65_536])
            process.stdin.close()
        except (OSError, ValueError):
            pass
        finally:
            writer_done.set()

    reader = threading.Thread(target=read_output, name='leakguard-worker-output', daemon=True)
    writer = threading.Thread(target=write_input, name='leakguard-worker-input', daemon=True)
    reader.start()
    writer.start()
    deadline = time.monotonic() + timeout
    failure = None
    try:
        while process.poll() is None:
            if overflow.is_set():
                failure = 'worker-output-limit'; break
            if cancel is not None and cancel():
                failure = 'cancelled'; break
            if time.monotonic() >= deadline:
                failure = 'worker-timeout'; break
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
    except BaseException:
        failure = 'cancelled'
    finally:
        # Kill the group even after the direct child exits: descendants can retain
        # pipes or continue working after their parent has returned a response.
        if os.name == 'posix':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif process.poll() is None:
            process.kill()
        process.wait()
        reader.join(timeout=2)
        writer.join(timeout=2)
        for pipe in (process.stdin, process.stdout):
            if pipe and not pipe.closed:
                pipe.close()
    if failure:
        raise WorkerError(failure)
    if overflow.is_set() or not reader_done.is_set() or not writer_done.is_set():
        raise WorkerError('worker-output-limit')
    return WorkerResult(bytes(output), process.returncode)
