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
import sys
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
               OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', MKL_NUM_THREADS='1',
               GOMAXPROCS='1', GOMEMLIMIT='384MiB')
    if extra:
        env.update(extra)
    return env


# Python preexec_fn can deadlock in a multithreaded embedding application before
# Popen returns. Apply limits in a fresh isolated interpreter, then exec fixed
# argv in the same process/session. No extension/input code runs before limits.
# https://docs.python.org/3/library/subprocess.html#popen-constructor
_POSIX_LAUNCH = '''import os, resource, sys
try:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    memory = int(sys.argv[1])
    if memory:
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    resource.setrlimit(resource.RLIMIT_FSIZE, (80000000, 80000000))
except BaseException:
    os._exit(126)
try:
    os.execvpe(sys.argv[2], sys.argv[2:], os.environ)
except BaseException:
    os._exit(127)
'''


def run_worker(argv: Sequence[str], data: bytes, *, timeout: float,
               max_output_bytes: int = 80_000_000,
               memory_bytes: int | None = 512 * 1024 * 1024,
               max_input_bytes: int = 80_000_000,
               env: Mapping[str, str] | None = None,
               cwd: str | os.PathLike | None = None,
               cancel: Callable[[], bool] | None = None) -> WorkerResult:
    """Execute fixed argv with bounded output, timeout, and owned group cleanup."""
    started = time.monotonic()
    if (isinstance(argv, (str, bytes)) or not argv or any(type(x) is not str or not x or '\x00' in x for x in argv)
            or type(data) is not bytes or type(max_input_bytes) is not int or max_input_bytes <= 0 or len(data) > max_input_bytes
            or not isinstance(timeout, (float, int)) or isinstance(timeout, bool)
            or not math.isfinite(timeout) or timeout <= 0
            or type(max_output_bytes) is not int or max_output_bytes <= 0):
        raise WorkerError('worker-input-invalid')
    if memory_bytes is not None and (type(memory_bytes) is not int or memory_bytes <= 0):
        raise WorkerError('worker-input-invalid')
    if os.name not in {'posix', 'nt'}:
        raise WorkerError('resource-bound-unavailable')
    job = None
    if os.name == 'nt':
        try:
            from ._windows_jobs import WindowsJob
            job = WindowsJob(memory_bytes)
        except Exception:
            raise WorkerError('resource-bound-unavailable') from None
    try:
        command = ([sys.executable, '-I', '-S', '-c', _POSIX_LAUNCH,
                    str(memory_bytes or 0), *argv] if os.name == 'posix' else list(argv))
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=cwd, env=dict(env) if env is not None else worker_environment(),
            start_new_session=os.name == 'posix',
            creationflags=(0x00000004 | 0x00000200) if os.name == 'nt' else 0,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        if job is not None:
            job.close()
        raise WorkerError('worker-start-failed') from None
    if job is not None:
        try:
            job.attach_and_resume(process)
        except Exception:
            job.terminate()
            process.kill()
            process.wait()
            job.close()
            for pipe in (process.stdin, process.stdout):
                if pipe:
                    pipe.close()
            raise WorkerError('resource-bound-unavailable') from None

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
    deadline = started + timeout
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
        elif job is not None:
            job.terminate()
        elif process.poll() is None:
            process.kill()
        process.wait()
        if job is not None:
            job.close()
        reader.join(timeout=2)
        writer.join(timeout=2)
        for pipe in (process.stdin, process.stdout):
            if pipe and not pipe.closed:
                pipe.close()
    if time.monotonic() >= deadline and failure is None:
        failure = 'worker-timeout'
    if failure:
        raise WorkerError(failure)
    if overflow.is_set() or not reader_done.is_set() or not writer_done.is_set():
        raise WorkerError('worker-output-limit')
    if os.name == 'posix' and process.returncode == 126:
        raise WorkerError('resource-bound-unavailable')
    if os.name == 'posix' and process.returncode == 127:
        raise WorkerError('worker-start-failed')
    return WorkerResult(bytes(output), process.returncode)
