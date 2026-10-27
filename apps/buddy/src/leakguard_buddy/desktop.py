"""Parent-owned desktop entry. Stdout is a private, bounded JSONL protocol."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import signal
import sys
import threading
import time
from typing import Any

_LIMIT = 16 * 1024
_OPS = {"bootstrap", "status", "lock-credentials", "shutdown"}
_SAFE_ERRORS = {"profile-in-use", "worker-still-running", "requests-still-running",
                "vault-busy", "vault-io-failed", "state-checkpoint-failed",
                "state-capacity-limit", "backend-stopping"}


def _code(error: BaseException) -> str:
    candidate = getattr(error, "code", None) or str(error)
    return candidate if candidate in _SAFE_ERRORS else "desktop-operation-failed"


def _request(line: bytes) -> dict[str, Any]:
    if len(line) > _LIMIT:
        raise ValueError()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    value = json.loads(line.decode("utf-8"), object_pairs_hook=unique)
    if (type(value) is not dict or set(value) != {"id", "op"}
            or type(value["id"]) is not int or not 1 <= value["id"] <= 2**53 - 1
            or type(value["op"]) is not str or value["op"] not in _OPS):
        raise ValueError()
    return value


def _status(backend) -> dict[str, Any]:
    value = backend.status()
    observations = value["observations"]
    host = value.get("host", {})
    background = ("available" if observations.get("unattended_available") and not observations.get("startup_error")
                  else "unlock-required" if observations.get("created") else "unavailable")
    # Status notifications contain opaque job IDs and states, never source paths or values.
    jobs = backend.jobs() if observations.get("unlocked") and hasattr(backend, "jobs") else []
    events = [{"id": row["id"], "state": row["state"]} for row in jobs[:20]
              if type(row.get("id")) is str and row.get("state") in
              {"queued", "running", "completed", "failed", "paused", "backoff", "cancelled"}]
    return {
        "scan_events": events,
        "observations": {key: bool(observations.get(key)) for key in ("created", "unlocked")},
        "vault": {key: bool(value["vault"].get(key)) for key in ("created", "unlocked")},
        "scheduler": host.get("scheduler", "stopped"),
        "pending_jobs": host.get("pending_jobs", 0),
        "background": background,
        "error_codes": [code for code in (observations.get("startup_error"), host.get("error"))
                        if type(code) is str and code in _SAFE_ERRORS],
    }


def run(backend, *, input_stream, output_stream) -> int:
    from .server import LocalBuddy
    app = LocalBuddy(backend)
    app.start()
    messages: queue.Queue[bytes | None] = queue.Queue(maxsize=32)
    parent_gone = threading.Event()

    def emit(value):
        try:
            output_stream.write(json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n")
            output_stream.flush()
        except (BrokenPipeError, OSError):
            parent_gone.set()

    def read():
        # A daemon thread must not hold BufferedReader's lock at interpreter
        # shutdown. Read the inherited pipe fd directly on every platform.
        buffered = bytearray()
        discarding = False
        while True:
            try:
                chunk = os.read(input_stream.fileno(), _LIMIT)
            except OSError:
                parent_gone.set()
                return
            if not chunk:
                parent_gone.set()
                return
            for byte in chunk:
                if byte == 10:
                    messages.put(b"" if discarding else bytes(buffered))
                    buffered.clear()
                    discarding = False
                elif not discarding:
                    buffered.append(byte)
                    if len(buffered) > _LIMIT:
                        buffered.clear()
                        discarding = True

    threading.Thread(target=read, name="buddy-desktop-control", daemon=True).start()
    for signum in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if signum is not None and threading.current_thread() is threading.main_thread():
            signal.signal(signum, lambda _sig, _frame: parent_gone.set())
    emit({"type": "ready", "protocol": 1, "origin": app.server.origin, "pid": os.getpid(), "apiVersion": 1})
    while True:
        if parent_gone.is_set() and messages.empty():
            # Parent death cannot authorize closing a store with a live worker.
            try:
                app.close()
                return 0
            except Exception:
                time.sleep(1)
                continue
        try:
            line = messages.get(timeout=0.5)
        except queue.Empty:
            continue
        request = None
        try:
            request = _request(line)
            operation = request["op"]
            if operation == "bootstrap":
                result = {"token": app.fresh_bootstrap()}
            elif operation == "status":
                result = _status(backend)
            elif operation == "lock-credentials":
                backend.credential_lock()
                if backend.credential_status().get("unlocked"):
                    raise RuntimeError("vault-busy")
                result = {"locked": True}
            else:
                app.close()
                result = {"stopped": True}
            emit({"id": request["id"], "ok": True, "result": result})
            if operation == "shutdown":
                return 0
        except (ValueError, TypeError, UnicodeError, RecursionError):
            emit({"id": request["id"] if request else None, "ok": False, "error": "control-invalid"})
        except Exception as error:
            emit({"id": request["id"] if request else None, "ok": False, "error": _code(error)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="password-buddy-desktop-backend")
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    # Only the protocol writer keeps stdout. Library subprocess output and
    # unexpected exception text must never leak to the shell or diagnostics.
    protocol_output = sys.stdout
    with open(os.devnull, "w", encoding="utf-8") as sink:
        sys.stdout = sink
        sys.stderr = sink
        try:
            from .backend import BuddyBackend
            backend = BuddyBackend(state_dir=args.state_dir, config_path=args.config)
            return run(backend, input_stream=sys.stdin.buffer, output_stream=protocol_output)
        except Exception as error:
            protocol_output.write(json.dumps({"type": "error", "code": _code(error)}) + "\n")
            protocol_output.flush()
            return 1
        finally:
            sys.stdout = protocol_output


if __name__ == "__main__":
    raise SystemExit(main())
