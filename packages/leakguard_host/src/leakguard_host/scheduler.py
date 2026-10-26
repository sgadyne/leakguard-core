"""One bounded scan writer with encrypted, application-owned checkpoints.

The persistence capability is deliberately mandatory. A missing/locked encrypted
store never silently becomes a JSON file or a second plaintext ScanStore.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import threading
import time
from typing import Callable, Protocol
import uuid

from leakguard_core.api import ScanConfig, Scanner
from leakguard_core.models import ScanLimits, ScanPolicy

from .errors import HostError
from . import navigation

_ACTIVE = {"queued", "running", "paused", "backoff"}
_FINAL = {"completed", "cancelled", "failed"}
_UNSET = object()


class HostStateStore(Protocol):
    def load_host_state(self) -> dict: ...
    def save_host_state(self, state: dict) -> None:
        """Atomically checkpoint this state AND the associated encrypted ScanStore."""
        ...


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def _seconds(value: str | None) -> float:
    if value is None:
        return 0
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        raise HostError("host-state-invalid") from None


def _interval(value) -> int | None:
    if value is not None and (type(value) is not int or not 60 <= value <= 31_536_000):
        raise HostError("schedule-invalid")
    return value


class _SliceStore:
    """Observe progress while forwarding to the sole application-owned sink."""
    def __init__(self, store):
        self._store = store
        self.advanced = False

    def __getattr__(self, name):
        method = getattr(self._store, name)
        if name == "finish_directory":
            def finish(*args, **kwargs):
                result = method(*args, **kwargs)
                if kwargs.get("success") is True:
                    self.advanced = True
                return result
            return finish
        if name == "set_directory_progress":
            def progress(claim, value):
                previous = self._store.get_directory_progress(claim)
                result = method(claim, value)
                if value is not None and value != previous:
                    self.advanced = True
                return result
            return progress
        return method


class HostService:
    def __init__(self, *, config: ScanConfig, scan_store: object,
                 state_store: HostStateStore | None = None, limits: ScanLimits | None = None,
                 clock: Callable[[], float] = time.time,
                 scanner_factory: Callable = Scanner.open):
        if type(config) is not ScanConfig:
            raise TypeError("config must be ScanConfig")
        self._config = config
        self._store = scan_store
        self._state_store = state_store if state_store is not None else scan_store
        if not all(callable(getattr(self._state_store, name, None)) for name in ("load_host_state", "save_host_state")):
            raise HostError("encrypted-state-required")
        self._clock = clock
        self._scanner_factory = scanner_factory
        configured = config.to_mapping()
        self._limits = limits or ScanLimits(deadline_seconds=10, max_files=100,
            max_file_bytes=configured["max_file_bytes"], max_directory_entries=2000,
            max_report_bytes=4_000_000, detector_timeout_seconds=min(10, configured["scan_timeout_seconds"]))
        if self._limits.deadline_seconds > 60 or self._limits.max_files > 1000:
            raise HostError("slice-limit-invalid")
        self._lock = threading.RLock()
        self._slice_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._current: str | None = None
        self._storage_error: str | None = None
        self._worker_error: str | None = None
        try:
            value = self._state_store.load_host_state()
            self._state = self._validate_state(value)
        except HostError:
            raise
        except Exception:
            raise HostError("host-state-unavailable") from None
        changed = False
        for job in self._state["jobs"].values():
            if job["state"] in {"queued", "running", "backoff"}:
                job.update(state="paused", last_error="interrupted-restart", updated_at=_timestamp(self._clock()))
                changed = True
        if changed:
            self._save()

    @staticmethod
    def _validate_state(value: dict) -> dict:
        if value == {}:
            return {"version": 1, "sources": {}, "jobs": {}}
        try:
            if type(value) is not dict or set(value) != {"version", "sources", "jobs"} or value["version"] != 1:
                raise ValueError()
            if type(value["sources"]) is not dict or type(value["jobs"]) is not dict or len(value["sources"]) > 100 or len(value["jobs"]) > 300:
                raise ValueError()
            for key, source in value["sources"].items():
                if type(source) is not dict or source["id"] != key or not isinstance(key, str) or len(key) != 32:
                    raise ValueError()
                navigation._path(source["root"])
                if source["kind"] not in {"local", "mounted", "unc"} or type(source["enabled"]) is not bool:
                    raise ValueError()
                if type(source["exclusions"]) is not list or len(source["exclusions"]) > 100:
                    raise ValueError()
                for excluded in source["exclusions"]:
                    navigation.bounded_path(excluded, source["root"])
                _interval(source["schedule_seconds"])
                _seconds(source["next_run_at"])
                _seconds(source["last_success_at"])
            for key, job in value["jobs"].items():
                if type(job) is not dict or job["id"] != key or not isinstance(key, str) or len(key) != 32 or job["source_id"] not in value["sources"] or job["state"] not in _ACTIVE | _FINAL:
                    raise ValueError()
                for field in ("attempts", "slices", "files_scanned"):
                    if type(job[field]) is not int or job[field] < 0:
                        raise ValueError()
                for field in ("created_at", "updated_at", "next_retry_at"):
                    _seconds(job[field])
            active = [job["source_id"] for job in value["jobs"].values() if job["state"] in _ACTIVE]
            if len(active) != len(set(active)):
                raise ValueError()
            return deepcopy(value)
        except (ValueError, KeyError, TypeError, HostError):
            raise HostError("host-state-invalid") from None

    def _save(self) -> None:
        try:
            self._state_store.save_host_state(deepcopy(self._state))
            self._storage_error = None
        except Exception as error:
            code = getattr(error, "code", "state-checkpoint-failed")
            self._storage_error = code if code in {"state-capacity-limit"} else "state-checkpoint-failed"
            self._stop.set()
            raise HostError(self._storage_error) from None

    def _mutate(self, action):
        with self._lock:
            if self._storage_error:
                raise HostError(self._storage_error)
            prior = deepcopy(self._state)
            try:
                result = action()
                self._save()
                return deepcopy(result)
            except Exception:
                self._state = prior
                raise

    def capabilities(self) -> dict:
        return navigation.capabilities()

    def roots(self, *, supplied_unc: tuple[str, ...] = ()) -> list[dict]:
        return navigation.roots(supplied_unc=supplied_unc)

    def browse(self, path, *, root=None, cursor=None, limit=100) -> dict:
        return navigation.browse(path, root=root, cursor=cursor, limit=limit)

    def reveal(self, path, *, source_id: str) -> dict:
        with self._lock:
            source = self._source(source_id)
            root = source["root"]
        return navigation.reveal(path, root=root)

    def sources(self) -> list[dict]:
        with self._lock:
            return deepcopy(list(self._state["sources"].values()))

    def add_source(self, root, *, label: str | None = None, kind: str = "local", exclusions=()) -> dict:
        if kind not in {"local", "mounted", "unc"}:
            raise HostError("source-kind-invalid")
        path = navigation.bounded_path(root)
        if kind == "unc" and not navigation.capabilities()["unc"]:
            raise HostError("platform-unavailable")
        if label is not None and (type(label) is not str or not 1 <= len(label) <= 200):
            raise HostError("source-label-invalid")
        if not isinstance(exclusions, (list, tuple)) or len(exclusions) > 100:
            raise HostError("exclusions-invalid")
        excluded = [str(navigation.bounded_path(item if Path(item).is_absolute() else path / item, path)) for item in exclusions]
        status = navigation.path_status(path)
        if status != "available" and kind == "local":
            raise HostError(status)
        try:
            info = path.stat()
            identity = [info.st_dev, info.st_ino] if status == "available" else None
        except OSError:
            identity = None
        def action():
            if len(self._state["sources"]) >= 100:
                raise HostError("source-limit")
            if any(source["root"] == str(path) for source in self._state["sources"].values()):
                raise HostError("source-exists")
            source = {"id": uuid.uuid4().hex, "label": label or path.name or str(path), "root": str(path),
                      "kind": kind, "exclusions": excluded, "schedule_seconds": None, "enabled": True,
                      "last_success_at": None, "next_run_at": None, "root_identity": identity,
                      "mount_marker": navigation.mount_marker(path) if kind == "mounted" else None}
            self._state["sources"][source["id"]] = source
            return source
        return self._mutate(action)

    def update_source(self, source_id: str, *, schedule_seconds=_UNSET, enabled: bool | None = None) -> dict:
        if schedule_seconds is not _UNSET:
            _interval(schedule_seconds)
        if enabled is not None and type(enabled) is not bool:
            raise HostError("source-invalid")
        def action():
            source = self._source(source_id)
            if schedule_seconds is not _UNSET:
                source["schedule_seconds"] = schedule_seconds
                source["next_run_at"] = _timestamp(self._clock() + schedule_seconds) if schedule_seconds is not None else None
            if enabled is not None:
                source["enabled"] = enabled
                if not enabled:
                    for job in self._state["jobs"].values():
                        if job["source_id"] == source_id and job["state"] in _ACTIVE:
                            job.update(state="paused", updated_at=_timestamp(self._clock()), next_retry_at=None)
            return source
        result = self._mutate(action)
        self._wake.set()
        return result

    def remove_source(self, source_id: str) -> dict:
        def action():
            self._source(source_id)
            # Cancel is acknowledged before the scanner has necessarily
            # returned. Keep its source/job available to cancellation and
            # final checkpoint callbacks until that slice releases ownership.
            if self._current is not None and self._job(self._current)["source_id"] == source_id:
                raise HostError("source-busy")
            if any(job["source_id"] == source_id and job["state"] in _ACTIVE for job in self._state["jobs"].values()):
                raise HostError("source-busy")
            del self._state["sources"][source_id]
            self._state["jobs"] = {key: job for key, job in self._state["jobs"].items() if job["source_id"] != source_id}
            return {"removed": True, "source_id": source_id}
        return self._mutate(action)

    def _source(self, source_id):
        try:
            return self._state["sources"][source_id]
        except (KeyError, TypeError):
            raise HostError("source-not-found") from None

    def _job(self, job_id):
        try:
            return self._state["jobs"][job_id]
        except (KeyError, TypeError):
            raise HostError("job-not-found") from None

    def jobs(self) -> list[dict]:
        with self._lock:
            return deepcopy(sorted(self._state["jobs"].values(), key=lambda job: (job["created_at"], job["id"]), reverse=True))

    def job(self, job_id: str) -> dict:
        with self._lock:
            return deepcopy(self._job(job_id))

    def _submit(self, source_id: str) -> dict:
        source = self._source(source_id)
        if not source["enabled"]:
            raise HostError("source-disabled")
        for job in self._state["jobs"].values():
            if job["source_id"] == source_id and job["state"] in _ACTIVE:
                return job
        if self._current is not None and self._job(self._current)["source_id"] == source_id:
            raise HostError("source-busy")
        prior_jobs = [job for job in self._state["jobs"].values() if job["source_id"] == source_id]
        reset = getattr(self._store, "reset_cycle", None)
        latest = max(prior_jobs, key=lambda job: (job["created_at"], job["id"])) if prior_jobs else None
        abandoned = latest is not None and latest["state"] in {"cancelled", "failed"}
        try:
            if callable(reset):
                reset("audit:host-" + source_id)
            elif abandoned:
                raise HostError("state-reset-unavailable")
            if abandoned:
                self._store.invalidate_scope(source["root"], reason="source-unavailable")
        except HostError:
            raise
        except Exception as error:
            raise HostError("state-cycle-busy" if getattr(error, "code", None) == "state-cycle-busy" else "state-reset-failed") from None
        # Retain a bounded history; engine evidence belongs to the ScanStore.
        final = sorted((key for key, job in self._state["jobs"].items() if job["state"] in _FINAL),
                       key=lambda key: (self._state["jobs"][key]["created_at"], key))
        for key in final[:max(0, len(self._state["jobs"]) - 199)]:
            del self._state["jobs"][key]
        now = _timestamp(self._clock())
        job = {"id": uuid.uuid4().hex, "source_id": source_id, "state": "queued", "created_at": now,
               "updated_at": now, "next_retry_at": None, "attempts": 0, "slices": 0, "files_scanned": 0,
               "stalled_slices": 0,
               "work_identity": None, "policy_resets": 0,
               "pending_files": None, "pending_directories": None, "coverage": "incomplete", "last_error": None, "report_id": None}
        self._state["jobs"][job["id"]] = job
        return job

    def submit(self, source_id: str) -> dict:
        result = self._mutate(lambda: self._submit(source_id))
        self._wake.set()
        return result

    def _control(self, job_id: str, state: str) -> dict:
        def action():
            job = self._job(job_id)
            if job["state"] in _FINAL:
                if job["state"] == state:
                    return job
                raise HostError("job-finished")
            if state == "queued" and not self._source(job["source_id"])["enabled"]:
                raise HostError("source-disabled")
            job.update(state=state, updated_at=_timestamp(self._clock()), next_retry_at=None)
            if state == "queued":
                job["stalled_slices"] = 0
            return job
        result = self._mutate(action)
        self._wake.set()
        return result

    def pause(self, job_id: str) -> dict:
        return self._control(job_id, "paused")

    def resume(self, job_id: str) -> dict:
        return self._control(job_id, "queued")

    def cancel(self, job_id: str) -> dict:
        return self._control(job_id, "cancelled")

    def _cancelled(self, job_id: str) -> bool:
        with self._lock:
            return self._stop.is_set() or self._job(job_id)["state"] != "running"

    def _available(self, source: dict) -> str:
        path = Path(source["root"])
        try:
            if path.resolve() != path:
                return "source-changed"
        except (OSError, RuntimeError):
            return "unreadable"
        status = navigation.path_status(path)
        if status != "available":
            return status
        try:
            info = path.stat()
            if source["kind"] == "local" and source["root_identity"] is not None and source["root_identity"] != [info.st_dev, info.st_ino]:
                return "source-changed"
            if source["mount_marker"] is not None and navigation.mount_marker(path) != source["mount_marker"]:
                return "offline"
        except OSError:
            return "offline"
        return "available"

    def _fence_work(self, job_id, source, scope, scanner) -> bool:
        method = getattr(scanner, "work_identity", None)
        if not callable(method):
            raise HostError("work-identity-unavailable")
        identity = method(policy=ScanPolicy.inventory(), limits=self._limits)
        if type(identity) is not dict or set(identity) != {"policy_id", "runtime_id"} or any(type(value) is not str or not 1 <= len(value) <= 256 for value in identity.values()):
            raise HostError("work-identity-invalid")
        with self._lock:
            if self._cancelled(job_id):
                return False
            job = self._job(job_id)
            if job.get("work_identity") != identity:
                reset = getattr(self._store, "reset_cycle", None)
                if not callable(reset):
                    raise HostError("state-reset-unavailable")
                try:
                    reset("audit:" + scope)
                    if job.get("work_identity") is not None or job["slices"]:
                        self._store.invalidate_scope(source["root"], reason="source-unavailable")
                        job["policy_resets"] = job.get("policy_resets", 0) + 1
                except Exception as error:
                    raise HostError("state-cycle-busy" if getattr(error, "code", None) == "state-cycle-busy" else "state-reset-failed") from None
                job.update(work_identity=dict(identity), files_scanned=0, pending_files=None,
                           pending_directories=None, stalled_slices=0, coverage="incomplete", report_id=None)
            return True

    def tick(self) -> dict:
        """Run at most one bounded slice; concurrent callers never duplicate work."""
        if not self._slice_lock.acquire(blocking=False):
            return {"worked": False, "status": "busy"}
        try:
            with self._lock:
                if self._storage_error:
                    raise HostError(self._storage_error)
                if self._stop.is_set():
                    return {"worked": False, "status": "stopped"}
                now = self._clock()
                scheduled = []
                for source in self._state["sources"].values():
                    if source["enabled"] and source["schedule_seconds"] is not None and _seconds(source["next_run_at"]) <= now:
                        scheduled.append(source["id"])
                if scheduled:
                    def enqueue():
                        for source_id in scheduled:
                            self._submit(source_id)
                            source = self._source(source_id)
                            source["next_run_at"] = _timestamp(now + source["schedule_seconds"])
                    self._mutate(enqueue)
                ready = [job for job in self._state["jobs"].values() if job["state"] == "queued" or job["state"] == "backoff" and _seconds(job["next_retry_at"]) <= now]
                if not ready:
                    return {"worked": False, "status": "idle"}
                # Rotate unfinished slices so a large scope cannot starve others.
                job = min(ready, key=lambda value: (value["updated_at"], value["created_at"], value["id"]))
                source = deepcopy(self._source(job["source_id"]))
                job_id = job["id"]
                def running():
                    job.update(state="running", updated_at=_timestamp(now), next_retry_at=None)
                self._mutate(running)
                self._current = job_id
            status = self._available(source)
            report = None
            slice_store = _SliceStore(self._store)
            failure = None
            if status != "available":
                failure = status
                try:
                    self._store.invalidate_scope(source["root"], reason="source-unavailable")
                except Exception:
                    failure = "state-failed"
            else:
                values = self._config.to_mapping()
                scope = "host-" + source["id"]
                values["audit_scopes"] = {scope: source["root"]}
                values["priority_paths"] = {}
                values["exclude_roots"] = list(values.get("exclude_roots", ())) + source["exclusions"]
                try:
                    config = ScanConfig.from_mapping(values)
                    with self._scanner_factory(config=config, store=slice_store) as scanner:
                        if self._fence_work(job_id, source, scope, scanner):
                            report = scanner.audit(scope, limits=self._limits, use_cache=True, cancel=lambda: self._cancelled(job_id))
                except HostError as error:
                    failure = error.code
                except Exception:
                    failure = "scan-failed"
            with self._lock:
                self._current = None
                def finish():
                    job = self._job(job_id)
                    source_now = self._source(job["source_id"])
                    job["updated_at"] = _timestamp(self._clock())
                    job["slices"] += 1
                    previous_pending = (job["pending_files"], job["pending_directories"])
                    if report is not None:
                        job.update(report_id=report.run_id, files_scanned=job["files_scanned"] + report.counts.scanned + report.counts.reused,
                                   pending_files=report.coverage.pending_files, pending_directories=report.coverage.pending_directories)
                    # A control action received during the slice takes precedence.
                    if job["state"] != "running":
                        return job
                    if self._stop.is_set():
                        job.update(state="paused", last_error="service-stopped")
                        return job
                    if failure is not None:
                        if failure in {"work-identity-unavailable", "work-identity-invalid", "state-reset-unavailable"}:
                            job.update(state="failed", last_error=failure, coverage="incomplete")
                        else:
                            self._backoff(job, failure)
                    elif report.coverage.enumeration_complete and report.coverage.required_complete:
                        job.update(state="completed", coverage="complete", attempts=0, last_error=None)
                        source_now["last_success_at"] = job["updated_at"]
                    else:
                        codes = {issue.code.value for issue in report.issues if issue.required}
                        codes.update(issue.code.value for result in report.results for issue in result.issues if issue.required)
                        if codes & {"source-unavailable", "enumeration-failed", "input-unreadable", "state-failed"}:
                            self._backoff(job, "source-unavailable")
                        elif codes - {"budget-exhausted", "cancelled"}:
                            job.update(state="failed", last_error=sorted(codes - {"budget-exhausted", "cancelled"})[0], coverage="incomplete")
                        else:
                            pending = (report.coverage.pending_files, report.coverage.pending_directories)
                            stalled = report.counts.results == 0 and pending == previous_pending and not slice_store.advanced
                            job["stalled_slices"] = job.get("stalled_slices", 0) + 1 if stalled else 0
                            job.update(state="paused" if job["stalled_slices"] >= 3 else "queued",
                                       last_error="scan-progress-stalled" if job["stalled_slices"] >= 3 else None)
                    return job
                result = self._mutate(finish)
            return {"worked": True, "status": result["state"], "job": result}
        finally:
            self._current = None
            self._slice_lock.release()

    def _backoff(self, job: dict, code: str) -> None:
        attempts = min(30, job["attempts"] + 1)
        delay = min(3600, 5 * 2 ** min(attempts - 1, 10))
        job.update(state="backoff", coverage="incomplete", last_error=code, attempts=attempts,
                   next_retry_at=_timestamp(self._clock() + delay))

    def status(self) -> dict:
        with self._lock:
            try:
                store_status = self._state_store.status() if callable(getattr(self._state_store, "status", None)) else {}
            except Exception:
                store_status = {}
            available = self._storage_error is None and store_status.get("unlocked") is not False and store_status.get("healthy") is not False
            return {"scheduler": "running" if self._thread and self._thread.is_alive() else "stopped",
                    "active_job": self._current, "observation_available": available,
                    "unattended_available": available and store_status.get("unattended_available") is True,
                    "storage_error": self._storage_error, "worker_error": self._worker_error, "sources": len(self._state["sources"]),
                    "pending_jobs": sum(job["state"] in _ACTIVE for job in self._state["jobs"].values()),
                    "slice_seconds": self._limits.deadline_seconds, "slice_max_files": self._limits.max_files}

    def start(self) -> dict:
        with self._lock:
            if self._storage_error:
                raise HostError(self._storage_error)
            if self._thread and self._thread.is_alive():
                return self.status()
            self._stop.clear()
            self._worker_error = None
            self._thread = threading.Thread(target=self._run, name="leakguard-host-scheduler", daemon=True)
            self._thread.start()
            return self.status()

    def _run(self):
        while not self._stop.is_set():
            try:
                result = self.tick()
            except Exception:
                with self._lock:
                    self._worker_error = "scheduler-failed"
                    if self._storage_error is None:
                        def pause_failed_worker():
                            for job in self._state["jobs"].values():
                                if job["state"] == "running":
                                    job.update(state="paused", coverage="incomplete", last_error="scheduler-failed", updated_at=_timestamp(self._clock()))
                        try:
                            self._mutate(pause_failed_worker)
                        except HostError:
                            pass
                self._stop.set()
                return
            self._wake.wait(0.05 if result["worked"] else 1)
            self._wake.clear()

    def stop(self, *, timeout: float | None = None) -> dict:
        wait_seconds = self._limits.deadline_seconds + 5 if timeout is None else timeout
        if isinstance(wait_seconds, bool) or not isinstance(wait_seconds, (int, float)) or wait_seconds < 0:
            raise HostError("stop-timeout-invalid")
        deadline = time.monotonic() + wait_seconds
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(max(0, deadline - time.monotonic()))
        if thread and thread.is_alive():
            # The caller MUST retain the store until the worker has stopped.
            raise HostError("worker-still-running")
        # tick() is public and may also be running in an application-owned thread.
        if not self._slice_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            raise HostError("worker-still-running")
        self._slice_lock.release()
        return self.status()
