"""Explicit Python entry point for the single LeakGuard scan service.

Importing this module is inert. Configuration is validated only through an
explicit ``ScanConfig`` constructor, and the engine is imported only by
``Scanner.open``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .models import (
    BytesInput,
    FileInput,
    GitRequest,
    ScanLimits,
    ScanPolicy,
    ScanReport,
)


class ConfigurationError(ValueError):
    """Safe configuration failure with a stable code and optional key name."""

    code = "configuration-invalid"

    def __init__(self, field_name: str = "configuration") -> None:
        self.field = field_name if field_name in _SAFE_CONFIG_FIELDS else "configuration"
        super().__init__(f"Invalid LeakGuard configuration at {self.field}")


class ReportError(ValueError):
    """An invalid or oversized external report, without echoing its content."""

    code = 'report-invalid'

    def __init__(self) -> None:
        super().__init__(self.code)


def parse_report(data: str | bytes, *, max_bytes: int = 64_000_000) -> ScanReport:
    """Validate the public redacted wire schema using the store's strict parser.

    Duplicate keys, unknown fields, non-finite numbers, invalid counts and
    inconsistent coverage all fail closed. This does not authenticate a sender.
    """
    if type(data) not in {str, bytes} or type(max_bytes) is not int or not 1 <= max_bytes <= 64_000_000:
        raise ReportError()
    try:
        if len(data) > max_bytes or type(data) is str and len(data.encode('utf-8')) > max_bytes:
            raise ReportError()

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ReportError()
                result[key] = value
            return result

        def reject_constant(value):
            raise ReportError()

        value = json.loads(data, object_pairs_hook=unique, parse_constant=reject_constant)
        from .scan_store import _report_from
        return _report_from(value)
    except Exception:
        raise ReportError() from None


@dataclass(frozen=True, slots=True, repr=False)
class ScanConfig:
    """Validated immutable snapshot of operator configuration.

    Use ``from_mapping`` or ``from_file`` so values are normalized, copied and
    checked by the same settings helper as the CLI. The private serialized
    snapshot is omitted from repr because extension options can be sensitive.
    """

    _canonical_json: str = field(repr=False)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, object]) -> ScanConfig:
        if not isinstance(mapping, Mapping):
            raise ConfigurationError()
        try:
            # Importing settings itself performs no environment reads. Keep the
            # import here so `import leakguard_core.api` remains entirely inert.
            from . import settings

            normalized = settings.validate(dict(mapping))
            encoded = json.dumps(
                normalized,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except Exception as error:
            field_name = getattr(error, "field", "configuration")
            raise ConfigurationError(field_name) from None
        return cls(encoded)

    @classmethod
    def from_file(cls, path: Path) -> ScanConfig:
        if not isinstance(path, Path):
            raise ConfigurationError()
        try:
            from . import settings

            normalized = settings.read_config(path)
            encoded = json.dumps(
                normalized,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except Exception as error:
            field_name = getattr(error, "field", "configuration")
            raise ConfigurationError(field_name) from None
        return cls(encoded)

    def to_mapping(self) -> dict[str, object]:
        """Return a fresh mutable copy for the service's private setup."""
        value = json.loads(self._canonical_json)
        if type(value) is not dict:
            raise ConfigurationError("configuration")
        return value

    def __repr__(self) -> str:
        return "ScanConfig(<validated>)"


class Scanner:
    """Thin, explicit facade over the shared engine service."""

    def __init__(self, service: object) -> None:
        self._service = service
        self._closed = False

    @classmethod
    def open(
        cls,
        *,
        config: ScanConfig,
        state_dir: Path | None = None,
        store: object | None = None,
    ) -> Scanner:
        if type(config) is not ScanConfig:
            raise ConfigurationError("configuration")
        if state_dir is not None and not isinstance(state_dir, Path):
            raise TypeError("state_dir must be a pathlib.Path or None")
        # This is the first import of engine internals. Calling open is the
        # explicit point at which backend and durable-state setup may occur.
        from .engine import ScanService

        service = ScanService(config.to_mapping(), state_dir=state_dir, store=store)
        return cls(service)

    def capabilities(self) -> dict[str, object]:
        """Report selected execution policy and actual platform primitives."""
        self._ensure_open()
        from ._supervision import worker_capabilities
        return worker_capabilities(self._service.config["worker_policy"])

    def work_identity(self, *, policy: ScanPolicy, limits: ScanLimits) -> dict[str, str]:
        """Identify this prepared service's effective policy and runtime bytes.

        A host compares this value before resuming persisted jobs. Its policy
        digest excludes slice-only budgets and worker count; a report's policy_id
        still identifies its full limits. Scans revalidate artifacts themselves.
        """
        self._ensure_open()
        if type(policy) is not ScanPolicy or type(limits) is not ScanLimits:
            raise TypeError('policy and limits must be ScanPolicy and ScanLimits')
        from .execution import work_identity
        return work_identity(config=self._service.config, runtime=self._service._runtime,
                             policy=policy, limits=limits)

    def scan(
        self,
        inputs: Iterable[FileInput | BytesInput],
        *,
        policy: ScanPolicy,
        limits: ScanLimits,
        use_cache: bool = True,
        cancel: Callable[[], bool] | None = None,
    ) -> ScanReport:
        self._ensure_open()
        _validate_scan_args(policy, limits, use_cache, cancel)
        result = self._service.scan(
            _validated_inputs(inputs),
            policy=policy,
            limits=limits,
            use_cache=use_cache,
            cancel=cancel,
        )
        if type(result) is not ScanReport:
            raise RuntimeError("Scan service returned an invalid report")
        return result

    def scan_paths(
        self,
        paths: Iterable[Path],
        *,
        policy: ScanPolicy,
        limits: ScanLimits,
        use_cache: bool = True,
        cancel: Callable[[], bool] | None = None,
    ) -> ScanReport:
        """Scan bounded filesystem targets, expanding directories in the service."""
        self._ensure_open()
        _validate_scan_args(policy, limits, use_cache, cancel)
        result = self._service.scan_paths(
            paths,
            policy=policy,
            limits=limits,
            use_cache=use_cache,
            cancel=cancel,
        )
        if type(result) is not ScanReport:
            raise RuntimeError("Scan service returned an invalid report")
        return result

    def scan_git(
        self,
        repo: Path,
        *,
        request: GitRequest,
        limits: ScanLimits,
        cancel: Callable[[], bool] | None = None,
    ) -> ScanReport:
        self._ensure_open()
        if not isinstance(repo, Path):
            raise TypeError("repo must be a pathlib.Path")
        if type(request) is not GitRequest:
            raise TypeError("request must be a GitRequest")
        if type(limits) is not ScanLimits:
            raise TypeError("limits must be ScanLimits")
        if cancel is not None and not callable(cancel):
            raise TypeError("cancel must be callable or None")
        result = self._service.scan_git(repo, request=request, limits=limits, cancel=cancel)
        if type(result) is not ScanReport:
            raise RuntimeError("Scan service returned an invalid report")
        return result

    def audit(
        self,
        scope: str,
        *,
        limits: ScanLimits,
        use_cache: bool = True,
        cancel: Callable[[], bool] | None = None,
    ) -> ScanReport:
        """Advance one bounded scope audit through the shared service."""
        self._ensure_open()
        if not isinstance(scope, str) or not scope:
            raise TypeError("scope must be a nonempty string")
        if type(limits) is not ScanLimits:
            raise TypeError("limits must be ScanLimits")
        if type(use_cache) is not bool:
            raise TypeError("use_cache must be a bool")
        if cancel is not None and not callable(cancel):
            raise TypeError("cancel must be callable or None")
        result = self._service.audit(scope, limits=limits, use_cache=use_cache, cancel=cancel)
        if type(result) is not ScanReport:
            raise RuntimeError("Scan service returned an invalid report")
        return result

    def drain(
        self,
        *,
        limits: ScanLimits,
        use_cache: bool = False,
        cancel: Callable[[], bool] | None = None,
    ) -> ScanReport:
        """Process one bounded notification-queue batch through the service."""
        self._ensure_open()
        if type(limits) is not ScanLimits:
            raise TypeError("limits must be ScanLimits")
        if type(use_cache) is not bool:
            raise TypeError("use_cache must be a bool")
        if cancel is not None and not callable(cancel):
            raise TypeError("cancel must be callable or None")
        result = self._service.drain(limits=limits, use_cache=use_cache, cancel=cancel)
        if type(result) is not ScanReport:
            raise RuntimeError("Scan service returned an invalid report")
        return result

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._service.close()

    def __enter__(self) -> Scanner:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("Scanner is closed")


def _validate_scan_args(
    policy: ScanPolicy,
    limits: ScanLimits,
    use_cache: bool,
    cancel: Callable[[], bool] | None,
) -> None:
    if type(policy) is not ScanPolicy:
        raise TypeError("policy must be a ScanPolicy")
    if type(limits) is not ScanLimits:
        raise TypeError("limits must be ScanLimits")
    if type(use_cache) is not bool:
        raise TypeError("use_cache must be a bool")
    if cancel is not None and not callable(cancel):
        raise TypeError("cancel must be callable or None")


def _validated_inputs(inputs: Iterable[FileInput | BytesInput]) -> Iterable[FileInput | BytesInput]:
    for item in inputs:
        if type(item) not in {FileInput, BytesInput}:
            raise TypeError("inputs must contain only FileInput or BytesInput values")
        yield item


# Only static configuration keys may appear in the exception message.
_SAFE_CONFIG_FIELDS = frozenset({
    "max_file_bytes", "scan_timeout_seconds", "review_only_rules", "audit_scopes",
    "watch_scopes", "scope_aliases", "profiles", "priority_paths", "exclude_roots",
    "exclude_components", "plugins", "credential_store", "gitleaks_executable",
    "gitleaks_config", "script_checks", "required_formats", "omissions",
    "extractor_overrides", "worker_policy", "scan_workers", "detection_profile",
    "extension_registry", "observation_backend", "observation_path", "configuration",
})


__all__ = [
    "BytesInput", "ConfigurationError", "FileInput", "GitRequest", "ScanConfig",
    "ScanLimits", "ScanPolicy", "ScanReport", "Scanner", "ReportError", "parse_report",
]
