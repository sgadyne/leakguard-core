"""Immutable public models for LeakGuard scan requests and redacted results.

This module is deliberately inert: importing it reads no configuration, creates
no state, imports no extensions and starts no processes.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TypeAlias


# Provenance is repeated across findings in a report, so cap it at the same
# size accepted by the public legacy-report adapter. Surrogateescaped POSIX
# path characters remain valid and serialize through JSON escaping.
MAX_PROVENANCE_STRING_LENGTH = 4_096


class StringEnum(str, Enum):
    """Base for stable string-valued public enums."""


class SourceKind(StringEnum):
    FILESYSTEM = "filesystem"
    BYTES = "bytes"
    GIT_INDEX = "git-index"
    GIT_COMMIT = "git-commit"


class FindingSeverity(StringEnum):
    BLOCK = "block"
    REVIEW = "review"
    INFO = "info"


class DetectorSeverity(StringEnum):
    BLOCK = "block"
    REVIEW = "review"


class FindingClassification(StringEnum):
    CREDENTIAL_CANDIDATE = "credential-candidate"
    HEURISTIC = "heuristic"
    VERIFIED_FILE_SHA256 = "verified-file-sha256"
    VERIFIED_FUNCTION_AST_SHA256 = "verified-function-ast-sha256"


class ScanOutcome(StringEnum):
    SCANNED = "scanned"
    REUSED = "reused"
    SKIPPED = "skipped"
    ERROR = "error"
    INTERRUPTED = "interrupted"


class CoverageState(StringEnum):
    COMPLETE = "complete"
    OMITTED = "omitted"
    INCOMPLETE = "incomplete"


class ScanMode(StringEnum):
    INVENTORY = "inventory"
    GIT = "git"


class DecisionVerdict(StringEnum):
    ALLOW = "allow"
    ALLOW_WITH_OMISSIONS = "allow-with-omissions"
    BLOCK = "block"
    INCOMPLETE = "incomplete"


class GitRequestKind(StringEnum):
    INDEX = "index"
    PUSH = "push"


class ErrorCode(StringEnum):
    INPUT_MISSING = "input-missing"
    INPUT_UNREADABLE = "input-unreadable"
    INPUT_NONREGULAR = "input-nonregular"
    INPUT_CHANGED = "input-changed"
    INPUT_LIMIT = "input-limit"
    UNSUPPORTED_FORMAT = "unsupported-format"
    FORMAT_MISMATCH = "format-mismatch"
    AMBIGUOUS_FORMAT = "ambiguous-format"
    DECODE_FAILED = "decode-failed"
    ENCRYPTED = "encrypted"
    NO_TEXT = "no-text"
    DEPENDENCY_UNAVAILABLE = "dependency-unavailable"
    EXTRACT_FAILED = "extract-failed"
    EXTRACT_TIMEOUT = "extract-timeout"
    EXTRACT_CRASHED = "extract-crashed"
    EXTRACT_OUTPUT_LIMIT = "extract-output-limit"
    EXTRACT_PART_LIMIT = "extract-part-limit"
    RESOURCE_BOUND_UNAVAILABLE = "resource-bound-unavailable"
    WORKER_MEMORY_LIMIT = "worker-memory-limit"
    SUPERVISED_ALPHA_POLICY = "supervised-alpha-policy"
    OBSERVATIONS_EPHEMERAL = "observations-ephemeral"
    DETECTOR_FAILED = "detector-failed"
    DETECTOR_TIMEOUT = "detector-timeout"
    DETECTOR_OUTPUT_INVALID = "detector-output-invalid"
    DETECTOR_OUTPUT_LIMIT = "detector-output-limit"
    PLUGIN_INVALID = "plugin-invalid"
    PLUGIN_TIMEOUT = "plugin-timeout"
    PLUGIN_CRASHED = "plugin-crashed"
    POLICY_OMISSION = "policy-omission"
    BUDGET_EXHAUSTED = "budget-exhausted"
    CANCELLED = "cancelled"
    ENUMERATION_FAILED = "enumeration-failed"
    SOURCE_UNAVAILABLE = "source-unavailable"
    GIT_RANGE_INCOMPLETE = "git-range-incomplete"
    GIT_INPUT_INVALID = "git-input-invalid"
    STATE_FAILED = "state-failed"
    CONFIGURATION_INVALID = "configuration-invalid"


class PolicyReason(StringEnum):
    """Fixed public reasons for explicit coverage omissions."""

    UNSUPPORTED_BINARY = "unsupported-binary"
    OPTIONAL_FORMAT = "optional-format"
    OPERATOR_EXCLUSION = "operator-exclusion"


class OmissionSelectorKind(StringEnum):
    FORMAT = "format"
    PATH = "path"


@dataclass(frozen=True, slots=True)
class OmissionSelector:
    """An explicit omission selector; its value is a format ID or path glob."""

    kind: OmissionSelectorKind
    value: str

    def __post_init__(self) -> None:
        _require_enum("kind", self.kind, OmissionSelectorKind)
        _require_nonempty("value", self.value)


@dataclass(frozen=True, slots=True)
class Omission:
    id: str
    selector: OmissionSelector
    reason_code: PolicyReason

    def __post_init__(self) -> None:
        _require_token("id", self.id)
        if type(self.selector) is not OmissionSelector:
            raise TypeError("selector must be an OmissionSelector")
        _require_enum("reason_code", self.reason_code, PolicyReason)


@dataclass(frozen=True, slots=True)
class FileInput:
    """A single filesystem file; directory expansion belongs to the caller."""

    path: Path

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("path must be a pathlib.Path")


@dataclass(frozen=True, slots=True)
class BytesInput:
    """Bounded bytes and their caller-supplied logical location."""

    data: bytes = field(repr=False)
    logical_path: str

    def __post_init__(self) -> None:
        if type(self.data) is not bytes:
            raise TypeError("data must be bytes")
        _require_bounded_provenance("logical_path", self.logical_path)


@dataclass(frozen=True, slots=True)
class RefUpdate:
    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str

    def __post_init__(self) -> None:
        for name in ("local_ref", "local_oid", "remote_ref", "remote_oid"):
            _require_nonempty(name, getattr(self, name))
        for name in ("local_oid", "remote_oid"):
            if not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", getattr(self, name)):
                raise ValueError(f"{name} must be a full Git object ID")


@dataclass(frozen=True, slots=True)
class GitRequest:
    kind: GitRequestKind
    updates: tuple[RefUpdate, ...] = ()

    def __post_init__(self) -> None:
        _require_enum("kind", self.kind, GitRequestKind)
        if type(self.updates) is not tuple or any(type(item) is not RefUpdate for item in self.updates):
            raise TypeError("updates must be a tuple of RefUpdate values")
        if self.kind is GitRequestKind.PUSH and not self.updates:
            raise ValueError("push requests require at least one ref update")


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    mode: ScanMode
    block_severities: tuple[FindingSeverity, ...] = (FindingSeverity.BLOCK,)
    required_formats: tuple[str, ...] = ()
    omissions: tuple[Omission, ...] = ()
    report_schema: int = 1

    def __post_init__(self) -> None:
        _require_enum("mode", self.mode, ScanMode)
        if type(self.block_severities) is not tuple or any(type(x) is not FindingSeverity for x in self.block_severities):
            raise TypeError("block_severities must be a tuple of FindingSeverity values")
        if len(set(self.block_severities)) != len(self.block_severities):
            raise ValueError("block_severities must not contain duplicates")
        if type(self.required_formats) is not tuple:
            raise TypeError("required_formats must be a tuple")
        for value in self.required_formats:
            _require_token("required_formats item", value)
        if len(set(self.required_formats)) != len(self.required_formats):
            raise ValueError("required_formats must not contain duplicates")
        if type(self.omissions) is not tuple or any(type(x) is not Omission for x in self.omissions):
            raise TypeError("omissions must be a tuple of Omission values")
        if len({item.id for item in self.omissions}) != len(self.omissions):
            raise ValueError("omission IDs must be unique")
        if type(self.report_schema) is not int or self.report_schema != 1:
            raise ValueError("report_schema must be 1")

    @classmethod
    def inventory(cls, *, required_formats: tuple[str, ...] = (), omissions: tuple[Omission, ...] = ()) -> ScanPolicy:
        return cls(ScanMode.INVENTORY, required_formats=required_formats, omissions=omissions)

    @classmethod
    def git(cls, *, required_formats: tuple[str, ...] = (), omissions: tuple[Omission, ...] = ()) -> ScanPolicy:
        return cls(ScanMode.GIT, required_formats=required_formats, omissions=omissions)


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Hard admission limits. Aggregate deadline and max_files are mandatory."""

    deadline_seconds: float
    max_files: int
    max_file_bytes: int = 20_971_520
    max_parts: int = 1_000
    max_text_bytes: int = 12_000_000
    max_member_bytes: int = 5_000_000
    max_archive_members: int = 10_000
    max_pages: int = 300
    extract_timeout_seconds: float = 25.0
    detector_timeout_seconds: float = 45.0
    max_findings: int = 100_000
    max_report_bytes: int = 64_000_000
    worker_memory_bytes: int = 512 * 1024 * 1024
    max_ipc_bytes: int = 80_000_000
    max_directory_entries: int = 10_000

    def __post_init__(self) -> None:
        for name in ("deadline_seconds", "extract_timeout_seconds", "detector_timeout_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        for name in (
            "max_files", "max_file_bytes", "max_parts", "max_text_bytes", "max_member_bytes",
            "max_archive_members", "max_pages", "max_findings", "max_report_bytes",
            "worker_memory_bytes", "max_ipc_bytes", "max_directory_entries",
        ):
            _require_positive_int(name, getattr(self, name))
        if self.max_report_bytes < 2_048:
            raise ValueError("max_report_bytes must be at least 2048")


@dataclass(frozen=True, slots=True)
class SourceRef:
    kind: SourceKind
    path: str
    repository: str | None = None
    commit: str | None = None
    blob_oid: str | None = None
    index_tree_oid: str | None = None

    def __post_init__(self) -> None:
        _require_enum("kind", self.kind, SourceKind)
        _require_bounded_provenance("path", self.path)
        _require_optional_bounded_provenance("repository", self.repository)
        for name in ("commit", "blob_oid", "index_tree_oid"):
            _require_optional_string(name, getattr(self, name))
        for name in ("commit", "blob_oid", "index_tree_oid"):
            value = getattr(self, name)
            if value is not None and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
                raise ValueError(f"{name} must be a full lowercase Git object ID or None")
        if self.kind in {SourceKind.FILESYSTEM, SourceKind.BYTES} and any(
            getattr(self, name) is not None for name in ("commit", "blob_oid", "index_tree_oid")
        ):
            raise ValueError("non-Git sources cannot include Git object IDs")
        if self.kind is SourceKind.GIT_INDEX and self.commit is not None:
            raise ValueError("index sources cannot include a commit ID")
        if self.kind is SourceKind.GIT_COMMIT and self.index_tree_oid is not None:
            raise ValueError("commit sources cannot include an index tree ID")


@dataclass(frozen=True, slots=True)
class ContentIdentity:
    algorithm: str
    digest: str
    size_bytes: int

    def __post_init__(self) -> None:
        if self.algorithm != "sha256":
            raise ValueError("algorithm must be sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", self.digest):
            raise ValueError("digest must be a lowercase SHA-256 hex digest")
        _require_nonnegative_int("size_bytes", self.size_bytes)


@dataclass(frozen=True, slots=True)
class RuntimeIdentity:
    policy_id: str
    runtime_id: str
    context_id: str
    cache_eligible: bool

    def __post_init__(self) -> None:
        for name in ("policy_id", "runtime_id", "context_id"):
            _require_nonempty(name, getattr(self, name))
        _require_bool("cache_eligible", self.cache_eligible)


@dataclass(frozen=True, slots=True)
class FindingRecord:
    id: str
    source: SourceRef
    part_id: str
    start_line: int
    end_line: int
    rule: str
    detector_id: str
    detector_severity: DetectorSeverity
    severity: FindingSeverity
    classification: FindingClassification
    proof_id: str | None = None

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.id):
            raise ValueError("id must be an opaque lowercase SHA-256 identifier")
        if type(self.source) is not SourceRef:
            raise TypeError("source must be a SourceRef")
        if not re.fullmatch(r"[a-z][a-z0-9-]*(?:-[1-9][0-9]*)?", self.part_id):
            raise ValueError("part_id must be a core-generated static token")
        _require_positive_int("start_line", self.start_line)
        _require_positive_int("end_line", self.end_line)
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,79}", self.rule):
            raise ValueError("rule must be a stable rule ID")
        _require_token("detector_id", self.detector_id)
        _require_enum("detector_severity", self.detector_severity, DetectorSeverity)
        _require_enum("severity", self.severity, FindingSeverity)
        _require_enum("classification", self.classification, FindingClassification)
        _require_optional_string("proof_id", self.proof_id)


@dataclass(frozen=True, slots=True)
class CoverageIssue:
    code: ErrorCode
    source: SourceRef | None = None
    part_id: str | None = None
    required: bool = False
    omission_id: str | None = None

    def __post_init__(self) -> None:
        _require_enum("code", self.code, ErrorCode)
        if self.source is not None and type(self.source) is not SourceRef:
            raise TypeError("source must be a SourceRef or None")
        if self.part_id is not None and not re.fullmatch(r"[a-z][a-z0-9-]*(?:-[1-9][0-9]*)?", self.part_id):
            raise ValueError("part_id must be a core-generated static token")
        _require_bool("required", self.required)
        _require_optional_string("omission_id", self.omission_id)


@dataclass(frozen=True, slots=True)
class ScanResult:
    source: SourceRef
    content: ContentIdentity | None
    identity: RuntimeIdentity
    outcome: ScanOutcome
    coverage: CoverageState
    findings: tuple[FindingRecord, ...]
    issues: tuple[CoverageIssue, ...]
    observed_at: datetime
    last_executed_at: datetime | None = None
    last_verified_at: datetime | None = None
    reused_from: str | None = None

    def __post_init__(self) -> None:
        if type(self.source) is not SourceRef:
            raise TypeError("source must be a SourceRef")
        if self.content is not None and type(self.content) is not ContentIdentity:
            raise TypeError("content must be a ContentIdentity or None")
        if type(self.identity) is not RuntimeIdentity:
            raise TypeError("identity must be a RuntimeIdentity")
        _require_enum("outcome", self.outcome, ScanOutcome)
        _require_enum("coverage", self.coverage, CoverageState)
        if type(self.findings) is not tuple or any(type(item) is not FindingRecord for item in self.findings):
            raise TypeError("findings must be a tuple of FindingRecord values")
        if type(self.issues) is not tuple or any(type(item) is not CoverageIssue for item in self.issues):
            raise TypeError("issues must be a tuple of CoverageIssue values")
        _require_utc_datetime("observed_at", self.observed_at)
        _require_optional_utc_datetime("last_executed_at", self.last_executed_at)
        _require_optional_utc_datetime("last_verified_at", self.last_verified_at)
        _require_optional_string("reused_from", self.reused_from)
        if self.last_executed_at is not None and self.last_executed_at > self.observed_at:
            raise ValueError("last_executed_at must not follow observed_at")
        if self.last_verified_at is not None and self.last_verified_at > self.observed_at:
            raise ValueError("last_verified_at must not follow observed_at")
        if (self.last_executed_at is not None and self.last_verified_at is not None
                and self.last_verified_at < self.last_executed_at):
            raise ValueError("last_verified_at must not precede last_executed_at")
        if any(finding.source != self.source for finding in self.findings):
            raise ValueError("finding source must match its containing result source")
        if self.coverage is CoverageState.COMPLETE and any(issue.required for issue in self.issues):
            raise ValueError("complete coverage cannot contain a required issue")
        if self.outcome is ScanOutcome.REUSED and not self.reused_from:
            raise ValueError("reused results require reused_from")
        if self.outcome is ScanOutcome.REUSED:
            if self.coverage is not CoverageState.COMPLETE:
                raise ValueError("reused results require complete coverage")
            if not self.identity.cache_eligible:
                raise ValueError("reused results require a cache-eligible identity")
            if self.last_executed_at is None or self.last_verified_at is None:
                raise ValueError("reused results require execution and verification timestamps")


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    enumeration_complete: bool
    required_complete: bool
    omission_count: int
    pending_files: int | None = None
    pending_directories: int | None = None
    cycle_id: str | None = None

    def __post_init__(self) -> None:
        _require_bool("enumeration_complete", self.enumeration_complete)
        _require_bool("required_complete", self.required_complete)
        _require_nonnegative_int("omission_count", self.omission_count)
        _require_optional_nonnegative_int("pending_files", self.pending_files)
        _require_optional_nonnegative_int("pending_directories", self.pending_directories)
        _require_optional_string("cycle_id", self.cycle_id)


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    verdict: DecisionVerdict
    reason_codes: tuple[ErrorCode, ...]
    policy_id: str

    def __post_init__(self) -> None:
        _require_enum("verdict", self.verdict, DecisionVerdict)
        if type(self.reason_codes) is not tuple or any(type(x) is not ErrorCode for x in self.reason_codes):
            raise TypeError("reason_codes must be a tuple of ErrorCode values")
        _require_nonempty("policy_id", self.policy_id)


@dataclass(frozen=True, slots=True)
class ScanCounts:
    results: int
    scanned: int
    reused: int
    skipped: int
    errors: int
    interrupted: int
    findings: int
    block_findings: int
    review_findings: int
    info_findings: int
    omitted_results: int
    incomplete_results: int
    issues: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    schema_version: int
    run_id: str
    started_at: datetime
    finished_at: datetime
    policy_id: str
    results: tuple[ScanResult, ...]
    coverage: CoverageSummary
    decision: PolicyDecision
    issues: tuple[CoverageIssue, ...] = ()

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        _require_nonempty("run_id", self.run_id)
        _require_utc_datetime("started_at", self.started_at)
        _require_utc_datetime("finished_at", self.finished_at)
        if self.finished_at < self.started_at:
            raise ValueError("finished_at must not precede started_at")
        _require_nonempty("policy_id", self.policy_id)
        if type(self.results) is not tuple or any(type(item) is not ScanResult for item in self.results):
            raise TypeError("results must be a tuple of ScanResult values")
        if type(self.coverage) is not CoverageSummary:
            raise TypeError("coverage must be a CoverageSummary")
        if type(self.decision) is not PolicyDecision:
            raise TypeError("decision must be a PolicyDecision")
        if self.decision.policy_id != self.policy_id:
            raise ValueError("decision policy_id must match the report")
        if any(result.identity.policy_id != self.policy_id for result in self.results):
            raise ValueError("result policy_id must match the report")
        if (not self.coverage.enumeration_complete or not self.coverage.required_complete) and self.decision.verdict is not DecisionVerdict.INCOMPLETE:
            raise ValueError("incomplete coverage requires an incomplete decision")
        if type(self.issues) is not tuple or any(type(item) is not CoverageIssue for item in self.issues):
            raise TypeError("issues must be a tuple of CoverageIssue values")
        expected_omissions = sum(
            not issue.required and issue.omission_id is not None for issue in self.issues
        )
        for result in self.results:
            expected_omissions += sum(
                not issue.required and issue.omission_id is not None for issue in result.issues
            )
            if result.coverage is CoverageState.OMITTED and not result.issues:
                expected_omissions += 1
        if self.coverage.omission_count != expected_omissions:
            raise ValueError("omission_count must match the report's typed omissions")
        if self.coverage.required_complete:
            if any(issue.required for issue in self.issues):
                raise ValueError("required-complete reports cannot contain required issues")
            if any(
                result.coverage is CoverageState.INCOMPLETE
                or any(issue.required for issue in result.issues)
                for result in self.results
            ):
                raise ValueError("required-complete reports cannot contain incomplete results")
            if (self.coverage.pending_files or 0) > 0 or (self.coverage.pending_directories or 0) > 0:
                raise ValueError("required-complete reports cannot have pending work")

    @property
    def counts(self) -> ScanCounts:
        """Counts are always derived from this report's immutable results."""
        outcomes = [result.outcome for result in self.results]
        findings = [finding for result in self.results for finding in result.findings]
        return ScanCounts(
            results=len(self.results),
            scanned=outcomes.count(ScanOutcome.SCANNED),
            reused=outcomes.count(ScanOutcome.REUSED),
            skipped=outcomes.count(ScanOutcome.SKIPPED),
            errors=outcomes.count(ScanOutcome.ERROR),
            interrupted=outcomes.count(ScanOutcome.INTERRUPTED),
            findings=len(findings),
            block_findings=sum(item.severity is FindingSeverity.BLOCK for item in findings),
            review_findings=sum(item.severity is FindingSeverity.REVIEW for item in findings),
            info_findings=sum(item.severity is FindingSeverity.INFO for item in findings),
            omitted_results=sum(item.coverage is CoverageState.OMITTED for item in self.results),
            incomplete_results=sum(item.coverage is CoverageState.INCOMPLETE for item in self.results),
            issues=len(self.issues) + sum(len(item.issues) for item in self.results),
        )

    def to_dict(self) -> dict[str, object]:
        return report_to_dict(self)

    def to_json(self) -> str:
        return report_to_json(self)


PublicModel: TypeAlias = (
    SourceRef | ContentIdentity | RuntimeIdentity | FindingRecord | CoverageIssue |
    ScanResult | CoverageSummary | PolicyDecision | ScanCounts | ScanReport
)


def report_to_dict(report: ScanReport) -> dict[str, object]:
    """Serialize only the public report model through an explicit allowlist."""
    if type(report) is not ScanReport:
        raise TypeError("report must be a ScanReport")
    return {
        "schema_version": report.schema_version,
        "run_id": report.run_id,
        "started_at": _format_datetime(report.started_at),
        "finished_at": _format_datetime(report.finished_at),
        "policy_id": report.policy_id,
        "results": [_result_dict(item) for item in report.results],
        "coverage": _coverage_summary_dict(report.coverage),
        "decision": _decision_dict(report.decision),
        "counts": _counts_dict(report.counts),
        "issues": [_issue_dict(item) for item in report.issues],
    }


def report_to_json(report: ScanReport) -> str:
    """Return stable UTF-8-safe JSON with no caller-supplied payloads.

    ``ensure_ascii`` preserves Git paths containing surrogateescaped bytes as
    valid JSON text that can be written to UTF-8 files and stdout.
    """
    return json.dumps(report_to_dict(report), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _source_dict(item: SourceRef) -> dict[str, object]:
    return {
        "kind": item.kind.value, "path": item.path, "repository": item.repository,
        "commit": item.commit, "blob_oid": item.blob_oid, "index_tree_oid": item.index_tree_oid,
    }


def _content_dict(item: ContentIdentity | None) -> dict[str, object] | None:
    if item is None:
        return None
    return {"algorithm": item.algorithm, "digest": item.digest, "size_bytes": item.size_bytes}


def _runtime_dict(item: RuntimeIdentity) -> dict[str, object]:
    return {
        "policy_id": item.policy_id, "runtime_id": item.runtime_id,
        "context_id": item.context_id, "cache_eligible": item.cache_eligible,
    }


def _finding_dict(item: FindingRecord) -> dict[str, object]:
    return {
        "id": item.id, "source": _source_dict(item.source), "part_id": item.part_id,
        "start_line": item.start_line, "end_line": item.end_line, "rule": item.rule,
        "detector_id": item.detector_id, "detector_severity": item.detector_severity.value,
        "severity": item.severity.value, "classification": item.classification.value,
        "proof_id": item.proof_id,
    }


def _issue_dict(item: CoverageIssue) -> dict[str, object]:
    return {
        "code": item.code.value, "source": _source_dict(item.source) if item.source else None,
        "part_id": item.part_id, "required": item.required, "omission_id": item.omission_id,
    }


def _result_dict(item: ScanResult) -> dict[str, object]:
    return {
        "source": _source_dict(item.source), "content": _content_dict(item.content),
        "identity": _runtime_dict(item.identity), "outcome": item.outcome.value,
        "coverage": item.coverage.value,
        "findings": [_finding_dict(finding) for finding in item.findings],
        "issues": [_issue_dict(issue) for issue in item.issues],
        "observed_at": _format_datetime(item.observed_at),
        "last_executed_at": _format_datetime(item.last_executed_at) if item.last_executed_at else None,
        "last_verified_at": _format_datetime(item.last_verified_at) if item.last_verified_at else None,
        "reused_from": item.reused_from,
    }


def _coverage_summary_dict(item: CoverageSummary) -> dict[str, object]:
    return {
        "enumeration_complete": item.enumeration_complete,
        "required_complete": item.required_complete,
        "omission_count": item.omission_count, "pending_files": item.pending_files,
        "pending_directories": item.pending_directories, "cycle_id": item.cycle_id,
    }


def _decision_dict(item: PolicyDecision) -> dict[str, object]:
    return {
        "verdict": item.verdict.value,
        "reason_codes": [code.value for code in item.reason_codes],
        "policy_id": item.policy_id,
    }


def _counts_dict(item: ScanCounts) -> dict[str, object]:
    return {
        "results": item.results, "scanned": item.scanned, "reused": item.reused,
        "skipped": item.skipped, "errors": item.errors, "interrupted": item.interrupted,
        "findings": item.findings, "block_findings": item.block_findings,
        "review_findings": item.review_findings, "info_findings": item.info_findings,
        "omitted_results": item.omitted_results, "incomplete_results": item.incomplete_results,
        "issues": item.issues,
    }


def _format_datetime(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_enum(name: str, value: object, enum_type: type[Enum]) -> None:
    if type(value) is not enum_type:
        raise TypeError(f"{name} must be a {enum_type.__name__}")


def _require_nonempty(name: str, value: object) -> None:
    if not isinstance(value, str) or not value:
        raise TypeError(f"{name} must be a nonempty string")


def _require_bounded_provenance(name: str, value: object) -> None:
    _require_nonempty(name, value)
    if len(value) > MAX_PROVENANCE_STRING_LENGTH or "\x00" in value:
        raise ValueError(f"{name} must be a bounded path without NUL")


def _require_optional_bounded_provenance(name: str, value: object) -> None:
    if value is not None:
        _require_bounded_provenance(name, value)


def _require_optional_string(name: str, value: object) -> None:
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{name} must be a string or None")


def _require_token(name: str, value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,79}", value):
        raise ValueError(f"{name} must be a stable lowercase token")


def _require_bool(name: str, value: object) -> None:
    if type(value) is not bool:
        raise TypeError(f"{name} must be a bool")


def _require_positive_int(name: str, value: object) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _require_nonnegative_int(name: str, value: object) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


def _require_optional_nonnegative_int(name: str, value: object) -> None:
    if value is not None:
        _require_nonnegative_int(name, value)


def _require_utc_datetime(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timezone.utc.utcoffset(value):
        raise ValueError(f"{name} must be a timezone-aware UTC datetime")


def _require_optional_utc_datetime(name: str, value: object) -> None:
    if value is not None:
        _require_utc_datetime(name, value)
