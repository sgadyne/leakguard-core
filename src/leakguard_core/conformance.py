"""Reusable, redacted conformance cases and reports for LeakGuard extensions.

Case inputs are supplied by the extension author. Reports deliberately contain
only static case/check identifiers and closed result codes; they never serialize
case text, input bytes, options, plugin output, or exception messages.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import argparse
import base64
import hashlib
import json
import math
import os
import re
from pathlib import Path
import stat
import sys
from typing import Mapping, Sequence


_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,63}\Z", re.ASCII)
_COMPONENT_TOKEN = re.compile(r"[a-z][a-z0-9-]{0,79}\Z", re.ASCII)
_RULE = re.compile(r"[a-z][a-z0-9-]{0,79}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z", re.ASCII)
_CONFORMANCE_TIMEOUT_SECONDS = 10.0
_MAX_DETECTOR_TEXT_BYTES = 12_000_000
_MAX_EXTRACTOR_INPUT_BYTES = 20_971_520
_MAX_CASES = 1000
_EXTRACTION_CODES = frozenset({
    "input-limit", "unsupported-format", "format-mismatch", "ambiguous-format",
    "decode-failed", "encrypted", "no-text", "dependency-unavailable", "extract-failed",
    "extract-timeout", "extract-crashed", "extract-output-limit", "extract-part-limit",
    "resource-bound-unavailable", "worker-memory-limit", "cancelled",
})


class ConformanceKind(str, Enum):
    DETECTOR = "detector"
    EXTRACTOR = "extractor"


class ConformanceCode(str, Enum):
    CASE_INVALID = "case-invalid"
    CASE_MISMATCH = "case-mismatch"
    COMPONENT_INVALID = "component-invalid"
    DEPENDENCY_UNAVAILABLE = "dependency-unavailable"
    PLUGIN_INVALID = "plugin-invalid"
    PLUGIN_TIMEOUT = "plugin-timeout"
    PLUGIN_CRASHED = "plugin-crashed"
    DETECTOR_OUTPUT_INVALID = "detector-output-invalid"
    EXTRACTOR_OUTPUT_INVALID = "extractor-output-invalid"
    SETUP_FAILED = "setup-failed"


def _token(value: str, label: str) -> None:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise ValueError(label)


def _component_token(value: str) -> None:
    if type(value) is not str or not _COMPONENT_TOKEN.fullmatch(value):
        raise ValueError("component-invalid")


def _validated_options(options: Mapping) -> dict:
    """Admit only bounded JSON values before passing options to a worker."""
    if not isinstance(options, Mapping):
        raise ValueError("case-invalid")
    value = dict(options)
    pending = [(value, 0)]
    seen = 0
    while pending:
        item, depth = pending.pop()
        seen += 1
        if seen > 100_000 or depth > 32:
            raise ValueError("case-invalid")
        if type(item) is dict:
            for key, nested in item.items():
                if type(key) is not str:
                    raise ValueError("case-invalid")
                pending.append((nested, depth + 1))
        elif type(item) is list:
            pending.extend((nested, depth + 1) for nested in item)
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("case-invalid")
        elif type(item) not in {str, int, bool, type(None)}:
            raise ValueError("case-invalid")
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 1_048_576:
        raise ValueError("case-invalid")
    return value


@dataclass(frozen=True)
class ExpectedFinding:
    rule: str
    start_line: int
    end_line: int
    severity: str

    def __post_init__(self):
        if type(self.rule) is not str or not _RULE.fullmatch(self.rule):
            raise ValueError("case-invalid")
        if type(self.start_line) is not int or type(self.end_line) is not int:
            raise ValueError("case-invalid")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("case-invalid")
        if type(self.severity) is not str or self.severity not in {"block", "review"}:
            raise ValueError("case-invalid")


@dataclass(frozen=True)
class DetectorCase:
    case_id: str
    text: str = field(repr=False)
    logical_path: str
    format_id: str
    part_id: str
    expected_findings: tuple[ExpectedFinding, ...] = ()

    def __post_init__(self):
        _token(self.case_id, "case-invalid")
        if (type(self.text) is not str or len(self.text.encode("utf-8")) > _MAX_DETECTOR_TEXT_BYTES
                or type(self.logical_path) is not str or not self.logical_path
                or len(self.logical_path) > 4096):
            raise ValueError("case-invalid")
        _token(self.format_id, "case-invalid")
        _token(self.part_id, "case-invalid")
        if type(self.expected_findings) is not tuple or any(
            type(item) is not ExpectedFinding for item in self.expected_findings
        ):
            raise ValueError("case-invalid")


@dataclass(frozen=True)
class ExpectedPart:
    part_id: str
    text_sha256: str
    line_count: int

    def __post_init__(self):
        _token(self.part_id, "case-invalid")
        if type(self.text_sha256) is not str or not _SHA256.fullmatch(self.text_sha256):
            raise ValueError("case-invalid")
        if type(self.line_count) is not int or self.line_count < 0:
            raise ValueError("case-invalid")

    @classmethod
    def from_text(cls, part_id: str, text: str) -> "ExpectedPart":
        if type(text) is not str:
            raise ValueError("case-invalid")
        return cls(part_id, hashlib.sha256(text.encode("utf-8")).hexdigest(), _line_count(text))


def _line_count(text: str) -> int:
    # Empty text has no lines; a final newline does not create an extra line.
    return 0 if not text else text.count("\n") + (0 if text.endswith("\n") else 1)


@dataclass(frozen=True)
class ExtractorCase:
    case_id: str
    data: bytes = field(repr=False)
    logical_path: str
    expected_format: str
    expected_disposition: str
    expected_parts: tuple[ExpectedPart, ...] = ()
    expected_issues: tuple[str, ...] = ()

    def __post_init__(self):
        _token(self.case_id, "case-invalid")
        if (type(self.data) is not bytes or len(self.data) > _MAX_EXTRACTOR_INPUT_BYTES
                or type(self.logical_path) is not str or not self.logical_path
                or len(self.logical_path) > 4096):
            raise ValueError("case-invalid")
        _token(self.expected_format, "case-invalid")
        if type(self.expected_disposition) is not str or self.expected_disposition not in {"extracted", "unsupported", "encrypted", "no-text"}:
            raise ValueError("case-invalid")
        if type(self.expected_parts) is not tuple or len(self.expected_parts) > 1000 or any(
            type(item) is not ExpectedPart for item in self.expected_parts
        ):
            raise ValueError("case-invalid")
        if type(self.expected_issues) is not tuple or len(self.expected_issues) > 100 or any(
            type(code) is not str or code not in _EXTRACTION_CODES for code in self.expected_issues
        ):
            raise ValueError("case-invalid")


@dataclass(frozen=True)
class ConformanceIssue:
    check_id: str
    code: ConformanceCode
    case_id: str | None = None

    def __post_init__(self):
        _token(self.check_id, "case-invalid")
        if type(self.code) is not ConformanceCode:
            raise TypeError("code")
        if self.case_id is not None:
            _token(self.case_id, "case-invalid")


@dataclass(frozen=True)
class ConformanceReport:
    component_id: str
    kind: ConformanceKind
    total_cases: int
    passed_cases: int
    failed_cases: int
    skipped_cases: int
    issues: tuple[ConformanceIssue, ...] = ()

    def __post_init__(self):
        _component_token(self.component_id)
        if type(self.kind) is not ConformanceKind:
            raise TypeError("kind")
        values = (self.total_cases, self.passed_cases, self.failed_cases, self.skipped_cases)
        if any(type(value) is not int or value < 0 for value in values):
            raise ValueError("case-invalid")
        if self.total_cases != self.passed_cases + self.failed_cases + self.skipped_cases:
            raise ValueError("case-invalid")
        if type(self.issues) is not tuple or len(self.issues) > _MAX_CASES + 1 or any(type(issue) is not ConformanceIssue for issue in self.issues):
            raise ValueError("case-invalid")

    @property
    def passed(self) -> bool:
        return self.failed_cases == 0 and not self.issues

    def to_dict(self) -> dict:
        return {
            "component_id": self.component_id,
            "kind": self.kind.value,
            "total_cases": self.total_cases,
            "passed_cases": self.passed_cases,
            "failed_cases": self.failed_cases,
            "skipped_cases": self.skipped_cases,
            "passed": self.passed,
            "issues": [
                {"check_id": item.check_id, "code": item.code.value, "case_id": item.case_id}
                for item in self.issues
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def check_detector(module: str, options: Mapping, cases: Sequence[DetectorCase], *, worker_policy='strict') -> ConformanceReport:
    """Check an explicitly configured detector through the core plugin adapter.

    Adapter execution is deliberately delegated to the core plugin worker; this
    module never imports an extension or invokes extension code itself.
    """
    return _check_component(ConformanceKind.DETECTOR, module, options, cases, worker_policy=worker_policy)


def check_extractor(module: str, options: Mapping, cases: Sequence[ExtractorCase], *, worker_policy='strict') -> ConformanceReport:
    """Check an explicitly configured extractor through the core plugin adapter."""
    return _check_component(ConformanceKind.EXTRACTOR, module, options, cases, worker_policy=worker_policy)


def _check_component(kind: ConformanceKind, module: str, options: Mapping, cases: Sequence, *, worker_policy='strict') -> ConformanceReport:
    # This thin bridge intentionally depends on the public core registry contract
    # that owns supervised loading, manifest validation and output sanitization.
    try:
        if type(worker_policy) is not str or worker_policy not in {'strict', 'supervised-alpha'}:
            raise ValueError
        if type(module) is not str or len(module) > 240 or not _MODULE.fullmatch(module):
            raise ValueError
        normalized_options = _validated_options(options)
        if not isinstance(cases, Sequence) or isinstance(cases, (str, bytes)):
            raise ValueError
        normalized_cases = tuple(cases)
        if len(normalized_cases) > _MAX_CASES:
            raise ValueError
        if not normalized_cases:
            raise ValueError
        expected_type = DetectorCase if kind is ConformanceKind.DETECTOR else ExtractorCase
        if any(type(case) is not expected_type for case in normalized_cases):
            raise ValueError
        if len({case.case_id for case in normalized_cases}) != len(normalized_cases):
            raise ValueError
    except Exception:
        return ConformanceReport(
            component_id="invalid-component", kind=kind, total_cases=0,
            passed_cases=0, failed_cases=0, skipped_cases=0,
            issues=(ConformanceIssue("setup", ConformanceCode.CASE_INVALID),),
        )

    loaded = ()
    try:
        from . import plugins
        try:
            loaded = plugins.load([{"module": module, "options": normalized_options}], worker_policy=worker_policy)
        except plugins.PluginError as error:
            count = len(normalized_cases)
            issue = _plugin_issue(error.code, "component-load", None, kind)
            return ConformanceReport(
                component_id="configured-component", kind=kind, total_cases=count,
                passed_cases=0, failed_cases=count, skipped_cases=0, issues=(issue,),
            )
        if len(loaded) != 1:
            raise ValueError
        handle = loaded[0]
        manifest = getattr(handle, "manifest", None)
        component_id = manifest.id if manifest is not None else "legacy-plugin"
        if manifest is not None and manifest.kind != kind.value:
            count = len(normalized_cases)
            return ConformanceReport(
                component_id=component_id, kind=kind, total_cases=count,
                passed_cases=0, failed_cases=count, skipped_cases=0,
                issues=(ConformanceIssue("component-kind", ConformanceCode.COMPONENT_INVALID),),
            )
        if kind is ConformanceKind.DETECTOR:
            return _check_detector_loaded(plugins, handle, component_id, normalized_cases, worker_policy=worker_policy)
        return _check_extractor_loaded(plugins, handle, component_id, normalized_cases, worker_policy=worker_policy)
    except Exception:
        # Never surface an extension exception, option, input, or traceback.
        count = len(normalized_cases)
        return ConformanceReport(
            component_id="configured-component", kind=kind, total_cases=count,
            passed_cases=0, failed_cases=count, skipped_cases=0,
            issues=(ConformanceIssue("setup", ConformanceCode.SETUP_FAILED),),
        )
    finally:
        if loaded:
            plugins.close(loaded)


def _plugin_issue(code: str, check_id: str, case_id: str | None,
                  kind: ConformanceKind) -> ConformanceIssue:
    if code == "plugin-timeout":
        fixed = ConformanceCode.PLUGIN_TIMEOUT
    elif code == "plugin-crashed":
        fixed = ConformanceCode.PLUGIN_CRASHED
    elif code == "resource-bound-unavailable":
        fixed = ConformanceCode.DEPENDENCY_UNAVAILABLE
    elif code == "dependency-unavailable":
        fixed = ConformanceCode.DEPENDENCY_UNAVAILABLE
    elif code in {"detector-output-invalid", "detector-output-limit"}:
        fixed = ConformanceCode.DETECTOR_OUTPUT_INVALID
    elif code in {"extract-output-limit", "extract-part-limit", "extractor-output-invalid"}:
        fixed = ConformanceCode.EXTRACTOR_OUTPUT_INVALID
    elif code == "plugin-invalid":
        # A loaded component that violates its manifest/API is a contract
        # failure (exit 1), including during its initial inspection.
        fixed = ConformanceCode.COMPONENT_INVALID
    elif code == "component-invalid":
        fixed = ConformanceCode.COMPONENT_INVALID
    elif code == "cancelled":
        fixed = ConformanceCode.SETUP_FAILED
    else:
        fixed = ConformanceCode.SETUP_FAILED
    return ConformanceIssue(check_id, fixed, case_id)


def _check_detector_loaded(plugins, handle, component_id: str,
                          cases: tuple[DetectorCase, ...], *, worker_policy=None) -> ConformanceReport:
    issues = []
    passed = 0
    for case in cases:
        try:
            actual = tuple(plugins.detect(
                [handle], case.text, case.logical_path, case.part_id,
                format_id=case.format_id, timeout=_CONFORMANCE_TIMEOUT_SECONDS,
                **({'worker_policy': worker_policy} if worker_policy is not None else {}),
            ))
            actual_rows = tuple(sorted((item.rule, item.line, item.line, item.severity) for item in actual))
            expected_rows = tuple(sorted(
                (item.rule, item.start_line, item.end_line, item.severity)
                for item in case.expected_findings
            ))
            if actual_rows == expected_rows:
                passed += 1
            else:
                issues.append(ConformanceIssue("case-match", ConformanceCode.CASE_MISMATCH, case.case_id))
        except plugins.PluginError as error:
            issues.append(_plugin_issue(error.code, "case-run", case.case_id, ConformanceKind.DETECTOR))
        except Exception:
            issues.append(ConformanceIssue("case-run", ConformanceCode.SETUP_FAILED, case.case_id))
    failed = len(cases) - passed
    return ConformanceReport(component_id, ConformanceKind.DETECTOR, len(cases), passed, failed, 0,
                             tuple(issues))


def _check_extractor_loaded(plugins, handle, component_id: str,
                            cases: tuple[ExtractorCase, ...], *, worker_policy=None) -> ConformanceReport:
    """Use the registry's disposition-aware helper, added with plugin SDK support."""
    runner = getattr(plugins, "extract_component", None)
    if not callable(runner):
        return ConformanceReport(
            component_id, ConformanceKind.EXTRACTOR, len(cases), 0, len(cases), 0,
            (ConformanceIssue("extractor-api", ConformanceCode.COMPONENT_INVALID),),
        )
    from .extraction import ExtractionLimits
    issues = []
    passed = 0
    for case in cases:
        try:
            result = runner(handle, case.data, case.logical_path,
                            format_id=case.expected_format, limits=ExtractionLimits(),
                            timeout=_CONFORMANCE_TIMEOUT_SECONDS,
                            **({'worker_policy': worker_policy} if worker_policy is not None else {}))
            parts = tuple(ExpectedPart.from_text(part.part_id, part.text) for part in result.parts)
            matched = (
                result.format_id == case.expected_format
                and result.disposition == case.expected_disposition
                and parts == case.expected_parts
                and tuple(result.issues) == case.expected_issues
            )
            if matched:
                passed += 1
            else:
                issues.append(ConformanceIssue("case-match", ConformanceCode.CASE_MISMATCH, case.case_id))
        except Exception as error:
            # Read only a fixed code attribute from core exceptions; never stringify.
            code = getattr(error, "code", "setup-failed")
            issues.append(_plugin_issue(code, "case-run", case.case_id, ConformanceKind.EXTRACTOR))
    return ConformanceReport(component_id, ConformanceKind.EXTRACTOR, len(cases), passed,
                             len(cases) - passed, 0, tuple(issues))


class _CliSetupError(Exception):
    """Internal marker for a safe CLI setup failure."""


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        del message
        raise _CliSetupError


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _read_json(path: str, maximum: int):
    descriptor = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError
        return json.loads(raw, object_pairs_hook=_object, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except Exception:
        raise _CliSetupError from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _required_keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError
    return value


def _detector_cases(value):
    if type(value) is not dict or set(value) != {"cases"} or type(value["cases"]) is not list:
        raise ValueError
    cases = []
    for raw in value["cases"]:
        if type(raw) is not dict:
            raise ValueError
        allowed = {"case_id", "text", "logical_path", "format_id", "part_id", "expected_findings"}
        if not {"case_id", "text", "logical_path", "format_id", "part_id"} <= set(raw) <= allowed:
            raise ValueError
        findings = raw.get("expected_findings", [])
        if type(findings) is not list:
            raise ValueError
        expected = []
        for item in findings:
            _required_keys(item, {"rule", "start_line", "end_line", "severity"})
            expected.append(ExpectedFinding(**item))
        cases.append(DetectorCase(
            case_id=raw["case_id"], text=raw["text"], logical_path=raw["logical_path"],
            format_id=raw["format_id"], part_id=raw["part_id"], expected_findings=tuple(expected),
        ))
    return tuple(cases)


def _extractor_cases(value):
    if type(value) is not dict or set(value) != {"cases"} or type(value["cases"]) is not list:
        raise ValueError
    cases = []
    for raw in value["cases"]:
        if type(raw) is not dict:
            raise ValueError
        required = {"case_id", "data_base64", "logical_path", "expected_format", "expected_disposition"}
        allowed = required | {"expected_parts", "expected_issues"}
        if not required <= set(raw) <= allowed or type(raw["data_base64"]) is not str:
            raise ValueError
        try:
            data = base64.b64decode(raw["data_base64"], validate=True)
        except Exception:
            raise ValueError from None
        parts = raw.get("expected_parts", [])
        issues = raw.get("expected_issues", [])
        if type(parts) is not list or type(issues) is not list:
            raise ValueError
        expected_parts = []
        for item in parts:
            _required_keys(item, {"part_id", "text_sha256", "line_count"})
            expected_parts.append(ExpectedPart(**item))
        cases.append(ExtractorCase(
            case_id=raw["case_id"], data=data, logical_path=raw["logical_path"],
            expected_format=raw["expected_format"], expected_disposition=raw["expected_disposition"],
            expected_parts=tuple(expected_parts), expected_issues=tuple(issues),
        ))
    return tuple(cases)


def _failure_report(kind: ConformanceKind, code: ConformanceCode) -> ConformanceReport:
    return ConformanceReport(
        component_id="invalid-component", kind=kind, total_cases=0,
        passed_cases=0, failed_cases=0, skipped_cases=0,
        issues=(ConformanceIssue("setup", code),),
    )


def _exit_status(report: ConformanceReport) -> int:
    if any(issue.code in {ConformanceCode.SETUP_FAILED,
                          ConformanceCode.DEPENDENCY_UNAVAILABLE,
                          ConformanceCode.CASE_INVALID}
           for issue in report.issues):
        return 2
    return 0 if report.passed else 1


def main(argv=None) -> int:
    """Run author-provided JSON cases against one explicitly named plugin.

    Detector case files contain a `cases` array with case_id, text,
    logical_path, format_id, part_id and optional expected_findings. Extractor
    files use data_base64 plus expected_format/disposition and optional
    expected_parts (part_id, text_sha256, line_count) and expected_issues.
    `--options` names a JSON object file. Only the redacted report is written.
    """
    kind = ConformanceKind.DETECTOR
    parser = _ArgumentParser(prog="python -m leakguard_core.conformance")
    parser.add_argument("--kind", required=True, choices=[item.value for item in ConformanceKind])
    parser.add_argument("--module", required=True, help="explicit component import path")
    parser.add_argument("--cases", required=True, help="author case JSON file")
    parser.add_argument("--options", help="optional JSON object file for component options")
    parser.add_argument("--worker-policy", choices=("strict", "supervised-alpha"), default="strict")
    try:
        args = parser.parse_args(argv)
        kind = ConformanceKind(args.kind)
        case_data = _read_json(args.cases, 64 * 1024 * 1024)
        options = _read_json(args.options, 1 * 1024 * 1024) if args.options else {}
        if type(options) is not dict:
            raise _CliSetupError
        cases = _detector_cases(case_data) if kind is ConformanceKind.DETECTOR else _extractor_cases(case_data)
        report = (check_detector(args.module, options, cases, worker_policy=args.worker_policy) if kind is ConformanceKind.DETECTOR
                  else check_extractor(args.module, options, cases, worker_policy=args.worker_policy))
    except SystemExit as error:
        # argparse's built-in help is static, successful output rather than a
        # machine-readable run receipt. Keep its standard exit-0 behavior.
        if error.code == 0:
            return 0
        report = _failure_report(kind, ConformanceCode.SETUP_FAILED)
    except _CliSetupError:
        report = _failure_report(kind, ConformanceCode.SETUP_FAILED)
    except (ValueError, TypeError, KeyError, OverflowError):
        report = _failure_report(kind, ConformanceCode.CASE_INVALID)
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, GeneratorExit)):
            report = _failure_report(kind, ConformanceCode.SETUP_FAILED)
        else:
            report = _failure_report(kind, ConformanceCode.SETUP_FAILED)
    sys.stdout.write(report.to_json() + "\n")
    return _exit_status(report)


if __name__ == "__main__":
    raise SystemExit(main())
