"""Compact terminal/chat summaries of sanitized reports; never read source values."""
import collections
import datetime
import json
import ntpath
import pathlib
import re
import subprocess

from .models import DecisionVerdict, ErrorCode, ScanReport, SourceKind, SourceRef


MAX_FINDINGS_PAGE_SIZE = 10_000
MAX_FINDINGS_CURSOR_LENGTH = 1_024


def sanitized_report(report):
    if type(report) is ScanReport:
        return report.to_dict()
    if type(report) is not dict:
        raise TypeError("report must be a typed or legacy report")
    result = {"legacy_schema": 0, "coverage": "unknown"}
    checked = report.get("checked_utc")
    if isinstance(checked, str) and len(checked) <= 64:
        try:
            result["checked_utc"] = _public_timestamp(checked)
        except ValueError:
            pass
    repository = report.get("repo")
    if isinstance(repository, str) and len(repository) <= 4096:
        result["repo"] = repository
    result["findings"] = [_sanitize_legacy_finding(item) for item in report.get("findings", []) if type(item) is dict]
    stable_codes = {item.value for item in ErrorCode} | {"error-directory"}
    issues = []
    for issue in report.get("coverage_issues", []):
        if type(issue) is not dict:
            continue
        path = issue.get("path")
        if not isinstance(path, str) or len(path) > 4096:
            path = "scan"
        status = issue.get("status")
        if not isinstance(status, str) or status not in stable_codes:
            status = "coverage-unknown"
        issues.append({"path": path, "status": status})
    result["coverage_issues"] = issues
    return result


def _sanitize_legacy_finding(finding):
    path = finding.get("path")
    if not isinstance(path, str) or len(path) > 4096:
        path = "unknown"
    line = finding.get("line")
    if type(line) is not int or line <= 0:
        line = 1
    end_line = finding.get("end_line")
    if type(end_line) is not int or end_line < line:
        end_line = line
    rule = finding.get("rule")
    if not isinstance(rule, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", rule) is None:
        rule = "unknown-rule"
    severity = finding.get("severity")
    if not isinstance(severity, str) or severity not in {"block", "review", "info"}:
        severity = "review"
    commit = finding.get("commit")
    if not isinstance(commit, str) or re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", commit) is None:
        commit = None
    return {"path": path, "line": line, "end_line": end_line, "rule": rule,
            "severity": severity, "commit": commit}


def clean(value):
    text = re.sub(r'[\x00-\x1f\x7f\x1b]', '?', str(value))
    return text.encode('utf-8', 'backslashreplace').decode('utf-8')


def render(report, report_path=None, limit=20):
    if type(report) is ScanReport:
        return render_scan_report(report, report_path=report_path, limit=limit)
    report = sanitized_report(report)
    findings = report['findings']; issues = report['coverage_issues']
    counts = collections.Counter(f.get('severity', 'review') for f in findings)
    blocked = bool(counts['block'])
    title = 'BLOCKED' if blocked else 'INCOMPLETE (coverage unknown)'
    lines = [f"LeakGuard legacy report: {title} ({counts['block']} blocking, {counts['review']} review, {counts['info']} informational)"]
    lines.append('Coverage: unknown (schema-0 report)')
    repo = report.get('repo')
    for finding in findings[:limit]:
        path = finding['path']
        if repo:
            try:
                relative = ntpath.relpath(path, repo)
                if relative != '..' and not relative.startswith('..\\'):
                    path = relative.replace('\\', '/')
            except ValueError:
                pass
        revision = finding.get('commit')
        version = revision[:12] if revision else 'commit not recorded'
        lines.append(f"  {clean(path)}:{finding['line']}  [{clean(version)}]  {clean(finding['severity'])}  rule={clean(finding['rule'])}")
    if len(findings) > limit:
        lines.append(f'  ... {len(findings) - limit} more findings in the report')
    for issue in issues[:limit]:
        lines.append(f"  {clean(issue.get('path', 'scan'))}: {clean(issue.get('status', 'incomplete scan'))}")
    if report_path:
        lines.append('Report: ' + clean(report_path))
    if blocked:
        lines.append('LeakGuard blocked this Git operation. Review the private report; values are redacted.')
    return '\n'.join(lines)


def render_scan_report(report: ScanReport, report_path=None, limit=20):
    """Render the service result without making or weakening policy decisions."""
    if type(report) is not ScanReport:
        raise TypeError("report must be a ScanReport")
    verdict_titles = {
        DecisionVerdict.ALLOW: "ALLOW",
        DecisionVerdict.ALLOW_WITH_OMISSIONS: "ALLOW WITH OMISSIONS",
        DecisionVerdict.BLOCK: "BLOCKING FINDINGS",
        DecisionVerdict.INCOMPLETE: "INCOMPLETE",
    }
    counts = report.counts
    lines = [
        f"LeakGuard scan {clean(report.run_id)}: {verdict_titles[report.decision.verdict]} "
        f"({counts.block_findings} blocking, {counts.review_findings} review, "
        f"{counts.info_findings} informational; {counts.results} inputs)"
    ]
    lines.append(
        f"Coverage: {'complete' if report.coverage.enumeration_complete else 'incomplete'} enumeration, "
        f"{'required surfaces complete' if report.coverage.required_complete else 'required surfaces incomplete'}, "
        f"{report.coverage.omission_count} omissions"
    )
    if report.coverage.pending_files is not None or report.coverage.pending_directories is not None:
        lines.append(
            f"Pending: {report.coverage.pending_files if report.coverage.pending_files is not None else 'unknown'} files, "
            f"{report.coverage.pending_directories if report.coverage.pending_directories is not None else 'unknown'} directories"
        )
    findings = [finding for result in report.results for finding in result.findings]
    for finding in findings[:limit]:
        location = f"{finding.source.path}:{finding.start_line}"
        if finding.end_line != finding.start_line:
            location += f"-{finding.end_line}"
        source_version = finding.source.commit
        if source_version:
            location += f" [{clean(source_version[:12])}]"
        if finding.part_id != "text":
            location += f" part={clean(finding.part_id)}"
        lines.append(
            f"  {clean(location)}  [{finding.severity.value}] {clean(finding.rule)} "
            f"({clean(finding.classification.value)})"
        )
    if len(findings) > limit:
        lines.append(f"  ... {len(findings) - limit} more findings in the structured report")
    issues = [issue for result in report.results for issue in result.issues] + list(report.issues)
    for issue in issues[:limit]:
        location = issue.source.path if issue.source else "scan"
        if issue.part_id:
            location += f" part={issue.part_id}"
        requirement = "required" if issue.required else "omitted"
        lines.append(f"  {clean(location)}: {clean(issue.code.value)} ({requirement})")
    if report_path:
        lines.append("Report: " + clean(report_path))
    if report.decision.verdict is DecisionVerdict.BLOCK:
        lines.append("Blocking findings are present; finding values remain redacted.")
    return '\n'.join(lines)


def findings_report_to_dict(state, profile, rows):
    """Compatibility schema-1 envelope for direct, already bounded rows."""
    if state not in {"current", "history"}:
        raise ValueError("invalid finding state")
    if profile not in {"general", "companion", "all"}:
        raise ValueError("invalid finding profile")
    if type(rows) not in {tuple, list}:
        raise TypeError("finding rows must be a tuple or list")
    if len(rows) > MAX_FINDINGS_PAGE_SIZE:
        raise ValueError("findings report exceeds the public bound")
    findings = [_public_finding_row(row) for row in rows]
    findings.sort(key=lambda row: (
        row["source"]["path"], row["start_line"], row["rule"], row["id"]
    ))
    return {
        "schema_version": 1,
        "report_type": "findings",
        "state": state,
        "profile": profile,
        "count": len(findings),
        "findings": findings,
    }


def findings_page_report_to_dict(state, profile, rows, *, has_more, next_cursor):
    """Serialize one bounded indexed page; the envelope version is independent of ScanReport."""
    if state not in {"current", "history"}:
        raise ValueError("invalid finding state")
    if profile not in {"general", "companion", "all"}:
        raise ValueError("invalid finding profile")
    if type(rows) not in {tuple, list}:
        raise TypeError("finding rows must be a tuple or list")
    if len(rows) > MAX_FINDINGS_PAGE_SIZE:
        raise ValueError("findings page exceeds the public bound")
    if type(has_more) is not bool:
        raise TypeError("has_more must be a boolean")
    if has_more:
        if not isinstance(next_cursor, str) or re.fullmatch(r"[A-Za-z0-9._~-]{1,1024}", next_cursor) is None:
            raise ValueError("invalid continuation cursor")
    elif next_cursor is not None:
        raise ValueError("cursor must be absent at the end of a page")
    # Preserve the indexed store's cursor order. Sorting here could skip or repeat rows.
    findings = [_public_finding_row(row) for row in rows]
    return {
        "schema_version": 2,
        "report_type": "findings-page",
        "state": state,
        "profile": profile,
        "page_count": len(findings),
        "has_more": has_more,
        "next_cursor": next_cursor,
        "findings": findings,
    }


def render_findings_report(report, limit=50):
    """Render a closed findings report without claiming a scan was clean."""
    old_expected = {"schema_version", "report_type", "state", "profile", "count", "findings"}
    page_expected = {"schema_version", "report_type", "state", "profile", "page_count", "has_more", "next_cursor", "findings"}
    if type(report) is not dict:
        raise TypeError("report must be a public findings report")
    version = report.get("schema_version")
    if type(version) is not int:
        raise TypeError("report must be a public findings report")
    if version == 1 and report.get("report_type") == "findings":
        is_page = False
        expected = old_expected
    elif version == 2 and report.get("report_type") == "findings-page":
        is_page = True
        expected = page_expected
    else:
        raise TypeError("report must be a public findings report")
    if set(report) != expected or report["report_type"] != ("findings-page" if is_page else "findings"):
        raise TypeError("report must be a public findings report")
    if report["state"] not in {"current", "history"} or report["profile"] not in {"general", "companion", "all"}:
        raise ValueError("invalid findings report")
    findings = report["findings"]
    count_key = "page_count" if is_page else "count"
    if (type(findings) is not list or len(findings) > MAX_FINDINGS_PAGE_SIZE or
            type(report[count_key]) is not int or report[count_key] != len(findings)):
        raise ValueError("invalid findings report")
    if is_page:
        if report["page_count"] > MAX_FINDINGS_PAGE_SIZE:
            raise ValueError("invalid findings report")
        cursor = report["next_cursor"]
        if type(report["has_more"]) is not bool:
            raise ValueError("invalid findings report")
        if report["has_more"]:
            if not isinstance(cursor, str) or re.fullmatch(r"[A-Za-z0-9._~-]{1,1024}", cursor) is None:
                raise ValueError("invalid findings report")
        elif cursor is not None:
            raise ValueError("invalid findings report")
    findings = [_validate_public_finding(item) for item in findings]
    lines = [
        f"LeakGuard findings ({report['state']}, profile={report['profile']}): "
        f"{report[count_key]} observations" + (" in this page" if is_page else "")
    ]
    for finding in findings[:limit]:
        source = finding["source"]
        location = f"{clean(source['path'])}:{finding['start_line']}"
        if finding["end_line"] != finding["start_line"]:
            location += f"-{finding['end_line']}"
        if finding["part_id"] != "text":
            location += f" part={clean(finding['part_id'])}"
        lines.append(f"  {location} [{finding['state']}/{finding['severity']}] {clean(finding['rule'])}")
        lines.append(
            f"    first seen {finding['first_seen']}; last seen {finding['last_seen']}; "
            f"last verified {finding['last_verified'] or 'unknown'}"
        )
    if len(findings) > limit:
        lines.append(f"  ... {len(findings) - limit} more observations in the structured report")
    if is_page and report["has_more"]:
        lines.append(f"More results are available. Continue with --cursor {report['next_cursor']}")
    return "\n".join(lines)


def _public_finding_row(row):
    """Copy only fixed, validated observation fields from a storage adapter."""
    if type(row) is not dict:
        raise ValueError("invalid stored finding")
    source = row.get("source")
    if type(source) is not dict:
        raise ValueError("invalid stored finding")
    source_fields = ("kind", "path", "repository", "commit", "blob_oid", "index_tree_oid")
    if any(key not in source for key in source_fields):
        raise ValueError("invalid stored finding")
    clean_source = {key: source[key] for key in source_fields}
    if clean_source["kind"] not in {"filesystem", "bytes", "git-index", "git-commit"}:
        raise ValueError("invalid stored finding")
    _public_text(clean_source["path"], allow_empty=False)
    for key in source_fields[2:]:
        _public_text(clean_source[key], allow_none=True)
    try:
        SourceRef(
            SourceKind(clean_source["kind"]), clean_source["path"],
            clean_source["repository"], clean_source["commit"],
            clean_source["blob_oid"], clean_source["index_tree_oid"],
        )
    except (TypeError, ValueError):
        raise ValueError("invalid stored finding") from None

    finding_id = row.get("id")
    if not isinstance(finding_id, str) or re.fullmatch(r"[0-9a-f]{64}", finding_id) is None:
        raise ValueError("invalid stored finding")
    part_id = row.get("part_id")
    rule = row.get("rule")
    detector_id = row.get("detector_id")
    if any(not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,79}", value) is None
           for value in (part_id, rule, detector_id)):
        raise ValueError("invalid stored finding")
    severity = row.get("severity")
    detector_severity = row.get("detector_severity")
    classification = row.get("classification")
    state = row.get("state")
    if severity not in {"block", "review", "info"} or detector_severity not in {"block", "review"}:
        raise ValueError("invalid stored finding")
    if classification not in {
        "credential-candidate", "heuristic", "verified-file-sha256", "verified-function-ast-sha256"
    } or state not in {"active", "resolved", "unknown"}:
        raise ValueError("invalid stored finding")
    start_line = row.get("start_line")
    end_line = row.get("end_line")
    if type(start_line) is not int or type(end_line) is not int or start_line <= 0 or end_line < start_line:
        raise ValueError("invalid stored finding")
    reason = row.get("state_reason")
    if reason not in {
        "historical-observation", "incomplete-scan", "policy-obsolete", "complete-content-scan",
        "verified-present", "partial-observation", "legacy-unverified", "source-event",
        "source-unavailable", "source-absent",
    }:
        raise ValueError("invalid stored finding")
    first_seen = _public_timestamp(row.get("first_seen"))
    last_seen = _public_timestamp(row.get("last_seen"))
    resolved_at = _public_timestamp(row.get("resolved_at"), allow_none=True)
    if datetime.datetime.fromisoformat(first_seen) > datetime.datetime.fromisoformat(last_seen):
        raise ValueError("invalid stored finding")
    if (state == "resolved") != (resolved_at is not None):
        raise ValueError("invalid stored finding")
    return {
        "id": finding_id,
        "source": clean_source,
        "part_id": part_id,
        "start_line": start_line,
        "end_line": end_line,
        "rule": rule,
        "detector_id": detector_id,
        "detector_severity": detector_severity,
        "severity": severity,
        "classification": classification,
        "state": state,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "last_verified": _public_timestamp(row.get("last_verified"), allow_none=True),
        "resolved_at": resolved_at,
        "state_reason": reason,
    }


def _public_text(value, allow_none=False, allow_empty=True):
    if allow_none and value is None:
        return
    if not isinstance(value, str) or (not allow_empty and not value) or len(value) > 4096:
        raise ValueError("invalid stored finding")


def _validate_public_finding(finding):
    fields = {
        "id", "source", "part_id", "start_line", "end_line", "rule", "detector_id",
        "detector_severity", "severity", "classification", "state", "first_seen",
        "last_seen", "last_verified", "resolved_at", "state_reason",
    }
    source_fields = {"kind", "path", "repository", "commit", "blob_oid", "index_tree_oid"}
    if (type(finding) is not dict or set(finding) != fields or
            type(finding.get("source")) is not dict or set(finding["source"]) != source_fields):
        raise ValueError("invalid findings report")
    normalized = _public_finding_row(finding)
    if normalized != finding:
        raise ValueError("invalid findings report")
    return normalized


def _public_timestamp(value, allow_none=False):
    if allow_none and value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("invalid stored finding")
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("invalid stored finding") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("invalid stored finding")
    if parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError("invalid stored finding")
    return parsed.astimezone(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def select_report(state, explicit=None, repo=None, cwd=None):
    if explicit:
        return pathlib.Path(explicit)
    if repo is None:
        process = subprocess.run(['git', 'rev-parse', '--show-toplevel'], cwd=cwd, capture_output=True)
        if process.returncode == 0:
            repo = process.stdout.decode().strip()
    if repo is None:
        path = state / 'LATEST-git.json'
        if path.is_file():
            return path
        raise ValueError('No Git scan report is available')
    for path in sorted((state / 'reports').glob('*git-*.json'), key=lambda p: p.stat().st_mtime_ns, reverse=True):
        try:
            report = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        if report.get('label', '').startswith('git-') and ntpath.normcase(ntpath.normpath(report.get('repo', ''))) == ntpath.normcase(ntpath.normpath(str(repo))):
            return path
    raise ValueError('No Git scan report is available for this repository')
