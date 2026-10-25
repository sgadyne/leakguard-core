"""Compact terminal/chat summaries of sanitized reports; never read source values."""
import collections
import datetime
import json
import ntpath
import pathlib
import re
import subprocess

from .models import DecisionVerdict, ScanReport


def sanitized_report(report):
    if type(report) is ScanReport:
        return report.to_dict()
    allowed = {'path', 'line', 'end_line', 'rule', 'severity', 'info', 'field', 'commit', 'part', 'classification', 'material_name'}
    return {key: report.get(key) for key in ['label', 'checked_utc', 'repo', 'hook_passed'] if key in report} | {
        'findings': [{k: v for k, v in f.items() if k in allowed} for f in report.get('findings', [])],
        'coverage_issues': [{k: v for k, v in x.items() if k in {'path', 'status', 'error_type'}} for x in report.get('coverage_issues', [])],
    }


def clean(value):
    text = re.sub(r'[\x00-\x1f\x7f\x1b]', '?', str(value))
    return text.encode('utf-8', 'backslashreplace').decode('utf-8')


def render(report, report_path=None, limit=20):
    if type(report) is ScanReport:
        return render_scan_report(report, report_path=report_path, limit=limit)
    report = sanitized_report(report)
    findings = report['findings']; issues = report['coverage_issues']
    counts = collections.Counter(f.get('severity', 'review') for f in findings)
    blocked = bool(counts['block'] or issues)
    title = 'BLOCKED' if blocked else 'PASS'
    lines = [f"LeakGuard {clean(report.get('label', 'report'))}: {title} ({counts['block']} blocking, {counts['review']} review, {counts['info']} verified metadata)"]
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
        version = revision[:12] if revision else ('index' if report.get('label') == 'git-pre-commit' else 'commit not recorded')
        part = finding.get('part')
        part_note = '  part=' + clean(part) if part and part != 'text' else ''
        lines.append(f"  {clean(path)}:{finding['line']}  [{clean(version)}]  {clean(finding['severity'])}{part_note}")
        detail = finding.get('info', finding['rule'])
        if detail != finding['rule']:
            detail += ' [rule: ' + finding['rule'] + ']'
        if finding.get('field'):
            detail = finding['field'] + ' - ' + detail
        if finding.get('classification') not in {'verified-function-ast-sha256', 'verified-file-sha256'}:
            detail += ' [value redacted]'
        lines.append('    ' + clean(detail))
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
        DecisionVerdict.BLOCK: "BLOCKED",
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
        lines.append("LeakGuard blocked this Git operation; finding values remain redacted.")
    return '\n'.join(lines)


def findings_report_to_dict(state, profile, rows):
    """Build the closed public shape for current/history store queries."""
    if state not in {"current", "history"}:
        raise ValueError("invalid finding state")
    if profile not in {"general", "companion", "all"}:
        raise ValueError("invalid finding profile")
    if type(rows) not in {tuple, list}:
        raise TypeError("finding rows must be a tuple or list")
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


def render_findings_report(report, limit=50):
    """Render a closed findings report without claiming a scan was clean."""
    expected = {"schema_version", "report_type", "state", "profile", "count", "findings"}
    if type(report) is not dict or set(report) != expected or report["report_type"] != "findings":
        raise TypeError("report must be a public findings report")
    findings = report["findings"]
    if type(findings) is not list or report["count"] != len(findings):
        raise ValueError("invalid findings report")
    lines = [
        f"LeakGuard findings ({report['state']}, profile={report['profile']}): {report['count']} observations"
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
        "verified-present", "partial-observation", "legacy-unverified", "source-absent", "source-event",
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
    return value


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
