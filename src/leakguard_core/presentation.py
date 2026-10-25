"""Compact terminal/chat summaries of sanitized reports; never read source values."""
import collections
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
    return re.sub(r'[\x00-\x1f\x7f\x1b]', '?', str(value))


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
