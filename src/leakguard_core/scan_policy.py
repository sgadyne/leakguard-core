"""Policy evaluation and content-based implementation/runtime identities."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys

from .models import (CoverageSummary, CoverageState, DecisionVerdict, ErrorCode,
                     Omission, OmissionSelector, OmissionSelectorKind, PolicyDecision,
                     PolicyReason, ScanPolicy)


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def effective_policy(policy, config=None):
    config = config or {}
    required = tuple(dict.fromkeys((*policy.required_formats, *config.get('required_formats', ()))))
    omissions = list(policy.omissions)
    by_id = {item.id: item for item in omissions}
    for item in config.get('omissions', ()):
        omission = Omission(item['id'], OmissionSelector(OmissionSelectorKind(item['selector']['kind']), item['selector']['value']), PolicyReason(item['reason_code']))
        if omission.id in by_id:
            if omission != by_id[omission.id]:
                raise ValueError('configuration-invalid')
        else:
            omissions.append(omission); by_id[omission.id] = omission
    return replace(policy, required_formats=required, omissions=tuple(omissions))


def policy_identity(*, config=None, policy=None, limits=None):
    return _digest({'abi': 'leakguard-policy-1', 'config': config or {},
                    'policy': asdict(policy) if policy is not None else None,
                    'limits': asdict(limits) if limits is not None else None})


def _file_identity(path):
    try:
        source = Path(path)
        if not source.is_file() or source.stat().st_size > 512 * 1024 * 1024:
            return 'unavailable'
        before = source.stat()
        digest = hashlib.sha256()
        with source.open('rb') as stream:
            while chunk := stream.read(1_048_576):
                digest.update(chunk)
        after = source.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return 'unavailable'
        return digest.hexdigest()
    except (OSError, ValueError, TypeError):
        return 'unavailable'


def _distribution_identity(name):
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return {'name': name, 'status': 'absent'}, True
    files = distribution.files
    if not files:
        return {'name': name, 'version': distribution.version, 'status': 'unverifiable'}, False
    artifacts = []; complete = True
    for entry in sorted(files, key=str):
        label = str(entry)
        if label.endswith(('.pyc', '.pyo')) or '__pycache__' in Path(label).parts:
            continue
        identity = _file_identity(distribution.locate_file(entry))
        complete = complete and identity != 'unavailable'
        artifacts.append((label, identity))
    # Unknown dependency marker evaluation cannot authorize persistent reuse.
    # Include every installed declared dependency and missing sentinel. No option
    # enables reuse for module-backed plugins with an undeclared import closure.
    requirements = distribution.requires or []
    return {'name': name, 'version': distribution.version, 'artifacts': artifacts,
            'requires': sorted(requirements)}, complete


def runtime_identity(config=None, binary=None, plugin_specs=()):
    """Hash actual behavior-bearing bytes; unknown extension closure disables reuse."""
    config = config or {}
    root = Path(__file__).resolve().parent
    core = [(str(path.relative_to(root)), _file_identity(path))
            for path in sorted(root.rglob('*')) if path.suffix in {'.py', '.toml'}]
    executable = binary or config.get('gitleaks_executable') or os.environ.get('LEAKGUARD_GITLEAKS') or shutil.which('gitleaks')
    if executable and not Path(executable).is_file():
        executable = shutil.which(str(executable))
    binary_id = _file_identity(executable) if executable else 'unavailable'
    parsers = []; complete = binary_id != 'unavailable'
    for name in ('pypdf', 'olefile'):
        identity, verified = _distribution_identity(name)
        parsers.append(identity); complete = complete and verified
        # Conservative base dependency closure. Optional extra requirements are
        # fingerprinted with their installed-or-missing state as well.
        for requirement in identity.get('requires', ()):
            match = re.match(r'([A-Za-z0-9_.-]+)', requirement)
            if not match:
                complete = False; continue
            dependency, valid = _distribution_identity(match.group(1))
            parsers.append(dependency); complete = complete and valid
            # Dependencies of dependencies need a complete manifest. Keep scans
            # executable but uncacheable rather than claim an incomplete closure.
            if dependency.get('requires'):
                complete = False
    rules = config.get('gitleaks_config') or root / 'rules.toml'
    value = {'abi': 'leakguard-runtime-1', 'core': core,
             'python': [sys.implementation.name, platform.python_version(), _file_identity(sys.executable)],
             'platform': [platform.system(), platform.machine()], 'gitleaks': binary_id,
             'rules': _file_identity(rules), 'parsers': parsers,
             'plugins': list(plugin_specs or config.get('plugins', ())),
             'scripts': [{'spec': spec, 'artifacts': [(index, _file_identity(value)) for index, value in enumerate(spec['argv']) if Path(value).is_file()]} for spec in config.get('script_checks', ())]}
    if value['plugins'] or value['scripts'] or config.get('credential_store'):
        complete = False
    return _digest(value), complete and value['rules'] != 'unavailable'


def evaluate(results, *, policy, policy_id, enumeration_complete=True, issues=(),
             pending_files=None, pending_directories=None, cycle_id=None):
    results = tuple(results); issues = tuple(issues)
    all_issues = (*issues, *(issue for result in results for issue in result.issues))
    required_complete = enumeration_complete and not any(issue.required for issue in all_issues)
    required_complete = required_complete and not any(result.coverage is CoverageState.INCOMPLETE for result in results)
    omission_count = sum(not issue.required and issue.omission_id is not None for issue in all_issues)
    omission_count += sum(result.coverage is CoverageState.OMITTED and not result.issues for result in results)
    coverage = CoverageSummary(bool(enumeration_complete), bool(required_complete), omission_count,
                               pending_files, pending_directories, cycle_id)
    reasons = tuple(dict.fromkeys(issue.code for issue in all_issues if issue.required))
    if not required_complete:
        verdict = DecisionVerdict.INCOMPLETE
        if not reasons:
            reasons = (ErrorCode.BUDGET_EXHAUSTED,)
    elif any(finding.severity in policy.block_severities for result in results for finding in result.findings):
        verdict = DecisionVerdict.BLOCK
    elif omission_count or any(result.coverage is CoverageState.OMITTED for result in results):
        verdict = DecisionVerdict.ALLOW_WITH_OMISSIONS
    else:
        verdict = DecisionVerdict.ALLOW
    return coverage, PolicyDecision(verdict, reasons, policy_id)
