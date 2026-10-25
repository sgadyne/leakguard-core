"""Policy evaluation and content-based implementation/runtime identities."""
from __future__ import annotations

from dataclasses import asdict, replace
from contextvars import ContextVar
import hashlib
import importlib.metadata
import importlib.machinery
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import time

from .models import (CoverageSummary, CoverageState, DecisionVerdict, ErrorCode,
                     Omission, OmissionSelector, OmissionSelectorKind, PolicyDecision,
                     PolicyReason, ScanPolicy)


class RuntimeIdentityError(RuntimeError):
    def __init__(self, code='budget-exhausted'):
        self.code = code if code in {'budget-exhausted', 'cancelled', 'source-unavailable'} else 'budget-exhausted'
        super().__init__(self.code)


class _IdentityBudget:
    def __init__(self, deadline, cancel):
        self.deadline = deadline
        self.cancel = cancel
        self.files = 0
        self.bytes = 0
        self.entries = 0

    def check(self):
        if self.cancel is not None:
            try:
                cancelled = self.cancel()
            except Exception:
                cancelled = True
            if cancelled:
                raise RuntimeIdentityError('cancelled')
        if time.monotonic() >= self.deadline:
            raise RuntimeIdentityError()

    def admit(self, size):
        self.check()
        self.files += 1
        self.bytes += size
        if self.files > 20_000 or self.bytes > 1_073_741_824:
            raise RuntimeIdentityError()


_IDENTITY_BUDGET = ContextVar('leakguard_identity_budget', default=None)


def _check_budget():
    budget = _IDENTITY_BUDGET.get()
    if budget is not None:
        budget.check()


def _python_files(root):
    """Bound directory discovery before sorting or hashing package artifacts."""
    pending = [Path(root)]
    paths = []
    while pending:
        _check_budget()
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                _check_budget()
                budget = _IDENTITY_BUDGET.get()
                if budget is not None:
                    budget.entries += 1
                    if budget.entries > 100_000:
                        raise RuntimeIdentityError()
                if entry.is_dir(follow_symlinks=False):
                    if entry.name != '__pycache__':
                        pending.append(Path(entry.path))
                elif entry.name.endswith(('.py', '.toml')) and entry.is_file():
                    paths.append(Path(entry.path))
                    if len(paths) > 10_000:
                        raise RuntimeIdentityError()
    return sorted(paths)


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
        _check_budget()
        source = Path(path)
        if not source.is_file() or source.stat().st_size > 512 * 1024 * 1024:
            return 'unavailable'
        before = source.stat()
        budget = _IDENTITY_BUDGET.get()
        if budget is not None:
            budget.admit(before.st_size)
        digest = hashlib.sha256()
        with source.open('rb') as stream:
            while chunk := stream.read(1_048_576):
                _check_budget()
                digest.update(chunk)
        after = source.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return 'unavailable'
        return digest.hexdigest()
    except (OSError, ValueError, TypeError):
        return 'unavailable'


def _distribution_identity(name):
    _check_budget()
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return {'name': name, 'status': 'absent'}, True
    files = distribution.files
    if not files:
        return {'name': name, 'version': distribution.version, 'status': 'unverifiable'}, False
    if len(files) > 20_000:
        raise RuntimeIdentityError()
    artifacts = []; complete = True
    for entry in sorted(files, key=str):
        _check_budget()
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


def _module_artifacts(name):
    """Locate explicitly configured module bytes without importing parent code."""
    search = list(sys.path)
    artifacts = []
    prefix = []
    try:
        for component in name.split('.'):
            _check_budget()
            prefix.append(component)
            spec = importlib.machinery.PathFinder.find_spec('.'.join(prefix), search)
            if spec is None:
                return [('unavailable', 'unavailable')]
            if spec.origin and spec.origin not in {'built-in', 'frozen'}:
                artifacts.append(('.'.join(prefix), _file_identity(spec.origin)))
            search = list(spec.submodule_search_locations or ())
        # Local/editable packages have no verified distribution closure. Hash
        # their own Python implementation as identity, while reuse stays disabled.
        if search:
            count = 0
            for directory in search:
                for path in _python_files(directory):
                    count += 1
                    if count > 10_000:
                        return artifacts + [('closure', 'unavailable')]
                    artifacts.append((str(path.relative_to(directory)), _file_identity(path)))
        return artifacts
    except (ImportError, AttributeError, OSError, ValueError):
        return [('unavailable', 'unavailable')]


def _dependency_closure(names):
    # Requirement markers must be evaluated rather than interpreting development
    # extras as runtime dependencies. packaging is a small maintained dependency.
    try:
        from packaging.requirements import Requirement
    except ImportError:
        Requirement = None
    pending = list(dict.fromkeys(names)); seen = set(); closure = []; complete = True
    while pending:
        _check_budget()
        name = pending.pop()
        key = re.sub('[-_.]+', '-', name).lower()
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > 1000:
            return closure, False
        identity, valid = _distribution_identity(name)
        closure.append(identity); complete = complete and valid
        for raw in identity.get('requires', ()):
            if Requirement is None:
                complete = False
                continue
            try:
                requirement = Requirement(raw)
                marker = requirement.marker
                active = marker is None or marker.evaluate({'extra': ''})
                # Parsers can use installed optional backends without an explicit
                # extra at invocation. Include their installed-or-missing state,
                # excluding build/documentation/test-only requirements.
                if marker is not None and not active and 'extra' in str(marker):
                    extras = set(re.findall(r"extra == ['\"]([^'\"]+)['\"]", str(marker)))
                    runtime_extras = extras - {'dev', 'docs', 'doc', 'test', 'tests', 'testing', 'lint'}
                    active = any(marker.evaluate({'extra': extra}) for extra in runtime_extras)
                    if not extras:
                        complete = False
                if active:
                    pending.append(requirement.name)
            except Exception:
                complete = False
    return sorted(closure, key=lambda item: item['name'].lower()), complete


def runtime_identity(config=None, binary=None, plugin_specs=(), *, plugin_manifests=(), deadline=None, cancel=None):
    """Bound artifact inspection by both wall time and total filesystem work."""
    budget = _IdentityBudget(deadline if deadline is not None else time.monotonic() + 30, cancel)
    token = _IDENTITY_BUDGET.set(budget)
    try:
        budget.check()
        return _runtime_identity(config, binary, plugin_specs, plugin_manifests=plugin_manifests)
    except (OSError, ValueError, TypeError):
        raise RuntimeIdentityError('source-unavailable') from None
    finally:
        _IDENTITY_BUDGET.reset(token)


def _runtime_identity(config=None, binary=None, plugin_specs=(), *, plugin_manifests=()):
    """Hash actual behavior-bearing bytes; unknown extension closure disables reuse."""
    config = config or {}
    root = Path(__file__).resolve().parent
    core = [(str(path.relative_to(root)), _file_identity(path))
            for path in _python_files(root)]
    executable = binary or config.get('gitleaks_executable') or os.environ.get('LEAKGUARD_GITLEAKS') or shutil.which('gitleaks')
    if executable and not Path(executable).is_file():
        executable = shutil.which(str(executable))
    binary_id = _file_identity(executable) if executable else 'unavailable'
    specs = list(plugin_specs or config.get('plugins', ()))
    dependencies = ['pypdf', 'olefile', 'packaging']
    module_artifacts = []
    try:
        distributions = importlib.metadata.packages_distributions() if specs else {}
    except Exception:
        distributions = {}
    for spec in specs:
        _check_budget()
        module = spec['module']
        module_artifacts.append((module, _module_artifacts(module)))
        dependencies.extend(distributions.get(module.split('.')[0], ()))
    manifests = []
    for manifest in plugin_manifests:
        _check_budget()
        if manifest is not None:
            manifests.append(asdict(manifest))
            dependencies.extend(item.name for item in manifest.dependencies)
    for script in config.get('script_checks', ()):
        _check_budget()
        dependencies.extend(script.get('dependencies', ()))
    closure, complete = _dependency_closure(dependencies)
    value = {'abi': 'leakguard-runtime-2', 'core': core,
             'python': [sys.implementation.name, platform.python_version(), _file_identity(sys.executable)],
             'platform': [platform.system(), platform.machine()], 'gitleaks': binary_id,
             'rules': _file_identity(config.get('gitleaks_config') or root / 'rules.toml'),
             'dependencies': closure, 'plugins': specs, 'plugin_artifacts': module_artifacts,
             'manifests': manifests,
             'scripts': [{'spec': spec, 'artifacts': [(index, _file_identity(value)) for index, value in enumerate(spec['argv']) if Path(value).is_file()]} for spec in config.get('script_checks', ())]}
    if specs or value['scripts'] or config.get('credential_store'):
        complete = False
    _check_budget()
    complete = complete and all(identity != 'unavailable' for _, identity in core)
    return _digest(value), complete and binary_id != 'unavailable' and value['rules'] != 'unavailable'


def evaluate(results, *, policy, policy_id, enumeration_complete=True, issues=(),
             pending_files=None, pending_directories=None, cycle_id=None):
    results = tuple(results); issues = tuple(issues)
    all_issues = (*issues, *(issue for result in results for issue in result.issues))
    if pending_directories is not None and pending_directories > 0:
        enumeration_complete = False
    required_complete = enumeration_complete and not any(issue.required for issue in all_issues)
    required_complete = required_complete and not any(result.coverage is CoverageState.INCOMPLETE for result in results)
    required_complete = required_complete and not (pending_files is not None and pending_files > 0)
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
