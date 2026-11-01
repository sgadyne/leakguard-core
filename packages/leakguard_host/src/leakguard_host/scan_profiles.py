"""Declarative scan presets compiled to the existing scanner and host contracts.

Resolution performs no plugin imports, network requests, scans or installation.
Code extensions retain DetectorV2/ExtractorV2 and their supervised preflight.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from leakguard_core import settings
from leakguard_core.recognizer_profiles import compose

from .errors import HostError
from .protection import validate as validate_protection

_TOKEN = re.compile(r'[a-z][a-z0-9-]{0,79}\Z')
_MAX_BYTES = 1_000_000
_INSPECTION = {'mode', 'recognizers', 'max_file_bytes', 'scan_workers'}
_JOBS = {'reconcile', 'changes', 'deep', 'access'}
_PACK_FIELDS = {'id', 'version', 'plugins', 'extractor_overrides', 'required_formats', 'review_only_rules', 'omissions', 'requires'}
_BUILTINS = {
    'standard': {'id': 'standard', 'version': 1, 'inspection': {'mode': 'inspect', 'recognizers': 'credentials'}},
    'sensitive': {'id': 'sensitive', 'version': 1, 'inspection': {'mode': 'inspect', 'recognizers': 'sensitive'}},
    'inventory': {'id': 'inventory', 'version': 1, 'inspection': {'mode': 'inventory', 'recognizers': 'credentials'}},
}
CAPABILITIES = ('bounded-reconciliation', 'detector-v2', 'extractor-v2', 'document-text')
UNAVAILABLE = ('filesystem-events', 'recursive-archives', 'process-access')


def _fail(code='scan-profile-invalid'):
    raise HostError(code)


def _token(value):
    return type(value) is str and _TOKEN.fullmatch(value) is not None


def _clone(value):
    try:
        raw = json.dumps(value, allow_nan=False, ensure_ascii=True)
        if len(raw) > _MAX_BYTES:
            _fail()
        return json.loads(raw)
    except (TypeError, ValueError, RecursionError):
        _fail()


def _keys(value, required, allowed):
    if type(value) is not dict or not required <= set(value) <= allowed:
        _fail()


def _tokens(value):
    if type(value) is not list or len(value) > 100 or any(not _token(x) for x in value) or len(set(value)) != len(value):
        _fail()


def _layer(value):
    _keys(value, set(), {'inspection', 'jobs', 'packs', 'requires'})
    inspection = value.get('inspection', {})
    _keys(inspection, set(), _INSPECTION)
    if type(inspection.get('mode', 'inspect')) is not str or inspection.get('mode', 'inspect') not in {'inspect', 'inventory'}:
        _fail()
    if type(inspection.get('recognizers', 'credentials')) is not str or inspection.get('recognizers', 'credentials') not in {'credentials', 'sensitive', 'firm'}:
        _fail()
    for key in ('max_file_bytes', 'scan_workers'):
        if key in inspection:
            try:
                settings.validate({key: inspection[key]})
            except settings.ConfigurationError:
                _fail()
    jobs = value.get('jobs', {})
    _keys(jobs, set(), _JOBS)
    if 'reconcile' in jobs:
        try:
            validate_protection({'schedule': jobs['reconcile']})
        except HostError:
            _fail()
    for key, choices in (('changes', {'polling', 'events'}), ('deep', {'off', 'archives'}), ('access', {'off', 'audit'})):
        if key in jobs and (type(jobs[key]) is not str or jobs[key] not in choices):
            _fail()
    for key in ('packs', 'requires'):
        _tokens(value.get(key, []))


def validate_document(value):
    """Validate structure, including unused definitions; reject ambiguous merges."""
    value = _clone(value)
    _keys(value, {'version', 'preset'}, {'version', 'preset', 'presets', 'packs', 'overrides'})
    if type(value['version']) is not int or value['version'] != 1 or not _token(value['preset']):
        _fail()
    for key in ('presets', 'packs'):
        rows = value.setdefault(key, [])
        if type(rows) is not list or len(rows) > 100:
            _fail()
        seen = set(_BUILTINS) if key == 'presets' else set()
        for row in rows:
            allowed = _PACK_FIELDS if key == 'packs' else {'id', 'version', 'extends', 'inspection', 'jobs', 'packs', 'requires'}
            _keys(row, {'id', 'version'}, allowed)
            if not _token(row['id']) or row['id'] in seen or type(row['version']) is not int or not 1 <= row['version'] <= 1_000_000:
                _fail()
            seen.add(row['id'])
            if key == 'presets':
                if 'extends' in row and not _token(row['extends']):
                    _fail()
                _layer({k: v for k, v in row.items() if k not in {'id', 'version', 'extends'}})
            else:
                _tokens(row.get('requires', []))
                try:
                    cfg = settings.validate({k: v for k, v in row.items() if k not in {'id', 'version', 'requires'}})
                except settings.ConfigurationError:
                    _fail()
                modules = [p['module'] for p in cfg['plugins']]
                if len(modules) != len(set(modules)):
                    _fail('scan-profile-component-conflict')
                if any(not re.fullmatch(r'\.[a-z0-9]{1,16}', suffix) for suffix in cfg['extractor_overrides']):
                    _fail()
    _layer(value.setdefault('overrides', {}))
    return value


def read_document(path):
    """Read one explicit bounded regular JSON file; no includes or ambient lookup."""
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                _fail()
            obj[key] = value
        return obj
    try:
        if Path(path).is_symlink():
            _fail()
        flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(Path(path), flags), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_BYTES:
                _fail()
            data = stream.read(_MAX_BYTES + 1)
        if len(data) > _MAX_BYTES:
            _fail()
        return validate_document(json.loads(data.decode('utf-8'), object_pairs_hook=unique))
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        _fail()


def effective_digest(config, protection):
    raw = json.dumps([settings.validate(config), validate_protection(protection)], sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


def catalog():
    return {'schema_version': 1, 'presets': deepcopy(list(_BUILTINS.values())),
            'capabilities': list(CAPABILITIES), 'unavailable': list(UNAVAILABLE),
            'extension_interfaces': ['DetectorV2', 'ExtractorV2'],
            'job_executor': 'existing-host-scheduler', 'plugin_installation': 'explicit-only'}


def _safe_values(config, protection):
    # Deliberately excludes paths, plugin options, aliases and credential material.
    return {'inspection.mode': protection['new_content'],
            'inspection.recognizers': config['detection_profile'],
            'inspection.max_file_bytes': config['max_file_bytes'],
            'inspection.scan_workers': config['scan_workers'],
            'jobs.reconcile': deepcopy(protection['schedule']),
            'jobs.changes': 'polling', 'jobs.deep': 'off', 'jobs.access': 'off'}


@dataclass(frozen=True)
class ResolvedProfile:
    document: dict
    config: dict
    protection: dict
    provenance: dict
    identity: str
    prior: dict

    def preview(self):
        """No plugin option values, paths, source bytes or credential material."""
        effective = _safe_values(self.config, self.protection)
        changes = [{'field': key, 'prior': deepcopy(self.prior[key]),
                    'effective': deepcopy(value), 'provenance': self.provenance[key]}
                   for key, value in effective.items() if self.prior[key] != value]
        return {'changes': changes, 'preset': self.document['preset'], 'identity': self.identity,
                'effective_digest': effective_digest(self.config, self.protection),
                'inspection': {'mode': self.protection['new_content'], 'recognizers': self.config['detection_profile'],
                               'max_file_bytes': self.config['max_file_bytes'], 'scan_workers': self.config['scan_workers']},
                'jobs': {'reconcile': deepcopy(self.protection['schedule']), 'changes': 'polling', 'deep': 'off', 'access': 'off'},
                'components': [{'module': p['module'], 'option_names': sorted(p.get('options', {}))} for p in self.config['plugins']],
                'extractor_count': len(self.config['extractor_overrides']), 'omission_count': len(self.config['omissions']),
                'provenance': deepcopy(self.provenance), 'runtime_preflight': 'required-before-inspection',
                'limitations': ['No native event/read monitoring', 'No general recursive archive traversal',
                                'Source-specific schedule overrides remain in force',
                                'Existing recognition components are retained; removing one requires explicit plugin configuration'],
                'capabilities': list(CAPABILITIES)}


def resolve(document, *, base_config=None, base_protection=None, ceilings=None):
    """Resolve explicit inheritance then packs, then overrides; retain site config.

    Ceilings come from the caller's trusted policy, never from a preset pack.
    Unsupported requested capabilities are errors, not silent fallback.
    """
    doc = validate_document(document)
    config = settings.validate({} if base_config is None else base_config)
    protection = validate_protection({} if base_protection is None else deepcopy(base_protection))
    prior = _safe_values(config, protection)
    presets = {**deepcopy(_BUILTINS), **{x['id']: x for x in doc['presets']}}
    packs = {x['id']: x for x in doc['packs']}
    layers = []
    visiting = set()

    def visit(name):
        if name not in presets:
            _fail('scan-profile-not-found')
        if name in visiting or len(visiting) >= 8:
            _fail('scan-profile-inheritance-cycle')
        visiting.add(name)
        row = presets[name]
        if 'extends' in row:
            visit(row['extends'])
        layers.append((name + '@' + str(row['version']), row))
        visiting.remove(name)

    # Invalid dormant inheritance must not become a delayed surprise on selection.
    for name in presets:
        visit(name)
        layers.clear()
    visit(doc['preset'])
    layers.append(('overrides', doc['overrides']))
    inspection = {}; jobs = {}; pack_ids = []; required = set()
    provenance = {name: 'existing-settings' for name in ('inspection.mode', 'inspection.recognizers',
                  'inspection.max_file_bytes', 'inspection.scan_workers', 'jobs.reconcile')}
    provenance.update({key: 'runtime-default' for key in ('jobs.changes', 'jobs.deep', 'jobs.access')})
    for origin, layer in layers:
        for group, target in (('inspection', inspection), ('jobs', jobs)):
            for key, value in layer.get(group, {}).items():
                target[key] = deepcopy(value)
                provenance[group + '.' + key] = origin
        for name in layer.get('packs', []):
            if name not in packs:
                _fail('scan-profile-pack-not-found')
            if name not in pack_ids:
                pack_ids.append(name)
        required.update(layer.get('requires', []))
    for key, value, capability in (('changes', 'events', 'filesystem-events'), ('deep', 'archives', 'recursive-archives'), ('access', 'audit', 'process-access')):
        if jobs.get(key) == value:
            required.add(capability)
    for name in pack_ids:
        required.update(packs[name].get('requires', []))
    if required - set(CAPABILITIES):
        _fail('scan-profile-capability-unavailable')
    # Compose explicitly: changing a display/profile label alone is insufficient.
    mode = inspection.get('mode', protection['new_content'])
    if mode == 'inspect':
        config = compose(inspection.get('recognizers', config['detection_profile']), config)
    protection['new_content'] = mode
    for key in ('max_file_bytes', 'scan_workers'):
        if key in inspection:
            config[key] = inspection[key]
    if 'reconcile' in jobs:
        protection['schedule'] = jobs['reconcile']
    touched = set(); omission_ids = set()
    for name in pack_ids:
        pack = packs[name]; origin = name + '@' + str(pack['version'])
        for plugin in pack.get('plugins', []):
            module = plugin['module']
            if module in touched:
                _fail('scan-profile-component-conflict')
            touched.add(module)
            matches = [p for p in config['plugins'] if p['module'] == module]
            if len(matches) > 1:
                _fail('scan-profile-component-conflict')
            if matches:
                target = matches[0]
                target['options'] = {**target.get('options', {}), **deepcopy(plugin.get('options', {}))}
                if 'component' in plugin:
                    target['component'] = plugin['component']
            else:
                config['plugins'].append(deepcopy(plugin))
            provenance['component.' + module] = origin
        for suffix, component in pack.get('extractor_overrides', {}).items():
            if 'extractor.' + suffix in provenance:
                _fail('scan-profile-component-conflict')
            config['extractor_overrides'][suffix] = component
            provenance['extractor.' + suffix] = origin
        for key in ('required_formats', 'review_only_rules'):
            for item in pack.get(key, []):
                if item not in config[key]:
                    config[key].append(item)
        for omission in pack.get('omissions', []):
            identifier = omission['id']
            if identifier in omission_ids:
                _fail('scan-profile-component-conflict')
            omission_ids.add(identifier)
            config['omissions'] = [row for row in config['omissions'] if row['id'] != identifier]
            config['omissions'].append(deepcopy(omission))
            provenance['omission.' + identifier] = origin
    if ceilings is not None:
        _keys(ceilings, set(), {'max_file_bytes', 'scan_workers'})
        for key, limit in ceilings.items():
            try:
                settings.validate({key: limit})
            except settings.ConfigurationError:
                _fail()
            if config[key] > limit:
                _fail('scan-profile-policy-limit')
    try:
        config = settings.validate(config); protection = validate_protection(protection)
    except settings.ConfigurationError:
        _fail()
    digest = effective_digest(config, protection)
    identity = hashlib.sha256(json.dumps([doc, digest], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return ResolvedProfile(doc, config, protection, provenance, identity, prior)


def preflight(plan):
    """Explicit execution boundary: verify the installed scanner/plugin closure."""
    from leakguard_core.api import ScanConfig, Scanner, ScanLimits, ScanPolicy
    from leakguard_core.scan_store import MemoryScanStore
    if plan.protection['new_content'] == 'inventory':
        return {'inspection_enabled': False}
    try:
        config = ScanConfig.from_mapping(plan.config)
        with Scanner.open(config=config, store=MemoryScanStore(config=plan.config)) as scanner:
            scanner.work_identity(policy=ScanPolicy.inventory(), limits=ScanLimits(10, 100))
    except Exception:
        _fail('scan-profile-runtime-unavailable')
    return {'inspection_enabled': True}
