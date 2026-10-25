"""Generic defaults; site configuration and runtime state always live outside source."""
import copy
import json
import os
import pathlib
import math
import re

DEFAULTS = {
    'max_file_bytes': 20_971_520,
    'scan_timeout_seconds': 45,
    'review_only_rules': [],
    'audit_scopes': {},
    'watch_scopes': {},
    'scope_aliases': {},
    'profiles': {'general': {'sources': []}, 'companion': {'sources': []}},
    'priority_paths': {},
    'exclude_roots': [],
    'exclude_components': ['.git'],
    'plugins': [],
    'credential_store': None,
    'gitleaks_executable': None,
    'gitleaks_config': None,
    'script_checks': [],
    'required_formats': [],
    'omissions': [],
    'extractor_overrides': {},
}


def load():
    config = copy.deepcopy(DEFAULTS)
    name = os.environ.get('LEAKGUARD_CONFIG')
    path = pathlib.Path(name).expanduser().resolve() if name else None
    if path:
        try:
            config = validate(json.loads(path.read_text(encoding='utf-8-sig')))
        except (OSError, ValueError, TypeError):
            raise ConfigurationError('configuration') from None
    return config, path


def state_directory():
    explicit = os.environ.get('LEAKGUARD_STATE_DIR')
    if explicit:
        return pathlib.Path(explicit).expanduser().resolve()
    if os.name == 'nt':
        return pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home())) / 'LeakGuard' / 'state'
    return pathlib.Path(os.environ.get('XDG_STATE_HOME', pathlib.Path.home() / '.local' / 'state')) / 'leakguard'


class ConfigurationError(ValueError):
    """A fixed error code and safe schema field; never echo supplied values."""
    code = 'configuration-invalid'

    def __init__(self, field='configuration'):
        self.field = field if field in DEFAULTS else 'configuration'
        super().__init__(self.code + ':' + self.field)


def validate(mapping):
    """Validate explicit configuration without reading environment or filesystem."""
    if type(mapping) is not dict or any(type(key) is not str or key not in DEFAULTS for key in mapping):
        raise ConfigurationError()
    try:
        raw = json.dumps(mapping, allow_nan=False, ensure_ascii=True)
        if len(raw) > 1_000_000:
            raise ConfigurationError()
        result = copy.deepcopy(DEFAULTS)
        result.update(json.loads(raw))
    except (TypeError, ValueError, RecursionError):
        raise ConfigurationError() from None

    def fail(field):
        raise ConfigurationError(field)

    def text(value, size=4096):
        return type(value) is str and 0 < len(value) <= size and '\x00' not in value

    def token(value):
        return type(value) is str and re.fullmatch('[a-z][a-z0-9-]{0,79}', value) is not None

    def texts(value, size=4096):
        return type(value) is list and len(value) <= 10_000 and all(text(item, size) for item in value)

    for key, maximum in (('max_file_bytes', 1_073_741_824), ('scan_timeout_seconds', 3600)):
        value = result[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
            fail(key)
        if key == 'max_file_bytes' and type(value) is not int:
            fail(key)
    for key in ('review_only_rules', 'required_formats'):
        if not texts(result[key], 80) or any(not token(item) for item in result[key]):
            fail(key)
    for key in ('exclude_roots', 'exclude_components'):
        if not texts(result[key]):
            fail(key)
    for key in ('gitleaks_executable', 'gitleaks_config', 'credential_store'):
        if result[key] is not None and not text(result[key]):
            fail(key)
    for key in ('audit_scopes', 'watch_scopes', 'extractor_overrides'):
        if type(result[key]) is not dict or len(result[key]) > 10_000 or any(not text(name, 200) or not text(value) for name, value in result[key].items()):
            fail(key)
    for key in ('scope_aliases', 'priority_paths'):
        if type(result[key]) is not dict or len(result[key]) > 10_000 or any(not text(name, 200) or not texts(value) for name, value in result[key].items()):
            fail(key)
    if type(result['profiles']) is not dict or len(result['profiles']) > 100:
        fail('profiles')
    for name, profile in result['profiles'].items():
        if not token(name) or type(profile) is not dict or set(profile) != {'sources'} or not texts(profile['sources'], 200):
            fail('profiles')
    if type(result['plugins']) is not list or len(result['plugins']) > 100:
        fail('plugins')
    for spec in result['plugins']:
        if (type(spec) is not dict or not {'module'} <= set(spec) <= {'module', 'options', 'component'}
                or type(spec['module']) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', spec['module'])
                or type(spec.get('options', {})) is not dict
                or 'component' in spec and not token(spec['component'])):
            fail('plugins')
    if type(result['omissions']) is not list or len(result['omissions']) > 1000:
        fail('omissions')
    ids = set()
    for omission in result['omissions']:
        if type(omission) is not dict or set(omission) != {'id', 'selector', 'reason_code'}:
            fail('omissions')
        selector = omission['selector']
        if (not token(omission['id']) or omission['id'] in ids or type(selector) is not dict
                or set(selector) != {'kind', 'value'} or selector['kind'] not in {'format', 'path'}
                or not text(selector['value']) or omission['reason_code'] not in {'unsupported-binary', 'optional-format', 'operator-exclusion'}):
            fail('omissions')
        ids.add(omission['id'])
    if type(result['script_checks']) is not list or len(result['script_checks']) > 100:
        fail('script_checks')
    for spec in result['script_checks']:
        allowed = {'id', 'argv', 'rules', 'implementation_version', 'dependencies', 'deterministic', 'external_state', 'options'}
        if (type(spec) is not dict or not {'id', 'argv', 'rules'} <= set(spec) <= allowed
                or not token(spec['id']) or not texts(spec['argv']) or not spec['argv']
                or not pathlib.Path(spec['argv'][0]).is_absolute()
                or type(spec['rules']) is not list or not spec['rules']):
            fail('script_checks')
        for rule in spec['rules']:
            if (type(rule) is not dict or not {'id'} <= set(rule) <= {'id', 'minimum_severity'}
                    or not token(rule['id']) or rule.get('minimum_severity', 'review') not in {'block', 'review'}):
                fail('script_checks')
        if 'implementation_version' in spec and not text(spec['implementation_version'], 200):
            fail('script_checks')
        if 'deterministic' in spec and type(spec['deterministic']) is not bool:
            fail('script_checks')
        if spec.get('external_state', 'unknown') not in {'none', 'declared', 'unknown'}:
            fail('script_checks')
        if type(spec.get('dependencies', [])) is not list or any(not text(item, 200) for item in spec.get('dependencies', [])):
            fail('script_checks')
        if type(spec.get('options', {})) is not dict:
            fail('script_checks')
    return result


normalize_config = validate
