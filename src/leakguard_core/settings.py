"""Generic defaults; site configuration and runtime state always live outside source."""
import copy
import json
import os
import pathlib

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
}


def load():
    config = copy.deepcopy(DEFAULTS)
    name = os.environ.get('LEAKGUARD_CONFIG')
    path = pathlib.Path(name).expanduser().resolve() if name else None
    if path:
        config.update(json.loads(path.read_text(encoding='utf-8-sig')))
    return config, path


def state_directory():
    explicit = os.environ.get('LEAKGUARD_STATE_DIR')
    if explicit:
        return pathlib.Path(explicit).expanduser().resolve()
    if os.name == 'nt':
        return pathlib.Path(os.environ.get('LOCALAPPDATA', pathlib.Path.home())) / 'LeakGuard' / 'state'
    return pathlib.Path(os.environ.get('XDG_STATE_HOME', pathlib.Path.home() / '.local' / 'state')) / 'leakguard'
