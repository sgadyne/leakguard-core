"""Shared-drive detection policy and local-companion routing."""
import json
import ntpath
import re
import os


def windows(path):
    return bool(re.match(r'^[A-Za-z]:[\\/]|^\\\\', str(path)))


def normalize(path):
    return ntpath.normpath(str(path)) if windows(path) else os.path.normpath(str(path))


def canonical(path, config):
    value = normalize(path)
    for name, root in config.get('audit_scopes', {}).items():
        if name == 'local':
            continue
        for alias in config.get('scope_aliases', {}).get(name, []):
            prefix = normalize(alias).rstrip('\\/')
            if value.lower() == prefix.lower() or value.lower().startswith(prefix.lower() + '\\'):
                return normalize(root + value[len(prefix):])
    return value


def profile(path, config):
    value = canonical(path, config)
    matches = []
    for name, root in config.get('audit_scopes', {}).items():
        prefix = normalize(root).rstrip('\\/')
        compared, base = (value.lower(), prefix.lower()) if windows(root) else (value, prefix)
        separator = '\\' if windows(root) else os.sep
        if compared == base or compared.startswith(base + separator):
            chosen = next((kind for kind, spec in config.get('profiles', {}).items() if name in spec.get('sources', [])), 'companion' if name == 'local' else 'general')
            matches.append((len(prefix), chosen))
    if matches:
        return max(matches)[1]
    return 'general' if value.startswith('\\\\') else 'companion'


def classify(path):
    value = str(path).lower()
    suffix = ntpath.splitext(value)[1]
    if any(p in value for p in ['\\pwds\\', '\\passwords\\', '\\secrets\\']) or suffix in {'.pem', '.key', '.pfx', '.kdbx'}:
        return 'credential-material'
    if suffix in {'.log', '.jsonl'}:
        return 'history-or-log'
    if suffix in {'.docx', '.pdf', '.xlsx', '.xlsm', '.pptx', '.msg'}:
        return 'document'
    if suffix in {'.json', '.toml', '.config', '.ini', '.env', '.yaml', '.yml', '.properties'}:
        return 'configuration'
    if suffix in {'.py', '.cs', '.ts', '.tsx', '.js', '.sql', '.ps1', '.sh', '.go'}:
        return 'source-code'
    return 'other'

