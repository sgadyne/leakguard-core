"""Explicit configuration for optional native recognizer coverage.

Composing a profile neither imports Presidio nor installs a dependency. The
normal supervised plugin preflight remains responsible for availability.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import settings


JOSE_FACTORY = 'jose_recognizers.plugin:build_recognizers'
JOSE_ENTITIES = ('JOSE_COMPACT_JWE', 'JOSE_COMPACT_JWS_CANDIDATE', 'JOSE_COMPACT_UNVERIFIED')
PII_ENTITIES = ('EMAIL_ADDRESS', 'PHONE_NUMBER', 'CREDIT_CARD', 'US_SSN', 'IBAN_CODE', 'IP_ADDRESS')
PROFILES = ('credentials', 'sensitive', 'firm')


def compose(profile: str, base: dict | None = None, *, healthcare: bool = False) -> dict:
    """Return a detached explicit config, retaining existing firm factories.

    All named native profiles cover JOSE. Sensitive and firm additionally select
    bounded PII presets; changing the name in an existing config does not itself
    recompose that config. Re-run this explicit operation when changing coverage.
    """
    if profile not in PROFILES or type(healthcare) is not bool or healthcare and profile == 'credentials':
        raise settings.ConfigurationError('detection_profile')
    config = settings.validate({} if base is None else base)
    config['detection_profile'] = profile
    matches = [spec for spec in config['plugins'] if spec['module'] == 'presidio_detector.plugin']
    if len(matches) > 1:
        raise settings.ConfigurationError('plugins')
    if matches:
        spec = matches[0]
        options = spec.setdefault('options', {})
    else:
        spec = {'module': 'presidio_detector.plugin', 'options': {}}
        config['plugins'].append(spec)
        options = spec['options']

    # Keep existing operator choices and custom entity/factory dependencies.
    defaults = list(PII_ENTITIES) if profile != 'credentials' or matches else []
    entities = options.setdefault('entities', defaults)
    modules = options.setdefault('recognizer-modules', [])
    presets = options.setdefault('presets', [])
    for values in (entities, modules, presets):
        if type(values) is not list or any(type(value) is not str for value in values):
            raise settings.ConfigurationError('plugins')
    for entity in JOSE_ENTITIES:
        if entity not in entities:
            entities.append(entity)
    if JOSE_FACTORY not in modules:
        modules.append(JOSE_FACTORY)
    if profile in ('sensitive', 'firm'):
        for preset in ('financial', 'identity'):
            if preset not in presets:
                presets.append(preset)
    if healthcare and 'healthcare' not in presets:
        presets.append('healthcare')
    options.setdefault('ner-mode', 'pattern-only')
    options.setdefault('score-threshold', '0.35')
    options.setdefault('block-entities', [])
    return settings.validate(config)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Write an explicit optional Presidio/JOSE profile; no installation or scan.')
    parser.add_argument('--profile', choices=PROFILES, required=True)
    parser.add_argument('--base-config', type=Path)
    parser.add_argument('--healthcare', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        base = settings.read_config(args.base_config) if args.base_config else None
        config = compose(args.profile, base, healthcare=args.healthcare)
        payload = (json.dumps(config, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')
        # Never replace an existing profile implicitly. Base options can contain
        # firm-specific settings, so the new file is private from creation.
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as target:
            target.write(payload)
    except (OSError, ValueError, TypeError, RecursionError):
        parser.exit(2, 'recognizer-profile-configuration-failed\n')
    print(json.dumps({'profile': args.profile, 'jose_configured': True,
                      'runtime_checked': False, 'dependencies_installed': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
