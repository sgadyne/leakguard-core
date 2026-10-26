"""Offline private extension installation and explicit profile activation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .extensions import ExtensionError, ExtensionRegistry, _json, _read, inspect_wheel


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ExtensionError('extension-arguments-invalid')


def main(argv=None):
    parser = _Parser(prog='leakguard-extensions', description=__doc__)
    parser.add_argument('--registry', type=Path, required=True, help='private absolute extension registry directory')
    parser.add_argument('--worker-policy', choices=['strict', 'supervised-alpha'], default='strict')
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='read wheel metadata without importing or installing it')
    inspect.add_argument('wheel', type=Path)
    install = commands.add_parser('install', help='install reviewed wheel into this private runtime, disabled initially')
    install.add_argument('wheel', type=Path)
    install.add_argument('--options', type=Path, help='optional JSON options file')
    install.add_argument('--cases', type=Path, help='reviewed option-specific conformance JSON; defaults to bundled cases')
    register = commands.add_parser('register-script', help='register a reviewed fixed-argv script, disabled initially')
    register.add_argument('spec', type=Path)
    register.add_argument('--cases', type=Path)
    commands.add_parser('list', help='list static metadata without importing extensions')
    for action in ('enable', 'disable'):
        command = commands.add_parser(action)
        command.add_argument('id')
        command.add_argument('--profile', choices=['credentials', 'sensitive', 'firm'], default='firm')
    check = commands.add_parser('check', help='explicitly load extension and run its bundled conformance cases')
    check.add_argument('id')
    export = commands.add_parser('export-profile', help='write a separate scan config with the selected profile')
    export.add_argument('--profile', choices=['credentials', 'sensitive', 'firm'], default='firm')
    export.add_argument('--base-config', type=Path)
    export.add_argument('--output', type=Path, required=True)
    try:
        args = parser.parse_args(argv)
        registry = ExtensionRegistry(args.registry)
        if args.command == 'inspect':
            metadata, cases, digest = inspect_wheel(args.wheel)
            result = {'metadata': metadata, 'sha256': digest, 'has_conformance': cases is not None}
        elif args.command == 'install':
            options = _json(_read(args.options)) if args.options else {}
            result = registry.install_wheel(args.wheel, options=options, cases=_json(_read(args.cases)) if args.cases else None)
        elif args.command == 'register-script':
            result = registry.register_script(_json(_read(args.spec)), cases=_json(_read(args.cases)) if args.cases else None)
        elif args.command == 'list':
            result = {'extensions': registry.list()}
        elif args.command == 'check':
            result = registry.check(args.id, worker_policy=args.worker_policy)
        elif args.command == 'enable':
            result = registry.enable(args.id, profile=args.profile, worker_policy=args.worker_policy)
        elif args.command == 'disable':
            result = registry.disable(args.id, profile=args.profile)
        else:
            from .settings import read_config, validate
            from .extensions import _atomic
            config = read_config(args.base_config) if args.base_config else validate({})
            config['extension_registry'] = str(args.registry)
            config['detection_profile'] = args.profile
            config['worker_policy'] = args.worker_policy
            # Resolve now to reject an invalid registry, but save only the
            # registry reference so later disable operations affect this profile.
            registry.apply(config, args.profile)
            _atomic(args.output, json.dumps(validate(config), ensure_ascii=True, sort_keys=True, indent=2).encode())
            result = {'profile': args.profile, 'config_written': str(args.output), 'extensions_enabled':
                      sum(args.profile in row['profiles'] for row in registry.list())}
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
        return 1 if result.get('passed') is False else 0
    except Exception as error:
        code = error.code if isinstance(error, ExtensionError) else 'extension-operation-failed'
        print(json.dumps({'error': code}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
