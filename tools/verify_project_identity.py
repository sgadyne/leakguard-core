#!/usr/bin/env python3
"""Compare synthetic qualification project modules and resources to wheels."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sysconfig
import zipfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--wheelhouse', type=Path, required=True)
    args = p.parse_args()
    source = args.source.resolve(strict=True)
    roots = {
        'leakguard_core': source/'src/leakguard_core',
        'leakguard_vault': source/'packages/leakguard_vault/src/leakguard_vault',
        'leakguard_broker': source/'packages/leakguard_broker/src/leakguard_broker',
        'leakguard_host': source/'packages/leakguard_host/src/leakguard_host',
        'presidio_detector': source/'plugins/presidio_detector/src/presidio_detector',
        'jose_recognizers': source/'plugins/jose_recognizers/src/jose_recognizers',
        'firm_presidio_recognizer': source/'plugins/presidio_detector/examples/firm_presidio_recognizer/src/firm_presidio_recognizer',
        'sensitive_basics': source/'plugins/sensitive_basics/src/sensitive_basics',
        'firm_plugin': source/'templates/firm_plugin/src/firm_plugin',
    }
    wheelhouse = args.wheelhouse.resolve(strict=True)
    wheels = sorted(wheelhouse.glob('*.whl'))
    spec = importlib.util.spec_from_file_location('_identity_helpers', source/'tools/installed_acceptance.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    site = Path(sysconfig.get_paths()['purelib']).resolve()
    if site.is_relative_to(source):
        raise SystemExit('installed-site-inside-source')
    identity = helper._project_python_identity(roots, wheels, site)
    if any(not row['source_equals_wheel'] or not row['wheel_equals_installed'] for row in identity.values()):
        raise SystemExit('project-python-mismatch')
    required = {'leakguard_core/rules.toml', 'presidio_detector/cases.json',
                'presidio_detector/leakguard-plugin.json', 'jose_recognizers/py.typed',
                'sensitive_basics/cases.json', 'sensitive_basics/leakguard-plugin.json',
                'firm_plugin/cases.json', 'firm_plugin/leakguard-plugin.json'}
    resources = {}
    for name, row in identity.items():
        wheel = wheelhouse/row['wheel']
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.namelist():
                if not member.startswith(name + '/') or member.endswith(('/', '.py')):
                    continue
                rel = member[len(name)+1:]
                expected = hashlib.sha256(archive.read(member)).hexdigest()
                if hashlib.sha256((roots[name]/rel).read_bytes()).hexdigest() != expected or hashlib.sha256((site/member).read_bytes()).hexdigest() != expected:
                    raise SystemExit('project-resource-mismatch')
                resources[member] = expected
    if not required <= set(resources):
        raise SystemExit('required-resources-missing')
    print(json.dumps({'status':'passed','project_python_identity':identity,
                      'project_resource_sha256':resources}, sort_keys=True))


if __name__ == '__main__':
    main()
