#!/usr/bin/env python3
"""One synthetic installed extension journey in an explicitly owned private root.

Run via the shared heavy admission wrapper. The source is built into wheels;
only the new private virtual environment is modified. Receipts contain metadata
and finding IDs, never fixture text. All subprocess logs remain in the owned root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--gitleaks', type=Path, required=True)
    parser.add_argument('--uv', default='uv')
    args = parser.parse_args()
    root = args.work.absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    source = args.source.absolute()
    environment = {key: value for key, value in os.environ.items()
                   if key not in {'PYTHONPATH', 'PYTHONHOME', 'LEAKGUARD_CONFIG', 'LEAKGUARD_STATE_DIR', 'LEAKGUARD_GITLEAKS'}}
    environment['LEAKGUARD_STATE_DIR'] = str(root / 'state')
    environment['LEAKGUARD_GITLEAKS'] = str(args.gitleaks.absolute())
    environment['GIT_CONFIG_GLOBAL'] = os.devnull
    environment['GIT_CONFIG_NOSYSTEM'] = '1'
    steps = []
    started = time.monotonic()
    def run(label, command, *, accepted=(0,), timeout=120, decode=False):
        result = subprocess.run(list(map(str, command)), cwd=source, env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        steps.append({'id': label, 'exit_code': result.returncode})
        print(json.dumps(steps[-1]), flush=True)
        if result.returncode not in accepted:
            raise RuntimeError('journey-step-failed:' + label)
        return json.loads(result.stdout) if decode else result.stdout
    def write(name, value):
        path = root / name
        path.write_text(json.dumps(value), encoding='utf-8')
        path.chmod(0o600)
        return path
    receipt = {'schema_version': 1, 'passed': False, 'steps': steps}
    try:
        receipt['source_commit'] = run('source-commit', ['git', 'rev-parse', 'HEAD']).decode().strip()
        run('private-runtime', [args.uv, 'venv', '--python', sys.executable, root / 'runtime'])
        python = root / 'runtime' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        run('private-build-dependencies', [args.uv, 'pip', 'install', '--python', python, '--no-deps',
                                          'pip==25.3', 'setuptools==80.9.0', 'wheel==0.45.1', 'packaging==26.0', 'psutil==7.2.2'])
        wheels = root / 'wheels'; wheels.mkdir()
        for label, project in [('core', source), ('sensitive', source / 'plugins/sensitive_basics'), ('firm', source / 'templates/firm_plugin')]:
            run('build-' + label, [python, '-I', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-index',
                                   '--wheel-dir', wheels, project])
        core = next(wheels.glob('leakguard_core-*.whl'))
        firm = next(wheels.glob('leakguard_firm_example-*.whl'))
        sensitive = next(wheels.glob('leakguard_sensitive_basics-*.whl'))
        run('install-core', [python, '-I', '-m', 'pip', 'install', '--no-index', '--no-deps', core])
        registry = root / 'registry'
        ext = [python, '-I', '-m', 'leakguard_core.extension_cli', '--registry', registry]
        for label, wheel in [('firm', firm), ('sensitive', sensitive)]:
            run('inspect-' + label, [*ext, 'inspect', wheel], decode=True)
            installed = run('install-' + label, [*ext, 'install', wheel], decode=True)
            assert installed['profiles'] == []
        listed = run('list-disabled', [*ext, 'list'], decode=True)
        assert all(not item['profiles'] for item in listed['extensions'])
        for extension in ['firm-example', 'sensitive-basics']:
            checked = run('check-' + extension, [*ext, 'check', extension], decode=True)
            assert checked['passed']
        run('enable-firm', [*ext, 'enable', 'firm-example', '--profile', 'firm'], decode=True)
        run('enable-sensitive', [*ext, 'enable', 'sensitive-basics', '--profile', 'sensitive'], decode=True)
        run('enable-sensitive-firm', [*ext, 'enable', 'sensitive-basics', '--profile', 'firm'], decode=True)
        base = write('base.json', {'gitleaks_executable': str(args.gitleaks.absolute()), 'observation_backend': 'encrypted'})
        configurations = {}
        for profile in ['credentials', 'sensitive', 'firm']:
            configurations[profile] = root / (profile + '.json')
            run('export-' + profile, [*ext, 'export-profile', '--profile', profile, '--base-config', base,
                                      '--output', configurations[profile]], decode=True)
        fixture = root / 'sample.txt'
        fixture.write_text('customer_id: ACME-CUST-004812\nCONFIDENTIAL - synthetic demo record\ncustomer_email=alex@example.invalid\n')
        def scan(label, profile, expected, *, block=False):
            command = [python, '-I', '-m', 'leakguard_core', 'scan', '--config', configurations[profile],
                       '--state-dir', root / 'state', '--format', 'json', '--budget-seconds', '30', '--max-files', '1', fixture]
            if block:
                command += ['--fail-on', 'block']
            report = run(label, command, accepted=(1,) if block else (0,), decode=True)
            findings = [finding for result in report['results'] for finding in result['findings']]
            assert {finding['rule'] for finding in findings} == set(expected)
            assert report['coverage']['required_complete']
            serialized = json.dumps(report)
            assert all(value not in serialized for value in ['ACME-CUST-004812', 'alex@example.invalid', 'synthetic demo record'])
            return findings
        scan('scan-credentials', 'credentials', [])
        scan('scan-sensitive', 'sensitive', ['pii-contact-email'])
        scan('scan-firm', 'firm', ['firm-customer-number', 'firm-confidentiality-marker', 'pii-contact-email'])
        run('disable-firm', [*ext, 'disable', 'firm-example', '--profile', 'firm'], decode=True)
        scan('scan-disabled-firm', 'firm', ['pii-contact-email'])
        run('disable-sensitive-firm', [*ext, 'disable', 'sensitive-basics', '--profile', 'firm'], decode=True)
        scan('scan-disabled-all', 'firm', [])
        promoted_cases = json.loads((source / 'templates/firm_plugin/src/firm_plugin/cases.json').read_text())
        for case in promoted_cases['cases']:
            for finding in case.get('expected_findings', []):
                if finding['rule'] == 'firm-customer-number':
                    finding['severity'] = 'block'
        options = write('promoted-options.json', {'promote-rules': ['firm-customer-number']})
        cases = write('promoted-cases.json', promoted_cases)
        run('install-promoted-firm', [*ext, 'install', firm, '--options', options, '--cases', cases], decode=True)
        run('check-promoted-firm', [*ext, 'check', 'firm-example'], decode=True)
        run('enable-promoted-firm', [*ext, 'enable', 'firm-example', '--profile', 'firm'], decode=True)
        findings = scan('scan-promoted-firm', 'firm', ['firm-customer-number', 'firm-confidentiality-marker'], block=True)
        assert next(f for f in findings if f['rule'] == 'firm-customer-number')['severity'] == 'block'
        assert not list((root / 'state').rglob('*.sqlite3*'))
        receipt.update(passed=True, platform=sys.platform, python=sys.version.split()[0],
                       conformance_cases={'firm': 4, 'sensitive': 16},
                       checks=['private-install', 'inert-discovery', 'explicit-activation', 'profile-isolation',
                               'disable-future-scans', 'option-specific-conformance', 'promoted-rule-blocks',
                               'value-free-reports', 'no-plaintext-observation-fallback'],
                       artifacts=[{'path': str(wheel), 'sha256': hashlib.sha256(wheel.read_bytes()).hexdigest()} for wheel in sorted(wheels.glob('*.whl'))])
    except Exception as error:
        receipt['failure'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    finally:
        receipt['elapsed_seconds'] = round(time.monotonic() - started, 3)
        write('receipt.json', receipt)
        print(json.dumps({'passed': receipt['passed'], 'receipt': str(root / 'receipt.json')}), flush=True)
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
