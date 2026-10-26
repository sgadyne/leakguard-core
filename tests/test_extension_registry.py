"""Registry discovery is inert; explicit activation is checked and profile scoped."""
import hashlib
import base64
import csv
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from leakguard_core import extensions
from leakguard_core.extensions import ExtensionError, ExtensionRegistry, inspect_wheel


def _write_wheel(path, *, extension_id='example', module='example', distribution='leakguard-example',
                 version='1.0', extra_files=None, component=None, record_mutation=None):
    metadata = {'schema_version': 1, 'id': extension_id, 'api_version': 2,
                'module': module, 'version': version}
    if component is not None:
        metadata['component'] = component
    dist_stem = f"{distribution.replace('-', '_')}-{version.replace('-', '_')}"
    info = f'{dist_stem}.dist-info'
    files = {f'{module}/__init__.py': 'raise RuntimeError("must not import")\n',
             f'{module}/leakguard-plugin.json': json.dumps(metadata),
             f'{info}/METADATA': f'Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n\n',
             f'{info}/WHEEL': 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n'}
    files.update(extra_files or {})
    rows = []
    for name, value in sorted(files.items()):
        content = value.encode('utf-8')
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode('ascii').rstrip('=')
        rows.append([name, f'sha256={digest}', str(len(content))])
    if record_mutation is not None:
        rows = record_mutation(rows)
    rows.append([f'{info}/RECORD', '', ''])
    record_stream = io.StringIO(newline='')
    csv.writer(record_stream, lineterminator='\n').writerows(rows)
    files[f'{info}/RECORD'] = record_stream.getvalue()
    with zipfile.ZipFile(path, 'w') as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return metadata


def _empty_inventory(details):
    destinations = []
    for row in details['files']:
        path = f"/private/runtime/{row['scheme']}/{row['relative']}"
        destinations.append({'scheme': row['scheme'], 'relative': row['relative'], 'path': path,
                             'path_key': extensions._path_key(path), 'exists': False, 'symlink': False,
                             'regular': False, 'sha256': None, 'owners': []})
    return {'prefix': '/private/runtime', 'scheme_roots': {}, 'stdlib_roots': [],
            'physical_roots': [], 'root_owners': {root: [] for root in details['payload_roots']},
            'destinations': destinations, 'matching_distributions': [], 'cache_files': [],
            'payload_roots': details['payload_roots'], 'root_files': [], 'expected_root_paths': []}


def _matching_inventory(details):
    inventory = _empty_inventory(details)
    name, version = details['distribution_name'], details['distribution_version']
    inventory['physical_roots'] = details['payload_roots']
    inventory['root_owners'] = {
        root: [{'name': name, 'version': version}] for root in details['payload_roots']
    }
    for row, destination in zip(details['files'], inventory['destinations']):
        destination.update({'exists': True, 'regular': True, 'sha256': row['sha256'],
                            'owners': [{'name': name, 'version': version, 'record_valid': True}]})
    payload = [(row, destination) for row, destination in zip(details['files'], inventory['destinations'])
               if row['payload']]
    paths = sorted(destination['path_key'] for _, destination in payload)
    inventory['expected_root_paths'] = paths
    inventory['root_files'] = [
        {'path_key': destination['path_key'], 'roots': details['payload_roots'],
         'symlink': False, 'regular': True,
         'owners': [{'name': name, 'version': version, 'record_valid': True}]}
        for _, destination in payload
    ]
    inventory['matching_distributions'] = [{
        'name': name, 'version': version, 'payload_paths': paths, 'payload_complete': True,
    }]
    return inventory


class RegistryTests(unittest.TestCase):
    def test_export_preserves_base_worker_policy_unless_explicitly_overridden(self):
        from leakguard_core.extension_cli import main
        with tempfile.TemporaryDirectory(prefix='leakguard-profile-policy-') as folder:
            root = Path(folder)
            registry = ExtensionRegistry(root / 'registry')
            registry.initialize()
            base = root / 'base.json'
            base.write_text(json.dumps({'worker_policy': 'supervised-alpha'}))
            output = root / 'firm.json'
            args = ['--registry', str(registry.directory), 'export-profile', '--profile', 'firm',
                    '--base-config', str(base), '--output', str(output)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            self.assertEqual(json.loads(output.read_text())['worker_policy'], 'supervised-alpha')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--worker-policy', 'strict', *args]), 0)
            self.assertEqual(json.loads(output.read_text())['worker_policy'], 'strict')

    def test_wheel_inspection_never_imports_code_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'example-1-py3-none-any.whl'
            metadata = _write_wheel(wheel, module='never_import_me', component='example',
                                    extra_files={'never_import_me/__init__.py':
                                                 'raise RuntimeError("must not import")'})
            with patch('leakguard_core.plugins.load', side_effect=AssertionError('discovery executed code')):
                found, cases, digest = inspect_wheel(wheel)
            self.assertEqual(found, metadata)
            self.assertIsNone(cases)
            self.assertEqual(digest, hashlib.sha256(wheel.read_bytes()).hexdigest())
            with zipfile.ZipFile(wheel, 'a') as archive:
                archive.writestr('../escape.py', '')
            with self.assertRaises(ExtensionError):
                inspect_wheel(wheel)

    def test_wheel_record_rejects_paths_duplicates_missing_payload_and_bad_digests(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-record-') as folder:
            root = Path(folder)
            scenarios = (
                ('record-traversal.whl', lambda rows: rows + [['../../outside', '', '']]),
                ('record-duplicate.whl', lambda rows: rows + [rows[0]]),
                ('record-missing.whl', lambda rows: [row for row in rows
                                                     if row[0] != 'example/__init__.py']),
                ('record-digest.whl', lambda rows: [
                    [row[0], 'sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', row[2]]
                    if row[0] == 'example/__init__.py' else row for row in rows]),
                ('record-size.whl', lambda rows: [
                    [row[0], row[1], str(int(row[2]) + 1)]
                    if row[0] == 'example/__init__.py' else row for row in rows]),
            )
            for filename, mutation in scenarios:
                with self.subTest(filename=filename):
                    wheel = root / filename
                    _write_wheel(wheel, record_mutation=mutation)
                    with self.assertRaises(ExtensionError) as failure:
                        inspect_wheel(wheel)
                    self.assertEqual(failure.exception.code, 'extension-wheel-invalid')

            signed = root / 'record-signed.whl'
            _write_wheel(signed, extra_files={
                'leakguard_example-1.0.dist-info/RECORD.jws': 'signature',
            })
            with self.assertRaises(ExtensionError) as failure:
                inspect_wheel(signed)
            self.assertEqual(failure.exception.code, 'extension-wheel-invalid')

    def test_capitalized_console_script_preserves_name_and_detects_casefold_collision(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-script-case-') as folder:
            wheel = Path(folder) / 'example.whl'
            _write_wheel(wheel, extra_files={
                'leakguard_example-1.0.dist-info/entry_points.txt':
                    '[console_scripts]\nHello=example:main\n',
            })
            details = extensions._wheel_details(wheel)
            self.assertEqual(details['script_names'], ['Hello'])
            inventory = _empty_inventory(details)
            for name in details['script_names']:
                for script in (name, name + '.exe', name + '-script.py'):
                    path = f"/private/runtime/scripts/{script}"
                    inventory['destinations'].append({
                        'scheme': 'scripts', 'relative': script, 'path': path,
                        'path_key': extensions._path_key(path), 'exists': False,
                        'symlink': False, 'regular': False, 'sha256': None, 'owners': [],
                    })
            lower_path = '/private/runtime/scripts/hello'
            inventory['destinations'].append({
                'scheme': 'scripts', 'relative': 'hello', 'path': lower_path,
                'path_key': extensions._path_key(lower_path), 'exists': False,
                'symlink': False, 'regular': False, 'sha256': None, 'owners': [],
            })
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(details, inventory)
            self.assertEqual(failure.exception.code, 'extension-wheel-invalid')

    def test_wheel_startup_hooks_are_rejected_without_import_or_install(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'example-1-py3-none-any.whl'
            startup_paths = ['bootstrap.pth', 'sitecustomize.py', 'usercustomize/__init__.py',
                             'leakguard_example-1.0.data/purelib/bootstrap.pth',
                             'leakguard_example-1.0.data/platlib/sitecustomize.cpython-311-x86_64-linux-gnu.so']
            for startup in startup_paths:
                with self.subTest(member=startup):
                    _write_wheel(wheel, extra_files={startup: 'raise RuntimeError("must not execute")'})
                    with patch('leakguard_core.plugins.load', side_effect=AssertionError('inspection imported code')), patch('subprocess.run', side_effect=AssertionError('inspection installed code')):
                        with self.assertRaises(ExtensionError) as failure:
                            inspect_wheel(wheel)
                    self.assertEqual(failure.exception.code, 'extension-startup-artifact')

    def test_wheel_layout_rejects_unknown_or_misbound_data_schemes(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'example.whl'
            for member in ('leakguard_example-1.0.data/unknown/payload.py',
                           'other-1.0.data/purelib/example/payload.py',
                           'leakguard_example-1.0.data/purelib/../outside.py'):
                with self.subTest(member=member):
                    _write_wheel(wheel, extra_files={member: 'payload = True\n'})
                    with self.assertRaises(ExtensionError):
                        inspect_wheel(wheel)

    def test_runtime_reserved_namespace_and_distribution_file_collisions_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            root = Path(folder)
            for module, standard in (('json', True), ('leakguard_core', False), ('buddy', False)):
                wheel = root / f'{module}.whl'
                _write_wheel(wheel, module=module)
                details = extensions._wheel_details(wheel)
                inventory = _empty_inventory(details)
                inventory['stdlib_roots'] = ['json'] if standard else []
                with self.subTest(module=module), self.assertRaises(ExtensionError) as failure:
                    extensions._guard_wheel_collisions(details, inventory)
                self.assertEqual(failure.exception.code, 'extension-conflict')

            wheel = root / 'example.whl'
            _write_wheel(wheel)
            details = extensions._wheel_details(wheel)
            inventory = _empty_inventory(details)
            first = inventory['destinations'][0]
            first.update({'exists': True, 'regular': True, 'sha256': 'a' * 64,
                          'owners': [{'name': 'leakguard-core', 'version': '0.2.0',
                                      'record_valid': True}]})
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(details, inventory)
            self.assertEqual(failure.exception.code, 'extension-conflict')

    def test_existing_unowned_module_root_and_script_are_protected(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            root = Path(folder)
            wheel = root / 'example.whl'
            _write_wheel(wheel)
            details = extensions._wheel_details(wheel)
            inventory = _empty_inventory(details)
            inventory['physical_roots'] = ['example']
            with self.assertRaises(ExtensionError):
                extensions._guard_wheel_collisions(details, inventory)

            script_wheel = root / 'script.whl'
            _write_wheel(script_wheel, extra_files={
                'leakguard_example-1.0.data/scripts/firm-command': '#!/bin/sh\n',
            })
            script_details = extensions._wheel_details(script_wheel)
            script_inventory = _empty_inventory(script_details)
            script_destination = next(
                item for item in script_inventory['destinations'] if item['scheme'] == 'scripts')
            script_destination.update({'exists': True, 'regular': True, 'sha256': 'b' * 64,
                                       'owners': [{'name': 'leakguard-host-tools', 'version': '2.0',
                                                   'record_valid': True}]})
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(script_details, script_inventory)
            self.assertEqual(failure.exception.code, 'extension-conflict')

    def test_data_scheme_cannot_smuggle_a_runtime_import_root(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'example.whl'
            _write_wheel(wheel, extra_files={
                'leakguard_example-1.0.data/data/lib/python3.11/site-packages/json/rogue.py':
                    'raise RuntimeError("shadow stdlib")\n',
            })
            details = extensions._wheel_details(wheel)
            self.assertTrue(any(row['scheme'] == 'data' for row in details['files']))
            inventory = _empty_inventory(details)
            # The runtime inventory derives this root from the mapped data-scheme
            # destination, which is importable on this standard venv layout.
            inventory['payload_roots'] = sorted(set(inventory['payload_roots']) | {'json'})
            inventory['stdlib_roots'] = ['json']
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(details, inventory)
            self.assertEqual(failure.exception.code, 'extension-conflict')

    def test_runtime_inventory_derives_import_roots_from_data_scheme(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            root = Path(folder)
            base_wheel = root / 'base.whl'
            _write_wheel(base_wheel)
            base_details = extensions._wheel_details(base_wheel)
            layout = extensions._runtime_inventory(sys.executable, base_details)
            data_root = layout['scheme_roots']['data']
            purelib = layout['scheme_roots']['purelib']
            try:
                relative_site = os.path.relpath(purelib, data_root).replace(os.sep, '/')
                if os.path.commonpath([os.path.realpath(data_root), os.path.realpath(purelib)]) != os.path.realpath(data_root):
                    self.skipTest('selected Python does not install purelib below its data scheme')
            except ValueError:
                self.skipTest('selected Python has separate data and purelib volumes')
            injected = root / 'smuggled.whl'
            _write_wheel(injected, extra_files={
                f'leakguard_example-1.0.data/data/{relative_site}/json/rogue.py':
                    'raise RuntimeError("shadow stdlib")\n',
            })
            details = extensions._wheel_details(injected)
            inventory = extensions._runtime_inventory(sys.executable, details)
            self.assertIn('json', inventory['payload_roots'])
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(details, inventory)
            self.assertEqual(failure.exception.code, 'extension-conflict')

    def test_unverifiable_bytecode_cache_blocks_install(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'example.whl'
            _write_wheel(wheel)
            details = extensions._wheel_details(wheel)
            inventory = _empty_inventory(details)
            inventory['cache_files'] = [{'path_key': '/private/runtime/site-packages/example/__pycache__/bad.pyc',
                                         'safe': False, 'in_cache_dir': True}]
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(details, inventory)
            self.assertEqual(failure.exception.code, 'extension-conflict')

    def test_registered_distribution_upgrade_is_allowed_but_legacy_collision_is_not(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'example.whl'
            _write_wheel(wheel)
            details = extensions._wheel_details(wheel)
            inventory = _empty_inventory(details)
            inventory['matching_distributions'] = [{
                'name': details['distribution_name'], 'version': '0.9',
                'payload_paths': [], 'payload_complete': True,
            }]
            inventory['physical_roots'] = ['example']
            inventory['root_owners']['example'] = [{'name': details['distribution_name'], 'version': '0.9'}]
            for destination in inventory['destinations']:
                destination.update({'exists': True, 'regular': True, 'sha256': 'c' * 64,
                                    'owners': [{'name': details['distribution_name'], 'version': '0.9',
                                                'record_valid': False}]})
            previous = {'id': 'example', 'kind': 'wheel',
                        'distribution_name': details['distribution_name'],
                        'distribution_version': '0.9'}
            extensions._guard_wheel_collisions(details, inventory, previous)
            inventory['root_files'] = [{
                'path_key': '/private/runtime/site-packages/example/injected.py',
                'roots': ['example'], 'symlink': False, 'regular': True, 'owners': [],
            }]
            with self.assertRaises(ExtensionError) as unowned:
                extensions._guard_wheel_collisions(details, inventory, previous)
            self.assertEqual(unowned.exception.code, 'extension-conflict')
            inventory['root_files'] = []
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(
                    details, inventory, {'id': 'example', 'kind': 'wheel'})
            self.assertEqual(failure.exception.code, 'extension-conflict')

    def test_initial_bundled_registration_requires_actual_byte_matching_install(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'firm.whl'
            _write_wheel(wheel, extension_id='firm-example', module='firm_plugin',
                         distribution='leakguard-firm-example', version='0.1.0')
            details = extensions._wheel_details(wheel)
            inventory = _matching_inventory(details)
            extensions._guard_wheel_collisions(details, inventory)

            payload_target = next(row for row in inventory['destinations'] if row['relative'].endswith('__init__.py'))
            payload_target['sha256'] = '0' * 64
            with self.assertRaises(ExtensionError) as failure:
                extensions._guard_wheel_collisions(details, inventory)
            self.assertEqual(failure.exception.code, 'extension-conflict')

    def test_preinstalled_first_party_wheel_registration_clears_bytecode_before_pip(self):
        from subprocess import CompletedProcess
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            root = Path(folder)
            wheel = root / 'firm.whl'
            _write_wheel(wheel, extension_id='firm-example', module='firm_plugin',
                         distribution='leakguard-firm-example', version='0.1.0')
            details = extensions._wheel_details(wheel)
            inventory = _matching_inventory(details)
            registry = ExtensionRegistry(root / 'registry')
            registry.initialize()
            events = []
            def clear(*args):
                events.append('clear')
            def pip(*args, **kwargs):
                events.append('pip')
                return CompletedProcess(args[0], 0, b'', b'')
            with patch.object(extensions, '_private_python', return_value='/private/python'), \
                    patch.object(extensions, '_runtime_inventory', return_value=inventory), \
                    patch.object(extensions, '_clear_plugin_bytecode', side_effect=clear), \
                    patch.object(extensions.subprocess, 'run', side_effect=pip):
                registered = registry.install_wheel(wheel)
            self.assertEqual(registered['id'], 'firm-example')
            self.assertEqual(events, ['clear', 'pip'])
            entry = registry._entry('firm-example')
            self.assertEqual(entry['distribution_name'], 'leakguard-firm-example')
            self.assertEqual(entry['distribution_version'], '0.1.0')

    def test_script_activation_is_explicit_checked_profile_scoped_and_private(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            registry = ExtensionRegistry(Path(folder))
            spec = {'id': 'firm-check', 'argv': [str(Path(sys.executable).absolute()), str(Path(folder) / 'check.py')],
                    'rules': [{'id': 'firm-code', 'minimum_severity': 'review'}]}
            with patch('leakguard_core.plugins.load_scripts', side_effect=AssertionError('registration executed code')):
                registered = registry.register_script(spec)
                listed = registry.list()
                credentials = registry.apply({}, 'credentials')
            self.assertEqual(registered['profiles'], [])
            self.assertEqual(listed, [registered])
            self.assertEqual(credentials['script_checks'], [])
            with patch.object(registry, 'check', return_value={'id': 'firm-check', 'passed': False}):
                with self.assertRaises(ExtensionError):
                    registry.enable('firm-check')
            self.assertEqual(registry.list()[0]['profiles'], [])
            with patch.object(registry, 'check', return_value={'id': 'firm-check', 'passed': True}):
                registry.enable('firm-check', profile='firm')
            self.assertEqual(registry.apply({}, 'firm')['script_checks'], [spec])
            self.assertEqual(registry.apply({}, 'credentials')['script_checks'], [])
            registry.disable('firm-check')
            self.assertEqual(registry.apply({}, 'firm')['script_checks'], [])
            if os.name == 'nt':
                # POSIX mode bits do not describe Windows confidentiality.
                # Check this private fixture's inherited DACL instead.
                script = '''
$ErrorActionPreference = 'Stop'
$allowed = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
$bad = @((Get-Acl -LiteralPath $env:LEAKGUARD_TEST_REGISTRY).Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed
})
if ($bad.Count -ne 0) { exit 1 }
'''
                checked = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                         text=True, capture_output=True, timeout=15,
                                         env=dict(os.environ, LEAKGUARD_TEST_REGISTRY=str(registry.path)))
                self.assertEqual(checked.returncode, 0, 'registry fixture grants access beyond its owner, SYSTEM and administrators')
            else:
                self.assertEqual(registry.path.stat().st_mode & 0o777, 0o600)
            registry.path.unlink()
            with self.assertRaises(ExtensionError):
                registry.apply({}, 'firm')

    def test_initialize_is_idempotent_but_never_recreates_lost_registry(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            registry = ExtensionRegistry(Path(folder) / 'extensions')
            registry.initialize()
            original = registry.path.read_bytes()
            registry.initialize()
            self.assertEqual(registry.path.read_bytes(), original)
            self.assertEqual(registry.apply({}, 'credentials')['plugins'], [])
            registry.path.unlink()
            with self.assertRaises(ExtensionError) as lost:
                registry.initialize()
            self.assertEqual(lost.exception.code, 'extension-unavailable')
            self.assertFalse(registry.path.exists())
            with self.assertRaises(ExtensionError):
                registry.apply({}, 'credentials')

    def test_runtime_requires_private_current_environment(self):
        from leakguard_core.extensions import _private_python
        import sys
        from subprocess import CompletedProcess
        with patch('subprocess.run', return_value=CompletedProcess([], 0, json.dumps(['/system', '/system']).encode())):
            with self.assertRaises(ExtensionError) as failed:
                _private_python(sys.executable)
            self.assertEqual(failed.exception.code, 'extension-private-runtime-required')

    def test_failed_upgrade_state_write_keeps_prior_version_disabled(self):
        from subprocess import CompletedProcess
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            root = Path(folder)
            registry = ExtensionRegistry(root / 'registry')
            wheel = root / 'example-1-py3-none-any.whl'
            metadata = _write_wheel(wheel)
            details = extensions._wheel_details(wheel)
            entry = {'id': 'example', 'kind': 'wheel', 'metadata': metadata, 'spec': {'module': 'example', 'options': {}},
                     'profiles': ['firm'], 'sha256': '0' * 64, 'cases': None}
            with registry._mutation() as value:
                value['extensions']['example'] = entry
            calls = []
            atomic = extensions._atomic
            def failed_publication(path, raw):
                calls.append(1)
                if len(calls) == 2:
                    raise ExtensionError('extension-state-failed')
                return atomic(path, raw)
            with patch.object(extensions, '_private_python', return_value='/private/python'), \
                    patch.object(extensions, '_runtime_inventory', return_value=_empty_inventory(details)), \
                    patch.object(extensions.subprocess, 'run', return_value=CompletedProcess([], 0)), \
                    patch.object(extensions, '_atomic', side_effect=failed_publication):
                with self.assertRaises(ExtensionError) as failure:
                    registry.install_wheel(wheel)
            self.assertEqual(failure.exception.code, 'extension-state-failed')
            self.assertEqual(registry.list()[0]['profiles'], [])
            self.assertEqual(list(registry.directory.glob('.install-*')), [])

    def test_kernel_lock_reports_busy_without_leaking_or_breaking_registry(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            registry = ExtensionRegistry(Path(folder))
            with registry._mutation():
                with self.assertRaises(ExtensionError) as busy:
                    with ExtensionRegistry(Path(folder))._mutation():
                        self.fail('second mutation acquired lock')
                self.assertEqual(busy.exception.code, 'extension-registry-busy')
            with registry._mutation():
                pass
            self.assertEqual(registry.list(), [])
