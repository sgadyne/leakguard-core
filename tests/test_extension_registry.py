"""Registry discovery is inert; explicit activation is checked and profile scoped."""
import hashlib
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from leakguard_core.extensions import ExtensionError, ExtensionRegistry, inspect_wheel


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
            metadata = {'schema_version': 1, 'id': 'example', 'api_version': 2, 'module': 'never_import_me',
                        'component': 'example', 'version': '1'}
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('never_import_me/__init__.py', 'raise RuntimeError("must not import")')
                archive.writestr('never_import_me/leakguard-plugin.json', json.dumps(metadata))
            with patch('leakguard_core.plugins.load', side_effect=AssertionError('discovery executed code')):
                found, cases, digest = inspect_wheel(wheel)
            self.assertEqual(found, metadata)
            self.assertIsNone(cases)
            self.assertEqual(digest, hashlib.sha256(wheel.read_bytes()).hexdigest())
            with zipfile.ZipFile(wheel, 'a') as archive:
                archive.writestr('../escape.py', '')
            with self.assertRaises(ExtensionError):
                inspect_wheel(wheel)

    def test_wheel_startup_hooks_are_rejected_without_import_or_install(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            wheel = Path(folder) / 'example-1-py3-none-any.whl'
            metadata = {'schema_version': 1, 'id': 'example', 'api_version': 2, 'module': 'example', 'version': '1'}
            startup_paths = ['bootstrap.pth', 'sitecustomize.py', 'usercustomize/__init__.py',
                             'example-1.data/purelib/bootstrap.pth',
                             'example-1.data/platlib/sitecustomize.cpython-311-x86_64-linux-gnu.so']
            for startup in startup_paths:
                with self.subTest(member=startup):
                    with zipfile.ZipFile(wheel, 'w') as archive:
                        archive.writestr('example/leakguard-plugin.json', json.dumps(metadata))
                        archive.writestr(startup, 'raise RuntimeError("must not execute")')
                    with patch('leakguard_core.plugins.load', side_effect=AssertionError('inspection imported code')), patch('subprocess.run', side_effect=AssertionError('inspection installed code')):
                        with self.assertRaises(ExtensionError) as failure:
                            inspect_wheel(wheel)
                    self.assertEqual(failure.exception.code, 'extension-startup-artifact')

    def test_script_activation_is_explicit_checked_profile_scoped_and_private(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            registry = ExtensionRegistry(Path(folder))
            spec = {'id': 'firm-check', 'argv': ['/private/runtime/python', '/private/firm/check.py'],
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
        from leakguard_core import extensions
        from subprocess import CompletedProcess
        with tempfile.TemporaryDirectory(prefix='leakguard-registry-') as folder:
            root = Path(folder)
            registry = ExtensionRegistry(root / 'registry')
            wheel = root / 'example-1-py3-none-any.whl'
            metadata = {'schema_version': 1, 'id': 'example', 'api_version': 2, 'module': 'example', 'version': '1'}
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('example/leakguard-plugin.json', json.dumps(metadata))
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
            with patch.object(extensions, '_private_python', return_value='/private/python'), patch.object(extensions.subprocess, 'run', return_value=CompletedProcess([], 0)), patch.object(extensions, '_atomic', side_effect=failed_publication):
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
