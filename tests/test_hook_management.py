"""Selected-repository install/restore keeps global Git configuration untouched."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from leakguard_core import hooks


class HookManagementTests(unittest.TestCase):
    def test_explicit_config_and_original_hook_survive_upgrade_and_uninstall(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-hook-manage-') as temporary:
            root = Path(temporary).resolve()
            repo = root / 'repository'
            subprocess.run(['git', '-c', 'init.templateDir=', 'init', '-q', str(repo)], check=True)
            target = repo / '.git/hooks/pre-commit'
            target.parent.mkdir(parents=True, exist_ok=True)
            original = b'#!/bin/sh\nexit 7\n'
            target.write_bytes(original)
            target.chmod(0o700)
            config = root / "profile's config.json"
            config.write_text('{"observation_backend":"encrypted"}')
            state = root / 'private state'
            first = hooks.install_repository(repo, config_path=config, state_dir=state)
            self.assertEqual(len(first['installed']), 2)
            self.assertIn(b'export LEAKGUARD_CONFIG=', target.read_bytes())
            hooks.install_repository(repo, config_path=config, state_dir=state)
            self.assertEqual(hooks.repository_status(repo)['managed'], ['pre-commit', 'pre-push'])
            self.assertEqual(len(hooks.uninstall_repository(repo)['uninstalled']), 2)
            self.assertEqual(target.read_bytes(), original)
            self.assertFalse((repo / '.git/hooks/pre-push').exists())
            self.assertEqual(hooks.repository_status(repo)['managed'], [])

    def test_inherited_external_hooks_path_is_not_mutated(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-hooks-shared-') as temporary:
            root = Path(temporary).resolve()
            repo = root / 'repository'
            shared = root / 'shared hooks'
            subprocess.run(['git', '-c', 'init.templateDir=', 'init', '-q', str(repo)], check=True)
            shared.mkdir()
            subprocess.run(['git', '-C', str(repo), 'config', '--local', 'core.hooksPath', str(shared)], check=True)
            with self.assertRaises(RuntimeError):
                hooks.install_repository(repo)
            self.assertEqual(list(shared.iterdir()), [])
