"""Behavior-bearing bytes must change runtime identity even when labels stay put."""
from __future__ import annotations

import importlib
import hashlib
import os
from pathlib import Path
from pathlib import PurePosixPath
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from leakguard_core import scan_policy
from leakguard_core.sources import acquire_file


class RuntimeIdentityTests(unittest.TestCase):
    def preserve_mtime_write(self, path: Path, value: bytes) -> None:
        previous = path.stat()
        path.write_bytes(value)
        os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))

    def test_script_bytes_change_identity_when_version_and_path_stay_fixed(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-script-identity-") as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            rules = root / "rules.toml"
            script = root / "check.py"
            binary.write_bytes(b"synthetic backend bytes")
            rules.write_text("title = 'fixture'\n", encoding="utf-8")
            first = b'__version__ = "1"\nVALUE = 1\n'
            second = b'__version__ = "1"\nVALUE = 2\n'
            self.assertEqual(len(first), len(second))
            script.write_bytes(first)
            spec = {"id": "fixture", "implementation_version": "1",
                    "argv": [sys.executable, str(script)], "rules": []}
            config = {"gitleaks_config": str(rules), "script_checks": [spec]}

            before, _ = scan_policy.runtime_identity(config, binary)
            self.preserve_mtime_write(script, second)
            after, _ = scan_policy.runtime_identity(config, binary)

        self.assertNotEqual(before, after)

    def test_module_bytes_change_identity_without_importing_the_module(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-module-identity-") as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            rules = root / "rules.toml"
            module = root / "fixture_extension.py"
            binary.write_bytes(b"synthetic backend bytes")
            rules.write_text("title = 'fixture'\n", encoding="utf-8")
            first = b'__version__ = "1"\nVALUE = 1\n'
            second = b'__version__ = "1"\nVALUE = 2\n'
            self.assertEqual(len(first), len(second))
            module.write_bytes(first)
            sys.path.insert(0, temporary)
            importlib.invalidate_caches()
            try:
                config = {"gitleaks_config": str(rules)}
                specs = [{"module": "fixture_extension", "options": {}}]
                before, _ = scan_policy.runtime_identity(config, binary, specs)
                self.preserve_mtime_write(module, second)
                after, _ = scan_policy.runtime_identity(config, binary, specs)
            finally:
                sys.path.remove(temporary)
                sys.path_importer_cache.pop(temporary, None)

        self.assertNotEqual(before, after)

    def test_binary_bytes_change_identity_even_if_path_and_mtime_are_fixed(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-binary-identity-") as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            rules = root / "rules.toml"
            rules.write_text("title = 'fixture'\n", encoding="utf-8")
            first = b"synthetic backend version 1"
            second = b"synthetic backend version 2"
            self.assertEqual(len(first), len(second))
            binary.write_bytes(first)
            before, _ = scan_policy.runtime_identity({"gitleaks_config": str(rules)}, binary)
            self.preserve_mtime_write(binary, second)
            after, _ = scan_policy.runtime_identity({"gitleaks_config": str(rules)}, binary)

        self.assertNotEqual(before, after)

    def test_input_content_identity_and_snapshot_validation_ignore_size_mtime_cache(self):
        with tempfile.TemporaryDirectory(prefix="leakguard-input-identity-") as temporary:
            path = Path(temporary) / "input.txt"
            path.write_bytes(b"first")
            original = path.stat()
            snapshot = acquire_file(path, max_bytes=1024)

            self.preserve_mtime_write(path, b"other")
            changed = path.stat()
            self.assertEqual(changed.st_size, original.st_size)
            self.assertEqual(changed.st_mtime_ns, original.st_mtime_ns)
            self.assertFalse(snapshot.valid())
            refreshed = acquire_file(path, max_bytes=1024)

        self.assertNotEqual(snapshot.content.digest, refreshed.content.digest)

    def test_expired_deadline_and_cancellation_abort_with_fixed_codes(self):
        from leakguard_core.scan_policy import RuntimeIdentityError

        started = time.monotonic()
        with self.assertRaises(RuntimeIdentityError) as expired:
            scan_policy.runtime_identity(deadline=started - 1)
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertEqual(expired.exception.code, 'budget-exhausted')
        self.assertEqual(str(expired.exception), 'budget-exhausted')

        started = time.monotonic()
        with self.assertRaises(RuntimeIdentityError) as cancelled:
            scan_policy.runtime_identity(deadline=time.monotonic() + 10, cancel=lambda: True)
        self.assertLess(time.monotonic() - started, 0.2)
        self.assertEqual(cancelled.exception.code, 'cancelled')
        self.assertEqual(str(cancelled.exception), 'cancelled')

    def test_runtime_identity_caps_artifact_reads_and_discovery(self):
        from leakguard_core.scan_policy import RuntimeIdentityError

        with tempfile.TemporaryDirectory(prefix='leakguard-large-artifact-') as temporary:
            artifact = Path(temporary) / 'artifact.bin'
            artifact.write_bytes(b'small synthetic artifact')
            real_fstat = os.fstat

            def oversized_fstat(descriptor):
                observed = real_fstat(descriptor)
                fields = list(observed)
                fields[stat.ST_SIZE] = 512 * 1024 * 1024 + 1
                return os.stat_result(fields)

            with patch.object(scan_policy.os, 'fstat', side_effect=oversized_fstat) as fstat:
                self.assertEqual(scan_policy._file_identity(artifact), 'unavailable')
            fstat.assert_called()

        budget = scan_policy._IdentityBudget(time.monotonic() + 10, None)
        with self.assertRaises(RuntimeIdentityError):
            budget.admit(1_073_741_825)

        class Entry:
            name = 'one.py'
            path = 'synthetic-root/one.py'

            def is_dir(self, *, follow_symlinks=False):
                return False

            def is_file(self, *, follow_symlinks=False):
                return True

        class Entries:
            def __enter__(self):
                return iter((Entry(),))

            def __exit__(self, *args):
                return False

        budget = scan_policy._IdentityBudget(time.monotonic() + 10, None)
        budget.entries = 100_000
        token = scan_policy._IDENTITY_BUDGET.set(budget)
        try:
            with patch.object(scan_policy.os, 'scandir', return_value=Entries()):
                with self.assertRaises(RuntimeIdentityError) as error:
                    scan_policy._python_files(Path('synthetic-root'))
        finally:
            scan_policy._IDENTITY_BUDGET.reset(token)
        self.assertEqual(error.exception.code, 'budget-exhausted')

    @unittest.skipIf(os.name == 'nt', 'POSIX FIFO race regression')
    def test_regular_artifact_replaced_by_fifo_at_open_is_nonblocking(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-artifact-race-') as temporary:
            artifact = Path(temporary).resolve() / 'artifact.bin'
            artifact.write_bytes(b'synthetic artifact before race')
            script = r'''
import os
from pathlib import Path
import sys
from leakguard_core import scan_policy

artifact = Path(sys.argv[1])
real_open = os.open
def replace_then_open(path, flags, *args, **kwargs):
    if os.fspath(path) == str(artifact):
        artifact.unlink()
        os.mkfifo(artifact)
        if not flags & getattr(os, 'O_NONBLOCK', 0):
            raise AssertionError('artifact open must be nonblocking')
    return real_open(path, flags, *args, **kwargs)

scan_policy.os.open = replace_then_open
print(scan_policy._file_identity(artifact))
'''
            child_env = dict(os.environ)
            completed = subprocess.run(
                [sys.executable, '-c', script, str(artifact)],
                capture_output=True, timeout=2, check=False, env=child_env,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode('utf-8', 'replace'))
        self.assertEqual(completed.stdout.strip(), b'unavailable')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlink unavailable')
    def test_artifact_symlink_hashes_target_and_tracks_target_changes(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-symlink-artifact-') as temporary:
            root = Path(temporary)
            target = root / 'real-artifact.py'
            alias = root / 'artifact-alias.py'
            first = b'synthetic runtime artifact one\n'
            second = b'synthetic runtime artifact two\n'
            target.write_bytes(first)
            try:
                alias.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation unavailable')

            first_identity = scan_policy._file_identity(alias)
            self.assertEqual(first_identity, hashlib.sha256(first).hexdigest())
            target.write_bytes(second)
            second_identity = scan_policy._file_identity(alias)

        self.assertEqual(second_identity, hashlib.sha256(second).hexdigest())
        self.assertNotEqual(first_identity, second_identity)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlink unavailable')
    def test_package_directory_symlink_is_unknown_without_traversal(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-package-link-') as temporary:
            root = Path(temporary)
            package_tree = root / 'core'
            external_tree = root / 'external'
            package_tree.mkdir()
            external_tree.mkdir()
            (package_tree / 'visible.py').write_text('VALUE = 1\n', encoding='utf-8')
            hidden = external_tree / 'hidden.py'
            hidden.write_text('VALUE = 2\n', encoding='utf-8')
            linked_directory = package_tree / 'linked-package'
            try:
                linked_directory.symlink_to(external_tree, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation unavailable')

            artifacts = scan_policy._python_files(package_tree)
            self.assertIn(linked_directory, artifacts)
            self.assertNotIn(hidden, artifacts)
            self.assertEqual(scan_policy._file_identity(linked_directory), 'unavailable')

            binary = root / 'synthetic-backend'
            binary.write_bytes(b'synthetic scanner bytes')
            module_file = package_tree / 'scan_policy.py'
            module_file.write_text('# synthetic module root marker\n', encoding='utf-8')
            config = {'gitleaks_config': str(Path(scan_policy.__file__).resolve().parent / 'rules.toml')}
            with patch.object(scan_policy, '__file__', str(module_file)), \
                    patch.object(scan_policy, '_dependency_closure', return_value=([], True)):
                _identity, eligible = scan_policy.runtime_identity(config, binary)
            self.assertFalse(eligible)

    def test_distribution_artifact_bytes_change_runtime_identity(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-package-identity-') as temporary:
            root = Path(temporary)
            binary = root / 'gitleaks'
            rules = root / 'rules.toml'
            artifact = root / 'packaging.py'
            binary.write_bytes(b'synthetic scanner v1')
            rules.write_text("title = 'fixture'\n", encoding='utf-8')
            artifact.write_bytes(b'package runtime bytes 1')

            class Distribution:
                version = '1.0'
                files = (PurePosixPath('packaging.py'),)
                requires = ()

                def locate_file(self, entry):
                    self.assert_entry(entry)
                    return artifact

                @staticmethod
                def assert_entry(entry):
                    if str(entry) != 'packaging.py':
                        raise AssertionError('unexpected synthetic distribution entry')

            original = scan_policy.importlib.metadata.distribution

            def distribution(name):
                if name == 'packaging':
                    return Distribution()
                return original(name)

            config = {'gitleaks_config': str(rules)}
            with patch.object(scan_policy.importlib.metadata, 'distribution', side_effect=distribution):
                before, eligible_before = scan_policy.runtime_identity(config, binary)
                self.preserve_mtime_write(artifact, b'package runtime bytes 2')
                after, eligible_after = scan_policy.runtime_identity(config, binary)

        self.assertNotEqual(before, after)
        self.assertTrue(eligible_before)
        self.assertTrue(eligible_after)

    def test_unavailable_core_artifact_disables_persistent_reuse(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-core-identity-') as temporary:
            root = Path(temporary)
            binary = root / 'gitleaks'
            rules = root / 'rules.toml'
            binary.write_bytes(b'synthetic scanner')
            rules.write_text("title = 'fixture'\n", encoding='utf-8')
            original = scan_policy._file_identity
            core_artifact = Path(scan_policy.__file__).resolve().parent / 'models.py'

            def identity(path):
                if Path(path) == core_artifact:
                    return 'unavailable'
                return original(path)

            with patch.object(scan_policy, '_file_identity', side_effect=identity):
                digest, eligible = scan_policy.runtime_identity(
                    {'gitleaks_config': str(rules)}, binary,
                )

        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        self.assertFalse(eligible)


if __name__ == "__main__":
    unittest.main(verbosity=2)
