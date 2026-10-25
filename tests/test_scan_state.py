"""Synthetic regressions for identity, replay and durable scan state."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import engine, hooks


class ReplayTests(unittest.TestCase):
    def test_positive_replay_and_same_stat_content_change(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-state-') as folder:
            root = Path(folder)
            state = root / 'state'
            source = root / 'candidate.txt'
            source.write_bytes(b'first content')
            calls = []

            def scan(data, path, conn=None):
                calls.append(data)
                return engine.safe_findings([{'RuleID': 'literal-password', 'StartLine': 1}], path), 'scanned'

            with patch.object(engine, 'STATE', state), patch.object(engine, 'scan_blob', side_effect=scan):
                conn = engine.db()
                try:
                    first = engine.scan_file(source, conn)
                    warm = engine.scan_file(source, conn)
                    self.assertEqual(first['findings'], warm['findings'])
                    self.assertEqual(warm['status'], 'unchanged')
                    self.assertEqual(len(calls), 1)
                    before = source.stat()
                    source.write_bytes(b'other content')
                    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
                    changed = engine.scan_file(source, conn)
                    self.assertEqual(changed['status'], 'scanned')
                    self.assertEqual(len(calls), 2)
                finally:
                    conn.close()

    @unittest.skipIf(os.name == 'nt', 'POSIX mode bits')
    def test_install_and_upgrade_add_execute_bits_preserving_permissions(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-hooks-') as folder:
            root = Path(folder)
            hooks.install_at(root)
            for kind in ('pre-commit', 'pre-push'):
                target = root / kind
                self.assertTrue(target.stat().st_mode & 0o111)
                target.chmod(0o640)
            hooks.install_at(root)
            self.assertEqual((root / 'pre-commit').stat().st_mode & 0o777, 0o751)


if __name__ == '__main__':
    unittest.main()
