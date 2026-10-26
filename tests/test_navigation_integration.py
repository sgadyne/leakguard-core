"""Navigation shares core coverage, exclusion and resumable-directory policy."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, models as m


ROOT = Path(__file__).resolve().parents[1]
HELPER = Path(os.environ.get('LEAKGUARD_SCAN_WALKER', str(
    ROOT / 'native/scan_walk/target/release/leakguard-scan-walk')))


@unittest.skipUnless(os.name == 'posix' and HELPER.is_file(), 'optional POSIX helper not built')
class NavigationIntegrationTests(unittest.TestCase):
    def test_core_parity_hidden_ignored_hardlink_alias_and_cycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / 'selected'; root.mkdir()
            (root / '.gitignore').write_text('*.env\n')
            (root / '.hidden.env').write_text('synthetic-only')
            (root / 'nested').mkdir()
            (root / 'nested/ordinary.txt').write_text('synthetic-only')
            os.link(root / '.hidden.env', root / 'hardlink.env')
            (root / 'cycle').symlink_to(root, target_is_directory=True)
            # Alias ancestors remain valid while linked descendants are refused.
            (parent / 'alias').symlink_to(parent, target_is_directory=True)
            selected = parent / 'alias/selected'
            signatures = []
            with patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', True)), patch.object(backends, 'detect', return_value=()):
                for helper in (None, str(HELPER)):
                    with_service = engine.ScanService({'navigation_helper': helper,
                        'navigation_same_filesystem': True, 'scan_workers': 1})
                    process = with_service._navigation._process
                    try:
                        report = with_service.scan_paths([selected], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(5, 10))
                        signatures.append(sorted((Path(r.source.path).relative_to(selected).as_posix(),
                            r.content.digest if r.content else None, r.coverage.value,
                            tuple(i.code.value for i in r.issues)) for r in report.results))
                        self.assertFalse(report.coverage.required_complete)  # Refused cyclic link.
                    finally:
                        with_service.close()
                    if process is not None:
                        self.assertIsNotNone(process.poll())
            self.assertEqual(signatures[0], signatures[1])
            names = {row[0] for row in signatures[0]}
            self.assertEqual(names, {'.gitignore', '.hidden.env', 'hardlink.env', 'nested/ordinary.txt', 'cycle'})

    def test_requested_helper_failure_is_incomplete_and_never_falls_back(self):
        with tempfile.TemporaryDirectory() as temporary, patch('leakguard_core.scan_policy.runtime_identity', return_value=('synthetic', True)), patch.object(backends, 'detect', return_value=()):
            root = Path(temporary); (root / 'item.txt').write_text('synthetic')
            service = engine.ScanService({'navigation_helper': str(HELPER)})
            try:
                process = service._navigation._process
                process.kill(); process.wait(timeout=2)
                with patch.object(service._navigation, '_python_listing', side_effect=AssertionError('forbidden fallback')):
                    report = service.scan_paths([root], policy=m.ScanPolicy.inventory(), limits=m.ScanLimits(2, 10))
                self.assertFalse(report.coverage.required_complete)
                self.assertEqual(report.results, ())
                self.assertTrue(any(i.required for i in report.issues))
            finally:
                service.close()


if __name__ == '__main__':
    unittest.main()
