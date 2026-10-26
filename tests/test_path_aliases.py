"""Ancestor aliases preserve logical paths and remain fenced by target identity."""
import os
from pathlib import Path
import tempfile
import unittest

from leakguard_core.sources import capture_anchor, confirm_absence


@unittest.skipIf(os.name == 'nt', 'native Windows alias semantics require its runner')
class PathAliasTests(unittest.TestCase):
    def test_alias_anchor_can_prove_absence_in_the_same_directory(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-path-alias-') as temporary:
            base = Path(temporary)
            actual = base / 'actual'
            actual.mkdir()
            alias = base / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            root = alias / 'scope'
            root.mkdir()
            source = root / 'candidate.txt'
            source.write_text('synthetic')
            anchor = capture_anchor(source)
            self.assertEqual(anchor.source_path, str(source.absolute()))
            self.assertTrue(anchor.valid())
            source.unlink()
            self.assertTrue(confirm_absence(source, root, anchor).valid())

    def test_retargeted_alias_cannot_prove_absence(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-path-retarget-') as temporary:
            base = Path(temporary)
            actual = base / 'actual'
            other = base / 'other'
            actual.mkdir()
            other.mkdir()
            alias = base / 'alias'
            alias.symlink_to(actual, target_is_directory=True)
            source = alias / 'candidate.txt'
            source.write_text('synthetic')
            anchor = capture_anchor(source)
            source.unlink()
            alias.unlink()
            alias.symlink_to(other, target_is_directory=True)
            self.assertFalse(anchor.valid())
