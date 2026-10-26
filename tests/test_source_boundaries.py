"""A persisted claim cannot read through a newly linked scope descendant."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import backends, engine, models as m
from leakguard_core.scan_store import MemoryScanStore
from leakguard_core.sources import AcquisitionError, FilesystemBoundary, acquire_file, capture_anchor, confirm_absence, scoped_scandir, _bounded_file


class RegularAcquisitionTests(unittest.TestCase):
    def test_regular_file_acquisition_preserves_native_metadata_checks(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-regular-acquisition-') as temporary:
            path = Path(temporary) / 'synthetic.txt'
            path.write_bytes(b'synthetic content')
            try:
                acquired = _bounded_file(path, 1024)
            except AcquisitionError as error:
                # Synthetic metadata makes native stat/fstat differences
                # diagnosable without exposing file contents or source paths.
                named = path.stat()
                with path.open('rb') as stream:
                    opened = os.fstat(stream.fileno())
                fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                self.fail(f'{error.code}: path={tuple(getattr(named, key) for key in fields)}, '
                          f'fd={tuple(getattr(opened, key) for key in fields)}')
            self.assertEqual(acquired, b'synthetic content')


@unittest.skipIf(os.name == 'nt', 'native Windows reparse validation requires its runner')
class SourceBoundaryTests(unittest.TestCase):
    def test_same_inode_link_cannot_authorize_out_of_scope_absence(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-absence-boundary-') as temporary:
            base = Path(temporary).resolve()
            root, outside = base / 'scope', base / 'outside'
            root.mkdir(); outside.mkdir()
            child = root / 'nested'; child.mkdir()
            source = child / 'candidate.txt'; source.write_text('synthetic')
            anchor = capture_anchor(source)
            source.unlink()
            proof = confirm_absence(source, root, anchor)
            self.assertTrue(proof.valid())
            moved = outside / 'nested'
            child.rename(moved)
            child.symlink_to(moved, target_is_directory=True)
            # Following inode identity alone would accept this replacement.
            self.assertTrue(anchor.valid())
            self.assertFalse(proof.valid())
            with self.assertRaises(AcquisitionError):
                confirm_absence(source, root, anchor)

    def test_changed_ancestor_rejected_before_source_read_or_directory_enumeration(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-boundary-') as temporary:
            base = Path(temporary).resolve()
            root, outside = base / 'scope', base / 'outside'
            root.mkdir(); outside.mkdir()
            child = root / 'nested'; child.mkdir()
            source = child / 'candidate.txt'; source.write_text('synthetic in scope')
            (outside / source.name).write_text('synthetic outside scope')
            boundary = FilesystemBoundary(root)
            child.rename(root / 'previous')
            child.symlink_to(outside, target_is_directory=True)
            with patch('leakguard_core.sources._bounded_file') as read:
                with self.assertRaises(AcquisitionError):
                    acquire_file(source, max_bytes=1000, boundary=boundary)
                read.assert_not_called()
            with patch('leakguard_core.sources.os.scandir') as enumerate_directory:
                with self.assertRaises(AcquisitionError):
                    with scoped_scandir(child, boundary):
                        pass
                enumerate_directory.assert_not_called()

    def test_resumed_audit_file_claim_rejects_ancestor_escape_before_read(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-resume-boundary-') as temporary:
            base = Path(temporary).resolve()
            root, outside = base / 'scope', base / 'outside'
            root.mkdir(); outside.mkdir()
            child = root / 'nested'; child.mkdir()
            source = child / 'candidate.txt'; source.write_text('synthetic in scope')
            (outside / source.name).write_text('synthetic outside scope')
            store = MemoryScanStore()
            lease = store.acquire_cycle('audit:selected', root, lease_seconds=30)
            store.enqueue_work(lease, [(str(source), 'file', 0)])
            store.release_cycle(lease, allow_complete=False)
            child.rename(root / 'previous')
            child.symlink_to(outside, target_is_directory=True)
            service = engine.ScanService({'audit_scopes': {'selected': str(root)}}, store=store)
            with patch('leakguard_core.sources._bounded_file', wraps=_bounded_file) as read, patch.object(backends, 'detect', return_value=()):
                result = service.audit('selected', limits=m.ScanLimits(10, 1))
                self.assertFalse(any(call.args and Path(call.args[0]) == source for call in read.call_args_list))
            self.assertFalse(result.coverage.required_complete)
            self.assertEqual(result.counts.findings, 0)
            service.close(); store.close()

    def test_selected_scope_below_an_ancestor_alias_still_reads_normally(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-ancestor-alias-') as temporary:
            base = Path(temporary).resolve()
            actual = base / 'actual'; actual.mkdir()
            alias = base / 'alias'; alias.symlink_to(actual, target_is_directory=True)
            root = alias / 'scope'; root.mkdir()
            source = root / 'candidate.txt'; source.write_text('synthetic')
            snapshot = acquire_file(source, max_bytes=100, boundary=FilesystemBoundary(root))
            self.assertEqual(snapshot.data, b'synthetic')
            self.assertTrue(snapshot.valid())
