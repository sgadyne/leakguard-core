"""Redacted new-observation revision is durable and transactionally fenced."""
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from leakguard_core import models as m
from leakguard_core.scan_store import SQLiteScanStore, StateError


def result(present=True):
    source = m.SourceRef(m.SourceKind.FILESYSTEM, "/synthetic/revision.txt")
    now = datetime.now(timezone.utc)
    finding = m.FindingRecord("1" * 64, source, "text", 1, 1, "synthetic", "synthetic", m.DetectorSeverity.BLOCK, m.FindingSeverity.BLOCK, m.FindingClassification.CREDENTIAL_CANDIDATE)
    return m.ScanResult(source, m.ContentIdentity("sha256", "0" * 64, 1), m.RuntimeIdentity("policy", "runtime", "context", True), m.ScanOutcome.SCANNED, m.CoverageState.COMPLETE, (finding,) if present else (), (), now, now, now)


def record(store, value):
    store.record_result(value, generation=store.reserve(value.source))


class FindingRevisionTests(unittest.TestCase):
    def test_first_repeat_resolve_reappear_and_reopen(self):
        with TemporaryDirectory() as directory:
            store = SQLiteScanStore(Path(directory))
            self.assertEqual(store.finding_revision(), 0)
            record(store, result())
            record(store, result())
            self.assertEqual(store.finding_revision(), 1)
            record(store, result(False))
            self.assertEqual(store.finding_revision(), 1)
            record(store, result())
            self.assertEqual(store.finding_revision(), 2)
            store.close()
            store = SQLiteScanStore(Path(directory))
            self.assertEqual(store.finding_revision(), 2)
            store.close()

    def test_late_generation_and_transaction_rollback_do_not_increment(self):
        with TemporaryDirectory() as directory:
            store = SQLiteScanStore(Path(directory))
            positive = result()
            old = store.reserve(positive.source)
            store.reserve(positive.source)
            store.record_result(positive, generation=old)
            self.assertEqual(store.finding_revision(), 0)
            store.conn.execute("CREATE TRIGGER reject_current BEFORE INSERT ON finding_current BEGIN SELECT RAISE(ABORT, 'synthetic'); END")
            store.conn.commit()
            with self.assertRaises(StateError):
                record(store, positive)
            self.assertEqual(store.finding_revision(), 0)
            store.close()

    def test_existing_encrypted_profile_migrates_without_old_alert(self):
        from leakguard_vault import EncryptedScanStore
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.lgo"
            store = EncryptedScanStore.create(path, "synthetic-only-phrase")
            record(store, result())
            store._store.conn.execute("DROP TABLE finding_revision")
            store._store.conn.commit()
            store.checkpoint()
            store.close()
            store = EncryptedScanStore.open(path, "synthetic-only-phrase")
            self.assertEqual(store.finding_revision(), 0)
            record(store, result())
            self.assertEqual(store.finding_revision(), 0)
            record(store, result(False))
            record(store, result())
            self.assertEqual(store.finding_revision(), 1)
            store.save_host_state({"test": True})
            store.close()
            store = EncryptedScanStore.open(path, "synthetic-only-phrase")
            self.assertEqual(store.finding_revision(), 1)
            store.close()

    def test_encrypted_checkpoint_and_reopen(self):
        from leakguard_vault import EncryptedScanStore
        with TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.lgo"
            store = EncryptedScanStore.create(path, "synthetic-only-phrase")
            record(store, result())
            self.assertEqual(store.finding_revision(), 1)
            store.save_host_state({"test": True})
            store.close()
            store = EncryptedScanStore.open(path, "synthetic-only-phrase")
            self.assertEqual(store.finding_revision(), 1)
            store.close()
