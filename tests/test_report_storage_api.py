"""Wire validation and encrypted-profile failure semantics."""
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from leakguard_core import models as m
from leakguard_core.api import ReportError, parse_report
from leakguard_core.scan_store import MemoryScanStore, StateError
from leakguard_core.storage import open_scan_store


def report():
    now = datetime.now(timezone.utc)
    return m.ScanReport(1, 'synthetic', now, now, 'policy', (), m.CoverageSummary(True, True, 0), m.PolicyDecision(m.DecisionVerdict.ALLOW, (), 'policy'))


class ReportStorageTests(unittest.TestCase):
    def test_public_parser_roundtrip_and_fail_closed_schema(self):
        value = report()
        self.assertEqual(parse_report(value.to_json()), value)
        modified = value.to_dict()
        modified['secret'] = 'SYNTHETIC-DO-NOT-ECHO'
        for invalid in (json.dumps(modified), value.to_json().replace('"schema_version":1', '"schema_version":1,"schema_version":1'), '{"schema_version":NaN}', value.to_json()):
            with self.subTest(invalid=invalid[:20]):
                with self.assertRaises(ReportError) as failure:
                    parse_report(invalid, max_bytes=20 if invalid == value.to_json() else 64_000_000)
                self.assertEqual(str(failure.exception), 'report-invalid')

    def test_encrypted_unavailable_enforcement_writes_no_plaintext(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-state-policy-') as temporary:
            root = Path(temporary)
            # A missing optional module is representative of any unavailable
            # observation capability; the selected policy forbids disk fallback.
            with patch.dict('sys.modules', {'leakguard_vault': None}):
                store = open_scan_store(root, config={'observation_backend': 'encrypted'})
            self.assertIsInstance(store, MemoryScanStore)
            self.assertTrue(store._leakguard_ephemeral_observations)
            self.assertEqual(list(root.iterdir()), [])
            store.close()

    def test_unavailable_durable_query_cannot_look_empty(self):
        with tempfile.TemporaryDirectory(prefix='leakguard-state-query-') as temporary:
            with patch.dict('sys.modules', {'leakguard_vault': None}):
                with self.assertRaises(StateError):
                    open_scan_store(Path(temporary), config={'observation_backend': 'encrypted'}, allow_ephemeral=False)
            self.assertEqual(list(Path(temporary).iterdir()), [])
