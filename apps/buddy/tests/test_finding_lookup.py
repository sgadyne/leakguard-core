"""Finding lookup must reach later current and historical pages."""
import threading
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace

from leakguard_buddy.backend import BuddyBackend


class Store:
    def query_findings_page(self, *, state, limit, cursor):
        rows = [{"id": f"{state}-{n}"} for n in range(2005)]
        offset = int(cursor or 0)
        end = min(offset + limit, len(rows))
        return SimpleNamespace(rows=rows[offset:end], next_cursor=str(end) if end < len(rows) else None)

    def get_annotation(self, finding_id):
        return {"finding_id": finding_id, "state": "unreviewed"}


class FindingLookupTests(unittest.TestCase):
    def test_later_current_and_history_and_missing(self):
        backend = BuddyBackend.__new__(BuddyBackend)
        backend._lock = threading.RLock()
        backend._observation_store = Store()
        for finding_id in ("current-2001", "history-2003"):
            self.assertEqual(backend.finding(finding_id)["id"], finding_id)
        with self.assertRaises(KeyError):
            backend.finding("missing")

    def test_real_sqlite_pages_beyond_one_thousand(self):
        from leakguard_core.scan_store import SQLiteScanStore
        with TemporaryDirectory() as directory:
            store = SQLiteScanStore(Path(directory))
            with store.conn:
                for number in range(1002):
                    current = f"current-{number:04d}"
                    historic = f"history-{number:04d}"
                    store.conn.execute("INSERT INTO finding_current VALUES(?,?,?)", (f"input-{number:04d}", current, json.dumps({"id": current})))
                    store.conn.execute("INSERT INTO finding_history(scan_id,finding_id,payload) VALUES(?,?,?)", (f"scan-{number:04d}", historic, json.dumps({"id": historic})))
            store.get_annotation = lambda finding_id: {"finding_id": finding_id, "state": "unreviewed"}
            backend = BuddyBackend.__new__(BuddyBackend)
            backend._lock = threading.RLock()
            backend._observation_store = store
            self.assertEqual(backend.finding("current-1001")["id"], "current-1001")
            self.assertEqual(backend.finding("history-1001")["id"], "history-1001")
            store.close()
