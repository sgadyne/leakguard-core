"""Reserved fair admission progresses even while an earlier row stays active."""
from collections import OrderedDict, defaultdict
import sqlite3
from types import SimpleNamespace
import unittest

from leakguard_vault.partitions import EncryptedPartitions, _SCHEMA


def same_bucket_paths(count):
    groups = defaultdict(list)
    for number in range(4096):
        path = f'/synthetic/item-{number:04d}'
        bucket = EncryptedPartitions.bucket(path)
        groups[bucket].append(path)
        if len(groups[bucket]) == count:
            return bucket, sorted(groups[bucket])
    raise AssertionError('synthetic hash collision not found')


def partitions(bucket, serialized=None):
    connection = sqlite3.connect(':memory:')
    if serialized is None:
        connection.executescript(_SCHEMA)
    else:
        connection.deserialize(serialized)
    value = EncryptedPartitions.__new__(EncryptedPartitions)
    value.cache = OrderedDict([(bucket, (SimpleNamespace(conn=connection), [], [0]))])
    value.catalog = {}
    return value, connection


class InventoryFairnessEvidence(unittest.TestCase):
    def reproduce(self, kind, state, priority_a, priority_b):
        bucket, (early, late) = same_bucket_paths(2)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        rows = [(early, 'synthetic', kind, 'sig-a', state, priority_a, 1, 1, None, None),
                (late, 'synthetic', kind, 'sig-b', state, priority_b, 1, 1, None, None)]
        inventory.inventory_put(rows)
        cursor = 0
        observations = []
        # Mirrors the host: 9 priority selections followed by one fair selection.
        for step in range(30):
            page, cursor = inventory.inventory_page('synthetic', kind, state,
                cursor=cursor, limit=1, prefer_priority=(step % 10 != 0))
            self.assertEqual(len(page), 1)
            self.assertEqual(len(page[0]), 10)
            observations.append((step % 10 == 0, page[0][0]))
            # Model a partial directory page or a file still pending after a
            # bounded slice: the admitted row remains active and updates cursor.
            inventory.inventory_set(page[0][0], state, cursor=str(step + 1))
        self.assertTrue(all(path == early for fair, path in observations if not fair))
        self.assertIn(late, [path for fair, path in observations if fair])
        self.assertEqual(sum(fair for fair, _ in observations), 3)
        saved = connection.serialize()
        reopened, restored = partitions(bucket, saved)
        self.addCleanup(restored.close)
        page, next_cursor = reopened.inventory_page('synthetic', kind, state,
            cursor=cursor, limit=1, prefer_priority=False)
        self.assertEqual(page[0][0], late)
        self.assertIsNotNone(page[0][8])
        # Progress becomes possible as soon as the earlier row leaves the state.
        reopened.inventory_set(early, 'enumerated' if kind == 'directory' else 'inspected')
        page, _ = reopened.inventory_page('synthetic', kind, state,
            cursor=next_cursor, limit=1, prefer_priority=False)
        self.assertEqual(page[0][0], late)

    def test_active_wide_directory_cannot_starve_later_directory_on_fair_slices(self):
        self.reproduce('directory', 'enumerating', 0, 100)

    def test_still_pending_file_cannot_starve_later_equal_priority_file(self):
        self.reproduce('file', 'pending', 10, 10)

    def test_priority_mode_and_fair_mode_keep_their_existing_order_contract(self):
        bucket, (early, late) = same_bucket_paths(2)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        inventory.inventory_put([(early, 'synthetic', 'file', 'a', 'pending', 100, 1, 1, None, None),
                                 (late, 'synthetic', 'file', 'b', 'pending', 0, 1, 1, None, None)])
        normal, _ = inventory.inventory_page('synthetic', 'file', 'pending', limit=1, prefer_priority=True)
        fair, _ = inventory.inventory_page('synthetic', 'file', 'pending', limit=1, prefer_priority=False)
        self.assertEqual(normal[0][0], late)
        self.assertEqual(fair[0][0], early)
        self.assertEqual(len(normal[0]), 10)
        self.assertEqual(len(fair[0]), 10)


if __name__ == '__main__':
    unittest.main()


def test_fair_admission_survives_encrypted_checkpoint_from_old_base_and_new_journal(tmp_path):
    from unittest.mock import patch
    from leakguard_vault import EncryptedScanStore
    import leakguard_vault.partitions as module
    path=tmp_path/'observations.lgo';phrase='synthetic-fair-admission-checkpoint'
    bucket,(early,late)=same_bucket_paths(2)
    old_schema=module._SCHEMA[:module._SCHEMA.index('CREATE TABLE IF NOT EXISTS inventory_admissions')]
    with patch.object(module,'_SCHEMA',old_schema):
        store=EncryptedScanStore.create(path,phrase)
        store.inventory_put([(p,'synthetic','directory','sig','enumerating',0,1,0,None,None) for p in (early,late)])
        store.checkpoint();base=store._partitions.catalog[bucket]['base'];store.close()
    store=EncryptedScanStore.open(path,phrase)
    page,cursor=store.inventory_page('synthetic','directory','enumerating',limit=1)
    assert page[0][0]==early and len(page[0])==10
    store.checkpoint()
    assert store._partitions.catalog[bucket]['base']==base
    assert store._partitions.catalog[bucket]['logs'], 'test must replay a new scheduling journal against an old base'
    store.close()
    store=EncryptedScanStore.open(path,phrase)
    try:
        page,_=store.inventory_page('synthetic','directory','enumerating',cursor=cursor,limit=1,prefer_priority=False)
        assert page[0][0]==late and len(page[0])==10
        assert store.inventory_counts()=={'enumerating':2}, 'admission cannot certify inspection'
    finally:store.close()


def test_uncheckpointed_admission_may_replay_without_losing_work(tmp_path):
    from leakguard_vault import EncryptedScanStore
    path=tmp_path/'observations.lgo';phrase='synthetic-fair-admission-crash';bucket,(early,late)=same_bucket_paths(2)
    store=EncryptedScanStore.create(path,phrase)
    store.inventory_put([(p,'synthetic','file','sig','pending',0,1,1,None,None) for p in (early,late)])
    store.checkpoint()
    store.inventory_page('synthetic','file','pending',limit=1)
    store._partitions.prepare();store._dispose()  # crash before owner catalog commit
    store=EncryptedScanStore.open(path,phrase)
    try:
        page,cursor=store.inventory_page('synthetic','file','pending',limit=1,prefer_priority=False)
        assert page[0][0]==early
        page,_=store.inventory_page('synthetic','file','pending',cursor=cursor,limit=1,prefer_priority=False)
        assert page[0][0]==late
        assert store.inventory_counts()=={'pending':2}
    finally:store.close()


def test_admission_batch_and_cache_eviction_preserve_row_contract_and_fair_order(tmp_path):
    from leakguard_vault import EncryptedScanStore
    path=tmp_path/'observations.lgo';phrase='synthetic-fair-admission-eviction';bucket,paths=same_bucket_paths(5)
    store=EncryptedScanStore.create(path,phrase)
    try:
        store.inventory_put([(p,'synthetic','file','sig','pending',0,1,1,None,None) for p in paths])
        page,cursor=store.inventory_page('synthetic','file','pending',limit=3)
        assert [row[0] for row in page]==paths[:3] and all(len(row)==10 for row in page)
        # Loading unrelated partitions forces the updated scheduling journal out.
        for index in range(12):
            key=f'i{index:02x}'
            if key!=bucket:store._partitions.get(key)
        page,_=store.inventory_page('synthetic','file','pending',cursor=cursor,limit=2,prefer_priority=False)
        assert [row[0] for row in page]==paths[3:]
        assert store.inventory_counts()=={'pending':5}
    finally:store.close()


def test_admission_clock_update_rolls_back_if_row_stamp_fails(tmp_path):
    import sqlite3
    from leakguard_vault import EncryptedScanStore
    path=tmp_path/'observations.lgo';phrase='synthetic-fair-admission-rollback';bucket,paths=same_bucket_paths(2)
    store=EncryptedScanStore.create(path,phrase)
    try:
        store.inventory_put([(p,'synthetic','file','sig','pending',0,1,1,None,None) for p in paths])
        child=store._partitions.get(bucket)
        child.conn.execute("CREATE TRIGGER reject_admission BEFORE INSERT ON inventory_admissions BEGIN SELECT RAISE(ABORT,'synthetic-admission-failure'); END")
        try:store.inventory_page('synthetic','file','pending',limit=1)
        except sqlite3.IntegrityError:pass
        else:raise AssertionError('synthetic failure was not raised')
        assert child.conn.execute('SELECT sequence FROM inventory_admission_clock WHERE id=1').fetchone()[0]==0
        assert child.conn.execute('SELECT count(*) FROM inventory_admissions').fetchone()[0]==0
        assert store.inventory_counts()=={'pending':2}
    finally:store.close()


def test_old_loader_rejects_new_admission_journal_without_reinitializing_store(tmp_path):
    from unittest.mock import patch
    import hashlib
    import pytest
    from leakguard_core.scan_store import StateError
    from leakguard_vault import EncryptedScanStore
    import leakguard_vault.partitions as module
    path=tmp_path/'observations.lgo';phrase='synthetic-fair-admission-old-loader';bucket,paths=same_bucket_paths(2)
    old_schema=module._SCHEMA[:module._SCHEMA.index('CREATE TABLE IF NOT EXISTS inventory_admissions')]
    with patch.object(module,'_SCHEMA',old_schema):
        store=EncryptedScanStore.create(path,phrase)
        store.inventory_put([(p,'synthetic','file','sig','pending',0,1,1,None,None) for p in paths])
        store.checkpoint();store.close()
    store=EncryptedScanStore.open(path,phrase)
    store.inventory_page('synthetic','file','pending',limit=1);store.checkpoint();store.close()
    before=hashlib.sha256(path.read_bytes()).hexdigest()
    with patch.object(module,'_SCHEMA',old_schema):
        store=EncryptedScanStore.open(path,phrase)
        try:
            with pytest.raises(StateError,match='state-partition-unavailable'):
                store.inventory_page('synthetic','file','pending',limit=1)
        finally:store._dispose()
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    store=EncryptedScanStore.open(path,phrase)
    try:
        page,_=store.inventory_page('synthetic','file','pending',limit=1,prefer_priority=False)
        assert page[0][0]==paths[1]
    finally:store.close()
