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
        old_store = store._partitions.get(bucket)
        with old_store.conn:
            old_store.conn.executemany('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?)',
                [(p,'synthetic','directory','sig','enumerating',0,1,0,None,None) for p in (early,late)])
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
        clock_before=child.conn.execute('SELECT sequence FROM inventory_admission_clock WHERE id=1').fetchone()[0]
        admissions_before=child.conn.execute('SELECT path,sequence FROM inventory_admissions ORDER BY path').fetchall()
        try:store.inventory_page('synthetic','file','pending',limit=1)
        except sqlite3.IntegrityError:pass
        else:raise AssertionError('synthetic failure was not raised')
        assert child.conn.execute('SELECT sequence FROM inventory_admission_clock WHERE id=1').fetchone()[0]==clock_before
        assert child.conn.execute('SELECT path,sequence FROM inventory_admissions ORDER BY path').fetchall()==admissions_before
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
        old_store = store._partitions.get(bucket)
        with old_store.conn:
            old_store.conn.executemany('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?)',
                [(p,'synthetic','file','sig','pending',0,1,1,None,None) for p in paths])
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


class ArrivalFairnessEvidence(unittest.TestCase):
    def test_continuous_new_arrivals_cannot_monopolize_an_active_directory(self):
        for refresh in (False, True):
            with self.subTest(refresh=refresh):
                bucket, paths = same_bucket_paths(8)
                inventory, connection = partitions(bucket)
                self.addCleanup(connection.close)
                tag = 'metadata-refresh-during-backfill' if refresh else None
                def row(path):
                    return (path, 'one', 'directory', 'sig', 'enumerating', 0, 1, 0, None, tag)
                inventory.inventory_put([row(paths[0])])
                page, cursor = inventory.inventory_page('one', 'directory', 'enumerating', limit=1,
                    prefer_priority=False, queue_class='refresh' if refresh else None)
                self.assertEqual(page[0][0], paths[0])
                observed = []
                for path in paths[1:]:
                    inventory.inventory_put([row(path)])
                    page, cursor = inventory.inventory_page('one', 'directory', 'enumerating',
                        cursor=cursor, limit=1, prefer_priority=False,
                        queue_class='refresh' if refresh else None)
                    observed.append(page[0][0])
                self.assertGreaterEqual(observed.count(paths[0]), 2)
                self.assertEqual(observed[0], paths[0])

    def test_legacy_unstamped_rediscovery_stays_older_than_new_arrival(self):
        bucket, (new, old) = same_bucket_paths(2)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        legacy = (old, 'one', 'directory', 'sig', 'enumerating', 0, 1, 0, None, None)
        connection.execute('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?)', legacy)
        connection.commit()
        inventory.inventory_put([legacy])
        self.assertEqual(connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0], 0)
        self.assertEqual(connection.execute('SELECT count(*) FROM inventory_admissions').fetchone()[0], 0)
        inventory.inventory_put([(new, 'one', 'directory', 'sig', 'enumerating', 0, 1, 0, None, None)])
        page, _ = inventory.inventory_page('one', 'directory', 'enumerating', limit=1, prefer_priority=False)
        self.assertEqual(page[0][0], old)

    def test_rediscovery_does_not_advance_existing_stamp_or_clock(self):
        bucket, paths = same_bucket_paths(2)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        row = (paths[0], 'one', 'directory', 'sig', 'enumerating', 0, 1, 0, None, None)
        inventory.inventory_put([row])
        before = connection.execute('SELECT path,sequence FROM inventory_admissions').fetchall()
        clock = connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0]
        inventory.inventory_put([row, row])
        self.assertEqual(connection.execute('SELECT path,sequence FROM inventory_admissions').fetchall(), before)
        self.assertEqual(connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0], clock)

    def test_arrival_stamp_failure_rolls_back_row_and_clock(self):
        bucket, paths = same_bucket_paths(2)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        row = lambda path: (path, 'one', 'directory', 'sig', 'enumerating', 0, 1, 0, None, None)
        inventory.inventory_put([row(paths[0])])
        clock = connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0]
        old_stamps = connection.execute('SELECT path,sequence FROM inventory_admissions').fetchall()
        connection.execute("CREATE TRIGGER reject_arrival BEFORE INSERT ON inventory_admissions BEGIN SELECT RAISE(ABORT,'synthetic-arrival-failure'); END")
        connection.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            inventory.inventory_put([row(paths[1])])
        self.assertEqual(connection.execute('SELECT path FROM inventory').fetchall(), [(paths[0],)])
        self.assertEqual(connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0], clock)
        self.assertEqual(connection.execute('SELECT path,sequence FROM inventory_admissions').fetchall(), old_stamps)


class RefreshQueueEvidence(unittest.TestCase):
    def test_refresh_file_reinsertion_preserves_old_pending_or_changed_detail(self):
        bucket, paths = same_bucket_paths(7)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        old = [
            (paths[0], 'one', 'file', 'same', 'pending', 10, 1, 1, None, None),
            (paths[1], 'one', 'file', 'same', 'pending', 10, 1, 1, None, 'old-backfill'),
            (paths[2], 'one', 'file', 'same', 'changed', 10, 1, 1, None, 'changed-before-refresh'),
            (paths[3], 'one', 'file', 'same', 'inspected', 10, 1, 1, None, 'old-result'),
            (paths[4], 'one', 'file', 'before', 'pending', 10, 1, 1, None, None),
            (paths[5], 'two', 'file', 'same', 'pending', 10, 1, 1, None, 'other-source'),
        ]
        inventory.inventory_put(old)
        tag = 'content-refresh-during-backfill'
        refreshed = [(p, 'one', 'file', 'same' if i != 4 else 'after', 'pending', 10, 1, 1, None, tag)
                     for i, p in enumerate(paths[:5])]
        refreshed.append((paths[6], 'one', 'file', 'new', 'pending', 10, 1, 1, None, tag))
        inventory.inventory_put(refreshed)
        values = {row[0]: (row[1], row[4], row[9]) for row in connection.execute('SELECT * FROM inventory')}
        self.assertEqual(values[paths[0]], ('one', 'pending', None))
        self.assertEqual(values[paths[1]], ('one', 'pending', 'old-backfill'))
        self.assertEqual(values[paths[2]], ('one', 'changed', 'changed-before-refresh'))
        self.assertEqual(values[paths[3]], ('one', 'inspected', 'old-result'))
        self.assertEqual(values[paths[4]], ('one', 'changed', tag))
        self.assertEqual(values[paths[5]], ('two', 'pending', 'other-source'))
        self.assertEqual(values[paths[6]], ('one', 'pending', tag))
        fresh, cursor = inventory.inventory_page('one', 'file', ('pending', 'changed'), limit=1,
                                                  prefer_priority=False, queue_class='refresh')
        next_fresh, _ = inventory.inventory_page('one', 'file', ('pending', 'changed'), cursor=cursor,
                                                  limit=1, prefer_priority=False, queue_class='refresh')
        self.assertEqual({fresh[0][0], next_fresh[0][0]}, {paths[4], paths[6]})
        self.assertTrue(all(len(row) == 10 for row in (*fresh, *next_fresh)))

    def test_preservation_is_limited_to_same_source_and_refresh_tag(self):
        bucket, paths = same_bucket_paths(2)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        inventory.inventory_put([
            (paths[0], 'old-source', 'file', 'sig', 'changed', 10, 1, 1, None, 'old-detail'),
            (paths[1], 'one', 'file', 'sig', 'changed', 10, 1, 1, None, 'old-detail'),
        ])
        inventory.inventory_put([
            (paths[0], 'new-source', 'file', 'sig', 'pending', 10, 1, 1, None, 'content-refresh-during-backfill'),
            (paths[1], 'one', 'file', 'sig', 'pending', 10, 1, 1, None, 'ordinary-rediscovery'),
        ])
        values = {row[0]: (row[1], row[4], row[9]) for row in connection.execute('SELECT * FROM inventory')}
        self.assertEqual(values[paths[0]], ('new-source', 'pending', 'content-refresh-during-backfill'))
        self.assertEqual(values[paths[1]], ('one', 'pending', 'ordinary-rediscovery'))

    def test_active_directory_refresh_tag_survives_only_matching_rediscovery(self):
        bucket, paths = same_bucket_paths(8)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        tag = 'metadata-refresh-during-backfill'
        inventory.inventory_put([
            (path, 'one', 'directory', 'same', 'enumerating', 10, 1, 0, 'cursor',
             'ordinary' if i == 6 else tag)
            for i, path in enumerate(paths)
        ])
        inventory.inventory_put([
            (paths[0], 'one', 'directory', 'same', 'enumerating', 10, 1, 0, None, None),
            (paths[1], 'one', 'directory', 'changed', 'enumerating', 10, 1, 0, None, None),
            (paths[2], 'two', 'directory', 'same', 'enumerating', 10, 1, 0, None, None),
            (paths[3], 'one', 'directory', 'same', 'enumerating', 10, 2, 0, None, None),
            (paths[4], 'one', 'directory', 'same', 'enumerating', 10, 1, 0, None, 'new-detail'),
            (paths[5], 'one', 'directory', 'same', 'enumerated', 10, 1, 0, None, None),
            (paths[6], 'one', 'directory', 'same', 'enumerating', 10, 1, 0, None, None),
            (paths[7], 'one', 'file', 'same', 'enumerating', 10, 1, 0, None, None),
        ])
        rows = {row[0]: row for row in connection.execute('SELECT * FROM inventory')}
        self.assertEqual((rows[paths[0]][8], rows[paths[0]][9]), ('cursor', tag))
        self.assertEqual(rows[paths[1]][9], 'metadata-version-refresh-during-backfill')
        for path in (paths[2], paths[3], paths[5], paths[6], paths[7]):
            self.assertIsNone(rows[path][9])
        self.assertEqual(rows[paths[4]][9], 'new-detail')
        self.assertIsNone(rows[paths[3]][8])  # New generation cannot inherit cursor.
        filtered, _ = inventory.inventory_page('one', 'directory', 'enumerating',
                                                limit=10, queue_class='refresh')
        self.assertEqual([row[0] for row in filtered], [paths[1]])

    def test_refresh_parent_does_not_promote_existing_active_backfill(self):
        bucket, paths = same_bucket_paths(7)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        tag = 'metadata-refresh-during-backfill'
        details = [None, 'backfill-progress', tag, None, None, None]
        inventory.inventory_put([
            (path, 'one', 'directory', 'same', 'enumerating', 10, 1, 0, 'cursor', details[i])
            for i, path in enumerate(paths[:6])
        ])
        inventory.inventory_put([
            (paths[0], 'one', 'directory', 'same', 'enumerating', 10, 1, 0, None, tag),
            (paths[1], 'one', 'directory', 'same', 'enumerating', 10, 1, 0, None, tag),
            (paths[2], 'one', 'directory', 'same', 'enumerating', 10, 1, 0, None, tag),
            (paths[3], 'one', 'directory', 'changed', 'enumerating', 10, 1, 0, None, tag),
            (paths[4], 'two', 'directory', 'same', 'enumerating', 10, 1, 0, None, tag),
            (paths[5], 'one', 'directory', 'same', 'enumerating', 10, 2, 0, None, tag),
            (paths[6], 'one', 'directory', 'new', 'enumerating', 10, 1, 0, None, tag),
        ])
        rows = {row[0]: row for row in connection.execute('SELECT * FROM inventory')}
        self.assertEqual([(rows[path][4], rows[path][8], rows[path][9]) for path in paths[:3]],
                         [('enumerating', 'cursor', None), ('enumerating', 'cursor', 'backfill-progress'),
                          ('enumerating', 'cursor', tag)])
        self.assertEqual(rows[paths[3]][9], 'metadata-version-refresh-during-backfill')
        self.assertTrue(all(rows[path][9] == tag for path in paths[4:]))
        self.assertEqual(rows[paths[4]][1], 'two')
        self.assertIsNone(rows[paths[5]][8])
        selected, _ = inventory.inventory_page('one', 'directory', 'enumerating',
                                                limit=10, queue_class='refresh')
        self.assertEqual([row[0] for row in selected], [paths[3]])
        self.assertTrue(all(len(row) == 10 for row in selected))

    def test_known_changed_active_directory_version_is_refresh_work(self):
        bucket, paths = same_bucket_paths(9)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        tag = 'metadata-refresh-during-backfill'
        originals = [
            ('before', None), ('before', tag), (None, None), ('before', None),
            ('same', None), ('before', None), ('before', None), ('before', None),
            ('before', None),
        ]
        inventory.inventory_put([
            (path, 'one', 'directory', signature, 'enumerating', 10, 1, 0, 'cursor', detail)
            for path, (signature, detail) in zip(paths, originals)
        ])
        inventory.inventory_put([
            (paths[0], 'one', 'directory', 'after', 'enumerating', 10, 1, 0, None, None),
            (paths[1], 'one', 'directory', 'after', 'enumerating', 10, 1, 0, None, None),
            (paths[2], 'one', 'directory', 'first', 'enumerating', 10, 1, 0, None, None),
            (paths[3], 'one', 'directory', None, 'enumerating', 10, 1, 0, None, None),
            (paths[4], 'one', 'directory', 'same', 'enumerating', 10, 1, 0, None, None),
            (paths[5], 'two', 'directory', 'after', 'enumerating', 10, 1, 0, None, None),
            (paths[6], 'one', 'directory', 'after', 'enumerating', 10, 2, 0, None, None),
            (paths[7], 'one', 'directory', 'after', 'excluded', 10, 1, 0, None, 'operator-exclusion'),
            (paths[8], 'one', 'directory', 'after', 'protected', 10, 1, 0, None, 'protected'),
        ])
        rows = {row[0]: row for row in connection.execute('SELECT * FROM inventory')}
        for path in paths[:2]:
            self.assertEqual((rows[path][4], rows[path][8], rows[path][9]),
                             ('enumerating', None, 'metadata-version-refresh-during-backfill'))
        for path in paths[2:7]:
            self.assertIsNone(rows[path][9])
        self.assertEqual((rows[paths[7]][4], rows[paths[7]][9]), ('excluded', 'operator-exclusion'))
        self.assertEqual((rows[paths[8]][4], rows[paths[8]][9]), ('protected', 'protected'))
        selected, _ = inventory.inventory_page('one', 'directory', 'enumerating',
                                                limit=10, queue_class='refresh')
        self.assertCountEqual([row[0] for row in selected], paths[:2])
        self.assertTrue(all(len(row) == 10 for row in selected))

    def test_observed_only_updates_existing_exact_source_generation_and_kind(self):
        from leakguard_core.scan_store import StateError
        bucket, paths = same_bucket_paths(3)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        events = []
        evidence = 'e' + bucket[1:]
        inventory.cache[evidence] = (SimpleNamespace(record_event=lambda path, kind: events.append((path, kind))), [], [0])
        original = [(paths[0], 'one', 'file', 'before', 'inspected', 17, 7, 10, None, 'old-result'),
                    (paths[1], 'one', 'directory', 'before', 'enumerated', 23, 7, 10, None, 'metadata-only')]
        inventory.inventory_put(original)
        clock = connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0]
        self.assertFalse(inventory.inventory_observed(paths[0], 'one', 7, 'file', 'before', 10))
        for path, source, generation, kind in ((paths[2], 'one', 7, 'file'),
                                               (paths[0], 'two', 7, 'file'),
                                               (paths[0], 'one', 8, 'file'),
                                               (paths[0], 'one', 7, 'directory')):
            self.assertFalse(inventory.inventory_observed(path, source, generation, kind, 'after', 20))
        self.assertEqual(events, [])
        self.assertEqual(connection.execute('SELECT count(*) FROM inventory').fetchone()[0], 2)
        self.assertEqual(connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0], clock)
        self.assertTrue(inventory.inventory_observed(paths[0], 'one', 7, 'file', 'after', 20))
        self.assertTrue(inventory.inventory_observed(paths[1], 'one', 7, 'directory', 'after', 20))
        rows = {row[0]: row for row in connection.execute('SELECT * FROM inventory')}
        self.assertEqual((rows[paths[0]][3], rows[paths[0]][4], rows[paths[0]][5], rows[paths[0]][7], rows[paths[0]][9]),
                         ('after', 'changed', 17, 20, 'content-version-refresh-during-backfill'))
        self.assertEqual((rows[paths[1]][3], rows[paths[1]][4], rows[paths[1]][5], rows[paths[1]][7], rows[paths[1]][9]),
                         ('after', 'enumerating', 23, 20, 'metadata-version-refresh-during-backfill'))
        self.assertCountEqual(events, [(paths[0], 'changed'), (paths[1], 'changed')])
        self.assertEqual(connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0], clock)
        for signature, size in ((None, 1), ('after', -1), ('after', True)):
            with self.assertRaises(StateError):
                inventory.inventory_observed(paths[0], 'one', 7, 'file', signature, size)

    def test_version_refresh_outranks_periodic_across_bounded_bucket_set(self):
        from leakguard_vault import _envelope
        paths_by_bucket = {}
        for number in range(4096):
            path = f'/synthetic/version-priority-{number}'
            paths_by_bucket.setdefault(EncryptedPartitions.bucket(path), path)
            if len(paths_by_bucket) == 9:
                break
        buckets = sorted(paths_by_bucket)
        inventory = EncryptedPartitions.__new__(EncryptedPartitions)
        label = _envelope.canonical(['one', 'directory', 'enumerating']).decode()
        inventory.catalog = {bucket: {'counts': {label: 1}, 'priorities': {label: 0}} for bucket in buckets}
        inventory.cache = OrderedDict()
        stores = {}
        for index, bucket in enumerate(buckets):
            connection = sqlite3.connect(':memory:')
            self.addCleanup(connection.close)
            connection.executescript(_SCHEMA)
            detail = ('metadata-version-refresh-during-backfill' if index in (7, 8)
                      else 'metadata-refresh-during-backfill')
            connection.execute('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?)',
                (paths_by_bucket[bucket], 'one', 'directory', bucket, 'enumerating', 0, 1, 0, None, detail))
            connection.commit()
            stores[bucket] = SimpleNamespace(conn=connection)
        def get_cached(bucket):
            inventory.cache.setdefault(bucket, (stores[bucket], [], [0]))
            return stores[bucket]
        inventory.get = get_cached
        rows, cursor = inventory.inventory_page('one', 'directory', 'enumerating', cursor=0, limit=5,
                                                 prefer_priority=False, queue_class='refresh')
        self.assertEqual([row[0] for row in rows], [paths_by_bucket[buckets[7]]])
        self.assertEqual(cursor, (int(buckets[7][1:], 16) + 1) % 256)
        # The ninth bucket is outside the first bounded candidate set.
        self.assertNotEqual(rows[0][0], paths_by_bucket[buckets[8]])
        # An urgent row outside the eight-bucket set must not enlarge the cap.
        changed = stores[buckets[7]].conn
        changed.execute('UPDATE inventory SET detail=?', ('metadata-refresh-during-backfill',))
        changed.commit()
        fallback, _ = inventory.inventory_page('one', 'directory', 'enumerating', cursor=0, limit=1,
                                                prefer_priority=False, queue_class='refresh')
        self.assertEqual(fallback[0][0], paths_by_bucket[buckets[0]])

    def test_known_completed_directory_version_change_gets_urgent_refresh(self):
        bucket, paths = same_bucket_paths(9)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        initial_states = ['enumerated', 'inaccessible', 'enumerated', 'enumerated',
                          'enumerated', 'enumerated', 'enumerated', 'alias', 'enumerated']
        inventory.inventory_put([
            (path, 'one', 'directory', None if i == 8 else 'before', state, 10, 1, 0, None, 'old')
            for i, (path, state) in enumerate(zip(paths, initial_states))
        ])
        inventory.inventory_put([
            (paths[0], 'one', 'directory', 'after', 'enumerating', 10, 1, 0, None, None),
            (paths[1], 'one', 'directory', 'after', 'enumerating', 10, 1, 0, None, None),
            (paths[2], 'one', 'directory', 'before', 'enumerating', 10, 1, 0, None, None),
            (paths[3], 'two', 'directory', 'after', 'enumerating', 10, 1, 0, None, None),
            (paths[4], 'one', 'directory', 'after', 'enumerating', 10, 2, 0, None, None),
            (paths[5], 'one', 'directory', 'after', 'excluded', 10, 1, 0, None, 'operator-exclusion'),
            (paths[6], 'one', 'directory', 'after', 'protected', 10, 1, 0, None, 'protected'),
            (paths[7], 'one', 'directory', 'after', 'enumerating', 10, 1, 0, None, None),
            (paths[8], 'one', 'directory', 'first', 'enumerating', 10, 1, 0, None, None),
        ])
        rows = {row[0]: row for row in connection.execute('SELECT * FROM inventory')}
        version = 'metadata-version-refresh-during-backfill'
        self.assertEqual([(rows[path][4], rows[path][9]) for path in paths[:2]],
                         [('enumerating', version), ('enumerating', version)])
        self.assertEqual(rows[paths[2]][4], 'enumerated')
        for path in (paths[3], paths[4], paths[7], paths[8]):
            self.assertIsNone(rows[path][9])
        self.assertEqual((rows[paths[5]][4], rows[paths[5]][9]), ('excluded', 'operator-exclusion'))
        self.assertEqual((rows[paths[6]][4], rows[paths[6]][9]), ('protected', 'protected'))
        self.assertFalse(inventory.inventory_observed(paths[0], 'one', 1, 'directory', 'after', 0))
        selected, _ = inventory.inventory_page('one', 'directory', 'enumerating', limit=10,
                                                prefer_priority=False, queue_class='refresh')
        self.assertCountEqual([row[0] for row in selected], paths[:2])
        self.assertTrue(all(len(row) == 10 for row in selected))

    def test_version_tag_precedes_periodic_in_the_same_bucket(self):
        bucket, paths = same_bucket_paths(3)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        periodic = 'metadata-refresh-during-backfill'
        version = 'metadata-version-refresh-during-backfill'
        inventory.inventory_put([(paths[0], 'one', 'directory', 'a', 'enumerating', 0, 1, 0, None, periodic),
                                 (paths[1], 'one', 'directory', 'b', 'enumerating', 0, 1, 0, None, version),
                                 (paths[2], 'one', 'directory', 'c', 'enumerating', 0, 1, 0, None, periodic)])
        selected, _ = inventory.inventory_page('one', 'directory', 'enumerating', limit=3,
                                                prefer_priority=False, queue_class='refresh')
        self.assertEqual([row[0] for row in selected], [paths[1]])
        self.assertTrue(all(len(row) == 10 for row in selected))

    def test_version_tag_survives_unchanged_parent_rediscovery(self):
        bucket, paths = same_bucket_paths(2)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        version = 'metadata-version-refresh-during-backfill'
        inventory.inventory_put([(paths[0], 'one', 'directory', 'same', 'enumerating', 0, 1, 0, 'cursor', version),
                                 (paths[1], 'one', 'directory', 'same', 'enumerating', 0, 1, 0, 'cursor', None)])
        inventory.inventory_put([(paths[0], 'one', 'directory', 'same', 'enumerating', 0, 1, 0, None, None),
                                 (paths[1], 'one', 'directory', 'same', 'enumerating', 0, 1, 0, None, version)])
        rows = {row[0]: row for row in connection.execute('SELECT * FROM inventory')}
        self.assertEqual((rows[paths[0]][8], rows[paths[0]][9]), ('cursor', version))
        self.assertEqual((rows[paths[1]][8], rows[paths[1]][9]), ('cursor', None))

    def test_refresh_filter_is_exact_and_scoped_by_source_kind_and_state(self):
        bucket, paths = same_bucket_paths(7)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        tag = 'metadata-refresh-during-backfill'
        inventory.inventory_put([
            (paths[0], 'one', 'directory', 'a', 'enumerating', 10, 1, 1, None, tag),
            (paths[1], 'one', 'directory', 'b', 'enumerating', 10, 1, 1, None, tag + '-extra'),
            (paths[2], 'two', 'directory', 'c', 'enumerating', 10, 1, 1, None, tag),
            (paths[3], 'one', 'directory', 'd', 'enumerated', 10, 1, 1, None, tag),
            (paths[4], 'one', 'file', 'e', 'enumerating', 10, 1, 1, None, tag),
            (paths[5], 'one', 'directory', 'f', 'enumerating', 10, 1, 1, None, None),
            (paths[6], 'one', 'file', 'g', 'pending', 10, 1, 1, None, 'content-refresh-during-backfill'),
        ])
        rows, _ = inventory.inventory_page('one', 'directory', 'enumerating', limit=10, queue_class='refresh')
        self.assertEqual([row[0] for row in rows], [paths[0]])
        rows, _ = inventory.inventory_page('one', 'file', 'pending', limit=10, queue_class='refresh')
        self.assertEqual([row[0] for row in rows], [paths[6]])
        rows, _ = inventory.inventory_page('one', 'directory', 'enumerating', limit=10)
        self.assertCountEqual([row[0] for row in rows], [paths[0], paths[1], paths[5]])

    def test_sparse_refresh_can_exhaust_eight_bucket_budget_without_completeness(self):
        paths_by_bucket = {}
        for number in range(4096):
            path = f'/synthetic/sparse-{number}'
            paths_by_bucket.setdefault(EncryptedPartitions.bucket(path), path)
            if len(paths_by_bucket) == 9:
                break
        buckets = sorted(paths_by_bucket)
        inventory = EncryptedPartitions.__new__(EncryptedPartitions)
        from leakguard_vault import _envelope
        label = _envelope.canonical(['one', 'file', 'pending']).decode()
        inventory.catalog = {bucket: {'counts': {label: 1}, 'priorities': {label: 0}} for bucket in buckets}
        inventory.cache = OrderedDict()
        stores = {}
        for bucket in buckets:
            connection = sqlite3.connect(':memory:')
            self.addCleanup(connection.close)
            connection.executescript(_SCHEMA)
            connection.execute('INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?)',
                               (paths_by_bucket[bucket], 'one', 'file', bucket, 'pending', 0, 1, 1, None,
                                'content-refresh-during-backfill' if bucket == buckets[-1] else None))
            connection.commit()
            stores[bucket] = SimpleNamespace(conn=connection)
        def get_cached(bucket):
            inventory.cache.setdefault(bucket, (stores[bucket], [], [0]))
            return stores[bucket]
        inventory.get = get_cached
        from unittest.mock import patch
        with patch.object(inventory, 'get', wraps=inventory.get) as get:
            empty, cursor = inventory.inventory_page('one', 'file', 'pending', cursor=0, limit=1,
                                                      prefer_priority=False, queue_class='refresh')
        self.assertEqual(empty, [])
        self.assertEqual(cursor, 8)
        self.assertEqual(get.call_count, 8)
        fallback, _ = inventory.inventory_page('one', 'file', 'pending', cursor=0, limit=1, prefer_priority=False)
        self.assertTrue(fallback)
        found, _ = inventory.inventory_page('one', 'file', 'pending', cursor=int(buckets[-1][1:], 16), limit=1,
                                             prefer_priority=False, queue_class='refresh')
        self.assertEqual(found[0][0], paths_by_bucket[buckets[-1]])

    def test_unknown_refresh_selectors_fail_closed_without_admission(self):
        from leakguard_core.scan_store import StateError
        bucket, paths = same_bucket_paths(1)
        inventory, connection = partitions(bucket)
        self.addCleanup(connection.close)
        inventory.inventory_put([(paths[0], 'one', 'file', 'sig', 'pending', 0, 1, 1, None, 'content-refresh-during-backfill')])
        before_clock = connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0]
        before_rows = connection.execute('SELECT path,sequence FROM inventory_admissions').fetchall()
        for queue, kind in (('unknown', 'file'), ('', 'file'), (False, 'file'), ('refresh', 'other')):
            with self.subTest(queue=queue, kind=kind), self.assertRaises(StateError):
                inventory.inventory_page('one', kind, 'pending', queue_class=queue)
        self.assertEqual(connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0], before_clock)
        self.assertEqual(connection.execute('SELECT path,sequence FROM inventory_admissions').fetchall(), before_rows)


def test_refresh_selector_survives_encrypted_checkpoint(tmp_path):
    from leakguard_vault import EncryptedScanStore
    path = tmp_path / 'observations.lgo'
    phrase = 'synthetic-refresh-checkpoint'
    _, (old, fresh) = same_bucket_paths(2)
    store = EncryptedScanStore.create(path, phrase)
    try:
        store.inventory_put([(old, 'one', 'file', 'sig', 'pending', 10, 1, 1, None, None),
                             (fresh, 'one', 'file', 'sig', 'pending', 10, 1, 1, None, 'content-refresh-during-backfill')])
        store.checkpoint()
    finally:
        store.close()
    store = EncryptedScanStore.open(path, phrase)
    try:
        rows, _ = store.inventory_page('one', 'file', 'pending', limit=1,
                                       prefer_priority=False, queue_class='refresh')
        assert len(rows) == 1 and len(rows[0]) == 10 and rows[0][0] == fresh
        assert store.inventory_counts('one') == {'pending': 2}
    finally:
        store.close()


def test_arrival_sequence_survives_encrypted_checkpoint_and_reopen(tmp_path):
    from leakguard_vault import EncryptedScanStore
    path = tmp_path / 'arrival.lgo'
    phrase = 'synthetic-arrival-checkpoint'
    _, (new, old) = same_bucket_paths(2)
    def row(name):
        return (name, 'one', 'directory', 'sig', 'enumerating', 0, 1, 0, None, None)
    store = EncryptedScanStore.create(path, phrase)
    try:
        store.inventory_put([row(old)])
        page, _ = store.inventory_page('one', 'directory', 'enumerating', limit=1, prefer_priority=False)
        assert page[0][0] == old
        store.checkpoint()
    finally:
        store.close()
    store = EncryptedScanStore.open(path, phrase)
    try:
        store.inventory_put([row(new)])
        store.checkpoint()
    finally:
        store.close()
    store = EncryptedScanStore.open(path, phrase)
    try:
        page, cursor = store.inventory_page('one', 'directory', 'enumerating', limit=1, prefer_priority=False)
        assert page[0][0] == old and len(page[0]) == 10
        page, _ = store.inventory_page('one', 'directory', 'enumerating', cursor=cursor, limit=1, prefer_priority=False)
        assert page[0][0] == new and len(page[0]) == 10
        assert store.inventory_counts('one') == {'enumerating': 2}
    finally:
        store.close()


def test_failed_arrival_journal_replays_without_row_or_clock_change(tmp_path):
    from leakguard_vault import EncryptedScanStore
    path = tmp_path / 'arrival-rollback.lgo'
    phrase = 'synthetic-arrival-rollback'
    bucket, (old, new) = same_bucket_paths(2)
    def row(name):
        return (name, 'one', 'directory', 'sig', 'enumerating', 0, 1, 0, None, None)
    store = EncryptedScanStore.create(path, phrase)
    store.inventory_put([row(old)])
    store.checkpoint()
    child = store._partitions.get(bucket)
    before = child.conn.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0]
    child.conn.execute("CREATE TRIGGER reject_arrival BEFORE INSERT ON inventory_admissions BEGIN SELECT RAISE(ABORT,'synthetic-arrival-failure'); END")
    child.conn.commit()
    try:
        try:
            store.inventory_put([row(new)])
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError('synthetic failure not raised')
        child.conn.execute('DROP TRIGGER reject_arrival')
        child.conn.commit()
        store.checkpoint()
        assert store._partitions.catalog[bucket]['logs'], 'exercise replay, not only a new base'
    finally:
        store.close()
    store = EncryptedScanStore.open(path, phrase)
    try:
        child = store._partitions.get(bucket)
        assert child.conn.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0] == before
        assert child.conn.execute('SELECT path FROM inventory').fetchall() == [(old,)]
        assert child.conn.execute('SELECT path,sequence FROM inventory_admissions').fetchall() == [(old, before)]
    finally:
        store.close()


def test_observed_file_change_requeues_and_marks_existing_finding_unknown(tmp_path):
    import json
    from leakguard_vault import EncryptedScanStore
    path = tmp_path / 'observed.lgo'
    phrase = 'synthetic-observed-version'
    bucket, (file_path,) = same_bucket_paths(1)
    evidence = 'e' + bucket[1:]
    store = EncryptedScanStore.create(path, phrase)
    try:
        store.inventory_put([(file_path, 'one', 'file', 'before', 'inspected', 7, 1, 12, None, 'complete')])
        with store.partition(evidence) as child:
            payload = json.dumps({'state': 'active'})
            with child.conn:
                child.conn.execute('INSERT INTO finding_state VALUES(?,?,?,?,?,?)',
                                   ('key', 'finding', 'active', 'literal-password', file_path, payload))
                child.conn.execute('INSERT INTO finding_current VALUES(?,?,?)', ('key', 'finding', payload))
        store.checkpoint()
        assert not store.inventory_observed(file_path, 'other', 1, 'file', 'after', 14)
        with store.partition(evidence) as child:
            assert child.conn.execute('SELECT state FROM finding_state').fetchone()[0] == 'active'
        assert store.inventory_observed(file_path, 'one', 1, 'file', 'after', 14)
        with store.partition(evidence) as child:
            assert child.conn.execute('SELECT state FROM finding_state').fetchone()[0] == 'unknown'
        rows, _ = store.inventory_page('one', 'file', ('pending', 'changed'),
                                       limit=1, queue_class='refresh')
        assert len(rows) == 1 and len(rows[0]) == 10 and rows[0][0] == file_path and rows[0][4] == 'changed'
        store.checkpoint()
    finally:
        store.close()
    store = EncryptedScanStore.open(path, phrase)
    try:
        with store.partition(evidence) as child:
            assert child.conn.execute('SELECT state FROM finding_state').fetchone()[0] == 'unknown'
        rows, _ = store.inventory_page('one', 'file', ('pending', 'changed'),
                                       limit=1, queue_class='refresh')
        assert len(rows) == 1 and rows[0][0] == file_path
    finally:
        store.close()


def test_failed_page_admission_is_not_replayed_after_encrypted_reopen(tmp_path):
    from leakguard_vault import EncryptedScanStore
    path = tmp_path / 'page-rollback.lgo'
    phrase = 'synthetic-page-rollback'
    bucket, paths = same_bucket_paths(2)
    store = EncryptedScanStore.create(path, phrase)
    try:
        store.inventory_put([(p, 'one', 'file', 'sig', 'pending', 0, 1, 1, None, None)
                             for p in paths])
        store.checkpoint()
        base = store._partitions.catalog[bucket]['base']
        child = store._partitions.get(bucket)
        before = child.conn.execute('SELECT path,sequence FROM inventory_admissions ORDER BY path').fetchall()
        clock = child.conn.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0]
        child.conn.execute("CREATE TRIGGER reject_page BEFORE INSERT ON inventory_admissions BEGIN SELECT RAISE(ABORT,'synthetic-page-failure'); END")
        child.conn.commit()
        try:
            store.inventory_page('one', 'file', 'pending', limit=1, prefer_priority=False)
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError('synthetic failure was not raised')
        child.conn.execute('DROP TRIGGER reject_page')
        child.conn.commit()
        store.checkpoint()
        assert store._partitions.catalog[bucket]['base'] == base
        assert store._partitions.catalog[bucket]['logs'], 'exercise journal replay'
    finally:
        store.close()
    store = EncryptedScanStore.open(path, phrase)
    try:
        child = store._partitions.get(bucket)
        assert child.conn.execute('SELECT path,sequence FROM inventory_admissions ORDER BY path').fetchall() == before
        assert child.conn.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0] == clock
        assert store.inventory_counts('one') == {'pending': 2}
        rows, _ = store.inventory_page('one', 'file', 'pending', limit=1, prefer_priority=False)
        assert rows[0][0] == paths[0]
    finally:
        store.close()


def test_changed_content_precedes_periodic_refresh_without_promoting_old_pending():
    bucket, (periodic, changed, old) = same_bucket_paths(3)
    inventory, connection = partitions(bucket)
    try:
        inventory.inventory_put([
            (periodic, 'one', 'file', 'a', 'pending', 0, 1, 1, None, 'content-refresh-during-backfill'),
            (old, 'one', 'file', 'a', 'pending', 0, 1, 1, None, None),
            (changed, 'one', 'file', 'before', 'inspected', 200, 1, 1, None, None)])
        assert inventory.inventory_observed(changed, 'one', 1, 'file', 'b', 1)
        rows, _ = inventory.inventory_page('one', 'file', ('pending', 'changed'), limit=1,
                                           prefer_priority=False, queue_class='refresh')
        assert rows[0][0] == changed
        # Rediscovery cannot erase an urgent tag or promote an unchanged backlog item.
        inventory.inventory_put([(changed, 'one', 'file', 'b', 'pending', 200, 1, 1, None, 'content-refresh-during-backfill'),
                                 (old, 'one', 'file', 'a', 'pending', 0, 1, 1, None, 'content-version-refresh-during-backfill')])
        assert connection.execute('SELECT detail FROM inventory WHERE path=?', (changed,)).fetchone()[0] == 'content-version-refresh-during-backfill'
        assert connection.execute('SELECT detail FROM inventory WHERE path=?', (old,)).fetchone()[0] is None
        inventory.inventory_set(changed, 'inspected')
        rows, _ = inventory.inventory_page('one', 'file', 'pending', limit=1,
                                           prefer_priority=False, queue_class='refresh')
        assert rows[0][0] == periodic
    finally:
        connection.close()


def test_unexecuted_page_entries_keep_age_under_sustained_arrivals():
    bucket, paths = same_bucket_paths(8)
    inventory, connection = partitions(bucket)
    def row(path,priority=0):return (path,'one','file','sig','pending',priority,1,1,None,None)
    try:
        inventory.inventory_put([row(p) for p in paths[:3]])
        oldest=paths[1]
        before=connection.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(oldest,)).fetchone()[0]
        for arrival in paths[3:]:
            page,_=inventory.inventory_page('one','file','pending',limit=100,prefer_priority=False,admit=False)
            executed=page[0][0]
            inventory.inventory_admitted([executed])
            inventory.inventory_set(executed,'inspected')
            inventory.inventory_put([row(arrival)])
            if executed==oldest:break
            assert connection.execute('SELECT sequence FROM inventory_admissions WHERE path=?',(oldest,)).fetchone()[0]==before
        assert executed==oldest, 'page selection aged work that the scan budget never executed'
    finally:connection.close()


def test_same_version_runtime_invalidated_work_reenters_refresh_without_trusting_content(tmp_path):
    from leakguard_vault import EncryptedScanStore
    store=EncryptedScanStore.create(tmp_path/'invalidated.lgo','synthetic-invalidated-version')
    path='/synthetic/invalidated.env';source={'id':'one','root':'/synthetic'}
    try:
        store.inventory_put([(path,'one','file','same','inspected',0,1,1,None,'old-evidence')])
        store.invalidate_location(source,int(store._partitions.bucket(path)[1:],16))
        assert not store.inventory_observed(path,'other',1,'file','same',1)
        assert not store.inventory_observed(path,'one',2,'file','same',1)
        assert store.inventory_observed(path,'one',1,'file','same',1)
        rows,_=store.inventory_page('one','file','pending',queue_class='refresh')
        assert rows and rows[0][0]==path and rows[0][4]=='pending'
        assert store.inventory_counts()=={'pending':1}
    finally:store.close()


def test_interrupted_page_reload_rejects_changed_source_generation_and_state(tmp_path):
    from leakguard_vault import EncryptedScanStore
    path=tmp_path/'remainder.lgo';phrase='synthetic-remainder-fences'
    store=EncryptedScanStore.create(path,phrase)
    paths=[f'/synthetic/remainder-{number}' for number in range(4)]
    store.inventory_put([(p,'one','file','sig','pending',200,7,1,None,None) for p in paths])
    store.checkpoint();store.close();store=EncryptedScanStore.open(path,phrase)
    try:
        assert len(store.inventory_selected('one','file','pending',paths,7))==4
        assert store.inventory_selected('other','file','pending',paths,7)==[]
        assert store.inventory_selected('one','file','pending',paths,8)==[]
        store.inventory_set(paths[0],'protected')
        assert [r[0] for r in store.inventory_selected('one','file','pending',paths,7)]==paths[1:]
    finally:store.close()


def test_inventory_publication_reports_only_new_or_changed_metadata_versions():
    bucket, paths = same_bucket_paths(3)
    inventory, connection = partitions(bucket)
    def row(path,signature='same',state='pending',detail=None):return (path,'one','file',signature,state,0,1,1,None,detail)
    try:
        assert inventory.inventory_put([row(paths[0],state='inspected'),row(paths[1])])==[(paths[0],'file'),(paths[1],'file')]
        assert inventory.inventory_put([row(paths[0]),row(paths[1],detail='content-version-refresh-during-backfill')])==[]
        assert inventory.inventory_put([row(paths[0],'changed'),row(paths[2])])==[(paths[0],'file'),(paths[2],'file')]
        assert connection.execute('SELECT status FROM inventory WHERE path=?',(paths[0],)).fetchone()[0]=='changed'
    finally:connection.close()
