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
        for path in (paths[1], paths[2], paths[3], paths[5], paths[6], paths[7]):
            self.assertIsNone(rows[path][9])
        self.assertEqual(rows[paths[4]][9], 'new-detail')
        self.assertIsNone(rows[paths[3]][8])  # New generation cannot inherit cursor.
        filtered, _ = inventory.inventory_page('one', 'directory', 'enumerating',
                                                limit=10, queue_class='refresh')
        self.assertEqual([row[0] for row in filtered], [paths[0]])

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
        self.assertTrue(all(rows[path][9] == tag for path in paths[3:]))
        self.assertEqual(rows[paths[4]][1], 'two')
        self.assertIsNone(rows[paths[5]][8])
        selected, _ = inventory.inventory_page('one', 'directory', 'enumerating',
                                                limit=10, queue_class='refresh')
        self.assertCountEqual([row[0] for row in selected], [paths[2], paths[3], paths[5], paths[6]])
        self.assertTrue(all(len(row) == 10 for row in selected))

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
        inventory.get = stores.__getitem__
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
        for queue, kind in (('unknown', 'file'), ('', 'file'), (False, 'file'), ('refresh', 'other')):
            with self.subTest(queue=queue, kind=kind), self.assertRaises(StateError):
                inventory.inventory_page('one', kind, 'pending', queue_class=queue)
        self.assertEqual(connection.execute('SELECT sequence FROM inventory_admission_clock').fetchone()[0], 0)
        self.assertEqual(connection.execute('SELECT count(*) FROM inventory_admissions').fetchone()[0], 0)


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
