"""Tiny deterministic evidence of same-bucket inventory starvation.

These assertions describe the current behavior, not the desired fairness rule.
No scans, filesystem traversal or user data are involved. A SQLite serialize/
deserialize round trip models retained rows across a restart, but does not test
an encrypted envelope checkpoint or crash recovery.
"""
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
        self.assertTrue(all(path == early for _, path in observations))
        self.assertEqual(sum(fair for fair, _ in observations), 3)
        saved = connection.serialize()
        reopened, restored = partitions(bucket, saved)
        self.addCleanup(restored.close)
        page, next_cursor = reopened.inventory_page('synthetic', kind, state,
            cursor=cursor, limit=1, prefer_priority=False)
        self.assertEqual(page[0][0], early)
        self.assertEqual(page[0][8], '30')
        # Progress becomes possible as soon as the earlier row leaves the state.
        reopened.inventory_set(early, 'enumerated' if kind == 'directory' else 'inspected')
        page, _ = reopened.inventory_page('synthetic', kind, state,
            cursor=next_cursor, limit=1, prefer_priority=False)
        self.assertEqual(page[0][0], late)

    def test_active_wide_directory_starves_later_directory_on_fair_slices(self):
        self.reproduce('directory', 'enumerating', 0, 100)

    def test_still_pending_file_starves_later_equal_priority_file(self):
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
