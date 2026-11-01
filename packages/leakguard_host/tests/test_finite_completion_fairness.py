"""Finite synthetic completion accounting under arrivals and encrypted reopen.

Detector execution is mocked, but source-bound acquisition and result publication
are real. Tick counts are synthetic scheduling units, not a latency SLO.
"""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path

from leakguard_core import backends
from leakguard_core.api import ScanConfig, Scanner
from leakguard_host.discovery import DiscoveryCoordinator, _sig
from leakguard_host.protection import defaults
from leakguard_vault import EncryptedScanStore


def test_finite_old_and_arriving_versions_complete_across_reopen(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    root.mkdir()
    old = [root / f'old-{i}.txt' for i in range(4)]
    new = [root / f'new-{i}.env' for i in range(4)]
    for index, path in enumerate(old):
        path.write_text(f'ordinary synthetic old version {index}')
    store_path = tmp_path / 'observations.lgo'
    phrase = 'synthetic-finite-completion'
    store = EncryptedScanStore.create(store_path, phrase)
    config = ScanConfig.from_mapping({})
    source = {'id': 'synthetic', 'root': str(root), 'kind': 'local', 'exclusions': []}
    generation = 7
    def row(path, priority):
        return (str(path), source['id'], 'file', _sig(path.stat()), 'pending',
                priority, generation, path.stat().st_size, None, None)
    store.inventory_put([row(path, 200) for path in old])
    job = {'inventory_generation': generation, 'inventory_complete': True,
           'slices': 0, 'content_batch': 1, 'content_remainder': list(map(str, old)),
           'files_scanned': 0, 'new_findings': 0, 'reconcile_cursor': 256}
    expected = {}
    def admit(path, group, tick):
        content = path.read_bytes()
        expected[(str(path), hashlib.sha256(content).hexdigest())] = {
            'group': group, 'admitted': tick, 'signature': _sig(path.stat())}
    for path in old:
        admit(path, 'old', 0)
    observed_results = []
    current_tick = [0]
    original_scan = Scanner.scan_within
    def record(self, root, paths, **kwargs):
        report = original_scan(self, root, paths, **kwargs)
        for result in report.results:
            if result.coverage.value == 'complete' and result.content:
                observed_results.append((result.source.path, result.content.digest, current_tick[0]))
        return report
    monkeypatch.setattr(Scanner, 'scan_within', record)
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',
                        lambda *a, **k: ('synthetic-runtime', True))
    monkeypatch.setattr(backends, 'detect', lambda *a, **k: ())

    def make_owner():
        owner = DiscoveryCoordinator(store, config)
        owner.identity = lambda _settings: {'policy_id': 'synthetic-policy', 'runtime_id': 'synthetic-runtime'}
        return owner
    owner = make_owner()
    try:
        # Expire the first slice after admission but before execution.
        clock = [0.]
        @contextmanager
        def delayed(_view):
            clock[0] = 11.
            yield None
        with monkeypatch.context() as m:
            m.setattr('leakguard_host.discovery.time.monotonic', lambda: clock[0])
            m.setattr(owner, 'scanner', delayed)
            owner._known_availability = lambda *a, **k: []
            owner.tick(source, job, defaults(), cancel=lambda: False)
        assert job['files_scanned'] == 0
        assert set(job['content_remainder']) == set(map(str, old))
        saved_initial_remainder = job['content_remainder'][:]

        # Persist both scheduler remainder and encrypted inventory before continuing.
        store.save_host_state({'job': job, 'source': source})
        store.checkpoint()
        owner.close(); store.close()
        store = EncryptedScanStore.open(store_path, phrase)
        state = store.load_host_state()
        job, source = state['job'], state['source']
        assert job['content_remainder'] == saved_initial_remainder
        owner = make_owner()

        replacement_added = False
        for tick in range(1, 65):
            current_tick[0] = tick
            followup = []
            if tick <= len(new):
                path = new[tick - 1]
                path.write_text(f'ordinary synthetic arrival {tick}')
                store.inventory_put([row(path, 0)])
                admit(path, 'new', tick)
                followup.append((str(path), 'file'))
            # Replace one completed file with another inode/version; keep both
            # completed digests in the accounting and require the new version.
            if not replacement_added and any(path == str(old[0]) for path, _, _ in observed_results):
                replacement = root / 'temporary-replacement'
                replacement.write_text('ordinary synthetic replacement version')
                replacement.replace(old[0])
                store.inventory_put([row(old[0], 0)])
                admit(old[0], 'new', tick)
                followup.append((str(old[0]), 'file'))
                replacement_added = True
            owner._known_availability = lambda *a, _items=followup, **k: _items
            job['slices'] = tick
            job['content_batch'] = 1
            owner.tick(source, job, defaults(), cancel=lambda: False)
            if tick == 2:
                # Reopen again after actual execution while work remains.
                assert observed_results and job['content_remainder']
                saved_remainder = job['content_remainder'][:]
                store.save_host_state({'job': job, 'source': source})
                store.checkpoint()
                owner.close(); store.close()
                store = EncryptedScanStore.open(store_path, phrase)
                state = store.load_host_state()
                job, source = state['job'], state['source']
                assert job['content_remainder'] == saved_remainder
                owner = make_owner()
            complete = {(p, d) for p, d, _ in observed_results}
            if replacement_added and tick >= len(new) and set(expected) <= complete:
                break
        else:
            raise AssertionError('finite workload did not drain within 64 slices')

        completed = {(p, d): tick for p, d, tick in observed_results}
        assert set(completed) == set(expected)
        assert len(observed_results) == len(expected) == 9
        assert job['files_scanned'] == len(expected)
        store.checkpoint()
        evidence = store.inspection_evidence()
        assert sum(evidence['completed'][name] for name in
                   ('ordinary', 'observed_change', 'reserved_oldest')) == len(expected)
        assert evidence['pending']['with_known_age'] == 0
        assert evidence['pending']['with_unknown_age'] == 0
        for path in [*old, *new]:
            child = store._partitions.get(store._partitions.bucket(str(path)))
            inventory = child.conn.execute(
                'SELECT signature,status,generation,detail FROM inventory WHERE path=?', (str(path),)
            ).fetchone()
            current_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            assert inventory[0] == expected[(str(path), current_digest)]['signature']
            assert inventory[1:3] == ('inspected', generation)
            assert json.loads(inventory[3])['digest'] == current_digest
        waits = {group: [completed[key] - item['admitted'] for key, item in expected.items()
                         if item['group'] == group] for group in ('old', 'new')}
        assert all(wait >= 0 for group in waits.values() for wait in group)
        print('synthetic completion waits in slices:', waits)
    finally:
        owner.close()
        store.close()


def test_generation_change_fences_saved_remainder_after_root_replacement(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    root.mkdir()
    path = root / 'ordinary.txt'
    path.write_text('synthetic old generation')
    old_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    store = EncryptedScanStore.create(tmp_path / 'store.lgo', 'synthetic-source-replacement')
    source = {'id': 'synthetic', 'root': str(root), 'kind': 'local', 'exclusions': []}
    old_signature = _sig(path.stat())
    store.inventory_put([(str(path), source['id'], 'file', old_signature, 'pending', 200,
                          7, path.stat().st_size, None, None)])
    # Replace the source root while the old path remains in a saved page.
    old_inode = root.stat().st_ino
    root.rename(tmp_path / 'retired-source')
    root.mkdir()
    path.write_text('synthetic replacement generation')
    assert root.stat().st_ino != old_inode
    new_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert old_digest != new_digest
    job = {'inventory_generation': 8, 'inventory_complete': True, 'slices': 1,
           'content_batch': 1, 'content_remainder': [str(path)], 'files_scanned': 0,
           'new_findings': 0, 'reconcile_cursor': 256}
    owner = DiscoveryCoordinator(store, ScanConfig.from_mapping({}))
    owner.identity = lambda _settings: {'policy_id': 'synthetic-policy', 'runtime_id': 'synthetic-runtime'}
    owner._known_availability = lambda *a, **k: []
    monkeypatch.setattr('leakguard_core.scan_policy.runtime_identity',
                        lambda *a, **k: ('synthetic-runtime', True))
    monkeypatch.setattr(backends, 'detect', lambda *a, **k: ())
    completed = []
    original = Scanner.scan_within
    def record(self, root, paths, **kwargs):
        report = original(self, root, paths, **kwargs)
        completed.extend((r.source.path, r.content.digest) for r in report.results
                         if r.coverage.value == 'complete' and r.content)
        return report
    monkeypatch.setattr(Scanner, 'scan_within', record)
    try:
        owner.tick(source, job, defaults(), cancel=lambda: False)
        assert not completed and job['files_scanned'] == 0
        child = store._partitions.get(store._partitions.bucket(str(path)))
        row = child.conn.execute('SELECT signature,status,generation FROM inventory WHERE path=?',
                                 (str(path),)).fetchone()
        assert row == (old_signature, 'pending', 7)
        new_signature = _sig(path.stat())
        store.inventory_put([(str(path), source['id'], 'file', new_signature, 'pending', 0,
                              8, path.stat().st_size, None, None)])
        owner._known_availability = lambda *a, **k: [(str(path), 'file')]
        job['slices'] = 2
        owner.tick(source, job, defaults(), cancel=lambda: False)
        assert completed == [(str(path), new_digest)]
        assert job['files_scanned'] == 1
        child = store._partitions.get(store._partitions.bucket(str(path)))
        row = child.conn.execute('SELECT signature,status,generation,detail FROM inventory WHERE path=?',
                                 (str(path),)).fetchone()
        assert row[:3] == (new_signature, 'inspected', 8)
        assert json.loads(row[3])['digest'] == new_digest
    finally:
        owner.close()
        store.close()
