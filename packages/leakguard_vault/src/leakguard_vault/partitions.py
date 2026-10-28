"""Bounded encrypted SQLite partitions, committed by the owning envelope.

Every disk object uses the existing authenticated envelope. Immutable bases and
bounded SQL journals are published before the owner's atomic catalog checkpoint.
A crash before that checkpoint leaves only unreferenced ciphertext. No SQLite
file, rollback journal, temporary sort or inventory is written in plaintext.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
from pathlib import Path
import re
import secrets
import sqlite3
import zlib
import shutil

from leakguard_core.scan_store import SQLiteScanStore, StateError
from . import _envelope as envelope
from ._files import atomic_write, read_bounded

_MUTATION = re.compile(r'^(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b', re.I)
_NAME = re.compile(r'[a-f0-9]{32}\.lgo\Z')
_MAX_JOURNAL = 64 * 1024
_MAX_OPEN = 8
_SCHEMA = '''
CREATE TABLE IF NOT EXISTS inventory(path TEXT PRIMARY KEY,location TEXT NOT NULL,kind TEXT NOT NULL,signature TEXT,status TEXT NOT NULL,priority INTEGER NOT NULL,generation INTEGER NOT NULL,size INTEGER NOT NULL DEFAULT 0,cursor TEXT,detail TEXT);
CREATE INDEX IF NOT EXISTS inventory_pending ON inventory(location,kind,status,priority,path);
CREATE TABLE IF NOT EXISTS physical(identity TEXT PRIMARY KEY,generation INTEGER NOT NULL,path TEXT NOT NULL);
'''


class EncryptedPartitions:
    def __init__(self, owner):
        self.owner = owner
        self.directory = owner._path.with_name(owner._path.name + '.parts')
        row = owner._store.conn.execute("SELECT payload FROM app_state WHERE name='partitions-v1'").fetchone()
        self.catalog = envelope.load_json(row[0].encode()) if row else {}
        if type(self.catalog) is not dict or len(self.catalog) > 768:
            raise StateError('state-data-invalid')
        for bucket, item in self.catalog.items():
            if not re.fullmatch(r'[iep][a-f0-9]{2}', bucket) or type(item) is not dict or set(item) not in ({'base','logs','bytes','counts'},{'base','logs','bytes','counts','priorities'}):
                raise StateError('state-data-invalid')
            names = ([item['base']] if item['base'] else []) + item['logs']
            if len(item['logs']) > 64 or not all(type(n) is str and _NAME.fullmatch(n) for n in names):
                raise StateError('state-data-invalid')
        self.cache = OrderedDict()
        self._new_files = set()
        self.committed_refs={name for item in self.catalog.values() for name in ([item['base']] if item['base'] else [])+item['logs']}
        self.pinned = set()
        self.active_transaction=False

    @staticmethod
    def bucket(path, kind='i'):
        return kind + hashlib.sha256(str(path).encode('utf-8', 'surrogatepass')).hexdigest()[:2]

    def _read(self, name):
        if not _NAME.fullmatch(name):
            raise StateError('state-data-invalid')
        try:
            plain=envelope.decrypt_with_key(read_bounded(self.directory / name, envelope.MAX_FILE), 'observations', bytes(self.owner._key))[2]
            if plain.startswith(b'LGPZ1'):
                decoder=zlib.decompressobj()
                decoded=decoder.decompress(plain[5:],envelope.MAX_STATE+1)
                if len(decoded)>envelope.MAX_STATE or not decoder.eof or decoder.unused_data:
                    raise StateError('state-capacity-limit')
                return decoded
            return plain
        except Exception:
            raise StateError('state-partition-unavailable') from None

    def _write(self, plain):
        if self.directory.is_symlink():
            raise StateError('state-path-invalid')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        name = secrets.token_hex(16) + '.lgo'
        compressed=b'LGPZ1'+zlib.compress(plain,1)
        _, value = envelope.encode(self.owner._header, bytes(self.owner._key), compressed)
        if shutil.disk_usage(self.directory).free < len(value)*2+128*1024*1024:
            raise StateError('state-storage-unavailable')
        atomic_write(self.directory / name, value, replace=False)
        self._new_files.add(name)
        return name

    def get(self, bucket):
        if not re.fullmatch(r'[iep][a-f0-9]{2}', bucket):
            raise StateError('state-data-invalid')
        if bucket in self.cache:
            self.cache.move_to_end(bucket)
            return self.cache[bucket][0]
        if len(self.cache) >= _MAX_OPEN:
            old = next((key for key in self.cache if key not in self.pinned), None)
            if old is None: raise StateError('state-capacity-limit')
            self.flush(old)
            store, _, _ = self.cache.pop(old)
            store.close()
        item = self.catalog.get(bucket)
        plain = self._read(item['base']) if item and item['base'] else None
        store = SQLiteScanStore.from_memory(plain, config=self.owner._store.config, material_key=self.owner._store._memory_material_key)
        try:
            if item:
                for name in item['logs']:
                    commands = envelope.load_json(self._read(name))
                    if type(commands) is not list or len(commands) > 100_000 or not all(type(sql) is str and _MUTATION.match(sql.lstrip()) for sql in commands):
                        raise StateError('state-data-invalid')
                    for sql in commands:
                        store.conn.execute(sql)
                store.conn.commit()
            store.conn.executescript(_SCHEMA)
            # A partition cannot attach a plaintext database or invoke extension
            # loading, even if a future accidental SQL statement attempts it.
            store.conn.set_authorizer(lambda action, a, b, db, source: sqlite3.SQLITE_DENY if action in {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH} else sqlite3.SQLITE_OK)
            journal = []
            size = [0]
            def trace(sql):
                if _MUTATION.match(sql.lstrip()):
                    journal.append(sql)
                    size[0] += len(sql.encode('utf-8', 'surrogatepass'))
            store.conn.set_trace_callback(trace)
            self.cache[bucket] = (store, journal, size)
            return store
        except Exception:
            store.close()
            raise StateError('state-partition-unavailable') from None

    def flush(self, bucket):
        store, journal, size = self.cache[bucket]
        item = self.catalog.get(bucket, {'base':None,'logs':[],'bytes':0,'counts':{}})
        old_names=([item['base']] if item['base'] else [])+item['logs']
        if not journal and item['base']:
            return
        store.conn.commit()
        if not item['base'] or len(item['logs']) >= 63 or item['bytes'] + size[0] >= _MAX_JOURNAL:
            base = self._write(store.serialize())
            item = {**item, 'base':base, 'logs':[], 'bytes':0}
        elif journal:
            encoded = envelope.canonical(journal)
            if len(encoded) > _MAX_JOURNAL:
                raise StateError('state-capacity-limit')
            item = {**item, 'logs':[*item['logs'], self._write(encoded)], 'bytes':item['bytes'] + len(encoded)}
        aggregate=store.conn.execute('SELECT location,kind,status,count(*),min(priority) FROM inventory GROUP BY location,kind,status').fetchall()
        item['counts']={envelope.canonical([loc,kind,state]).decode():count for loc,kind,state,count,priority in aggregate}
        item['priorities']={envelope.canonical([loc,kind,state]).decode():priority for loc,kind,state,count,priority in aggregate}
        self.catalog[bucket] = item
        current_names=set(([item['base']] if item['base'] else [])+item['logs'])
        for name in old_names:
            if name not in self.committed_refs and name not in current_names:
                (self.directory/name).unlink(missing_ok=True)
                self._new_files.discard(name)
        journal.clear()
        size[0] = 0

    def prepare(self):
        if self.active_transaction:return False
        for bucket in list(self.cache):
            self.flush(bucket)
        self.owner._store.conn.execute("INSERT INTO app_state VALUES('partitions-v1',?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload", (envelope.canonical(self.catalog).decode(),))
        self.owner._store.conn.commit()
        return True

    def committed(self):
        # Reclaim only after the owner's fsynced atomic catalog publication.
        referenced = {name for item in self.catalog.values() for name in ([item['base']] if item['base'] else []) + item['logs']}
        if self.directory.exists():
            for path in self.directory.iterdir():
                if _NAME.fullmatch(path.name) and path.name not in referenced:
                    path.unlink(missing_ok=True)
        self._new_files.clear()
        self.committed_refs=referenced

    def counts(self, location=None):
        result = {}
        for bucket,item in self.catalog.items():
            if not bucket.startswith('i'): continue
            counts=item['counts']
            if bucket in self.cache:
                counts={envelope.canonical([loc,kind,state]).decode(): n for loc,kind,state,n in self.cache[bucket][0].conn.execute('SELECT location,kind,status,count(*) FROM inventory GROUP BY location,kind,status')}
            for label,count in counts.items():
                loc,kind,state=envelope.load_json(label.encode())
                if location is None or loc==location:
                    result[state]=result.get(state,0)+count
        for bucket in self.cache.keys()-self.catalog.keys():
            if not bucket.startswith('i'):continue
            for loc,state,n in self.cache[bucket][0].conn.execute('SELECT location,status,count(*) FROM inventory GROUP BY location,status'):
                if location is None or location==loc:result[state]=result.get(state,0)+n
        return result

    def close(self):
        for store,_,_ in self.cache.values():
            store.close()
        self.cache.clear()

    def inventory_put(self, rows):
        groups = {}
        for row in rows:
            if len(row) != 10 or len(row[0]) > 4096:
                raise StateError('state-data-invalid')
            groups.setdefault(self.bucket(row[0]), []).append(row)
        for bucket, group in sorted(groups.items()):
            store = self.get(bucket)
            changed=[]
            for row in group:
                previous=store.conn.execute('SELECT signature FROM inventory WHERE path=?',(row[0],)).fetchone()
                if previous and previous[0]!=row[3]:changed.append(row[0])
            evidence='e'+bucket[1:]
            if changed and (evidence in self.catalog or evidence in self.cache):
                child=self.get(evidence)
                for path in changed:child.record_event(path,'changed')
                store=self.get(bucket)
            with store.conn:
                store.conn.executemany('''INSERT INTO inventory VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET location=excluded.location,kind=excluded.kind,signature=excluded.signature,status=CASE WHEN inventory.signature=excluded.signature AND inventory.kind='directory' AND inventory.generation=excluded.generation AND inventory.status IN ('enumerated','alias','inaccessible','excluded') THEN inventory.status WHEN inventory.signature=excluded.signature AND inventory.kind='file' AND inventory.status IN ('inspected','inspected-with-omissions','unsupported','protected','remote-only','excluded') AND excluded.status='pending' THEN inventory.status WHEN inventory.signature IS NOT excluded.signature AND excluded.status='pending' THEN 'changed' ELSE excluded.status END,priority=excluded.priority,generation=excluded.generation,size=excluded.size,cursor=excluded.cursor,detail=CASE WHEN inventory.signature=excluded.signature AND inventory.kind='file' AND inventory.status IN ('inspected','inspected-with-omissions','unsupported','protected','remote-only','excluded') AND excluded.status='pending' THEN inventory.detail ELSE excluded.detail END''', group)

    def inventory_page(self, location, kind, status, *, cursor=0, limit=100,prefer_priority=True):
        states=(status,) if isinstance(status,str) else tuple(status)
        placeholders=','.join('?' for _ in states)
        candidates=[]
        for index in range(256):
            bucket=f'i{index:02x}'
            if bucket in self.cache:
                priority=self.cache[bucket][0].conn.execute('SELECT min(priority) FROM inventory WHERE location=? AND kind=? AND status IN ('+placeholders+')',(location,kind,*states)).fetchone()[0]
            elif bucket in self.catalog:
                item=self.catalog[bucket];labels=[envelope.canonical([location,kind,state]).decode() for state in states]
                priorities=[item.get('priorities',{}).get(label,100) for label in labels if item['counts'].get(label,0)]
                priority=min(priorities) if priorities else None
            else:continue
            if priority is not None:candidates.append((priority if prefer_priority else 0,(index-cursor)%256,index))
        for _,_,index in sorted(candidates)[:8]:
            store=self.get(f'i{index:02x}')
            order='priority,path' if prefer_priority else 'path'
            rows=store.conn.execute('SELECT * FROM inventory WHERE location=? AND kind=? AND status IN ('+placeholders+') ORDER BY '+order+' LIMIT ?',(location,kind,*states,limit)).fetchall()
            if rows:return rows,(index+1)%256
        return [],(cursor+8)%256

    def inventory_set(self, path, status, *, cursor=None, detail=None,signature=None):
        store = self.get(self.bucket(path))
        with store.conn:
            store.conn.execute('UPDATE inventory SET status=?,cursor=?,detail=? WHERE path=?', (status,cursor,detail,path))
            if signature is not None:store.conn.execute('UPDATE inventory SET signature=? WHERE path=?',(signature,path))

    def physical_visit(self, identity, generation, path):
        store = self.get(self.bucket(identity, 'p'))
        row = store.conn.execute('SELECT generation,path FROM physical WHERE identity=?', (identity,)).fetchone()
        if row and row[0] == generation and row[1] != path:
            return False
        with store.conn:
            store.conn.execute('INSERT INTO physical VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET generation=excluded.generation,path=excluded.path', (identity,generation,path))
        return True

    def invalidate_location(self, source, index):
        bucket=f'i{index:02x}'
        if bucket in self.catalog or bucket in self.cache:
            store=self.get(bucket)
            with store.conn:
                store.conn.execute("UPDATE inventory SET status='pending',detail='policy-or-runtime-changed' WHERE location=? AND kind='file' AND status IN ('inspected','inspected-with-omissions','unsupported')",(source['id'],))
        evidence=f'e{index:02x}'
        if evidence in self.catalog or evidence in self.cache:self.get(evidence).invalidate_scope(source['root'],reason='source-unavailable')

    def reprioritize_location(self, source, index, rank):
        bucket=f'i{index:02x}'
        if bucket not in self.catalog and bucket not in self.cache:return
        store=self.get(bucket)
        rows=store.conn.execute('SELECT path,priority FROM inventory WHERE location=?',(source['id'],)).fetchall()
        changes=[]
        for path,previous in rows:
            value=rank(Path(path))
            if type(value) is not int or not 0<=value<=1000:raise StateError('state-data-invalid')
            if value!=previous:changes.append((value,path))
        with store.conn:store.conn.executemany('UPDATE inventory SET priority=? WHERE path=?',changes)

    def reconcile_location(self, source, generation, index):
        bucket=f'i{index:02x}'
        if bucket not in self.catalog and bucket not in self.cache:return
        store=self.get(bucket)
        paths=store.conn.execute("SELECT path FROM inventory WHERE location=? AND generation<>? AND status<>'not-seen'",(source['id'],generation)).fetchall()
        with store.conn:
            store.conn.execute("UPDATE inventory SET status='not-seen',detail='not-seen-in-latest-enumeration; absence-not-verified' WHERE location=? AND generation<>?",(source['id'],generation))
        evidence=f'e{index:02x}'
        if paths and (evidence in self.catalog or evidence in self.cache):
            child=self.get(evidence)
            for path, in paths:child.record_event(path,'deleted')

    def queue_reconciliation(self,source,generation,index):
        bucket=f'i{index:02x}'
        if bucket in self.catalog or bucket in self.cache:
            store=self.get(bucket)
            with store.conn:
                store.conn.execute("UPDATE inventory SET status='enumerating',cursor=NULL,generation=? WHERE location=? AND kind='directory' AND status IN ('enumerated','enumerating','inaccessible','excluded','alias')",(generation,source['id']))
