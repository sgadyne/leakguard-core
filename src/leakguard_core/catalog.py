"""Local metadata/location history; no raw file content or secrets are persisted."""
import ast
import datetime
import hashlib
import hmac
import json
import pathlib
import socket
import uuid

from . import policies

HOST = socket.gethostname()


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def initialize(conn):
    conn.executescript('''
      CREATE TABLE IF NOT EXISTS locations(host TEXT,path TEXT,profile TEXT,category TEXT,size INTEGER,digest TEXT,first_seen TEXT,last_seen TEXT,present INTEGER,PRIMARY KEY(host,path));
      CREATE TABLE IF NOT EXISTS location_events(id TEXT PRIMARY KEY,host TEXT,path TEXT,old_path TEXT,kind TEXT,profile TEXT,digest TEXT,observed TEXT);
      CREATE TABLE IF NOT EXISTS material_sources(name TEXT PRIMARY KEY,source TEXT,format TEXT,field TEXT,kind TEXT);
      CREATE TABLE IF NOT EXISTS material_locations(host TEXT,name TEXT,path TEXT,fingerprint TEXT,first_seen TEXT,last_seen TEXT,present INTEGER,PRIMARY KEY(host,name,path));
    ''')


def observed(conn, path):
    return bool(conn.execute('SELECT 1 FROM locations WHERE host=? AND path=?', (HOST, path)).fetchone())


def event(conn, path, kind, config, old_path=None, digest=None, when=None):
    path = policies.canonical(path, config)
    old_path = policies.canonical(old_path, config) if old_path else None
    when = when or stamp()
    conn.execute('INSERT INTO location_events VALUES(?,?,?,?,?,?,?,?)', (uuid.uuid4().hex, HOST, path, old_path, kind, policies.profile(path, config), digest, when))
    if kind == 'deleted':
        conn.execute('UPDATE locations SET present=0,last_seen=? WHERE host=? AND path=?', (when, HOST, path))
        conn.execute('UPDATE material_locations SET present=0,last_seen=? WHERE host=? AND path=?', (when, HOST, path))
    if old_path and kind == 'renamed':
        conn.execute('UPDATE locations SET present=0,last_seen=? WHERE host=? AND path=?', (when, HOST, old_path))
        conn.execute('UPDATE material_locations SET present=0,last_seen=? WHERE host=? AND path=?', (when, HOST, old_path))
    conn.commit()


def observe(conn, path, data, config):
    path = policies.canonical(path, config)
    when = stamp(); digest = hashlib.sha256(data).hexdigest()
    previous = conn.execute('SELECT digest FROM locations WHERE host=? AND path=?', (HOST, path)).fetchone()
    if not previous or previous[0] != digest:
        event(conn, path, 'discovered' if not previous else 'content-changed', config, digest=digest, when=when)
    conn.execute('INSERT INTO locations VALUES(?,?,?,?,?,?,?,?,1) ON CONFLICT(host,path) DO UPDATE SET profile=excluded.profile,category=excluded.category,size=excluded.size,digest=excluded.digest,last_seen=excluded.last_seen,present=1', (HOST, path, policies.profile(path, config), policies.classify(path), len(data), digest, when, when))
    conn.commit()
    return digest


def metadata_only(conn, path, size, config):
    path = policies.canonical(path, config); when = stamp()
    previous = conn.execute('SELECT size FROM locations WHERE host=? AND path=?', (HOST, path)).fetchone()
    if not previous or previous[0] != size:
        event(conn, path, 'metadata-discovered' if not previous else 'metadata-size-changed', config, when=when)
    conn.execute('INSERT INTO locations(host,path,profile,category,size,digest,first_seen,last_seen,present) VALUES(?,?,?,?,?,NULL,?,?,1) ON CONFLICT(host,path) DO UPDATE SET size=excluded.size,digest=NULL,last_seen=excluded.last_seen,present=1', (HOST, path, policies.profile(path, config), policies.classify(path), size, when, when))
    conn.commit()


def known_values(conn):
    """Deprecated registration validator with fresh bounded reads and fixed errors."""
    rows = conn.execute('SELECT name,source,format,field,kind FROM material_sources ORDER BY name LIMIT 101').fetchall()
    snapshot = snapshot_materials(rows, __import__('secrets').token_bytes(32))
    if snapshot.issues:
        raise ValueError('source-unavailable')
    for reference in snapshot.references:
        yield reference.name, reference.value, reference.kind


def match_materials(conn, path, text, state, *, complete=True):
    key_path = state / 'material-key.bin'
    if not key_path.exists():
        try:
            import os
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(__import__('secrets').token_bytes(32))
        except FileExistsError:
            pass
    key = key_path.read_bytes(); when = stamp(); matches = []
    names = set()
    for name, value, kind in known_values(conn):
        if value not in text:
            continue
        names.add(name)
        fingerprint = hmac.new(key, value.encode(), hashlib.sha256).hexdigest()
        conn.execute('INSERT INTO material_locations VALUES(?,?,?,?,?,?,1) ON CONFLICT(host,name,path) DO UPDATE SET fingerprint=excluded.fingerprint,last_seen=excluded.last_seen,present=1', (HOST, name, path, fingerprint, when, when))
        matches.append({'name': name, 'kind': kind, 'line': text[:text.index(value)].count('\n') + 1})
    existing = conn.execute('SELECT name FROM material_locations WHERE host=? AND path=? AND present=1', (HOST, path)).fetchall()
    for (name,) in existing:
        if name not in names:
            conn.execute('UPDATE material_locations SET present=?,last_seen=? WHERE host=? AND path=? AND name=?', (0 if complete else None, when, HOST, path, name))
    conn.commit()
    return matches


# Typed pipeline material snapshots are transient capabilities. Only their keyed
# identity and redacted observations may reach ScanStore/report publication.
from dataclasses import dataclass, field as dataclass_field


@dataclass(frozen=True)
class MaterialReference:
    name: str
    kind: str
    value: str = dataclass_field(repr=False)
    fingerprint: str


@dataclass(frozen=True)
class MaterialObservation:
    name: str
    kind: str
    part_id: str
    line: int
    fingerprint: str
    end_line: int


@dataclass(frozen=True)
class MaterialSnapshot:
    references: tuple[MaterialReference, ...]
    identity: str
    issues: tuple[str, ...] = ()
    validate: object = dataclass_field(default=None, repr=False)

    def valid(self):
        return self.validate is None or self.validate()


def snapshot_materials(rows, key, *, max_bytes=1_000_000, max_sources=100):
    """Read a bounded fresh source closure; missing/invalid sources are failures."""
    from .sources import _bounded_file, AcquisitionError
    references = []
    identities = []
    expected = []
    issues = []
    from itertools import islice
    rows = tuple(islice(iter(rows), max_sources + 1))
    if len(rows) > max_sources:
        issues.append('detector-output-limit')
        rows = rows[:max_sources]
    def unique(pairs):
        result = {}
        for name, item in pairs:
            if name in result:
                raise ValueError()
            result[name] = item
        return result
    remaining = max_bytes
    for name, source, fmt, field, kind in rows:
        content = None
        source_identity = 'missing'
        try:
            if kind not in {'credential', 'license'} or not all(isinstance(item, str) for item in (name, source, fmt, field)):
                raise ValueError()
            content = _bounded_file(pathlib.Path(source), min(max_bytes, remaining))
            remaining -= len(content)
            source_identity = hmac.new(key, content, hashlib.sha256).hexdigest()
            text = content.decode('utf-8-sig', errors='strict')
            if fmt == 'json':
                value = json.loads(text, object_pairs_hook=unique)
                for component in field.split('.'):
                    value = value[component]
            elif fmt in {'python', 'py', 'python-assignment'}:
                tree = ast.parse(text)
                candidates = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == field for target in node.targets)]
                if len(candidates) != 1:
                    raise ValueError()
                value = candidates[0]
            else:
                raise ValueError()
            if type(value) is not str or not 8 <= len(value) <= max_bytes:
                raise ValueError()
            references.append(MaterialReference(name, kind, value, hmac.new(key, value.encode(), hashlib.sha256).hexdigest()))
        except (AcquisitionError, OSError):
            issues.append('source-unavailable')
        except (ValueError, KeyError, TypeError, SyntaxError, UnicodeError, RecursionError):
            issues.append('detector-failed')
        registration = [name, source, fmt, field, kind, source_identity]
        identities.append(hmac.new(key, json.dumps(registration, ensure_ascii=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest())
        expected.append((source, source_identity, len(content) if content is not None else None))
    identity = hmac.new(key, json.dumps(['materials-v1', identities], separators=(',', ':')).encode(), hashlib.sha256).hexdigest()

    def valid():
        # Compare keyed content identities, never retain source bytes or values.
        for source, original, original_size in expected:
            if original == 'missing':
                if pathlib.Path(source).exists():
                    return False
                continue
            try:
                current = hmac.new(key, _bounded_file(pathlib.Path(source), original_size), hashlib.sha256).hexdigest()
            except (AcquisitionError, OSError):
                current = 'missing'
            if current != original:
                return False
        return True
    return MaterialSnapshot(tuple(references), identity, tuple(dict.fromkeys(issues)), valid)


def material_observations(snapshot, part_id, text):
    observations = []
    for reference in snapshot.references:
        position = text.find(reference.value)
        if position >= 0:
            first = text[:position].count('\n') + 1
            last = first + reference.value.count('\n') - int(reference.value.endswith('\n'))
            observations.append(MaterialObservation(reference.name, reference.kind, part_id, first, reference.fingerprint, max(first, last)))
    return tuple(observations)
