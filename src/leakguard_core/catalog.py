"""Local metadata/location history; no raw file content or secrets are persisted."""
import ast
import datetime
import hashlib
import hmac
import json
import pathlib
import socket
import time
import uuid

from . import policies

HOST = socket.gethostname()
_VALUE_CACHE = {}


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
    for name, source, fmt, field, kind in conn.execute('SELECT name,source,format,field,kind FROM material_sources'):
        try:
            cached = _VALUE_CACHE.get((name, source, fmt, field))
            if cached and time.monotonic() - cached[0] < 30:
                yield name, cached[1], kind
                continue
            text = pathlib.Path(source).read_text(encoding='utf-8')
            if fmt == 'json':
                value = json.loads(text)
                for key in field.split('.'):
                    value = value[key]
            else:
                tree = ast.parse(text)
                value = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == field for t in node.targets))
            if isinstance(value, str) and len(value) >= 8:
                _VALUE_CACHE[(name, source, fmt, field)] = (time.monotonic(), value)
                yield name, value, kind
        except (OSError, ValueError, KeyError, StopIteration, SyntaxError):
            continue


def match_materials(conn, path, text, state):
    key_path = state / 'material-key.bin'
    if not key_path.exists():
        try:
            with key_path.open('xb') as stream:
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
            conn.execute('UPDATE material_locations SET present=0,last_seen=? WHERE host=? AND path=? AND name=?', (when, HOST, path, name))
    conn.commit()
    return matches
