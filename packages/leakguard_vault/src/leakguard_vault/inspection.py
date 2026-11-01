"""Wall-clock evidence kept separate from monotonic scheduling admissions.

Only a newly observed pending transition gets a wall-clock start. Installing this
schema, loading a historical row, or selecting work never manufactures its age.
The status projection reads encrypted catalog summaries, with no partition opens.
"""
from __future__ import annotations
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS inventory_chronology(
 path TEXT PRIMARY KEY, location TEXT NOT NULL, signature TEXT, generation INTEGER NOT NULL,
 pending_since REAL, last_complete_at REAL);
CREATE TABLE IF NOT EXISTS inspection_totals(
 id INTEGER PRIMARY KEY CHECK(id=1), observation_started_at REAL NOT NULL,
 observed_change INTEGER NOT NULL DEFAULT 0, ordinary INTEGER NOT NULL DEFAULT 0,
 reserved_oldest INTEGER NOT NULL DEFAULT 0, oldest_wait REAL, last_complete_at REAL);
"""
_PENDING = frozenset({'pending', 'changed'})
_ROUTES = frozenset({'observed_change', 'ordinary', 'reserved_oldest'})


def transition(conn, previous, current, *, route=None, now=None):
    """Run inside the inventory writer transaction, after its state transition."""
    if current is None or current[2] != 'file':
        if previous is not None:
            conn.execute('DELETE FROM inventory_chronology WHERE path=?', (previous[0],))
        return
    now = time.time() if now is None else now
    path, location, _, signature, status, _, generation, *_ = current
    existing = conn.execute('SELECT location,signature,generation,pending_since,last_complete_at FROM inventory_chronology WHERE path=?', (path,)).fetchone()
    same = previous is not None and all(previous[i] == current[i] for i in (1,2,3,6))
    matching = existing is not None and (existing[0],existing[1],existing[2]) == (location,signature,generation)
    pending_since = existing[3] if same and matching else None
    last_complete = existing[4] if same and matching else None
    # Legacy unchanged pending rows have no observed enqueue time. A real new
    # version/generation or a nonpending-to-pending transition does have one.
    if status in _PENDING and (not same or previous[4] not in _PENDING):
        pending_since = now
    conn.execute('INSERT OR IGNORE INTO inspection_totals(id,observation_started_at) VALUES(1,?)', (now,))
    complete = status == 'inspected' and route in _ROUTES and (
        not same or previous[4] != 'inspected')
    if complete:
        wait = max(0., now - pending_since) if pending_since is not None else None
        last_complete = now
        conn.execute('UPDATE inspection_totals SET '+route+'='+route+'+1,'
            'last_complete_at=?,oldest_wait=CASE WHEN ? IS NULL THEN oldest_wait '
            'WHEN oldest_wait IS NULL OR oldest_wait<? THEN ? ELSE oldest_wait END WHERE id=1',
            (now,wait,wait,wait))
    if status not in _PENDING:
        pending_since = None
    conn.execute('INSERT INTO inventory_chronology VALUES(?,?,?,?,?,?) '
        'ON CONFLICT(path) DO UPDATE SET location=excluded.location,signature=excluded.signature,'
        'generation=excluded.generation,pending_since=excluded.pending_since,last_complete_at=excluded.last_complete_at',
        (path,location,signature,generation,pending_since,last_complete))


def summary(conn, *, now=None):
    """Mutation-time aggregation; this work is never done by status polling."""
    known, unknown, oldest = conn.execute("""
        SELECT coalesce(sum(c.pending_since IS NOT NULL),0),
               coalesce(sum(c.pending_since IS NULL),0),min(c.pending_since)
        FROM inventory i LEFT JOIN inventory_chronology c ON c.path=i.path
          AND c.location=i.location AND c.signature IS i.signature AND c.generation=i.generation
        WHERE i.kind='file' AND i.status IN ('pending','changed')
    """).fetchone()
    row = conn.execute('SELECT observation_started_at,observed_change,ordinary,reserved_oldest,oldest_wait,last_complete_at FROM inspection_totals WHERE id=1').fetchone()
    return {'measured_at': time.time() if now is None else now,
            'observation_started_at':row[0] if row else None,
            'last_complete_inspection_at':row[5] if row else None,
            'pending':{'with_known_age':known,'with_unknown_age':unknown,
                       'oldest_observed_pending_at':oldest},
            'completed':{'observed_change':row[1] if row else 0,'ordinary':row[2] if row else 0,
                         'reserved_oldest':row[3] if row else 0,
                         'oldest_observed_wait_seconds':row[4] if row else None}}


def projection(catalog):
    result = {'schema_version':1,'measured_at':None,'observation_started_at':None,
              'last_complete_inspection_at':None,
              'pending':{'with_known_age':0,'with_unknown_age':0,'oldest_observed_pending_at':None},
              'completed':{'observed_change':0,'ordinary':0,'reserved_oldest':0,
                           'oldest_observed_wait_seconds':None}, 'diagnostics':[],
              'measurement':'last-encrypted-checkpoint-catalog',
              'age_buckets_available':False}
    def extreme(key, value, *, smallest=False, target=None):
        target = result if target is None else target
        if value is not None and (target[key] is None or (value < target[key] if smallest else value > target[key])):
            target[key] = value
    for bucket, item in catalog.items():
        if not bucket.startswith('i'):
            continue
        measured = item.get('inspection')
        if measured is None:
            # Old encrypted partitions are counted from their existing catalog;
            # no migration decrypt, invented enqueue time, or full-store walk.
            from . import _envelope as envelope
            for label,count in item['counts'].items():
                _,kind,state = envelope.load_json(label.encode())
                if kind == 'file' and state in _PENDING:
                    result['pending']['with_unknown_age'] += count
            continue
        extreme('measured_at',measured['measured_at'])
        extreme('observation_started_at',measured['observation_started_at'],smallest=True)
        extreme('last_complete_inspection_at',measured['last_complete_inspection_at'])
        for key in ('with_known_age','with_unknown_age'):
            result['pending'][key] += measured['pending'][key]
        extreme('oldest_observed_pending_at',measured['pending']['oldest_observed_pending_at'],smallest=True,target=result['pending'])
        for key in _ROUTES:
            result['completed'][key] += measured['completed'][key]
        extreme('oldest_observed_wait_seconds',measured['completed']['oldest_observed_wait_seconds'],target=result['completed'])
    return result
