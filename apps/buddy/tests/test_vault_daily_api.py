"""Exercise the real authenticated loopback API with disposable profiles."""
import base64
import http.client
import json

from leakguard_buddy.backend import BuddyBackend
from leakguard_buddy.server import LocalBuddy

OLD = 'synthetic-original-passphrase'
NEW = 'synthetic-new-passphrase'
RECOVERY = 'synthetic-recovery-passphrase'


class Client:
    def __init__(self, profile):
        self.app = LocalBuddy(BuddyBackend(state_dir=profile))
        self.app.start()
        status, data, headers = self.raw('POST', '/__bootstrap', {'token': self.app.bootstrap}, bootstrap=True)
        assert status == 200
        self.cookie = headers['Set-Cookie'].split(';', 1)[0]
        self.csrf = data['csrf']

    def raw(self, method, path, body=None, *, bootstrap=False, csrf=True, origin=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.app.server.server_address[1], timeout=15)
        headers = {'Host': self.app.server.expected_host}
        if body is not None:
            headers['Content-Type'] = 'application/json'
            headers['Origin'] = origin or self.app.server.origin
        if not bootstrap:
            headers['Cookie'] = self.cookie
            if csrf:
                headers['X-Buddy-CSRF'] = self.csrf
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = conn.getresponse()
        result = (response.status, json.loads(response.read()), dict(response.getheaders()))
        conn.close()
        return result

    def request(self, method, path, body=None, **kwargs):
        status, payload, _ = self.raw(method, '/api/vault' + path, body, **kwargs)
        return status, payload

    def close(self):
        self.app.close()


def test_credential_api_lifecycle_and_independent_restore(tmp_path):
    a = Client(tmp_path / 'a')
    b = None
    try:
        assert a.request('POST', '/create', {'passphrase': OLD})[0] == 201
        assert a.request('POST', '/generate', {'length': 24}, csrf=False)[0] == 403
        assert a.request('POST', '/generate', {'length': 24}, origin='http://localhost')[0] == 403
        assert a.request('POST', '/generate', {'length': True})[0] == 400
        status, generated = a.request('POST', '/generate', {'length': 24})
        assert status == 200 and len(generated['secret']) == 24
        secret = generated['secret']
        status, entry = a.request('POST', '/entries', {'title':'Example', 'location':'service.invalid', 'username':'synthetic-user', 'secret':secret})
        assert status == 201 and 'secret' not in entry and 'username' not in entry
        entry_path = '/entries/' + entry['id']
        assert a.request('GET', '/entries')[1]['entries'] == [entry]
        assert a.request('POST', entry_path + '/reveal', {})[1]['secret'] == secret
        assert a.request('POST', entry_path + '/copy', {})[1]['secret'] == secret
        assert a.request('PATCH', entry_path, {'title':'Renamed'})[0] == 200
        assert a.request('POST', entry_path + '/reveal', {})[1]['username'] == 'synthetic-user'
        status, backup = a.request('POST', '/backup', {'passphrase':RECOVERY})
        assert status == 200
        assert a.request('POST', '/change-passphrase', {'current_passphrase':'synthetic-wrong-passphrase', 'new_passphrase':NEW})[0] == 401
        assert a.request('POST', '/change-passphrase', {'current_passphrase':OLD, 'new_passphrase':NEW})[0] == 200
        assert a.request('POST', '/lock', {})[0] == 200
        assert a.request('POST', '/unlock', {'passphrase':OLD})[0] == 401
        assert a.request('POST', '/unlock', {'passphrase':NEW})[0] == 200
        assert a.request('DELETE', entry_path, {})[0] == 200
        assert a.request('GET', '/entries')[1]['entries'] == []
        a.close()
        a = Client(tmp_path / 'a')
        assert a.request('POST', '/unlock', {'passphrase':NEW})[0] == 200
        assert a.request('GET', '/entries')[1]['entries'] == []
        b = Client(tmp_path / 'b')
        payload = {'backup':backup['backup_base64'], 'backup_passphrase':RECOVERY, 'new_passphrase':OLD}
        assert b.request('POST', '/restore', {**payload, 'backup_passphrase':'synthetic-wrong-recovery'})[0] == 401
        assert b.request('POST', '/restore', {**payload, 'backup':base64.b64encode(b'truncated').decode()})[0] >= 400
        assert b.request('POST', '/restore', payload)[0] == 200
        assert b.request('POST', entry_path + '/reveal', {})[1]['secret'] == secret
        for path in tmp_path.rglob('*'):
            if path.is_file():
                raw = path.read_bytes()
                assert all(v.encode() not in raw for v in (secret, OLD, NEW, RECOVERY, 'synthetic-user'))
    finally:
        a.close()
        if b is not None:
            b.close()


def test_near_capacity_backup_restores_through_api(tmp_path):
    # Construct a valid near-capacity vault in one commit, avoiding hundreds of
    # progressively larger test writes; the backup and restore use real APIs.
    from datetime import datetime, timezone
    import uuid
    from leakguard_vault import _envelope
    from leakguard_vault.credentials import MAX_CREDENTIAL_BYTES

    a = Client(tmp_path / 'large-a')
    b = None
    try:
        assert a.request('POST', '/create', {'passphrase': OLD})[0] == 201
        session = a.app.backend._credential_session
        entries = {}
        now = datetime.now(timezone.utc).isoformat()
        for i in range(256):
            identity = uuid.uuid4().hex
            entries[identity] = {'id':identity, 'title':f'Item {i}', 'secret':'synthetic-value',
                'username':'', 'location':'', 'notes':'x' * 65000, 'finding_id':None,
                'created_at':now, 'updated_at':now}
        size = len(_envelope.canonical({'schema':1, 'entries':entries}))
        remaining = MAX_CREDENTIAL_BYTES - 64 - size
        # Distribute remaining space among entries without exceeding field limit.
        for entry in entries.values():
            amount = min(65536 - len(entry['notes']), remaining)
            entry['notes'] += 'x' * amount
            remaining -= amount
            if remaining == 0:
                break
        assert remaining == 0
        session._persist(entries)
        status, backup = a.request('POST', '/backup', {'passphrase':RECOVERY})
        assert status == 200
        assert len(base64.b64decode(backup['backup_base64'])) > 16 * 1024 * 1024
        b = Client(tmp_path / 'large-b')
        assert b.request('POST', '/restore', {'backup':backup['backup_base64'], 'backup_passphrase':RECOVERY, 'new_passphrase':NEW})[0] == 200
        assert len(b.request('GET', '/entries')[1]['entries']) == 256
    finally:
        a.close()
        if b is not None:
            b.close()
