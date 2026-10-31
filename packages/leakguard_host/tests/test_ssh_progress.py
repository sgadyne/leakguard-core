"""Synthetic reproducer for the stateless SSH enumeration deadline."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


WORKER = Path(__file__).resolve().parents[1] / 'src/leakguard_host/ssh_location_worker.py'
# Each clock check advances one simulated second. This models a directory
# whose prefix takes longer to walk than the per-request three-second budget,
# without sleeping or relying on filesystem speed.
SLOW_PREFIX = r'''
import runpy, sys, time
counter = iter(range(100000))
time.monotonic = lambda: next(counter)
runpy.run_path(sys.argv[1], run_name='__main__')
'''


def enumerate_page(root, cursor=None):
    request = {'op': 'enumerate', 'root': str(root), 'path': str(root),
               'cursor': cursor, 'limit': 1000}
    process = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', SLOW_PREFIX, str(WORKER)],
                             input=json.dumps(request).encode(), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, check=True, timeout=10)
    result = json.loads(process.stdout)
    if result['status'] == 'timeout':
        return result, None
    assert result['status'] == 'available'
    info = result['info']
    signature = [info[key] for key in ('st_dev', 'st_ino', 'st_mode', 'st_size',
                                       'st_mtime_ns', 'st_ctime_ns', 'st_flags')]
    next_cursor = {'signature': signature, 'entries': result['position'], 'prefix': result['prefix']}
    return result, next_cursor


def test_stateless_browse_surfaces_slow_prefix_as_timeout(tmp_path):
    root = tmp_path / 'synthetic'
    make_files(root)
    first, cursor = enumerate_page(root)
    assert first['stable'] and len(first['entries']) == 2 and not first['complete']
    stalled, _ = enumerate_page(root, cursor)
    assert stalled['status'] == 'timeout'


class LocalRunner:
    port = None

    def __init__(self, slow=False):
        self.slow = slow

    def _command(self, target, python, script, *, isolated):
        assert isolated
        clock = "import time\n_clock=iter(range(100000))\ntime.monotonic=lambda:next(_clock)\n" if self.slow else ''
        # Simulate a Linux endpoint for protocol tests running on the Mac.
        # Its real Linux address-space limit is verified only on Linux.
        platform = ("import sys,resource\nsys.platform='linux'\n_original_limit=resource.setrlimit\n"
                    "resource.setrlimit=lambda kind,limit: None if kind==resource.RLIMIT_AS else _original_limit(kind,limit)\n")
        return [sys.executable, '-I', '-S', '-B', '-c', platform + clock + script]


def cursor_for(page):
    info = page['info']
    return {'signature': [info[key] for key in ('st_dev', 'st_ino', 'st_mode', 'st_size',
                                                 'st_mtime_ns', 'st_ctime_ns', 'st_flags')],
            'entries': page['position'], 'prefix': page['prefix']}


def call(sessions, root, cursor=None, *, runner=None, expected=None, path=None, cancel=None, limit=1000):
    return sessions.request(runner or LocalRunner(), 'synthetic',
                            {'op': 'enumerate', 'root': str(root), 'path': str(path or root),
                             'expected': expected, 'cursor': cursor, 'limit': limit},
                            python='/usr/bin/python3', cancel=cancel)


def make_files(root, count=6):
    root.mkdir()
    names = {f'fixture-{i:02d}.txt' for i in range(count)}
    for name in sorted(names):
        (root / name).touch()
    return names


def test_session_advances_and_replays_a_durable_slow_prefix_after_restart(tmp_path):
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'synthetic'
    expected = make_files(root, 10)
    runner = LocalRunner(slow=True)
    sessions = DirectorySessions()
    try:
        first = call(sessions, root, runner=runner)
        assert first['stable'] and not first['complete'] and first['entries']
        assert first['session_capability'] == 'retained-linux'
        durable = cursor_for(first)
        # Restart discards the iterator. Replaying the old prefix may consume
        # several requests, but must never retreat the durable cursor or emit it.
        sessions.close()
        seen = {entry['name'] for entry in first['entries']}
        cursor = durable
        for _ in range(20):
            page = call(sessions, root, cursor, runner=runner)
            assert page['stable']
            new = {entry['name'] for entry in page['entries']}
            assert not seen.intersection(new)
            seen.update(new)
            next_cursor = cursor_for(page)
            assert next_cursor['entries'] >= cursor['entries']
            if not new and not page['complete']:
                assert next_cursor == cursor
            cursor = next_cursor
            if page['complete']:
                break
        assert page['complete'] and seen == expected
    finally:
        sessions.close()


def test_uncommitted_cursor_replays_without_skipping_entries(tmp_path):
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = DirectorySessions()
    try:
        first = call(sessions, root, limit=2)
        original_cursor = cursor_for(first)
        uncommitted = call(sessions, root, original_cursor, limit=2)
        replay = call(sessions, root, original_cursor, limit=2)
        assert replay['entries'] == uncommitted['entries']
        assert cursor_for(replay) == cursor_for(uncommitted)
    finally:
        sessions.close()


def test_mutated_directory_discards_stream_and_cursor(tmp_path):
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = DirectorySessions()
    try:
        first = call(sessions, root, limit=2)
        (root / 'new-file').touch()
        changed = call(sessions, root, cursor_for(first), limit=2)
        assert changed['stable'] is False and not changed['entries'] and not changed['complete']
        fresh = call(sessions, root, limit=1000)
        assert fresh['stable'] and fresh['complete'] and 'new-file' in {x['name'] for x in fresh['entries']}
    finally:
        sessions.close()


def test_session_revalidates_ancestry_and_source(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'root'
    root.mkdir()
    child = root / 'child'
    make_files(child)
    sessions = DirectorySessions()
    try:
        first = call(sessions, root, path=child, limit=2)
        child.rename(root / 'old')
        child.symlink_to(root / 'old', target_is_directory=True)
        with pytest.raises(HostError):
            call(sessions, root, cursor_for(first), path=child, limit=2)
        with pytest.raises(HostError) as error:
            call(sessions, root, expected={'machine': 'wrong', 'device': 1, 'inode': 1})
        assert error.value.code == 'source-changed'
    finally:
        sessions.close()


def test_cancellation_and_session_limit_release_processes(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions
    sessions = DirectorySessions(max_sessions=2)
    try:
        roots = [tmp_path / str(i) for i in range(3)]
        for root in roots:
            make_files(root)
            call(sessions, root, limit=1)
        assert len(sessions._sessions) == 2
        processes = [item['process'] for item in sessions._sessions.values()]
        with pytest.raises(HostError) as error:
            call(sessions, roots[-1], cancel=lambda: True)
        assert error.value.code == 'cancelled'
        assert processes[-1].poll() is not None
    finally:
        sessions.close()
    assert all(process.poll() is not None for process in processes)


def test_bad_prefix_is_rejected_after_incremental_replay(tmp_path):
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'synthetic'
    make_files(root, 10)
    sessions = DirectorySessions()
    runner = LocalRunner(slow=True)
    try:
        first = call(sessions, root, limit=3)
        cursor = cursor_for(first)
        cursor['prefix'] = '0' * 64
        sessions.close()
        for _ in range(10):
            page = call(sessions, root, cursor, runner=runner)
            assert not page['entries'] and not page['complete']
            if not page['stable']:
                break
            assert cursor_for(page) == cursor
        assert page['stable'] is False
    finally:
        sessions.close()


def test_remote_discovery_instances_share_owner_session(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from leakguard_host import discovery_remote
    root = tmp_path / 'synthetic'
    make_files(root)
    monkeypatch.setattr(discovery_remote, 'SSHRunner', lambda **kwargs: LocalRunner())
    owner = SimpleNamespace(store=None, config=None)
    source = {'ssh_target': 'synthetic', 'remote_root': str(root)}
    try:
        first = discovery_remote.RemoteDiscovery(owner)._request(source, 'enumerate', path=str(root), cursor=None, limit=1)
        process = next(iter(owner._ssh_directory_sessions._sessions.values()))['process']
        second = discovery_remote.RemoteDiscovery(owner)._request(source, 'enumerate', path=str(root), cursor=cursor_for(first), limit=1)
        assert process is next(iter(owner._ssh_directory_sessions._sessions.values()))['process']
        assert second['entries'] and second['entries'] != first['entries']
    finally:
        owner._ssh_directory_sessions.close()


def test_crashed_session_replays_and_repeated_losses_are_a_gap(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'synthetic'
    make_files(root, 10)
    sessions = DirectorySessions()
    try:
        page = call(sessions, root, limit=3)
        cursor = cursor_for(page)
        # Each replacement process loses its iterator while replaying. The
        # manager must eventually surface an unavailable coverage gap.
        for _ in range(3):
            next(iter(sessions._sessions.values()))['process'].kill()
            next(iter(sessions._sessions.values()))['process'].wait()
            try:
                page = call(sessions, root, cursor, runner=LocalRunner(slow=True))
            except HostError as error:
                assert error.code == 'ssh-directory-replay-stalled'
                break
            assert not page['complete'] and not page['entries'] and cursor_for(page) == cursor
        else:
            pytest.fail('repeated lost sessions were not reported as a gap')
    finally:
        sessions.close()


def test_inflight_cancel_kills_process_without_counting_a_failure(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions
    class SlowRunner(LocalRunner):
        def _command(self, target, python, script, *, isolated):
            return super()._command(target, python, 'import time; time.sleep(5)\n' + script, isolated=isolated)
    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = DirectorySessions()
    checks = iter([False, False, True])
    try:
        with pytest.raises(HostError) as error:
            call(sessions, root, runner=SlowRunner(), cancel=lambda: next(checks, True))
        assert error.value.code == 'cancelled'
        assert not sessions._sessions and not sessions._losses
    finally:
        sessions.close()


def test_replaced_root_rejects_expected_source_identity(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = DirectorySessions()
    try:
        probe = subprocess.run([sys.executable, '-I', '-S', '-B', str(WORKER)],
                               input=json.dumps({'op': 'probe', 'root': str(root)}).encode(),
                               stdout=subprocess.PIPE, check=True, timeout=10)
        identity = json.loads(probe.stdout)['identity']
        first = call(sessions, root, expected=identity, limit=1)
        root.rename(tmp_path / 'old')
        root.mkdir()
        with pytest.raises(HostError) as error:
            call(sessions, root, cursor_for(first), expected=identity, limit=1)
        assert error.value.code == 'source-changed'
    finally:
        sessions.close()


def test_unsupported_platform_falls_back_and_reports_a_stalled_prefix(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions
    class UnsupportedRunner(LocalRunner):
        def _command(self, target, python, script, *, isolated):
            if 'def _remote_main()' in script:
                prelude = "import sys\nsys.platform='darwin'\n"
            else:
                prelude = "import time\n_clock=iter(range(100000))\ntime.monotonic=lambda:next(_clock)\n"
            return [sys.executable, '-I', '-S', '-B', '-c', prelude + script]
    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = DirectorySessions()
    runner = UnsupportedRunner()
    try:
        first = call(sessions, root, runner=runner)
        assert first['session_capability'] == 'unsupported' and len(first['entries']) == 2
        assert not sessions._sessions
        with pytest.raises(HostError) as error:
            call(sessions, root, cursor_for(first), runner=runner)
        assert error.value.code == 'ssh-timeout'
    finally:
        sessions.close()


def test_completed_session_exits_normally_and_is_reaped(tmp_path):
    from leakguard_host.ssh_directory_session import DirectorySessions
    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = DirectorySessions()
    try:
        first = call(sessions, root, limit=2)
        process = next(iter(sessions._sessions.values()))['process']
        cursor = cursor_for(first)
        while True:
            page = call(sessions, root, cursor, limit=2)
            cursor = cursor_for(page)
            if page['complete']:
                break
        assert not sessions._sessions and process.returncode == 0
    finally:
        sessions.close()


def test_non_posix_client_uses_stateless_transport_without_starting_session(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from leakguard_host import ssh_directory_session as module

    class OneShotRunner(LocalRunner):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def _command(self, target, python, script, *, isolated):
            self.calls += 1
            assert 'def _remote_main()' not in script
            return super()._command(target, python, script, isolated=isolated)

    root = tmp_path / 'synthetic'
    expected = make_files(root)
    runner = OneShotRunner()
    sessions = module.DirectorySessions()
    # Isolate the simulated platform attribute from the real os module used
    # by subprocess and pathlib. This is not native Windows qualification.
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='nt'))
    try:
        first = call(sessions, root, runner=runner, limit=2)
        assert first['session_capability'] == 'client-unsupported'
        second = call(sessions, root, cursor_for(first), runner=runner, limit=2)
        assert second['session_capability'] == 'client-unsupported'
        assert {e['name'] for e in first['entries']}.isdisjoint(e['name'] for e in second['entries'])
        assert all(e['name'] in expected for e in first['entries'] + second['entries'])
        assert runner.calls == 2 and not sessions._sessions
    finally:
        sessions.close()


def test_session_worker_rejects_duplicate_request_keys(tmp_path):
    root = tmp_path / 'synthetic'
    make_files(root)
    request = json.dumps({'op': 'enumerate', 'root': str(root), 'path': str(root), 'limit': 1000})
    request = request.replace('"op": "enumerate"', '"op": "enumerate", "op": "enumerate"', 1)
    assert json.loads(request)['op'] == 'enumerate'
    script = (Path(__file__).resolve().parents[1] / 'src/leakguard_host/ssh_directory_session.py').read_text()
    runner = LocalRunner()
    process = subprocess.run(runner._command('synthetic', '/usr/bin/python3', script, isolated=True),
                             input=(request + '\n').encode(),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10)
    assert json.loads(process.stdout)['status'] == 'unavailable'


def test_session_client_rejects_duplicate_response_keys(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions

    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_flags')
    payload = json.dumps({'version': 1, 'status': 'available', 'identity': None,
                          'info': {key: 1 for key in fields}, 'entries': [], 'position': 0,
                          'prefix': hashlib.sha256().hexdigest(), 'stable': True, 'complete': True})
    payload = payload.replace('"version": 1', '"version": 1, "version": 1', 1)
    assert json.loads(payload)['status'] == 'available'

    class DuplicateRunner(LocalRunner):
        def _command(self, target, python, script, *, isolated):
            code = f'import sys;sys.stdin.readline();print({payload!r},flush=True)'
            return [sys.executable, '-I', '-S', '-B', '-c', code]

    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = DirectorySessions()
    try:
        with pytest.raises(HostError) as error:
            call(sessions, root, runner=DuplicateRunner())
        assert error.value.code == 'remote-report-invalid' and not sessions._sessions
    finally:
        sessions.close()


def test_posix_client_without_nonblocking_pipe_api_uses_stateless_transport(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from leakguard_host import ssh_directory_session as module
    root = tmp_path / 'synthetic'
    make_files(root)
    sessions = module.DirectorySessions()
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='posix'))
    try:
        page = call(sessions, root, limit=2)
        assert page['session_capability'] == 'client-unsupported'
        assert page['entries'] and not sessions._sessions
    finally:
        sessions.close()


@pytest.mark.parametrize('replacement', [b'synthetic-id-after!', b'x' * 4097])
@pytest.mark.parametrize('expect_identity', [True, False])
def test_machine_identity_is_rechecked_across_retained_pages(tmp_path, replacement, expect_identity):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions

    root = tmp_path / 'synthetic'
    make_files(root)
    machine_id = tmp_path / 'synthetic-machine-id'
    machine_id.write_bytes(b'synthetic-id-before')
    info = root.stat()
    identity = {'machine': hashlib.sha256(machine_id.read_bytes()).hexdigest(),
                'device': info.st_dev, 'inode': info.st_ino}

    class SyntheticMachineRunner(LocalRunner):
        def _command(self, target, python, script, *, isolated):
            prelude = f'''import pathlib
_original_is_file = pathlib.Path.is_file
_original_open = pathlib.Path.open
_synthetic_machine_id = pathlib.Path({str(machine_id)!r})
def _observed_is_file(path):
    return _original_is_file(_synthetic_machine_id) if str(path) == '/etc/machine-id' else _original_is_file(path)
def _observed_open(path, *args, **kwargs):
    return _original_open(_synthetic_machine_id, *args, **kwargs) if str(path) == '/etc/machine-id' else _original_open(path, *args, **kwargs)
pathlib.Path.is_file = _observed_is_file
pathlib.Path.open = _observed_open
'''
            return super()._command(target, python, prelude + script, isolated=isolated)

    sessions = DirectorySessions()
    runner = SyntheticMachineRunner()
    try:
        expected = identity if expect_identity else None
        first = call(sessions, root, expected=expected, runner=runner, limit=2)
        assert first['identity'] == identity and first['entries'] and not first['complete']
        # The root's device, inode, and directory metadata remain unchanged.
        # The first replacement also preserves the machine-id file size.
        machine_id.write_bytes(replacement)
        if expect_identity or len(replacement) > 4096:
            with pytest.raises(HostError) as error:
                call(sessions, root, cursor_for(first), expected=expected, runner=runner, limit=2)
            assert error.value.code == 'source-changed'
        else:
            changed = call(sessions, root, cursor_for(first), expected=None, runner=runner, limit=2)
            assert changed['stable'] is False and not changed['entries'] and not changed['complete']
        assert not sessions._sessions
    finally:
        sessions.close()


def test_absent_machine_id_uses_existing_hostname_identity(tmp_path):
    import platform
    from leakguard_host.ssh_directory_session import DirectorySessions

    root = tmp_path / 'synthetic'
    make_files(root)
    info = root.stat()
    identity = {'machine': hashlib.sha256(platform.node().encode()).hexdigest(),
                'device': info.st_dev, 'inode': info.st_ino}

    class NoMachineIDRunner(LocalRunner):
        def _command(self, target, python, script, *, isolated):
            prelude = '''import pathlib
_original_is_file = pathlib.Path.is_file
def _observed_is_file(path):
    return False if str(path) == '/etc/machine-id' else _original_is_file(path)
pathlib.Path.is_file = _observed_is_file
'''
            return super()._command(target, python, prelude + script, isolated=isolated)

    sessions = DirectorySessions()
    try:
        first = call(sessions, root, expected=identity, runner=NoMachineIDRunner(), limit=2)
        assert first['identity'] == identity and first['entries']
        second = call(sessions, root, cursor_for(first), expected=identity, runner=NoMachineIDRunner(), limit=2)
        assert second['identity'] == identity and second['entries']
    finally:
        sessions.close()


def test_absent_machine_id_rechecks_hostname_across_pages(tmp_path):
    from leakguard_host.errors import HostError
    from leakguard_host.ssh_directory_session import DirectorySessions

    root = tmp_path / 'synthetic'
    make_files(root)
    hostname = tmp_path / 'synthetic-hostname'
    hostname.write_text('synthetic-node-before')
    info = root.stat()
    identity = {'machine': hashlib.sha256(hostname.read_bytes()).hexdigest(),
                'device': info.st_dev, 'inode': info.st_ino}

    class SyntheticHostnameRunner(LocalRunner):
        def _command(self, target, python, script, *, isolated):
            prelude = f'''import collections,os,pathlib
_original_is_file = pathlib.Path.is_file
def _observed_is_file(path):
    return False if str(path) == '/etc/machine-id' else _original_is_file(path)
pathlib.Path.is_file = _observed_is_file
_original_uname = os.uname
_Uname = collections.namedtuple('_Uname', 'sysname nodename release version machine')
def _observed_uname():
    value = _original_uname()
    return _Uname(value.sysname, pathlib.Path({str(hostname)!r}).read_text(), value.release, value.version, value.machine)
os.uname = _observed_uname
'''
            return super()._command(target, python, prelude + script, isolated=isolated)

    sessions = DirectorySessions()
    runner = SyntheticHostnameRunner()
    try:
        first = call(sessions, root, expected=identity, runner=runner, limit=2)
        assert first['identity'] == identity and first['entries']
        hostname.write_text('synthetic-node-after!')
        with pytest.raises(HostError) as error:
            call(sessions, root, cursor_for(first), expected=identity, runner=runner, limit=2)
        assert error.value.code == 'source-changed' and not sessions._sessions
    finally:
        sessions.close()
