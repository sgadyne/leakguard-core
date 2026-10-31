"""Bounded SSH directory streams; the remote half is sent as isolated code.

The durable cursor, not the process, is the publication authority. A worker
replays it incrementally after restart and never reports replay as new work.
"""
import hashlib
import json
import os
import pathlib
import select
import signal
import stat
import sys
import time


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _client_supports_sessions():
    # Windows select() cannot wait on subprocess pipes.
    return os.name == 'posix' and callable(getattr(os, 'set_blocking', None))


def _sig(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, getattr(info, 'st_flags', 0)]


def _info(info):
    return dict(zip(('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns',
                     'st_ctime_ns', 'st_flags'), _sig(info)))


def _timeout(_signum, _frame):
    raise TimeoutError()


class _DirectoryChanged(Exception):
    pass


def _remote_main():
    if sys.platform != 'linux':
        sys.stdout.write('{"version":1,"status":"session-unsupported"}\n')
        sys.stdout.flush()
        return
    import resource
    if sys.platform == 'linux':
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    signal.signal(signal.SIGALRM, _timeout)
    started = time.monotonic()
    deadline = started + 900
    machine_path = pathlib.Path('/etc/machine-id')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0)
    iterator = None
    retained_fd = None
    expected_request = None
    anchor = None
    position = 0
    prefix = hashlib.sha256()
    resume = 0
    resume_prefix = None
    directory_signature = None
    root_identity = None

    def machine_identity():
        if machine_path.is_file():
            with machine_path.open('rb') as stream:
                value = stream.read(4097)
            if len(value) > 4096:
                raise RuntimeError('source-changed')
        else:
            # Linux platform.node() uses uname, but caches its first result.
            node = os.uname().nodename
            value = ('' if node == 'unknown' else node).encode()
        return hashlib.sha256(value).hexdigest()

    def opened(req):
        root = pathlib.Path(req.get('root') or str(pathlib.Path.home()))
        path = pathlib.Path(req['path'])
        for item in (root, path):
            if not item.is_absolute() or '..' in item.parts or len(str(item)) > 4096:
                raise ValueError()
        relative = path.relative_to(root)
        if len(relative.parts) > 128:
            raise ValueError()
        root_info = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            raise ValueError()
        identity = {'machine': machine_identity(), 'device': root_info.st_dev, 'inode': root_info.st_ino}
        if req.get('expected') is not None and req['expected'] != identity:
            raise RuntimeError('source-changed')
        fd = os.open(root, flags)
        try:
            if _sig(os.fstat(fd))[:3] != _sig(root_info)[:3]:
                raise RuntimeError('source-changed')
            for part in relative.parts:
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                if os.fstat(fd).st_dev != root_info.st_dev:
                    raise OSError('mount-boundary')
            return fd, identity
        except BaseException:
            os.close(fd)
            raise

    try:
        while time.monotonic() < deadline:
            if not select.select([sys.stdin.buffer], [], [], min(60, max(0, deadline - time.monotonic())))[0]:
                break
            signal.alarm(8)
            raw = sys.stdin.buffer.readline(262146)
            if not raw:
                break
            if len(raw) > 262145 or not raw.endswith(b'\n'):
                raise ValueError()
            req = json.loads(raw, object_pairs_hook=_unique_json_pairs)
            if req.get('op') != 'enumerate' or type(req.get('limit', 1000)) is not int or not 1 <= req.get('limit', 1000) <= 1000:
                raise ValueError()
            fixed = (req.get('root'), req.get('path'), req.get('expected'))
            cursor = req.get('cursor')
            if expected_request is not None and (fixed != expected_request or cursor != anchor):
                raise ValueError()
            current_fd, identity = opened(req)
            try:
                before = os.fstat(current_fd)
                if iterator is None:
                    expected_request = fixed
                    root_identity = identity
                    directory_signature = _sig(before)
                    retained_fd = current_fd
                    current_fd = None
                    if cursor is not None and cursor.get('signature') == directory_signature:
                        resume = cursor['entries']
                        resume_prefix = cursor['prefix']
                        if type(resume) is not int or not 0 <= resume <= 100_000_000 or type(resume_prefix) is not str or len(resume_prefix) != 64:
                            raise ValueError()
                        if resume == 0 and resume_prefix != prefix.hexdigest():
                            raise ValueError()
                    iterator = os.scandir(retained_fd)
                elif identity != root_identity or _sig(before) != directory_signature or _sig(os.fstat(retained_fd)) != directory_signature:
                    raise _DirectoryChanged(before, identity)
                entries = []
                complete = False
                mismatch = False
                slice_deadline = time.monotonic() + 3
                while len(entries) < req.get('limit', 1000) and time.monotonic() < slice_deadline:
                    try:
                        entry = next(iterator)
                    except StopIteration:
                        complete = True
                        if position < resume:
                            mismatch = True
                        break
                    position += 1
                    prefix.update(os.fsencode(entry.name) + b'\0')
                    if position <= resume:
                        if position == resume and prefix.hexdigest() != resume_prefix:
                            mismatch = True
                            break
                        continue
                    try:
                        value = _info(entry.stat(follow_symlinks=False))
                    except OSError:
                        value = None
                    entries.append({'name': entry.name, 'info': value})
                if current_fd is not None:
                    os.close(current_fd)
                    current_fd = None
                current_fd, current_identity = opened(req)
                stable = (current_identity == root_identity and _sig(os.fstat(current_fd)) == directory_signature
                          and _sig(os.fstat(retained_fd)) == directory_signature and not mismatch)
                if position < resume and not mismatch:
                    # Do not replace a committed cursor with a partially verified prefix.
                    out_position, out_prefix = resume, resume_prefix
                else:
                    out_position, out_prefix = position, prefix.hexdigest()
                result = {'version': 1, 'status': 'available', 'identity': root_identity,
                          'info': _info(before), 'entries': entries if stable else [],
                          'position': out_position, 'prefix': out_prefix,
                          'complete': complete and stable, 'stable': stable}
                anchor = {'signature': directory_signature, 'entries': out_position, 'prefix': out_prefix}
                if complete or not stable:
                    finish = True
                else:
                    finish = False
            finally:
                if current_fd is not None:
                    os.close(current_fd)
            encoded = json.dumps(result, ensure_ascii=True, separators=(',', ':'))
            if len(encoded) > 1_500_000:
                raise ValueError()
            sys.stdout.write(encoded + '\n')
            sys.stdout.flush()
            signal.alarm(0)
            if finish:
                break
    except _DirectoryChanged as exc:
        changed, identity = exc.args
        result = {'version': 1, 'status': 'available', 'identity': identity,
                  'info': _info(changed), 'entries': [], 'position': 0,
                  'prefix': hashlib.sha256().hexdigest(), 'complete': False, 'stable': False}
        sys.stdout.write(json.dumps(result, separators=(',', ':')) + '\n')
        sys.stdout.flush()
    except PermissionError:
        sys.stdout.write('{"version":1,"status":"permission-denied"}\n')
        sys.stdout.flush()
    except TimeoutError:
        sys.stdout.write('{"version":1,"status":"timeout"}\n')
        sys.stdout.flush()
    except RuntimeError:
        sys.stdout.write('{"version":1,"status":"source-changed"}\n')
        sys.stdout.flush()
    except Exception:
        sys.stdout.write('{"version":1,"status":"unavailable"}\n')
        sys.stdout.flush()
    finally:
        if iterator is not None:
            iterator.close()
        if retained_fd is not None:
            os.close(retained_fd)


if __name__ == '__main__':
    _remote_main()


class DirectorySessions:
    """Own at most eight isolated SSH processes, each with one directory stream."""
    def __init__(self, *, max_sessions=8, idle_seconds=60):
        from collections import OrderedDict
        import threading
        if not 1 <= max_sessions <= 8 or not 1 <= idle_seconds <= 60:
            raise ValueError('invalid session limits')
        self._sessions = OrderedDict()
        self._losses = OrderedDict()
        self._unsupported = OrderedDict()
        self._lock = threading.Lock()
        self._max_sessions = max_sessions
        self._idle_seconds = idle_seconds

    def _discard(self, key, *, graceful=False):
        from .ssh import _terminate
        session = self._sessions.pop(key, None)
        if session is None:
            return
        process = session['process']
        if graceful:
            if process.stdin is not None:
                process.stdin.close()
            try:
                process.wait(timeout=2)
            except Exception:
                _terminate(process)
        else:
            _terminate(process)
        try:
            process.wait(timeout=2)
        except Exception:
            pass
        for pipe in (process.stdin, process.stdout):
            if pipe is not None and not pipe.closed:
                pipe.close()

    def close(self):
        with self._lock:
            for key in list(self._sessions):
                self._discard(key)
            self._losses.clear()
            self._unsupported.clear()

    def _lost(self, key):
        self._losses[key] = self._losses.get(key, 0) + 1
        self._losses.move_to_end(key)
        while len(self._losses) > 64:
            self._losses.popitem(last=False)
        return self._losses[key]

    def request(self, runner, target, req, *, python, cancel=None):
        import subprocess
        from .errors import HostError
        from .ssh import _target
        key = (_target(target), runner.port, python, req.get('root'), req.get('path'),
               json.dumps(req.get('expected'), sort_keys=True, separators=(',', ':')))
        with self._lock:
            if cancel is not None and cancel():
                self._discard(key)
                raise HostError('cancelled')
            if not _client_supports_sessions():
                self._discard(key)
                from .ssh_locations import SSHLocations
                result = SSHLocations(runner=runner).request(target, req, python=python, cancel=cancel)
                return {**result, 'session_capability': 'client-unsupported'}
            now = time.monotonic()
            if self._unsupported.get(key, 0) > now:
                from .ssh_locations import SSHLocations
                result = SSHLocations(runner=runner).request(target, req, python=python, cancel=cancel)
                return {**result, 'session_capability': 'unsupported'}
            self._unsupported.pop(key, None)
            for old_key, old in list(self._sessions.items()):
                if now - old['used'] > self._idle_seconds or old['process'].poll() is not None:
                    self._discard(old_key)
                    self._lost(old_key)
            session = self._sessions.get(key)
            if session is not None and session['anchor'] != req.get('cursor'):
                # Publication did not commit, or the caller changed the cursor.
                self._discard(key)
                session = None
            if session is None:
                if self._losses.get(key, 0) >= 3:
                    self._losses.pop(key, None)
                    raise HostError('ssh-directory-replay-stalled')
                while len(self._sessions) >= self._max_sessions:
                    old_key = next(iter(self._sessions))
                    self._discard(old_key)
                    self._lost(old_key)
                script = pathlib.Path(__file__).read_text()
                if len(script) > 100000:
                    raise HostError('ssh-worker-invalid')
                process = None
                try:
                    process = subprocess.Popen(runner._command(target, python, script, isolated=True),
                                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                               stderr=subprocess.DEVNULL, start_new_session=os.name == 'posix')
                    os.set_blocking(process.stdin.fileno(), False)
                    os.set_blocking(process.stdout.fileno(), False)
                except OSError:
                    if process is not None:
                        from .ssh import _terminate
                        _terminate(process)
                        process.wait()
                        for pipe in (process.stdin, process.stdout):
                            if pipe is not None:
                                pipe.close()
                    raise HostError('ssh-unavailable') from None
                session = {'process': process, 'anchor': req.get('cursor'), 'used': now}
                self._sessions[key] = session
            self._sessions.move_to_end(key)
            process = session['process']
            payload = json.dumps(req, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
            if len(payload) > 262145:
                self._discard(key)
                raise HostError('remote-limit-invalid')
            try:
                output = bytearray()
                offset = 0
                deadline = time.monotonic() + 10
                while True:
                    if cancel is not None and cancel():
                        raise HostError('cancelled')
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise HostError('ssh-timeout')
                    ready, writable, _ = select.select([process.stdout],
                                                       [process.stdin] if offset < len(payload) else [],
                                                       [], min(0.05, remaining))
                    if writable:
                        offset += os.write(process.stdin.fileno(), payload[offset:])
                    if ready:
                        chunk = os.read(process.stdout.fileno(), 65536)
                        if not chunk:
                            raise HostError('ssh-execution-failed')
                        output.extend(chunk)
                        if len(output) > 1_500_000:
                            raise HostError('ssh-output-limit')
                        if b'\n' in output:
                            if not output.endswith(b'\n') or output.count(b'\n') != 1:
                                raise HostError('remote-report-invalid')
                            break
                result = json.loads(output, object_pairs_hook=_unique_json_pairs)
                if type(result) is not dict or result.get('version') != 1:
                    raise HostError('remote-report-invalid')
                if result.get('status') == 'session-unsupported':
                    self._discard(key)
                    self._unsupported[key] = time.monotonic() + 60
                    while len(self._unsupported) > 64:
                        self._unsupported.popitem(last=False)
                    from .ssh_locations import SSHLocations
                    fallback = SSHLocations(runner=runner).request(target, req, python=python, cancel=cancel)
                    return {**fallback, 'session_capability': 'unsupported'}
                if result.get('status') != 'available':
                    raise HostError({'permission-denied': 'permission-denied', 'source-changed': 'source-changed',
                                     'timeout': 'ssh-timeout'}.get(result.get('status'), 'source-unavailable'))
                info = result['info']
                keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_flags')
                if (type(info) is not dict or any(type(info.get(k)) is not int for k in keys)
                        or type(result.get('entries')) is not list or len(result['entries']) > req.get('limit', 1000)
                        or type(result.get('position')) is not int or not 0 <= result['position'] <= 100_000_000
                        or type(result.get('prefix')) is not str or len(result['prefix']) != 64
                        or any(c not in '0123456789abcdef' for c in result['prefix'])
                        or type(result.get('stable')) is not bool or type(result.get('complete')) is not bool
                        or not result['stable'] and (result['entries'] or result['complete'])
                        or result.get('identity') != req.get('expected') and req.get('expected') is not None):
                    raise HostError('remote-report-invalid')
                for entry in result['entries']:
                    if type(entry) is not dict or type(entry.get('name')) is not str:
                        raise HostError('remote-report-invalid')
                    name, value = entry['name'], entry.get('info')
                    if (not name or name in ('.', '..') or '/' in name or '\x00' in name
                            or len(os.fsencode(name)) > 255 or value is not None and
                            (type(value) is not dict or any(type(value.get(k)) is not int for k in keys))):
                        raise HostError('remote-report-invalid')
                signature = [info[k] for k in keys]
                session['anchor'] = {'signature': signature, 'entries': result['position'], 'prefix': result['prefix']}
                session['used'] = time.monotonic()
                if result['entries'] or result['complete']:
                    self._losses.pop(key, None)
                if result['complete'] or not result['stable']:
                    self._discard(key, graceful=True)
                return {**result, 'session_capability': 'retained-linux'}
            except HostError as error:
                self._discard(key)
                if error.code != 'cancelled':
                    self._lost(key)
                raise
            except (OSError, ValueError, TypeError, KeyError):
                self._discard(key)
                self._lost(key)
                raise HostError('remote-report-invalid') from None
