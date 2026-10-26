"""Explicit private-extension registry with inert wheel metadata discovery.

Extensions are trusted account-level code. Installation requires a selected
private virtual environment; simply listing/discovering extensions imports none.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

_TOKEN = re.compile(r'[a-z][a-z0-9-]{0,79}\Z', re.ASCII)
_MODULE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z', re.ASCII)
_PROFILES = {'credentials', 'sensitive', 'firm'}
_MAX_STATE = 1_000_000


class ExtensionError(RuntimeError):
    def __init__(self, code='extension-invalid'):
        self.code = code
        super().__init__(code)


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ExtensionError()
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(ExtensionError()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ExtensionError() from None


def _profile(value):
    if value not in _PROFILES:
        raise ExtensionError('extension-profile-invalid')
    return value


def _id(value):
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise ExtensionError()
    return value


def _read(path, maximum=_MAX_STATE):
    from .sources import _bounded_file, AcquisitionError
    try:
        return _bounded_file(path, maximum)
    except AcquisitionError:
        raise ExtensionError('extension-unavailable') from None


def _atomic(path, raw):
    if len(raw) > _MAX_STATE:
        raise ExtensionError('extension-capacity-limit')
    temporary = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.extension-', dir=path.parent)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != 'nt':
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except OSError:
        raise ExtensionError('extension-state-failed') from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _metadata(value):
    required = {'schema_version', 'id', 'api_version', 'module', 'version'}
    if (type(value) is not dict or not required <= set(value) <= required | {'component', 'conformance'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or type(value['api_version']) is not int or value['api_version'] not in {1, 2}
            or type(value['module']) is not str or not _MODULE.fullmatch(value['module'])
            or type(value['version']) is not str or not 1 <= len(value['version']) <= 200):
        raise ExtensionError()
    _id(value['id'])
    if 'component' in value:
        _id(value['component'])
    if value['api_version'] == 1 and 'component' in value:
        raise ExtensionError()
    if 'conformance' in value:
        _member(value['conformance'])
    return copy.deepcopy(value)


def _member(value):
    if type(value) is not str or not 0 < len(value) <= 4096 or '\\' in value or '\x00' in value:
        raise ExtensionError()
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or ':' in value:
        raise ExtensionError()
    return path


def inspect_wheel(path):
    """Return validated static metadata and optional cases, without importing code."""
    raw = _read(Path(path), 64_000_000)
    if Path(path).suffix != '.whl':
        raise ExtensionError('extension-wheel-invalid')
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
            members = wheel.infolist()
            if len(members) > 10_000 or sum(item.file_size for item in members) > 128_000_000:
                raise ExtensionError('extension-capacity-limit')
            names = set()
            metadata = []
            for item in members:
                member = _member(item.filename)
                # Wheel installation can place these in site-packages directly
                # or through .data/{purelib,platlib}. Python executes them before
                # registry activation, so disabled extensions must reject them.
                if any(part.endswith('.pth') or part in {'sitecustomize', 'usercustomize'}
                       or part.startswith(('sitecustomize.', 'usercustomize.'))
                       for part in (component.lower() for component in member.parts)):
                    raise ExtensionError('extension-startup-artifact')
                if item.filename in names or stat.S_ISLNK(item.external_attr >> 16):
                    raise ExtensionError('extension-wheel-invalid')
                names.add(item.filename)
                if item.filename.endswith('/leakguard-plugin.json'):
                    if item.file_size > 64_000:
                        raise ExtensionError('extension-wheel-invalid')
                    metadata.append(item)
            if len(metadata) != 1:
                raise ExtensionError('extension-metadata-required')
            value = _metadata(_json(wheel.read(metadata[0])))
            cases = None
            if 'conformance' in value:
                info = wheel.getinfo(value['conformance'])
                if info.file_size > _MAX_STATE:
                    raise ExtensionError('extension-capacity-limit')
                cases = _json(wheel.read(info))
                from .conformance import _detector_cases
                if not 1 <= len(_detector_cases(cases)) <= 1000:
                    raise ExtensionError('extension-conformance-invalid')
            return value, cases, hashlib.sha256(raw).hexdigest()
    except ExtensionError:
        raise
    except Exception:
        raise ExtensionError('extension-wheel-invalid') from None


def _private_python(executable):
    selected = Path(executable)
    if not selected.is_absolute():
        raise ExtensionError('extension-private-runtime-required')
    try:
        result = subprocess.run([str(selected), '-I', '-c',
                                 'import json,sys;print(json.dumps([sys.prefix,sys.base_prefix]))'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
        prefixes = _json(result.stdout)
        if (type(prefixes) is not list or len(prefixes) != 2 or prefixes[0] == prefixes[1]
                or Path(prefixes[0]).resolve() != Path(sys.prefix).resolve()):
            raise ExtensionError('extension-private-runtime-required')
    except Exception:
        raise ExtensionError('extension-private-runtime-required') from None
    return str(selected)


class ExtensionRegistry:
    def __init__(self, directory):
        self.directory = Path(directory)
        if not self.directory.is_absolute():
            raise ExtensionError('extension-path-invalid')
        self.path = self.directory / 'registry.json'

    def initialize(self):
        """Create a new empty registry once; never recreate lost enabled state."""
        marker = self.directory / '.registry-initialized'
        with self._mutation(save=False) as value:
            if marker.exists() and _read(marker, 16) != b'1':
                raise ExtensionError('extension-invalid')
            if not self.path.exists():
                if marker.exists():
                    raise ExtensionError('extension-unavailable')
                _atomic(self.path, json.dumps(value, sort_keys=True, ensure_ascii=True).encode())
            if not marker.exists():
                _atomic(marker, b'1')

    def _load(self):
        if not self.path.exists():
            return {'schema_version': 1, 'extensions': {}}
        value = _json(_read(self.path))
        if (type(value) is not dict or set(value) != {'schema_version', 'extensions'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or type(value['extensions']) is not dict or len(value['extensions']) > 100):
            raise ExtensionError()
        for key, entry in value['extensions'].items():
            _id(key)
            self._validate_entry(entry)
            if entry['id'] != key:
                raise ExtensionError()
        return value

    @staticmethod
    def _validate_entry(entry):
        if (type(entry) is not dict or set(entry) != {'id', 'kind', 'metadata', 'spec', 'profiles', 'sha256', 'cases'}
                or entry['kind'] not in {'wheel', 'script'} or type(entry['profiles']) is not list
                or any(profile not in _PROFILES for profile in entry['profiles'])
                or len(set(entry['profiles'])) != len(entry['profiles'])
                or type(entry['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])):
            raise ExtensionError()
        _id(entry['id'])
        from .settings import validate
        if entry['kind'] == 'wheel':
            metadata = _metadata(entry['metadata'])
            if metadata['id'] != entry['id']:
                raise ExtensionError()
            validate({'plugins': [entry['spec']]})
            if entry['spec']['module'] != metadata['module'] or entry['spec'].get('component') != metadata.get('component'):
                raise ExtensionError()
        else:
            if entry['metadata'] is not None or entry['spec'].get('id') != entry['id']:
                raise ExtensionError()
            validate({'script_checks': [entry['spec']]})
        if entry['cases'] is not None:
            from .conformance import _detector_cases
            if not 1 <= len(_detector_cases(entry['cases'])) <= 1000:
                raise ExtensionError('extension-conformance-invalid')

    @contextmanager
    def _mutation(self, *, save=True):
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise ExtensionError('extension-state-failed') from None
        lock = self.directory / '.registry-lock'
        descriptor = None
        try:
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ExtensionError('extension-registry-busy')
            if os.name == 'nt':
                import msvcrt
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b'0')
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ExtensionError):
            if descriptor is not None:
                os.close(descriptor)
            raise ExtensionError('extension-registry-busy') from None
        try:
            value = self._load()
            yield value
            if save:
                raw = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
                _atomic(self.path, raw)
        finally:
            # Kernel lock release survives process death; retain the inode so a
            # concurrent opener cannot hold an obsolete unlinked lock file.
            os.close(descriptor)

    @staticmethod
    def _public(entry):
        metadata = entry['metadata'] or {}
        return {'id': entry['id'], 'kind': entry['kind'], 'version': metadata.get('version'),
                'api_version': metadata.get('api_version', 2), 'profiles': list(entry['profiles']),
                'sha256': entry['sha256'], 'has_conformance': entry['cases'] is not None}

    def list(self):
        return [self._public(entry) for _, entry in sorted(self._load()['extensions'].items())]

    def install_wheel(self, wheel, *, python_executable=None, options=None, cases=None):
        metadata, bundled_cases, digest = inspect_wheel(wheel)
        cases = bundled_cases if cases is None else copy.deepcopy(cases)
        selected = _private_python(python_executable or sys.executable)
        spec = {'module': metadata['module'], 'options': {} if options is None else options}
        if 'component' in metadata:
            spec['component'] = metadata['component']
        entry = {'id': metadata['id'], 'kind': 'wheel', 'metadata': metadata, 'spec': spec,
                 'profiles': [], 'sha256': digest, 'cases': cases}
        self._validate_entry(entry)
        with self._mutation() as value:
            for existing in value['extensions'].values():
                if (existing['kind'] == 'wheel' and existing['id'] != entry['id']
                        and existing['spec']['module'] == spec['module']):
                    raise ExtensionError('extension-conflict')
            # Disable a prior version durably before replacing its installed
            # code. Failed install/state publication cannot reactivate new code
            # under an earlier enabled registry entry.
            previous = value['extensions'].get(entry['id'])
            if previous is not None and previous['profiles']:
                previous['profiles'] = []
                _atomic(self.path, json.dumps(value, sort_keys=True, ensure_ascii=True).encode())
            # Installation is explicit and offline; dependency wheels must already
            # be installed by the release/private-runtime owner.
            verified = _read(Path(wheel), 64_000_000)
            if hashlib.sha256(verified).hexdigest() != digest:
                raise ExtensionError('extension-input-changed')
            try:
                with tempfile.TemporaryDirectory(prefix='.install-', dir=self.directory) as scratch:
                    staged = Path(scratch) / Path(wheel).name
                    staged.write_bytes(verified)
                    staged.chmod(0o600)
                    result = subprocess.run([selected, '-I', '-m', 'pip', 'install', '--no-index', '--no-deps',
                                             '--force-reinstall', '--disable-pip-version-check', str(staged)],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
                    if result.returncode:
                        raise ExtensionError('extension-install-failed')
            except (OSError, subprocess.TimeoutExpired):
                raise ExtensionError('extension-install-failed') from None
            value['extensions'][entry['id']] = entry
        return self._public(entry)

    def register_script(self, spec, *, cases=None):
        from .settings import validate
        normalized = validate({'script_checks': [spec]})['script_checks'][0]
        raw = json.dumps(normalized, sort_keys=True, ensure_ascii=True).encode()
        entry = {'id': normalized['id'], 'kind': 'script', 'metadata': None, 'spec': normalized,
                 'profiles': [], 'sha256': hashlib.sha256(raw).hexdigest(), 'cases': cases}
        self._validate_entry(entry)
        with self._mutation() as value:
            value['extensions'][entry['id']] = entry
        return self._public(entry)

    def _entry(self, extension_id):
        entry = self._load()['extensions'].get(_id(extension_id))
        if entry is None:
            raise ExtensionError('extension-not-found')
        return entry

    def check(self, extension_id, *, worker_policy='strict'):
        from . import plugins, conformance
        entry = self._entry(extension_id)
        deadline = time.monotonic() + 60
        def detect(*args, **kwargs):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise plugins.PluginError('plugin-timeout')
            kwargs['timeout'] = min(kwargs.get('timeout') or 10, remaining)
            return plugins.detect(*args, **kwargs, worker_policy=worker_policy)
        try:
            if entry['kind'] == 'wheel':
                handle = plugins.load([entry['spec']], worker_policy=worker_policy)[0]
                if (handle.api_version != entry['metadata']['api_version']
                        or handle.manifest is not None and handle.manifest.id != entry['metadata'].get('component', entry['id'])):
                    raise ExtensionError('extension-api-incompatible')
            else:
                handle = plugins.load_scripts([entry['spec']])[0]
                if entry['cases'] is None:
                    tuple(detect([handle], '', 'extension-check.txt', 'text'))
            report = None
            if entry['cases'] is not None:
                cases = conformance._detector_cases(entry['cases'])
                manifest = getattr(handle, 'manifest', None)
                component = manifest.id if manifest is not None else entry['id']
                if not cases:
                    raise ExtensionError('extension-conformance-failed')
                from types import SimpleNamespace
                adapter = SimpleNamespace(PluginError=plugins.PluginError,
                    detect=detect)
                report = conformance._check_detector_loaded(adapter, handle, component, cases)
                if not report.passed:
                    return {'id': entry['id'], 'passed': False, 'conformance': report.to_dict()}
            return {'id': entry['id'], 'passed': True, 'conformance': report.to_dict() if report else None}
        except ExtensionError:
            raise
        except Exception:
            raise ExtensionError('extension-check-failed') from None

    def enable(self, extension_id, *, profile='firm', worker_policy='strict'):
        _profile(profile)
        with self._mutation() as value:
            checked = self.check(extension_id, worker_policy=worker_policy)
            if not checked['passed']:
                raise ExtensionError('extension-conformance-failed')
            entry = value['extensions'].get(_id(extension_id))
            if entry is None:
                raise ExtensionError('extension-not-found')
            if profile not in entry['profiles']:
                entry['profiles'].append(profile)
            return self._public(entry)

    def disable(self, extension_id, *, profile='firm'):
        _profile(profile)
        with self._mutation() as value:
            entry = value['extensions'].get(_id(extension_id))
            if entry is None:
                raise ExtensionError('extension-not-found')
            entry['profiles'] = [item for item in entry['profiles'] if item != profile]
            return self._public(entry)

    def apply(self, config, profile):
        """Compose explicit enabled specs; engine setup loads them fail closed."""
        from .settings import validate
        _profile(profile)
        if not self.path.is_file():
            raise ExtensionError('extension-unavailable')
        result = copy.deepcopy(config)
        for _, entry in sorted(self._load()['extensions'].items()):
            if profile in entry['profiles']:
                key = 'plugins' if entry['kind'] == 'wheel' else 'script_checks'
                spec = copy.deepcopy(entry['spec'])
                result.setdefault(key, [])
                if spec not in result[key]:
                    result[key].append(spec)
        return validate(result)
