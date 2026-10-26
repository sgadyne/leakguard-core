"""Explicit private-extension registry with inert wheel metadata discovery.

Extensions are trusted account-level code. Installation requires a selected
private virtual environment; simply listing/discovering extensions imports none.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import email.parser
import email.policy
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
_DIST_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z', re.ASCII)
_DIST_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9.!+_-]{0,199}\Z', re.ASCII)
_WHEEL_SCHEMES = {'purelib', 'platlib', 'scripts', 'headers', 'data'}
_RESERVED_MODULES = {
    'buddy', 'leakguard_core', 'leakguard_host', 'leakguard_vault',
    'leakguard_buddy', 'leakguard',
}
_BUNDLED_DISTRIBUTIONS = {
    'sensitive-basics': 'leakguard-sensitive-basics',
    'firm-example': 'leakguard-firm-example',
}


def _distribution_name(value):
    """Normalize a Python distribution name without importing packaging."""
    if type(value) is not str or not _DIST_NAME.fullmatch(value):
        raise ExtensionError('extension-wheel-invalid')
    return re.sub(r'[-_.]+', '-', value).lower()


def _version_key(value):
    if type(value) is not str or not _DIST_VERSION.fullmatch(value):
        raise ExtensionError('extension-wheel-invalid')
    return re.sub(r'[-_.]+', '_', value).lower()


def _header(message, name):
    values = message.get_all(name, [])
    if len(values) != 1 or type(values[0]) is not str:
        raise ExtensionError('extension-wheel-invalid')
    return values[0].strip()


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
    canonical = value[:-1] if value.endswith('/') else value
    if (path.is_absolute() or '..' in path.parts or ':' in value
            or not canonical or str(PurePosixPath(canonical)) != canonical):
        raise ExtensionError()
    return path


def _wheel_details(path):
    """Read inert wheel members and map them to standard installation schemes."""
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
            plugin_metadata = []
            dist_metadata = []
            wheel_metadata = []
            for item in members:
                member = _member(item.filename)
                # Wheel installation can place these in site-packages directly
                # or through .data/{purelib,platlib}. Python executes them before
                # registry activation, so disabled extensions must reject them.
                if any(part.endswith('.pth') or part in {'sitecustomize', 'usercustomize'}
                       or part.startswith(('sitecustomize.', 'usercustomize.'))
                       for part in (component.lower() for component in member.parts)):
                    raise ExtensionError('extension-startup-artifact')
                if '__pycache__' in member.parts or member.name.lower().endswith('.pyc'):
                    raise ExtensionError('extension-wheel-invalid')
                if item.filename in names or stat.S_ISLNK(item.external_attr >> 16):
                    raise ExtensionError('extension-wheel-invalid')
                names.add(item.filename)
                if item.filename.endswith('/leakguard-plugin.json'):
                    if item.file_size > 64_000:
                        raise ExtensionError('extension-wheel-invalid')
                    plugin_metadata.append(item)
                if item.filename.endswith('.dist-info/METADATA'):
                    dist_metadata.append(item)
                if item.filename.endswith('.dist-info/WHEEL'):
                    wheel_metadata.append(item)
            if len(plugin_metadata) != 1:
                raise ExtensionError('extension-metadata-required')
            if len(dist_metadata) != 1 or len(wheel_metadata) != 1:
                raise ExtensionError('extension-wheel-invalid')
            if dist_metadata[0].file_size > 2_000_000 or wheel_metadata[0].file_size > 64_000:
                raise ExtensionError('extension-capacity-limit')
            info_dir = dist_metadata[0].filename.rsplit('/', 1)[0]
            if (not info_dir.endswith('.dist-info') or info_dir.count('/') != 0
                    or wheel_metadata[0].filename.rsplit('/', 1)[0] != info_dir):
                raise ExtensionError('extension-wheel-invalid')
            distribution = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(
                wheel.read(dist_metadata[0]))
            if distribution.defects:
                raise ExtensionError('extension-wheel-invalid')
            distribution_name = _distribution_name(_header(distribution, 'Name'))
            distribution_version = _header(distribution, 'Version')
            version_key = _version_key(distribution_version)
            dist_stem = info_dir[:-len('.dist-info')]
            try:
                archive_name, archive_version = dist_stem.rsplit('-', 1)
            except ValueError:
                raise ExtensionError('extension-wheel-invalid') from None
            if (_distribution_name(archive_name) != distribution_name
                    or _version_key(archive_version) != version_key):
                raise ExtensionError('extension-wheel-invalid')
            wheel_info = email.parser.BytesParser(policy=email.policy.compat32).parsebytes(
                wheel.read(wheel_metadata[0]))
            if wheel_info.defects or _header(wheel_info, 'Wheel-Version') != '1.0':
                raise ExtensionError('extension-wheel-invalid')
            root_is_purelib = _header(wheel_info, 'Root-Is-Purelib').lower()
            if root_is_purelib not in {'true', 'false'}:
                raise ExtensionError('extension-wheel-invalid')
            root_scheme = 'purelib' if root_is_purelib == 'true' else 'platlib'
            value = _metadata(_json(wheel.read(plugin_metadata[0])))
            cases = None
            if 'conformance' in value:
                info = wheel.getinfo(value['conformance'])
                if info.file_size > _MAX_STATE:
                    raise ExtensionError('extension-capacity-limit')
                cases = _json(wheel.read(info))
                from .conformance import _detector_cases
                if not 1 <= len(_detector_cases(cases)) <= 1000:
                    raise ExtensionError('extension-conformance-invalid')
            data_directory = f'{dist_stem}.data'
            installed_files = []
            module_roots = set()
            install_targets = set()
            script_names = set()
            has_entrypoints = False
            for item in members:
                if item.is_dir():
                    continue
                archive_path = _member(item.filename)
                parts = archive_path.parts
                if parts[0] == info_dir:
                    scheme = root_scheme
                    relative = PurePosixPath(*parts)
                    in_dist_info = True
                elif parts[0] == data_directory:
                    if len(parts) < 3 or parts[1] not in _WHEEL_SCHEMES:
                        raise ExtensionError('extension-wheel-invalid')
                    scheme = parts[1]
                    relative = PurePosixPath(*parts[2:])
                    if (not relative.parts
                            or any(part.endswith(('.dist-info', '.data')) for part in relative.parts)):
                        raise ExtensionError('extension-wheel-invalid')
                    in_dist_info = False
                elif any(part.endswith(('.dist-info', '.data')) for part in parts):
                    raise ExtensionError('extension-wheel-invalid')
                else:
                    scheme = root_scheme
                    relative = archive_path
                    in_dist_info = False
                if item.filename == f'{info_dir}/entry_points.txt':
                    if item.file_size > 256_000:
                        raise ExtensionError('extension-capacity-limit')
                    has_entrypoints = True
                    try:
                        import configparser
                        parser = configparser.ConfigParser(interpolation=None, strict=True)
                        parser.read_string(wheel.read(item).decode('utf-8'))
                        for section in ('console_scripts', 'gui_scripts'):
                            if parser.has_section(section):
                                for name in parser[section]:
                                    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,199}', name):
                                        raise ExtensionError('extension-wheel-invalid')
                                    script_names.add(name.casefold())
                    except ExtensionError:
                        raise
                    except Exception:
                        raise ExtensionError('extension-wheel-invalid') from None
                content = wheel.read(item)
                target_key = (scheme, relative.as_posix().casefold())
                if target_key in install_targets:
                    raise ExtensionError('extension-wheel-invalid')
                install_targets.add(target_key)
                installed_files.append({
                    'scheme': scheme,
                    'relative': relative.as_posix(),
                    'sha256': hashlib.sha256(content).hexdigest(),
                    'size': len(content),
                    'payload': not in_dist_info,
                    'entrypoint_metadata': item.filename == f'{info_dir}/entry_points.txt',
                })
                if not in_dist_info and scheme in {'purelib', 'platlib'}:
                    root = _module_root(relative.as_posix())
                    if root:
                        module_roots.add(root.casefold())
            if value['module'].split('.')[0].casefold() not in module_roots:
                raise ExtensionError('extension-wheel-invalid')
            return {
                'metadata': value,
                'cases': cases,
                'sha256': hashlib.sha256(raw).hexdigest(),
                'distribution_name': distribution_name,
                'distribution_version': distribution_version,
                'root_scheme': root_scheme,
                'files': installed_files,
                'payload_roots': sorted(module_roots),
                'script_names': sorted(script_names),
                'has_entrypoints': has_entrypoints,
            }
    except ExtensionError:
        raise
    except Exception:
        raise ExtensionError('extension-wheel-invalid') from None


def _module_root(relative):
    parts = PurePosixPath(relative).parts
    if not parts:
        return None
    first = parts[0]
    if len(parts) == 1:
        if first.endswith('.py'):
            return first[:-3]
        extension = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z0-9_-]+)?\.(?:so|pyd)', first)
        if extension:
            return extension.group(1)
        return None
    return first


def inspect_wheel(path):
    """Return validated static metadata and optional cases, without importing code."""
    details = _wheel_details(path)
    return details['metadata'], details['cases'], details['sha256']


_INVENTORY_PROGRAM = r'''import base64, hashlib, importlib.metadata, json, os, pathlib, re, sys, sysconfig
request = json.loads(sys.argv[1])
paths = sysconfig.get_paths()
prefix = os.path.abspath(sys.prefix)
roots = {
    'purelib': paths['purelib'], 'platlib': paths['platlib'],
    'scripts': paths['scripts'], 'data': paths['data'],
    'headers': os.path.join(paths.get('include', paths.get('platinclude', prefix)),
                            request['distribution_name'].replace('-', '_')),
}
def key(path):
    return os.path.normcase(os.path.abspath(path)).casefold()
def contained(root, target):
    try:
        return os.path.commonpath([os.path.realpath(root), os.path.realpath(target)]) == os.path.realpath(root)
    except (OSError, ValueError):
        return False
def safe_scheme(root):
    root = os.path.abspath(root)
    if not contained(prefix, root):
        return False
    try:
        relative = os.path.relpath(root, prefix)
        if relative == os.pardir or relative.startswith(os.pardir + os.sep):
            return False
    except ValueError:
        return False
    current = prefix
    for part in pathlib.PurePath(relative).parts:
        if part == '.':
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            return False
    return True
target_rows = []
for row in request['targets']:
    root = os.path.abspath(roots[row['scheme']])
    if not safe_scheme(root):
        raise ValueError('scheme outside runtime')
    target = os.path.abspath(os.path.join(root, *pathlib.PurePosixPath(row['relative']).parts))
    if os.path.commonpath([root, target]) != root or not contained(root, os.path.dirname(target)):
        raise ValueError('target outside scheme')
    current = root
    for part in pathlib.PurePosixPath(row['relative']).parts[:-1]:
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise ValueError('symlink parent')
    target_rows.append((row, target, key(target)))
target_keys = {entry[2] for entry in target_rows}
lib_roots = sorted({os.path.abspath(paths['purelib']), os.path.abspath(paths['platlib'])})
search_roots = sorted(set(lib_roots) | {
    os.path.abspath(path) for path in sys.path if path and os.path.isdir(path)
})
def search_relative(path):
    candidates = []
    for base in search_roots:
        try:
            relative = os.path.relpath(path, base)
        except ValueError:
            continue
        if relative != os.pardir and not relative.startswith(os.pardir + os.sep):
            candidates.append((len(base), base, relative))
    return max(candidates, default=(0, None, None))
requested_roots = {root.casefold() for root in request['module_roots']}
for row, target, path_key in target_rows:
    if not row.get('payload'):
        continue
    _, _, relative = search_relative(target)
    if relative is None:
        continue
    parts = pathlib.PurePath(relative).parts
    if not parts or parts == ('.',):
        continue
    first = parts[0]
    if len(parts) == 1 and first.endswith('.py'):
        first = first[:-3]
    elif len(parts) == 1:
        extension = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z0-9_-]+)?\.(?:so|pyd)', first)
        if extension:
            first = extension.group(1)
    if first:
        requested_roots.add(first.casefold())
physical_roots = set()
for base in search_roots:
    try:
        names = os.listdir(base)
    except OSError:
        names = []
    for name in names:
        lowered = name.casefold()
        for root in requested_roots:
            if lowered == root or lowered in (root + '.py', root + '.pyc') or (
                    lowered.startswith(root + '.') and lowered.endswith(('.py', '.pyc', '.so', '.pyd'))):
                physical_roots.add(root)
root_owners = {root: set() for root in requested_roots}
destination_owners = {entry[2]: [] for entry in target_rows}
matching_distributions = []
target_actual = {}
cache_files = []
root_file_map = {}
expected_root_paths = set()
for row, target, path_key in target_rows:
    if not row.get('payload'):
        continue
    _, _, relative = search_relative(target)
    parts = pathlib.PurePath(relative).parts if relative is not None else ()
    if parts and parts[0].casefold() in requested_roots:
        expected_root_paths.add(path_key)

def add_root_file(path, root):
    path = os.path.abspath(path)
    try:
        mode = os.lstat(path).st_mode
        link = os.path.islink(path)
        regular = os.path.isfile(path) and not link
    except OSError:
        link, regular = False, False
    path_key = key(path)
    row = root_file_map.setdefault(path_key, {'path_key': path_key, 'roots': set(),
                                               'symlink': link, 'regular': regular,
                                               'owners': []})
    row['roots'].add(root)

for base in search_roots:
    try:
        names = os.listdir(base)
    except OSError:
        names = []
    for root in requested_roots:
        package_name = next((name for name in names if name.casefold() == root), None)
        package = os.path.join(base, package_name) if package_name is not None else ''
        if os.path.isdir(package) and not os.path.islink(package):
            for current, dirs, files_in_dir in os.walk(package, followlinks=False):
                for name in list(dirs):
                    path = os.path.join(current, name)
                    if os.path.islink(path):
                        add_root_file(path, root)
                        dirs.remove(name)
                for name in files_in_dir:
                    add_root_file(os.path.join(current, name), root)
        for name in names:
            lowered = name.casefold()
            if lowered == root + '.py' or (
                    lowered.startswith(root + '.') and lowered.endswith(('.py', '.pyc', '.so', '.pyd'))):
                add_root_file(os.path.join(base, name), root)
for row, target, path_key in target_rows:
    try:
        mode = os.lstat(target).st_mode
        exists = True
        symlink = os.path.islink(target)
        regular = os.path.isfile(target) and not symlink
        actual_hash = None
        if regular and os.path.getsize(target) <= 128_000_000:
            digest = hashlib.sha256()
            with open(target, 'rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            actual_hash = digest.hexdigest()
    except FileNotFoundError:
        exists, symlink, regular, actual_hash = False, False, False, None
    target_actual[path_key] = {'exists': exists, 'symlink': symlink,
                               'regular': regular, 'sha256': actual_hash}

for base in lib_roots:
    for root in requested_roots:
        package_root = os.path.join(base, root)
        if not os.path.isdir(package_root) or os.path.islink(package_root):
            continue
        for current, dirs, files_in_dir in os.walk(package_root, followlinks=False):
            dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(current, name))]
            for name in files_in_dir:
                if not name.endswith('.pyc'):
                    continue
                path = os.path.abspath(os.path.join(current, name))
                try:
                    mode = os.lstat(path).st_mode
                    safe = os.path.isfile(path) and not os.path.islink(path) and os.path.getsize(path) <= 64_000_000
                except OSError:
                    safe = False
                cache_files.append({'path_key': key(path), 'safe': safe,
                                    'in_cache_dir': '__pycache__' in pathlib.Path(path).parts})
for dist in importlib.metadata.distributions():
    raw_name = dist.metadata.get('Name')
    if not raw_name:
        continue
    norm_name = re.sub(r'[-_.]+', '-', raw_name).lower()
    version = dist.version or ''
    dist_info = os.path.abspath(str(getattr(dist, '_path', '')))
    dist_payload = set()
    files = list(dist.files or ())
    top_level = dist.read_text('top_level.txt') or ''
    for line in top_level.splitlines():
        root = line.strip().casefold()
        if root in root_owners:
            root_owners[root].add((norm_name, version))
    for item in files:
        try:
            path = os.path.abspath(str(dist.locate_file(item)))
            path_key = key(path)
        except (OSError, ValueError):
            continue
        try:
            if os.path.commonpath([dist_info, path]) != dist_info:
                # Bytecode caches are generated by Python, not wheel payload;
                # install removes them before the candidate can be imported.
                is_cache = '__pycache__' in pathlib.Path(path).parts and path.endswith('.pyc')
                if not is_cache:
                    dist_payload.add(path_key)
                _, _, relative = search_relative(path)
                parts = pathlib.PurePath(relative).parts if relative is not None else ()
                if parts:
                    first = parts[0]
                    if first.endswith('.py') and len(parts) == 1:
                        first = first[:-3]
                    elif len(parts) == 1:
                        extension = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z0-9_-]+)?\.(?:so|pyd)', first)
                        if extension:
                            first = extension.group(1)
                    root = first.casefold()
                    if root in root_owners:
                        root_owners[root].add((norm_name, version))
        except ValueError:
            pass
        if path_key not in target_keys:
            if path_key not in root_file_map:
                continue
        actual = target_actual.get(path_key)
        record_valid = None
        file_hash = getattr(item, 'hash', None)
        if actual is not None and actual['regular'] and actual['sha256'] is not None and file_hash is not None:
            try:
                algorithm = file_hash.mode
                expected = file_hash.value.rstrip('=')
                hasher = hashlib.new(algorithm)
                with open(path, 'rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        hasher.update(block)
                digest = base64.urlsafe_b64encode(hasher.digest()).decode('ascii').rstrip('=')
                record_valid = digest == expected
            except Exception:
                record_valid = False
        owner = {'name': norm_name, 'version': version, 'record_valid': record_valid}
        if path_key in target_keys:
            destination_owners[path_key].append(owner)
        if path_key in root_file_map:
            root_file_map[path_key]['owners'].append(owner)
    if norm_name == request['distribution_name']:
        complete = True
        for item in files:
            try:
                path = os.path.abspath(str(dist.locate_file(item)))
                if os.path.commonpath([dist_info, path]) == dist_info:
                    continue
                mode = os.lstat(path).st_mode
                if os.path.islink(path) or not os.path.isfile(path):
                    complete = False
            except (OSError, ValueError):
                complete = False
        matching_distributions.append({
            'name': norm_name, 'version': version,
            'payload_paths': sorted(dist_payload), 'payload_complete': complete,
        })
output = {
    'prefix': prefix,
    'scheme_roots': {name: os.path.abspath(path) for name, path in roots.items()},
    'stdlib_roots': sorted({name.casefold() for name in getattr(sys, 'stdlib_module_names', ())}
                           | {name.casefold() for name in sys.builtin_module_names}),
    'physical_roots': sorted(physical_roots),
    'payload_roots': sorted(requested_roots),
    'cache_files': cache_files,
    'expected_root_paths': sorted(expected_root_paths),
    'root_files': [dict(row, roots=sorted(row['roots'])) for _, row in sorted(root_file_map.items())],
    'root_owners': {name: [{'name': owner, 'version': version}
                           for owner, version in sorted(owners)]
                    for name, owners in root_owners.items()},
    'destinations': [
        {'scheme': row['scheme'], 'relative': row['relative'], 'path': path,
         'path_key': path_key, **target_actual[path_key],
         'owners': destination_owners[path_key]}
        for row, path, path_key in target_rows
    ],
    'matching_distributions': matching_distributions,
}
print(json.dumps(output, separators=(',', ':')))
'''


def _path_key(path):
    return os.path.normcase(os.path.abspath(os.fspath(path))).casefold()


def _runtime_inventory(executable, details):
    targets = list(details['files'])
    for name in details['script_names']:
        for script in (name, name + '.exe', name + '-script.py'):
            targets.append({'scheme': 'scripts', 'relative': script, 'sha256': None,
                            'payload': False, 'entrypoint_metadata': True})
    request = {
        'distribution_name': details['distribution_name'],
        'targets': [{'scheme': row['scheme'], 'relative': row['relative'],
                     'payload': row['payload']} for row in targets],
        'module_roots': details['payload_roots'],
    }
    try:
        result = subprocess.run([executable, '-I', '-c', _INVENTORY_PROGRAM,
                                 json.dumps(request, separators=(',', ':'))],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=True)
        raw = result.stdout
        if len(raw) > 32_000_000:
            raise ExtensionError('extension-capacity-limit')
        value = _json(raw)
        if type(value) is not dict or not {
                'prefix', 'scheme_roots', 'stdlib_roots', 'physical_roots',
                'root_owners', 'destinations', 'matching_distributions'} <= set(value):
            raise ExtensionError('extension-runtime-inspection-failed')
        return value
    except ExtensionError:
        raise
    except Exception:
        raise ExtensionError('extension-runtime-inspection-failed') from None


_CLEAR_CACHE_PROGRAM = r'''import json, os, sys, sysconfig
request = json.loads(sys.argv[1])
prefix = os.path.realpath(sys.prefix)
paths = sysconfig.get_paths()
removed = 0
total = 0
for scheme in ('purelib', 'platlib'):
    base = os.path.abspath(paths[scheme])
    if os.path.commonpath([prefix, os.path.realpath(base)]) != prefix:
        raise SystemExit(3)
    for root in request['roots']:
        try:
            names = os.listdir(base)
        except OSError:
            names = []
        package_name = next((name for name in names if name.casefold() == root.casefold()), None)
        package = os.path.join(base, package_name) if package_name is not None else ''
        if not package_name or not os.path.isdir(package) or os.path.islink(package):
            continue
        for current, dirs, files in os.walk(package, followlinks=False):
            dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(current, name))]
            for name in files:
                if not name.endswith('.pyc') or '__pycache__' not in os.path.normpath(current).split(os.sep):
                    continue
                path = os.path.join(current, name)
                try:
                    mode = os.lstat(path).st_mode
                    size = os.path.getsize(path)
                    if os.path.islink(path) or not os.path.isfile(path) or size > 64_000_000:
                        raise SystemExit(4)
                    total += size
                    removed += 1
                    if removed > 10000 or total > 256_000_000:
                        raise SystemExit(4)
                    os.unlink(path)
                except OSError:
                    raise SystemExit(4)
print(json.dumps({'removed': removed}))
'''


def _clear_plugin_bytecode(executable, roots):
    if not roots:
        return
    try:
        result = subprocess.run([executable, '-I', '-c', _CLEAR_CACHE_PROGRAM,
                                 json.dumps({'roots': sorted(set(roots))}, separators=(',', ':'))],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=True)
        if len(result.stdout) > 4096 or type(_json(result.stdout)) is not dict:
            raise ExtensionError('extension-runtime-inspection-failed')
    except ExtensionError:
        raise
    except Exception:
        raise ExtensionError('extension-runtime-inspection-failed') from None


def _exact_installed_bundle(details, inventory, destinations):
    expected_dist = _BUNDLED_DISTRIBUTIONS.get(details['metadata']['id'])
    if expected_dist != details['distribution_name'] or details['has_entrypoints']:
        return False
    matches = inventory['matching_distributions']
    if len(matches) != 1:
        return False
    installed = matches[0]
    destinations = destinations[:len(details['files'])]
    expected_paths = {
        destination['path_key'] for row, destination in zip(details['files'], destinations)
        if row['payload'] and not row['entrypoint_metadata']
    }
    if (installed['name'] != details['distribution_name']
            or _version_key(installed['version']) != _version_key(details['distribution_version'])
            or not installed['payload_complete']
            or set(installed['payload_paths']) != expected_paths):
        return False
    actual_root_paths = {
        item['path_key'] for item in inventory['root_files']
        if not ('__pycache__' in item['path_key'] and item['path_key'].endswith('.pyc'))
    }
    if actual_root_paths != set(inventory['expected_root_paths']):
        return False
    for row, destination in zip(details['files'], destinations):
        if not row['payload']:
            # Dist-info is installed metadata too; when present, require exact bytes.
            if destination['exists'] and (
                    (not row['relative'].endswith('/RECORD')
                     and destination['sha256'] != row['sha256'])
                    or not destination['owners']
                    or any(owner['name'] != details['distribution_name']
                           for owner in destination['owners'])):
                return False
            continue
        if (not destination['exists'] or not destination['regular'] or destination['symlink']
                or destination['sha256'] != row['sha256']
                or not destination['owners']
                or any(owner['name'] != details['distribution_name']
                       or owner['record_valid'] is False
                       for owner in destination['owners'])):
            return False
    return True


def _guard_wheel_collisions(details, inventory, previous=None):
    """Reject wheel writes into runtime namespaces owned by anything else."""
    if (type(inventory) is not dict or type(inventory.get('destinations')) is not list
            or type(inventory.get('matching_distributions')) is not list
            or type(inventory.get('root_owners')) is not dict
            or type(inventory.get('stdlib_roots')) is not list
            or type(inventory.get('cache_files')) is not list
            or type(inventory.get('payload_roots')) is not list
            or type(inventory.get('root_files')) is not list
            or type(inventory.get('expected_root_paths')) is not list):
        raise ExtensionError('extension-runtime-inspection-failed')
    if any(type(cache) is not dict or cache.get('safe') is not True
           or cache.get('in_cache_dir') is not True for cache in inventory['cache_files']):
        raise ExtensionError('extension-conflict')
    if len(inventory['destinations']) < len(details['files']):
        raise ExtensionError('extension-runtime-inspection-failed')
    for row, destination in zip(details['files'], inventory['destinations']):
        if (type(destination) is not dict or destination.get('scheme') != row['scheme']
                or destination.get('relative') != row['relative']):
            raise ExtensionError('extension-runtime-inspection-failed')
    if len({destination.get('path_key') for destination in inventory['destinations']}) != len(inventory['destinations']):
        raise ExtensionError('extension-wheel-invalid')
    roots = set(inventory['payload_roots'])
    reserved = _RESERVED_MODULES | set(inventory['stdlib_roots'])
    if roots & reserved:
        raise ExtensionError('extension-conflict')
    exact_bundle = _exact_installed_bundle(details, inventory, inventory['destinations'])
    same_registered = False
    if previous is not None:
        previous_name = previous.get('distribution_name')
        previous_version = previous.get('distribution_version')
        if previous_name is not None:
            if previous_name != details['distribution_name']:
                raise ExtensionError('extension-conflict')
            same_registered = previous['kind'] == 'wheel' and previous['id'] == details['metadata']['id']
        # Old registry entries have no distribution identity. Never infer a safe
        # overwrite from a module name or an unverified RECORD entry.
    matches = inventory['matching_distributions']
    if len(matches) > 1:
        raise ExtensionError('extension-conflict')
    if matches and not same_registered and not exact_bundle:
        raise ExtensionError('extension-conflict')
    authorized_name = details['distribution_name'] if same_registered or exact_bundle else None
    cache_keys = {cache.get('path_key') for cache in inventory['cache_files']}
    for item in inventory['root_files']:
        if (type(item) is not dict or type(item.get('path_key')) is not str
                or type(item.get('owners')) is not list):
            raise ExtensionError('extension-runtime-inspection-failed')
        if item['symlink'] or not item['regular']:
            raise ExtensionError('extension-conflict')
        if item['path_key'] in cache_keys:
            continue
        owner_names = {owner.get('name') for owner in item['owners'] if type(owner) is dict}
        if authorized_name is None or owner_names != {authorized_name}:
            raise ExtensionError('extension-conflict')
    physical_roots = set(inventory.get('physical_roots', ()))
    for root in roots:
        owners = inventory['root_owners'].get(root, [])
        owner_names = {owner.get('name') for owner in owners if type(owner) is dict}
        if root in physical_roots and not owner_names:
            raise ExtensionError('extension-conflict')
        if owner_names:
            if authorized_name is None or owner_names != {authorized_name}:
                raise ExtensionError('extension-conflict')
    candidate_payload = {
        _path_key(destination['path']) for row, destination in
        zip(details['files'], inventory['destinations']) if row['payload']
    }
    for index, destination in enumerate(inventory['destinations']):
        row = details['files'][index] if index < len(details['files']) else {'payload': False}
        if not destination['exists']:
            continue
        if destination['symlink'] or not destination['regular']:
            raise ExtensionError('extension-conflict')
        owner_names = {owner.get('name') for owner in destination['owners'] if type(owner) is dict}
        if authorized_name is None or owner_names != {authorized_name}:
            raise ExtensionError('extension-conflict')
        if exact_bundle and row['payload'] and destination['sha256'] != row['sha256']:
            raise ExtensionError('extension-conflict')
    if (exact_bundle and matches[0]['payload_paths'] != sorted(candidate_payload)):
        raise ExtensionError('extension-conflict')


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
        required = {'id', 'kind', 'metadata', 'spec', 'profiles', 'sha256', 'cases'}
        optional = {'distribution_name', 'distribution_version'}
        if (type(entry) is not dict or not required <= set(entry) <= required | optional
                or (('distribution_name' in entry) != ('distribution_version' in entry))
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
            if 'distribution_name' in entry:
                if _distribution_name(entry['distribution_name']) != entry['distribution_name']:
                    raise ExtensionError()
                _version_key(entry['distribution_version'])
            validate({'plugins': [entry['spec']]})
            if entry['spec']['module'] != metadata['module'] or entry['spec'].get('component') != metadata.get('component'):
                raise ExtensionError()
        else:
            if ('distribution_name' in entry or entry['metadata'] is not None
                    or entry['spec'].get('id') != entry['id']):
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
        details = _wheel_details(wheel)
        metadata, bundled_cases, digest = details['metadata'], details['cases'], details['sha256']
        cases = bundled_cases if cases is None else copy.deepcopy(cases)
        selected = _private_python(python_executable or sys.executable)
        spec = {'module': metadata['module'], 'options': {} if options is None else options}
        if 'component' in metadata:
            spec['component'] = metadata['component']
        entry = {'id': metadata['id'], 'kind': 'wheel', 'metadata': metadata, 'spec': spec,
                 'profiles': [], 'sha256': digest, 'cases': cases,
                 'distribution_name': details['distribution_name'],
                 'distribution_version': details['distribution_version']}
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
            inventory = _runtime_inventory(selected, details)
            _guard_wheel_collisions(details, inventory, previous)
            registered_upgrade = (previous is not None and previous.get('kind') == 'wheel'
                                  and previous.get('id') == metadata['id']
                                  and previous.get('distribution_name') == details['distribution_name'])
            bundled_preinstalled = (bool(inventory['matching_distributions'])
                                    and _BUNDLED_DISTRIBUTIONS.get(metadata['id'])
                                    == details['distribution_name'])
            if previous is not None and previous['profiles']:
                previous['profiles'] = []
                _atomic(self.path, json.dumps(value, sort_keys=True, ensure_ascii=True).encode())
            if registered_upgrade or bundled_preinstalled:
                _clear_plugin_bytecode(selected, inventory['payload_roots'])
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
