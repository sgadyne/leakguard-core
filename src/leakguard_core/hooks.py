"""Install local guards without changing tracked project files or discarding hooks."""
import json
from itertools import islice
import os
import pathlib
import stat
import tempfile
import subprocess
import sys

from ._python import core_command

ROOT = pathlib.Path(__file__).resolve().parent
PYTHON = pathlib.Path(sys.executable)


def run(*args, cwd=None, check=True):
    return subprocess.run(['git', *args], cwd=cwd, check=check, capture_output=True)


def quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def _trusted_paths(hooks):
    """Freeze installer-selected extension paths without ambient directory lookup."""
    excluded = {pathlib.Path.cwd().resolve()}
    if hooks.parent.name == '.git':
        excluded.add(hooks.parent.parent.resolve())
    existing = tuple(islice(iter(sys.path), 257))
    if len(existing) > 256:
        raise RuntimeError('hook-import-path-limit')
    paths = []
    for value in existing:
        if type(value) is not str or not value or not pathlib.Path(value).is_absolute():
            continue
        if len(value) > 4096 or '\x00' in value:
            raise RuntimeError('hook-import-path-limit')
        path = pathlib.Path(value).resolve()
        if path not in excluded and str(path) not in paths:
            paths.append(str(path))
    return tuple(paths)


def _read_hook(path, maximum=1_000_000):
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise RuntimeError('hook-target-nonregular')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError('hook-target-changed')
        chunks = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if total > maximum or identity(opened) != identity(after):
            raise RuntimeError('hook-target-changed')
        return b''.join(chunks), before
    finally:
        os.close(descriptor)


def _write_descriptor(descriptor, content):
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError('hook-write-failed')
        remaining = remaining[written:]


def install_at(hooks):
    hooks = pathlib.Path(hooks)
    trusted_paths = _trusted_paths(hooks)
    commands = {kind: core_command('leakguard_core', 'hook', kind, executable=PYTHON.as_posix(), search_paths=trusted_paths)
                for kind in ('pre-commit', 'pre-push')}
    hooks.mkdir(parents=True, exist_ok=True)
    changes = []
    for kind in ['pre-commit', 'pre-push']:
        target = hooks / kind
        marker = b'# local-leakguard-managed'
        previous = _read_hook(target)
        mode = stat.S_IMODE(previous[1].st_mode) if previous else 0o644
        if previous and marker not in previous[0]:
            backup = hooks / (kind + '.before-leakguard')
            # Exclusive creation never follows an existing backup link.
            descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), mode)
            try:
                _write_descriptor(descriptor, previous[0])
                if os.name != 'nt':
                    os.fchmod(descriptor, mode)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        text = '#!/bin/sh\n' + marker.decode('ascii') + '\nexec ' + ' '.join(quote(value) for value in commands[kind]) + ' "$@"\n'
        descriptor, temporary = tempfile.mkstemp(prefix='.' + kind + '.leakguard-', dir=hooks)
        try:
            _write_descriptor(descriptor, text.encode('utf-8'))
            if os.name != 'nt':
                os.fchmod(descriptor, mode | 0o111)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            # Replacement breaks a hardlink and replaces a link itself, never
            # opening an existing target for writing or chmodding its referent.
            os.replace(temporary, target)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        changes.append(kind)
    return changes


def discover(root):
    pending = [(root, 0)]
    while pending:
        path, depth = pending.pop()
        if (path / '.git').exists():
            yield path
            continue
        if depth >= 5:
            continue
        try:
            for child in path.iterdir():
                if child.is_dir() and not child.is_symlink() and child.name not in {'node_modules', '.venv', 'venv', 'forks', '.git', 'envs', 'pwds', 'leakguard'}:
                    pending.append((child, depth + 1))
        except OSError:
            continue


def main():
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path.cwd()
    records = []
    seen = set()
    for repo in discover(root):
        try:
            path = pathlib.Path(__import__('leakguard_core.git_scanning', fromlist=['path_output']).path_output(run('rev-parse', '--path-format=absolute', '--git-path', 'hooks', cwd=repo).stdout))
            key = os.path.normcase(str(path))
            if key not in seen:
                install_at(path); seen.add(key)
            records.append({'repo': str(repo), 'hooks_directory': str(path), 'status': 'installed'})
        except Exception as error:
            records.append({'repo': str(repo), 'status': 'error', 'error_type': type(error).__name__})
    template = __import__('leakguard_core.engine', fromlist=['STATE']).STATE / 'git-template'
    old = run('config', '--global', '--get', 'init.templateDir', check=False).stdout.removesuffix(b'\n').decode('utf-8', errors='surrogateescape')
    if old:
        template = pathlib.Path(os.path.expandvars(os.path.expanduser(old)))
    install_at(template / 'hooks')
    if not old:
        run('config', '--global', 'init.templateDir', str(template))
    output = {'repositories': records, 'future_git_template': str(template), 'previous_template_setting': old or None}
    (__import__('leakguard_core.engine', fromlist=['STATE']).STATE / 'installed-hooks.json').write_text(json.dumps(output, indent=2), encoding='utf-8')
    print(json.dumps({'installed_repositories': sum(r['status'] == 'installed' for r in records), 'errors': [r for r in records if r['status'] == 'error'], 'future_git_template': str(template)}))


if __name__ == '__main__':
    main()
