"""Install local guards without changing tracked project files or discarding hooks."""
import json
import argparse
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
    return subprocess.run(['git', *args], cwd=cwd, check=check, capture_output=True, timeout=10)


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


def install_at(hooks, *, config_path=None, state_dir=None):
    hooks = pathlib.Path(hooks)
    trusted_paths = _trusted_paths(hooks)
    commands = {kind: core_command('leakguard_core', 'hook', kind, executable=PYTHON.as_posix(), search_paths=trusted_paths)
                for kind in ('pre-commit', 'pre-push')}
    environment = ''
    for key, value in (('LEAKGUARD_CONFIG', config_path), ('LEAKGUARD_STATE_DIR', state_dir)):
        if value is not None:
            path = pathlib.Path(value)
            if not path.is_absolute() or '\x00' in str(path) or len(str(path)) > 4096:
                raise RuntimeError('hook-configuration-invalid')
            environment += 'export ' + key + '=' + quote(path) + '\n'
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
        text = '#!/bin/sh\n' + marker.decode('ascii') + '\n' + environment + 'exec ' + ' '.join(quote(value) for value in commands[kind]) + ' "$@"\n'
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


def uninstall_at(hooks):
    """Remove only managed hooks, atomically restoring preserved originals."""
    hooks = pathlib.Path(hooks)
    changes = []
    for kind in ('pre-commit', 'pre-push'):
        target = hooks / kind
        previous = _read_hook(target)
        if previous is None or not previous[0].startswith(b'#!/bin/sh\n# local-leakguard-managed\n'):
            continue
        backup = hooks / (kind + '.before-leakguard')
        preserved = _read_hook(backup)
        # Never follow a backup symlink or overwrite a replacement hook.
        current = _read_hook(target)
        if current is None or current[0] != previous[0] or (current[1].st_dev, current[1].st_ino) != (previous[1].st_dev, previous[1].st_ino):
            raise RuntimeError('hook-target-changed')
        if preserved is not None:
            os.replace(backup, target)
        else:
            target.unlink()
        changes.append(kind)
    return changes


def _repository_hooks(repo):
    repo = pathlib.Path(repo).expanduser().resolve(strict=True)
    root_result = run('rev-parse', '--show-toplevel', cwd=repo)
    from .git_scanning import path_output
    root = pathlib.Path(path_output(root_result.stdout)).resolve(strict=True)
    hooks = pathlib.Path(path_output(run('rev-parse', '--path-format=absolute', '--git-path', 'hooks', cwd=repo).stdout)).absolute()
    common = pathlib.Path(path_output(run('rev-parse', '--path-format=absolute', '--git-common-dir', cwd=repo).stdout)).resolve(strict=True)
    # An inherited external core.hooksPath may serve unrelated repositories.
    # Installing into it would exceed the selected repository's scope.
    physical = hooks.resolve()
    if not physical.is_relative_to(root) and not physical.is_relative_to(common):
        raise RuntimeError('hook-directory-shared')
    return root, hooks


def install_repository(repo, *, config_path=None, state_dir=None):
    root, hooks = _repository_hooks(repo)
    if config_path is not None:
        from .settings import read_config
        config_path = pathlib.Path(config_path).expanduser().resolve(strict=True)
        read_config(config_path)
    if state_dir is not None:
        state_dir = pathlib.Path(state_dir).expanduser().absolute()
    changed = install_at(hooks, config_path=config_path, state_dir=state_dir)
    return {'repository': str(root), 'hooks_directory': str(hooks), 'installed': changed}


def uninstall_repository(repo):
    root, hooks = _repository_hooks(repo)
    return {'repository': str(root), 'hooks_directory': str(hooks), 'uninstalled': uninstall_at(hooks)}


def repository_status(repo):
    root, hooks = _repository_hooks(repo)
    managed = []
    for kind in ('pre-commit', 'pre-push'):
        previous = _read_hook(hooks / kind)
        if previous is not None and previous[0].startswith(b'#!/bin/sh\n# local-leakguard-managed\n'):
            managed.append(kind)
    return {'repository': str(root), 'hooks_directory': str(hooks), 'managed': managed}


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


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Preserve the old one-repository shorthand without recursive discovery or
    # global init.templateDir mutation.
    if arguments and arguments[0] not in {'install', 'uninstall', 'status', '-h', '--help'}:
        arguments.insert(0, 'install')
    parser = argparse.ArgumentParser(description='Manage Git guards for one explicitly selected repository')
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('install', 'uninstall', 'status'):
        child = commands.add_parser(command)
        child.add_argument('repository')
        if command == 'install':
            child.add_argument('--config')
            child.add_argument('--state-dir')
    args = parser.parse_args(arguments)
    try:
        if args.command == 'install':
            result = install_repository(args.repository, config_path=args.config, state_dir=args.state_dir)
        elif args.command == 'uninstall':
            result = uninstall_repository(args.repository)
        else:
            result = repository_status(args.repository)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except Exception:
        print('LeakGuard: hook-management-failed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
