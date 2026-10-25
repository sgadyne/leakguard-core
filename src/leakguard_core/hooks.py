"""Install local guards without changing tracked project files or discarding hooks."""
import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PYTHON = pathlib.Path(sys.executable)


def run(*args, cwd=None, check=True):
    return subprocess.run(['git', *args], cwd=cwd, check=check, capture_output=True, text=True)


def quote(value):
    return "'" + str(value).replace('\\', '/').replace("'", "'\"'\"'") + "'"


def install_at(hooks):
    hooks.mkdir(parents=True, exist_ok=True)
    changes = []
    for kind in ['pre-commit', 'pre-push']:
        target = hooks / kind
        marker = '# local-leakguard-managed'
        if target.exists() and marker not in target.read_text(encoding='utf-8', errors='replace'):
            backup = hooks / (kind + '.before-leakguard')
            if backup.exists():
                raise RuntimeError('An existing hook backup needs review: ' + str(backup))
            shutil.copy2(target, backup)
        text = '#!/bin/sh\n' + marker + '\nexec ' + quote(PYTHON) + ' ' + '-X utf8 -m leakguard_core' + ' hook ' + kind + ' "$@"\n'
        target.write_text(text, encoding='utf-8', newline='\n')
        if os.name != 'nt':
            target.chmod(target.stat().st_mode | 0o111)
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
            path = pathlib.Path(run('rev-parse', '--path-format=absolute', '--git-path', 'hooks', cwd=repo).stdout.strip())
            key = os.path.normcase(str(path))
            if key not in seen:
                install_at(path); seen.add(key)
            records.append({'repo': str(repo), 'hooks_directory': str(path), 'status': 'installed'})
        except Exception as error:
            records.append({'repo': str(repo), 'status': 'error', 'error_type': type(error).__name__})
    template = __import__('leakguard_core.engine', fromlist=['STATE']).STATE / 'git-template'
    old = run('config', '--global', '--get', 'init.templateDir', check=False).stdout.strip()
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
