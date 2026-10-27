#!/usr/bin/env python3
"""Build and qualify credential wheels in fresh offline environments.

See plugins/credential_detector/README.md for inputs and invocation. No model,
service, or global installation is used. The receipt contains only metadata and
hashes, never fixture text.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata as metadata
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = (
    ("leakguard-core", "leakguard_core", ".", "src/leakguard_core"),
    ("leakguard-credential-detector", "credential_detector", "plugins/credential_detector", "plugins/credential_detector/src/credential_detector"),
    ("leakguard-private-credential-example", "private_credential_pack", "examples/private_credential_pack", "examples/private_credential_pack/src/private_credential_pack"),
)
GROUPS = ("common", "cloud", "developer-ci", "data-messaging", "saas-ai", "key-material")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_wheel(wheel: Path, source: Path, module: str, required: set[str]) -> dict[str, str]:
    """Verify all source Python/JSON bytes and required resources in a wheel."""
    expected = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob('*')
                if p.is_file() and p.suffix in {'.py', '.json', '.toml'} and '__pycache__' not in p.parts}
    if not required <= expected.keys():
        raise ValueError('source-resource-missing')
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            raise ValueError('wheel-duplicate-member')
        packaged = {n[len(module) + 1:]: n for n in names
                    if n.startswith(module + '/') and n.endswith(('.py', '.json', '.toml'))}
        if set(packaged) != set(expected):
            raise ValueError('wheel-file-set-mismatch')
        if any(z.read(packaged[n]) != data for n, data in expected.items()):
            raise ValueError('wheel-source-mismatch')
    return {f'{module}/{name}': sha(data) for name, data in sorted(expected.items())}


def inspect_install(source_root: Path, wheel_dir: Path) -> dict:
    if not sys.flags.isolated or Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve():
        raise ValueError('isolated-venv-required')
    source_root = source_root.resolve()
    if any(Path(p).resolve().is_relative_to(source_root) for p in sys.path if p):
        raise ValueError('source-on-import-path')
    result = {}
    for distribution, module, _, source_path in PROJECTS:
        dist = metadata.distribution(distribution)
        direct = dist.read_text('direct_url.json')
        if direct and json.loads(direct).get('dir_info', {}).get('editable'):
            raise ValueError('editable-install')
        imported = importlib.import_module(module)
        origin = Path(imported.__file__).resolve()
        prefix = Path(sys.prefix).resolve()
        if not origin.is_relative_to(prefix) or origin.is_relative_to(source_root):
            raise ValueError('import-origin-invalid')
        candidates = list(wheel_dir.glob(distribution.replace('-', '_') + '-*.whl'))
        if len(candidates) != 1:
            raise ValueError('wheel-ambiguous')
        required = set()
        if module == 'leakguard_core':
            required = {'rules.toml'}
        elif module == 'credential_detector':
            required = {'leakguard-plugin.json', 'cases.json'} | {f'resources/{x}.json' for x in GROUPS}
        elif module == 'private_credential_pack':
            required = {'leakguard-plugin.json', 'cases.json', 'resources/aliases.json'}
        hashes = verify_wheel(candidates[0], source_root / source_path, module, required)
        entries = {str(entry): entry for entry in dist.files or ()}
        for name, digest in hashes.items():
            if name not in entries:
                raise ValueError('installed-record-missing')
            path = Path(dist.locate_file(entries[name])).resolve()
            if not path.is_relative_to(prefix) or sha(path.read_bytes()) != digest:
                raise ValueError('installed-byte-mismatch')
        result[distribution] = {'version': dist.version, 'wheel': candidates[0].name,
                                'wheel_sha256': sha(candidates[0].read_bytes()),
                                'requires': sorted(dist.requires or []), 'files_sha256': hashes}
    private_reqs = result['leakguard-private-credential-example']['requires']
    if not any(re.match(r'^leakguard[-_.]credential[-_.]detector(?=$|[\s<>=!~;(\[])', r, re.I) for r in private_reqs):
        raise ValueError('private-dependency-missing')
    for module, sample, rule in (
        ('credential_detector.plugin', 'password=synthetic-example', 'credential-password'),
        ('private_credential_pack.plugin', 'acme_deploy_key=synthetic-example', 'credential-api-key'),
    ):
        plugin = importlib.import_module(module)
        if not Path(plugin.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()):
            raise ValueError('plugin-origin-invalid')
        if plugin.MANIFEST.external_state != 'unknown':
            raise ValueError('resource-fence-missing')
        findings = tuple(plugin.create_plugin({}).detect(sample, None))
        if not any(f.rule == rule for f in findings):
            raise ValueError('installed-detector-smoke-failed')
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--wheelhouse', type=Path)
    parser.add_argument('--python', default=sys.executable)
    parser.add_argument('--uv', default='uv')
    parser.add_argument('--inspect', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--source-root', type=Path, default=ROOT, help=argparse.SUPPRESS)
    parser.add_argument('--built-wheels', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inspect:
        print(json.dumps(inspect_install(args.source_root, args.built_wheels), sort_keys=True))
        return
    if not args.artifacts or not args.wheelhouse:
        parser.error('--artifacts and --wheelhouse are required')
    root = ROOT.resolve()
    artifacts = args.artifacts.absolute()
    if artifacts.exists() or artifacts.is_symlink() or artifacts.resolve().is_relative_to(root):
        raise SystemExit('artifact-root-invalid')
    inputs = args.wheelhouse.resolve(strict=True)
    if not inputs.is_dir() or inputs.is_relative_to(root):
        raise SystemExit('wheelhouse-invalid')
    artifacts.mkdir(mode=0o700, parents=True)
    os.umask(0o077)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'PIP_', 'UV_'))}
    env.update({'UV_NO_CONFIG': '1', 'UV_PYTHON_DOWNLOADS': 'never'})
    uv = str(Path(shutil.which(args.uv) or args.uv).resolve(strict=True))
    python = str(Path(shutil.which(args.python) or args.python).resolve(strict=True))
    wheels = artifacts / 'wheels'
    wheels.mkdir()
    constraints = artifacts / 'build-constraints.txt'
    constraints.write_text('setuptools==80.9.0\nwheel==0.45.1\n', encoding='utf-8')
    logs = []
    def run(label, command, *, success=True):
        completed = subprocess.run([str(x) for x in command], cwd=artifacts, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        (artifacts / f'{label}.log').write_bytes(completed.stdout)
        logs.append(label)
        if (completed.returncode == 0) != success:
            raise RuntimeError(f'{label}-failed')
        return completed.stdout.decode('utf-8', errors='replace')
    offline = ['--offline', '--no-index', '--no-cache']
    source_commit = run('source-commit', ['git', '-C', root, 'rev-parse', 'HEAD']).strip()
    source_status = run('source-status', ['git', '-C', root, 'status', '--porcelain', '--untracked-files=all'])
    if source_status.strip():
        raise RuntimeError('source-dirty')
    runtime_constraints = artifacts / 'runtime-constraints.txt'
    runtime_constraints.write_text('packaging==26.3\npsutil==7.2.2\ncachetools==7.2.5\n', encoding='utf-8')
    # Source is copied so builds cannot leave generated files in the checkout.
    source = artifacts / 'source'
    shutil.copytree(root, source, ignore=shutil.ignore_patterns('.git', '__pycache__', '*.pyc', 'build', 'dist', '*.egg-info'))
    for distribution, _, project, _ in PROJECTS:
        run('build-' + distribution, [uv, 'build', '--wheel', '--python', python, *offline,
            '--find-links', inputs, '--build-constraints', constraints, '--out-dir', wheels, source / project])
    def venv(name):
        path = artifacts / name
        run('venv-' + name, [uv, 'venv', '--python', python, '--no-python-downloads', path])
        return path / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    private = list(wheels.glob('leakguard_private_credential_example-*.whl'))
    if len(private) != 1:
        raise RuntimeError('private-wheel-ambiguous')
    missing_python = venv('missing-dependency')
    # Empty find-links and no cache prove the private wheel cannot silently stand alone.
    empty = artifacts / 'empty-wheelhouse'
    empty.mkdir()
    output = run('missing-dependency', [uv, 'pip', 'install', '--python', missing_python,
                  *offline, '--find-links', empty, private[0]], success=False)
    if 'leakguard-credential-detector' not in output.lower().replace('_', '-'):
        raise RuntimeError('missing-dependency-not-proven')
    installed = venv('installed')
    run('install-private', [uv, 'pip', 'install', '--python', installed, *offline,
        '--find-links', inputs, '--find-links', wheels, '--constraint', runtime_constraints,
        '--link-mode', 'copy', private[0]])
    run('dependency-check', [uv, 'pip', 'check', '--python', installed, '--offline'])
    payload = run('inspect', [installed, '-I', Path(__file__).resolve(), '--inspect',
                              '--source-root', root, '--built-wheels', wheels])
    receipt = {'schema': 1, 'outcome': 'passed', 'synthetic_only': True,
               'python': run('python-version', [installed, '-I', '--version']).strip(),
               'python_executable_sha256': sha(Path(python).read_bytes()),
               'uv_executable_sha256': sha(Path(uv).read_bytes()),
               'uv': run('uv-version', [uv, '--version']).strip(),
               'source_commit': source_commit,
               'build_constraints': constraints.read_text().splitlines(),
               'runtime_constraints': runtime_constraints.read_text().splitlines(),
               'input_wheels': {p.name: sha(p.read_bytes()) for p in sorted(inputs.glob('*.whl'))},
               'distributions': json.loads(payload), 'private_missing_dependency_rejected': True}
    (artifacts / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print('passed: ' + str(artifacts / 'receipt.json'))


if __name__ == '__main__':
    main()
