#!/usr/bin/env python3
"""Qualify a side-by-side alpha upgrade and rollback on a native target.

Build the exact earlier alpha's core and credential detector from a tracked Git
archive. Install them and the unchanged Presidio/JOSE wheels using the current
kit's hash-locked native dependency closure. The actual current kit is installed
separately. Only synthetic data and separate private state are used.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

PRIOR_COMMIT = '6fb7c089f238f105d781fea5c5a7363a37840978'
PRIOR_VERSIONS = {'leakguard-core': '0.2.1a2', 'leakguard-credential-detector': '0.1.0a1',
                  'leakguard-presidio-detector': '0.1.0a2', 'leakguard-jose-recognizers': '0.1.0a2'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def python_at(env):
    return env / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, type=Path)
    parser.add_argument('--kit', required=True, type=Path)
    parser.add_argument('--kit-archive', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    kit = args.kit.resolve(strict=True)
    if '*' in args.kit_archive.name:
        matches = [path for path in args.kit_archive.parent.glob(args.kit_archive.name) if path.is_file()]
        if len(matches) != 1:
            raise SystemExit('exactly-one-kit-archive-required')
        archive = matches[0].resolve(strict=True)
    else:
        archive = args.kit_archive.resolve(strict=True)
    out = args.output_dir.resolve()
    if out.exists() or out.is_relative_to(repository) or out.is_relative_to(kit):
        raise SystemExit('new-private-output-outside-source-and-kit-required')
    out.mkdir(mode=0o700, parents=True)
    os.umask(0o077)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'PIP_', 'LEAKGUARD_', 'GIT_'))}
    env.update({'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'GIT_CONFIG_NOSYSTEM': '1',
                'GIT_CONFIG_GLOBAL': os.devnull})
    secret = 'synthetic-disposable-4b7e1f9a83d2c670'
    token = '.'.join((base64.urlsafe_b64encode(b'{"alg":"dir","enc":"A256GCM"}').decode().rstrip('='), '',
                      base64.urlsafe_b64encode(b'i' * 12).decode().rstrip('='),
                      base64.urlsafe_b64encode(b'synthetic-payload').decode().rstrip('='),
                      base64.urlsafe_b64encode(b't' * 16).decode().rstrip('=')))

    def run(label, command, *, cwd=out, expected=0, text=True):
        result = subprocess.run([str(x) for x in command], cwd=cwd, env=env, capture_output=True,
                                text=text, timeout=600)
        if result.returncode != expected:
            raise RuntimeError(f'{label}:exit-{result.returncode}-expected-{expected}')
        if text and (secret in result.stdout + result.stderr or token in result.stdout + result.stderr):
            raise RuntimeError(f'{label}:value-leak')
        return result.stdout

    if importlib.metadata.version('setuptools') != '80.9.0' or importlib.metadata.version('wheel') != '0.45.1':
        raise RuntimeError('pinned-staging-build-tools-required')
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if len(names) != len(set(names)) or z.read('manifest.json') != (kit / 'manifest.json').read_bytes():
            raise RuntimeError('kit-archive-manifest-mismatch')
    manifest = json.loads((kit / 'manifest.json').read_text())
    new_commit = manifest['source_commit']
    if new_commit == PRIOR_COMMIT:
        raise RuntimeError('current-must-differ-from-prior')
    commit = run('prior-commit', ['git', 'rev-parse', '--verify', PRIOR_COMMIT + '^{commit}'], cwd=repository).strip()
    if commit != PRIOR_COMMIT:
        raise RuntimeError('prior-commit-mismatch')
    prior_tree = run('prior-tree', ['git', 'rev-parse', PRIOR_COMMIT + '^{tree}'], cwd=repository).strip()
    raw = run('prior-archive', ['git', '-c', 'core.autocrlf=false', '-c', 'core.eol=lf', 'archive', PRIOR_COMMIT],
              cwd=repository, text=False)
    source = out / 'prior-source'
    source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.isdir()) or member.name.startswith('/') or '..' in Path(member.name).parts:
                raise RuntimeError('prior-archive-member-invalid')
        tar.extractall(source)
    wheels = out / 'prior-wheels'
    wheels.mkdir()
    run('prior-build', [sys.executable, '-m', 'pip', 'wheel', '--no-index', '--no-cache-dir', '--no-deps',
                        '--no-build-isolation', '--wheel-dir', wheels, source, source / 'plugins/credential_detector'])
    prior_wheels = []
    for name, version in list(PRIOR_VERSIONS.items())[:2]:
        candidates = list(wheels.glob(name.replace('-', '_') + '-' + version + '-*.whl'))
        if len(candidates) != 1:
            raise RuntimeError('prior-wheel-version-mismatch')
        prior_wheels.append(candidates[0])
    # Authenticate the extracted kit against its own manifest before using the
    # locked wheels. The archive hash is recorded for comparison with receipt.
    expected_files = set(manifest['files']) | {'manifest.json'}
    actual_files = {p.relative_to(kit).as_posix() for p in kit.rglob('*') if p.is_file()}
    if actual_files != expected_files:
        raise RuntimeError('kit-file-set-mismatch')
    for name, digest in manifest['files'].items():
        path = kit / name
        if Path(name).is_absolute() or '..' in Path(name).parts or path.is_symlink() or sha(path) != digest:
            raise RuntimeError('kit-file-hash-mismatch')
    new_env = out / 'new-runtime'
    lock = out / 'prior-dependencies.lock'
    lines = (kit / 'requirements.lock').read_text().splitlines()
    lines = [line for line in lines if not line.lower().replace('_', '-').startswith(
        ('leakguard-core==', 'leakguard-credential-detector=='))]
    lock.write_text('\n'.join(lines) + '\n')
    old_env = out / 'old-runtime'
    run('old-venv', [sys.executable, '-m', 'venv', old_env])
    old_py, new_py = python_at(old_env), python_at(new_env)
    run('old-dependencies', [old_py, '-I', '-m', 'pip', 'install', '--no-index', '--no-cache-dir', '--no-deps',
                             '--require-hashes', '--find-links', kit / 'wheelhouse', '-r', lock])
    run('old-wheels', [old_py, '-I', '-m', 'pip', 'install', '--no-index', '--no-cache-dir', '--no-deps', *prior_wheels])
    run('old-check', [old_py, '-I', '-m', 'pip', 'check'])
    # Check installed versions and import paths from the environment, never the checkout.
    inspect = ('import importlib,importlib.metadata as m,json;'
               'names=("leakguard-core","leakguard-credential-detector","leakguard-presidio-detector","leakguard-jose-recognizers");'
               'mods=("leakguard_core","credential_detector","presidio_detector","jose_recognizers");'
               'print(json.dumps({"versions":{x:m.version(x) for x in names},'
               '"origins":{x:importlib.import_module(x).__file__ for x in mods}}))')
    def identity(python, environment, expected):
        info = json.loads(run('package-identity', [python, '-I', '-c', inspect]))
        if info['versions'] != expected:
            raise RuntimeError('installed-version-mismatch')
        if not all(Path(path).resolve().is_relative_to(environment.resolve()) for path in info['origins'].values()):
            raise RuntimeError('installed-import-outside-environment')
        return info
    new_versions = {name: next(row['version'] for row in manifest['packages']
                              if row['name'].lower().replace('_', '-') == name) for name in PRIOR_VERSIONS}
    if new_versions['leakguard-core'] == PRIOR_VERSIONS['leakguard-core'] or new_versions['leakguard-credential-detector'] == PRIOR_VERSIONS['leakguard-credential-detector']:
        raise RuntimeError('same-version-upgrade')
    old_identity = identity(old_py, old_env, PRIOR_VERSIONS)
    # Compare old project files to the built wheels and tracked-source archive.
    roots = {'leakguard_core': source / 'src/leakguard_core',
             'credential_detector': source / 'plugins/credential_detector/src/credential_detector'}
    site = Path(old_identity['origins']['leakguard_core']).resolve().parent.parent
    old_file_hashes = {}
    for module, wheel in zip(roots, prior_wheels):
        with zipfile.ZipFile(wheel) as z:
            expected = {p.relative_to(roots[module]).as_posix(): p.read_bytes()
                        for p in roots[module].rglob('*') if p.is_file() and
                        (p.suffix in ('.py', '.json', '.toml') or p.name == 'py.typed')}
            members = {name[len(module) + 1:]: name for name in z.namelist() if name.startswith(module + '/') and
                       (name.endswith(('.py', '.json', '.toml')) or name.endswith('/py.typed'))}
            if set(expected) != set(members):
                raise RuntimeError('prior-wheel-member-mismatch')
            for name, data in expected.items():
                if z.read(members[name]) != data or (site / module / name).read_bytes() != data:
                    raise RuntimeError('prior-installed-byte-mismatch')
                old_file_hashes[site / module / name] = hashlib.sha256(data).hexdigest()
    backend = kit / 'backend' / ('gitleaks.exe' if os.name == 'nt' else 'gitleaks')
    base_config = out / 'old-base.json'
    base_config.write_text(json.dumps({'gitleaks_executable': str(backend),
        'worker_policy': 'supervised-alpha' if sys.platform == 'darwin' else 'strict',
        'worker_memory_bytes': 2 * 1024**3}))
    old_config = out / 'old-config.json'
    run('old-compose', [old_py, '-I', '-m', 'leakguard_core.recognizer_profiles', '--profile', 'credentials',
                        '--base-config', base_config, '--output', old_config])
    config_hash = sha(old_config)
    fixtures = out / 'fixtures'
    fixtures.mkdir()
    positive, negative, review = (fixtures / name for name in ('positive.txt', 'negative.txt', 'review.txt'))
    positive.write_text('password=' + secret + '\n')
    negative.write_text('password=${SYNTHETIC_REFERENCE}\n')
    review.write_text(token + '\n')
    def exercise(label, python, config, state):
        def scan(file, status=0, extra=()):
            raw = run(label, [python, '-I', '-m', 'leakguard_core', 'scan', file, '--config', config,
                              '--state-dir', state, '--format', 'json', '--no-cache', *extra], expected=status)
            value = json.loads(raw)
            if not value['coverage']['required_complete']:
                raise RuntimeError('required-scan-incomplete')
            return value
        if scan(positive, 1, ('--fail-on', 'block'))['counts']['block_findings'] < 1:
            raise RuntimeError('positive-not-blocked')
        if scan(negative)['counts']['findings']:
            raise RuntimeError('negative-not-clean')
        result = scan(review)
        if result['counts']['review_findings'] < 1 or result['counts']['block_findings']:
            raise RuntimeError('jose-review-policy-mismatch')
    old_state, new_state = out / 'old-state', out / 'new-state'
    exercise('old', old_py, old_config, old_state)
    def state_digest(directory):
        entries = sorted((p.relative_to(directory).as_posix(), sha(p))
                         for p in directory.rglob('*') if p.is_file())
        return hashlib.sha256(json.dumps(entries, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
    snapshot = out / 'old-state-snapshot'
    shutil.copytree(old_state, snapshot)
    snapshot_hash = state_digest(snapshot)
    if state_digest(old_state) != snapshot_hash:
        raise RuntimeError('old-state-snapshot-mismatch')
    # Upgrade only after an actual prior-runtime scan and state snapshot.
    run('new-install', [sys.executable, kit / 'kit.py', 'install', '--env', new_env])
    run('new-verify', [sys.executable, kit / 'kit.py', 'verify', '--env', new_env])
    run('new-smoke', [sys.executable, kit / 'kit.py', 'smoke', '--env', new_env])
    new_identity = identity(new_py, new_env, new_versions)
    new_config_hash = sha(new_env / 'leakguard-config.json')
    exercise('new', new_py, new_env / 'leakguard-config.json', new_state)
    restored = out / 'restored-old-state'
    shutil.copytree(snapshot, restored)
    if state_digest(restored) != snapshot_hash:
        raise RuntimeError('restored-state-snapshot-mismatch')
    exercise('rollback', old_py, old_config, restored)
    if (sha(old_config) != config_hash or sha(new_env / 'leakguard-config.json') != new_config_hash
            or identity(old_py, old_env, PRIOR_VERSIONS)['versions'] != old_identity['versions']
            or any(sha(path) != digest for path, digest in old_file_hashes.items())
            or state_digest(snapshot) != snapshot_hash):
        raise RuntimeError('old-runtime-or-config-changed')
    for state in (old_state, new_state, snapshot, restored):
        for path in state.rglob('*'):
            if path.is_file():
                data = path.read_bytes()
                if secret.encode() in data or token.encode() in data:
                    raise RuntimeError('state-value-leak')
    receipt = {'status': 'passed', 'synthetic_only': True, 'prior_commit': PRIOR_COMMIT,
        'prior_tree': prior_tree, 'prior_wheels': {p.name: sha(p) for p in prior_wheels},
        'prior_versions': old_identity['versions'], 'current_commit': new_commit,
        'current_versions': new_identity['versions'], 'target': manifest['target'],
        'current_archive_sha256': sha(archive),
        'current_manifest_sha256': sha(kit / 'manifest.json'), 'old_config_sha256': config_hash,
        'new_config_sha256': new_config_hash, 'old_state_snapshot_sha256': snapshot_hash,
        'old_interpreter_sha256': sha(old_py), 'new_interpreter_sha256': sha(new_py),
        'gitleaks_sha256': sha(backend),
        'old_new_rollback_positive_negative_review': True, 'old_state_snapshot_separate': True,
        'old_config_and_runtime_retained': True, 'value_free_output_and_state': True,
        'scope': 'side-by-side CLI environments; no global launcher, service, hook or vault migration'}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
