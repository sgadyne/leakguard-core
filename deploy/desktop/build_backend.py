#!/usr/bin/env python3
"""Build the integrated Mac desktop offline backend from a qualified CLI kit.

Run with a native CPython 3.11 build interpreter and pinned build tools. The
kit supplies the previously qualified third-party scanner closure and backend;
all local product wheels are freshly built from the clean integrated checkout.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = {
    'leakguard-core': '.',
    'leakguard-buddy': 'apps/buddy',
    'leakguard-host': 'packages/leakguard_host',
    'leakguard-vault': 'packages/leakguard_vault',
    'leakguard-credential-detector': 'plugins/credential_detector',
    'leakguard-presidio-detector': 'plugins/presidio_detector',
    'leakguard-jose-recognizers': 'plugins/jose_recognizers',
    'leakguard-sensitive-basics': 'plugins/sensitive_basics',
    'leakguard-firm-example': 'templates/firm_plugin',
}
EXTRA = ('pip==26.2.2', 'cryptography==50.0.2', 'keyring==25.7.0',
         'pypdf==6.21.2', 'olefile==0.47')

def run(*args):
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)

def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualified-kit', type=Path, required=True, help='extracted qualified macOS CLI kit')
    parser.add_argument('--output', type=Path, required=True, help='new backend build directory outside checkout')
    args = parser.parse_args()
    if sys.platform != 'darwin' or platform.machine() != 'arm64' or sys.version_info[:2] != (3, 11):
        raise ValueError('native macOS CPython 3.11 build interpreter required')
    from importlib.metadata import version
    if version('setuptools') != '80.9.0' or version('wheel') != '0.45.1':
        raise ValueError('build tools must be setuptools 80.9.0 and wheel 0.45.1')
    if subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT).strip():
        raise ValueError('commit all source changes before building')
    commit = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    kit = args.qualified_kit.resolve(strict=True)
    info = json.loads((kit/'manifest.json').read_text())
    if info['target'] != 'macos-arm64' or info['python'] != 'CPython 3.11' or info['gitleaks_version'] != '8.30.1':
        raise ValueError('qualified kit target or pinned versions differ')
    for relative, expected in info['files'].items():
        rel = Path(relative)
        if rel.is_absolute() or '..' in rel.parts:
            raise ValueError('unsafe qualified kit path')
        path = kit/rel
        if path.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError('qualified kit integrity failure: '+relative)
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        raise ValueError('output must be new and outside checkout')
    output.mkdir(parents=True)
    wheels = output/'wheelhouse'; wheels.mkdir()
    for package in info['packages']:
        name = package['name'].lower().replace('_','-')
        if name not in PROJECTS:
            shutil.copyfile(kit/'wheelhouse'/package['filename'],wheels/package['filename'])
    # Preserve every qualified scanner dependency version while resolving the
    # additional vault/host dependencies on the target interpreter.
    constraints = output/'scanner-constraints.txt'
    constraints.write_text(''.join(f"{p['name']}=={p['version']}\n" for p in info['packages']
                                   if p['name'].lower().replace('_','-') not in PROJECTS))
    run(sys.executable,'-m','pip','wheel','--no-deps','--no-build-isolation','--no-index',
        '--wheel-dir',wheels,*[ROOT/p for p in PROJECTS.values()])
    run(sys.executable,'-m','pip','download','--only-binary=:all:','--dest',wheels,
        '--constraint',constraints,*EXTRA)
    spec=json.loads((ROOT/'deploy/release-manifest.json').read_text())
    from importlib.util import spec_from_file_location, module_from_spec
    module_spec=spec_from_file_location('bundle_builder',ROOT/'deploy/build_bundle.py')
    module=module_from_spec(module_spec); module_spec.loader.exec_module(module)
    found={}
    for wheel in wheels.glob('*.whl'):
        name,version_value=module.wheel_identity(wheel)
        name=module.normalized_name(name)
        if name in found: raise ValueError('duplicate distribution: '+name)
        found[name]=version_value
    for name in PROJECTS:
        if name not in found: raise ValueError('missing project: '+name)
        spec['pinned_distributions'][name]=found[name]
    spec['release_version']='desktop-0.1.0-alpha.1'
    spec_path=output/'release-manifest.json'
    spec_path.write_text(json.dumps(spec,indent=2,sort_keys=True)+'\n')
    archive=output/'integrated-backend.zip'
    run(sys.executable,ROOT/'deploy/build_bundle.py','--wheelhouse',wheels,'--output',archive,
        '--release-manifest',spec_path,'--default-config',ROOT/'deploy/desktop/default-config.json','--source-commit',commit,'--target-platform','macos-arm64',
        '--target-python','3.11','--backend-artifact',f'macos-arm64/gitleaks={kit / "backend/gitleaks"}',
        *sum((['--require-package',name] for name in PROJECTS),[]))
    with zipfile.ZipFile(archive) as z: z.extractall(output/'extracted')
    print(json.dumps({'source_commit':commit,'qualified_kit_source':info['source_commit'],
                      'backend_archive_sha256':digest(archive),'backend_input':str(output/'extracted/LeakGuard'),
                      'packages':found},sort_keys=True))

if __name__ == '__main__':
    main()
