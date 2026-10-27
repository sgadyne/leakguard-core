#!/usr/bin/env python3
"""Build a CLI deployment kit from a clean tracked commit (staging needs network)."""
from __future__ import annotations
import argparse
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    'linux-x86_64': ('linux', 'x64', ['manylinux_2_28_x86_64', 'manylinux2014_x86_64']),
    'macos-arm64': ('darwin', 'arm64', ['macosx_14_0_arm64']),
    'windows-x86_64': ('windows', 'x64', ['win_amd64']),
}

def sha(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def run(args, **kw):
    return subprocess.check_output([str(x) for x in args], **kw)

def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')

def fetch(url):
    with urllib.request.urlopen(url, timeout=90) as response:
        data = response.read(80_000_001)
    if len(data) > 80_000_000: raise ValueError('download-too-large')
    return data

def backend(stage, target, version):
    system, arch, _ = TARGETS[target]
    ext = 'zip' if system == 'windows' else 'tar.gz'
    filename = f'gitleaks_{version}_{system}_{arch}.{ext}'
    base = f'https://github.com/gitleaks/gitleaks/releases/download/v{version}/'
    checksums = fetch(base + f'gitleaks_{version}_checksums.txt')
    expected = next(x.split()[0] for x in checksums.decode().splitlines() if x.split()[-1].lstrip('*') == filename)
    data = fetch(base + filename)
    if hashlib.sha256(data).hexdigest() != expected: raise ValueError('backend-archive-hash-mismatch')
    name = 'gitleaks.exe' if system == 'windows' else 'gitleaks'
    if ext == 'zip':
        with zipfile.ZipFile(io.BytesIO(data)) as z: binary, license_text = z.read(name), z.read('LICENSE')
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as z:
            binary = z.extractfile(name).read(); license_text = z.extractfile('LICENSE').read()
    (stage/'backend').mkdir()
    p = stage/'backend'/name; p.write_bytes(binary); p.chmod(0o700)
    (stage/'backend'/'LICENSE').write_bytes(license_text)
    (stage/'backend'/'checksums.txt').write_bytes(checksums)
    write(stage/'backend'/'provenance.json', {'version': version, 'url': base+filename,
        'archive_filename': filename, 'archive_sha256': expected, 'binary_sha256': sha(p),
        'checksums_url': base+f'gitleaks_{version}_checksums.txt', 'license': 'MIT',
        'provenance': 'Official upstream release plus upstream checksum; integrity, not independent signature verification.'})

def wheels_info(wh, stage, source):
    packages=[]; licenses=[]
    for path in sorted(wh.glob('*.whl')):
        with zipfile.ZipFile(path) as z:
            names=z.namelist()
            if len(names)!=len(set(names)) or any(n.startswith('/') or '..' in n.split('/') for n in names):
                raise ValueError('wheel-members-invalid')
            meta=BytesParser().parsebytes(z.read(next(n for n in names if n.endswith('.dist-info/METADATA'))))
            rec={'name':meta['Name'],'version':meta['Version'],'filename':path.name,'sha256':sha(path)}
            packages.append(rec)
            files=[]
            for n in names:
                if not n.endswith('/') and ('/licenses/' in n.lower() or n.rsplit('/',1)[-1].lower() in ('license','license.txt','copying','notice','notice.txt')):
                    dest=stage/'licenses'/rec['name']/n
                    dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(z.read(n)); files.append(dest.relative_to(stage).as_posix())
            if rec['name'].lower().replace('_', '-') == 'presidio-analyzer':
                notice = source/'deploy/cli/licenses/presidio-analyzer-2.2.365-LICENSE'
                provenance = source/'deploy/cli/licenses/presidio-analyzer-2.2.365.json'
                expected = json.loads(provenance.read_text())
                if sha(notice) != expected['sha256'] or rec['version'] != expected['version']:
                    raise ValueError('presidio-license-provenance-mismatch')
                for item in (notice, provenance):
                    dest=stage/'licenses'/rec['name']/item.name
                    dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(item,dest)
                    files.append(dest.relative_to(stage).as_posix())
            if not files and rec['name'].startswith(('leakguard-', 'example-firm-')):
                files.append('LICENSE')
            if not files: raise ValueError('dependency-license-text-missing:' + rec['name'])
            licenses.append({'distribution':rec['name'],'version':rec['version'],
                'license_expression':meta.get('License-Expression'), 'license_metadata':meta.get('License'),
                'license_classifiers':[c for c in meta.get_all('Classifier',[]) if c.startswith('License ::')],
                'files':files, 'local_project_license':'LICENSE' if rec['name'].startswith(('leakguard-', 'example-firm-')) else None})
    write(stage/'licenses'/'inventory.json',licenses)
    (stage/'requirements.lock').write_text(''.join(f"{p['name']}=={p['version']} --hash=sha256:{p['sha256']}\n" for p in packages))
    return packages

def archive(stage, out):
    if out.exists(): raise FileExistsError(out)
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in sorted(stage.rglob('*')):
            if p.is_file(): z.write(p,p.relative_to(stage).as_posix())

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',required=True,type=Path,help='new directory outside checkout')
    p.add_argument('--target',action='append',choices=TARGETS,required=True)
    p.add_argument('--find-links',type=Path,help='optional immutable wheel cache for staging')
    a=p.parse_args(); out=a.output.absolute()
    if out.exists() or out.is_relative_to(ROOT): raise ValueError('new-output-outside-source-required')
    if run(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT): raise ValueError('clean-source-required')
    commit=run(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    tree=run(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip()
    # Pinned build tools in this fresh build environment; do not mutate an old venv.
    from importlib.metadata import version
    if version('setuptools')!='80.9.0' or version('wheel')!='0.45.1': raise ValueError('build-tools-must-be-setuptools80.9.0-wheel0.45.1')
    out.mkdir(parents=True)
    receipt={'schema':1,'source_commit':commit,'source_tree':tree,'artifacts':[],'platform_qualification':'built; native receipts required separately'}
    with tempfile.TemporaryDirectory(prefix='leakguard-cli-build-',dir=out.parent) as temp:
        temp=Path(temp); source=temp/'source'; source.mkdir()
        data=run(['git','archive',commit],cwd=ROOT)
        with tarfile.open(fileobj=io.BytesIO(data)) as z:
            for member in z.getmembers():
                if (not (member.isfile() or member.isdir()) or member.name.startswith('/') or '..' in Path(member.name).parts):
                    raise ValueError('tracked-archive-member-invalid')
            z.extractall(source)
        spec=json.loads((source/'deploy/cli/spec.json').read_text()); label=spec['version']
        built=temp/'built';built.mkdir()
        projects={**spec['projects'],**spec['examples']}
        run([sys.executable,'-m','pip','wheel','--no-deps','--no-build-isolation','--no-index','--no-cache-dir','--wheel-dir',built,
             *[source/r['path'] for r in projects.values()]])
        source_archive=out/f'leakguard-source-{label}-{commit[:12]}.tar.gz'
        # Release source contains tracked source files, excluding historical
        # machine-specific handoff/design/validation evidence and UI bundles.
        allowed_roots = {'.github', 'src', 'plugins', 'examples', 'tests', 'tools', 'scripts', 'native', 'packages', 'docs', 'deploy'}
        excluded = ('docs/design/', 'docs/handoff/', 'docs/validation/', 'deploy/desktop/')
        source_members = []
        with tarfile.open(fileobj=io.BytesIO(data)) as origin, tarfile.open(source_archive, 'w:gz') as dest:
            for member in origin.getmembers():
                name = member.name
                if not member.isfile() or name.startswith(excluded): continue
                if '/' in name and name.split('/')[0] not in allowed_roots: continue
                content = origin.extractfile(member)
                member.name = f'leakguard-source-{label}/' + name
                dest.addfile(member, content)
                source_members.append(name)
        receipt['source_archive_policy'] = {'tracked_files_only': True, 'allowed_roots': sorted(allowed_roots),
                                            'excluded_prefixes': list(excluded), 'members': source_members}
        receipt['artifacts'].append({'filename':source_archive.name,'sha256':sha(source_archive),'kind':'tracked-source'})
        for target in dict.fromkeys(a.target):
            stage=temp/target;stage.mkdir(); wh=stage/'wheelhouse';wh.mkdir()
            for name,r in spec['projects'].items():
                path=next(built.glob(f"{name.replace('-','_')}-{r['version']}-*.whl"));shutil.copyfile(path,wh/path.name)
            flags=['--platform',TARGETS[target][2][0]]
            for plat in TARGETS[target][2][1:]:flags+=['--platform',plat]
            flags+=['--python-version','3.11','--implementation','cp','--abi','cp311','--abi','abi3','--abi','none']
            # Cross-download markers use the staging OS. Include the locked Windows
            # helper explicitly on every target so the full lock stays conservative.
            lock=temp/f'{target}.lock'
            text=(source/'plugins/presidio_detector/requirements-py311.lock').read_text()
            lock.write_text(text.replace(" ; sys_platform == 'win32'",''))
            cache=['--find-links',a.find_links] if a.find_links else []
            run([sys.executable,'-m','pip','download','--only-binary=:all:','--no-cache-dir','--dest',wh,*flags,*cache,'--require-hashes','-r',lock])
            run([sys.executable,'-m','pip','download','--only-binary=:all:','--no-deps','--no-cache-dir','--dest',wh,*flags,*cache,
                 'pip==26.2.2','psutil==7.2.2','cachetools==7.2.5'])
            for filename in ('kit.py','README.md'):
                shutil.copyfile(source/'deploy/cli'/filename,stage/filename)
            for filename in ('LICENSE','THIRD_PARTY_NOTICES.md'):
                shutil.copyfile(source/filename,stage/filename)
            shutil.copyfile(source/'docs/credential-coverage.md',stage/'COVERAGE.md')
            backend(stage,target,spec['gitleaks'])
            packages=wheels_info(wh,stage,source)
            actual={x['name'].lower().replace('_','-'):x['version'] for x in packages}
            for n,r in spec['projects'].items():
                if actual.get(n)!=r['version']:raise ValueError('project-version-mismatch')
            manifest={'schema':1,'version':label,'source_commit':commit,'source_tree':tree,'target':target,
                      'python':'CPython 3.11','gitleaks_version':spec['gitleaks'],'packages':packages,
                      'source_archive':{'filename':source_archive.name,'sha256':sha(source_archive)},
                      'platform_qualification':'requires independent native receipt; target wheel selection alone is not qualification',
                      'files':{f.relative_to(stage).as_posix():sha(f) for f in sorted(stage.rglob('*')) if f.is_file()}}
            write(stage/'manifest.json',manifest)
            filename=f'leakguard-cli-{label}-{target}-cp311.zip'; archive(stage,out/filename)
            receipt['artifacts'].append({'filename':filename,'sha256':sha(out/filename),'manifest_sha256':sha(stage/'manifest.json'),'kind':'deployment-kit','target':target})
        examples=temp/'examples';examples.mkdir()
        for name,r in spec['examples'].items():
            path=next(built.glob(f"{name.replace('-','_')}-{r['version']}-*.whl"));shutil.copyfile(path,examples/path.name)
        shutil.copyfile(source/'deploy/cli/EXAMPLES.md',examples/'README.md');shutil.copyfile(source/'LICENSE',examples/'LICENSE')
        write(examples/'manifest.json',{'schema':1,'source_commit':commit,'source_tree':tree,'optional':True,
             'files':{f.name:sha(f) for f in examples.iterdir() if f.is_file()}})
        path=out/f'leakguard-examples-{label}.zip';archive(examples,path)
        receipt['artifacts'].append({'filename':path.name,'sha256':sha(path),'kind':'optional-synthetic-examples'})
    write(out/'build-receipt.json',receipt)
    print(json.dumps({k:v for k,v in receipt.items() if k != 'source_archive_policy'},sort_keys=True))

if __name__=='__main__': main()
