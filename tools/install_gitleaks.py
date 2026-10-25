"""Explicit optional installer: official pinned release, checksum, binary-only extraction."""
import hashlib
import io
import pathlib
import platform
import sys
import tarfile
import urllib.request
import zipfile

VERSION = '8.30.1'


def install(destination):
    system = {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'darwin'}.get(platform.system())
    machine = platform.machine().lower()
    architecture = 'arm64' if machine in {'arm64', 'aarch64'} else 'x64' if machine in {'amd64', 'x86_64'} else None
    if not system or not architecture:
        raise RuntimeError('Unsupported platform; install Gitleaks separately')
    extension = 'zip' if system == 'windows' else 'tar.gz'
    archive = f'gitleaks_{VERSION}_{system}_{architecture}.{extension}'
    base = f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/'
    def download(name):
        with urllib.request.urlopen(base + name, timeout=60) as response:
            return response.read(40_000_000)
    checksums = download(f'gitleaks_{VERSION}_checksums.txt').decode()
    expected = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1].lstrip('*') == archive)
    data = download(archive)
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Gitleaks archive checksum mismatch')
    name = 'gitleaks.exe' if system == 'windows' else 'gitleaks'
    if extension == 'zip':
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            binary = package.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as package:
            stream = package.extractfile(name)
            if stream is None:
                raise RuntimeError('Release archive has no scanner binary')
            binary = stream.read(40_000_000)
    root = pathlib.Path(destination); root.mkdir(parents=True, exist_ok=True)
    target = root / name; target.write_bytes(binary); target.chmod(0o700)
    print(target.resolve())


if __name__ == '__main__':
    install(sys.argv[1] if len(sys.argv) > 1 else '.tools')
