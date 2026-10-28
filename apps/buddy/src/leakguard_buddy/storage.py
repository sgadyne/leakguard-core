"""Verified ciphertext relocation; originals remain available for rollback."""
from __future__ import annotations
import hashlib,os,shutil,stat
from pathlib import Path
from leakguard_vault._files import FileLock,atomic_write,read_bounded
from leakguard_vault import _envelope


class StorageError(RuntimeError):
    def __init__(self,code='storage-unavailable'):self.code=code;super().__init__(code)


def validate_path(value):
    if type(value) is not str or not 0<len(value)<=4096 or '\x00' in value or not Path(value).is_absolute():raise StorageError('storage-path-invalid')
    path=Path(value)
    try:
        if path.parent.resolve(strict=True)!=path.parent or path.is_symlink():raise StorageError('storage-path-invalid')
        info=path.parent.stat()
        if not stat.S_ISDIR(info.st_mode) or hasattr(os,'getuid') and info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o022:raise StorageError('storage-ownership-invalid')
        if path.exists():
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or hasattr(os,'getuid') and info.st_uid!=os.getuid():raise StorageError('storage-ownership-invalid')
        from leakguard_host.navigation import _mounts
        matches=[m for m in _mounts() if path.is_relative_to(m['path'])]
        mount=max(matches,key=lambda m:len(m['path'])) if matches else None
        if mount and mount['filesystem'].lower() not in {'apfs','hfs','ext4','xfs','btrfs','zfs','tmpfs'}:raise StorageError('storage-filesystem-unsupported')
        return path
    except OSError:raise StorageError() from None


def _digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


class PreparedRelocation:
    def __init__(self,source,destination,*,source_owned=False):
        self.source,self.destination=source,validate_path(str(destination));self.lock=None;self.source_lock=None;self.created=[];self.verified=False
        if destination==source:raise StorageError('storage-path-unchanged')
        if destination.exists() or destination.with_name(destination.name+'.parts').exists():raise StorageError('storage-destination-exists')
        if not source.is_file():raise StorageError()
        try:
            self.source_lock=None if source_owned else FileLock(source)
            self.lock=FileLock(destination)
            pairs=[(source,destination)]
            parts=source.with_name(source.name+'.parts')
            if parts.exists():
                if parts.is_symlink():raise StorageError('storage-path-invalid')
                target=destination.with_name(destination.name+'.parts');target.mkdir(mode=0o700);self.created.append(target)
                for path in parts.iterdir():
                    if not path.is_file() or path.is_symlink() or not path.name.endswith('.lgo'):raise StorageError('storage-path-invalid')
                    pairs.append((path,target/path.name))
            total=sum(p.stat().st_size for p,_ in pairs)
            if shutil.disk_usage(destination.parent).free<total+128*1024*1024:raise StorageError('storage-space-unavailable')
            for old,new in pairs:
                value=read_bounded(old,_envelope.MAX_FILE)
                atomic_write(new,value,replace=False);self.created.append(new)
                if _digest(old)!=_digest(new):raise StorageError('storage-verification-failed')
            # Exercise the required replace and directory fsync on this exact
            # destination. Network filesystems are rejected above, not assumed.
            probe=destination.with_name('.buddy-relocation-probe-'+os.urandom(8).hex())
            atomic_write(probe,b'synthetic storage transaction probe',replace=False)
            atomic_write(probe,b'synthetic replaced transaction probe')
            probe.unlink()
            self.verified=True
        except Exception:
            self.abort();raise

    def close_locks(self):
        if self.lock is not None:self.lock.close();self.lock=None
        if self.source_lock is not None:self.source_lock.close();self.source_lock=None

    def take_lock(self):
        lock,self.lock=self.lock,None
        return lock

    def abort(self):
        for path in reversed(self.created):
            if path.is_dir():
                try:path.rmdir()
                except OSError:pass
            else:path.unlink(missing_ok=True)
        self.close_locks()

