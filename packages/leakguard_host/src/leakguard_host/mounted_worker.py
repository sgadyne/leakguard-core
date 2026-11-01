"""Owned, bounded subprocess boundary for potentially blocking mounted I/O.

Only redacted reports and metadata cross pipes. No mount commands, credentials,
plaintext inventory files or credential-vault capability enter this worker.
"""
from __future__ import annotations
import json,os,signal,stat,subprocess,sys,time,hashlib
from pathlib import Path


def call(request,*,timeout=3,cancel=None):
    from .errors import HostError
    encoded=json.dumps(request,ensure_ascii=True,separators=(',',':')).encode()
    if len(encoded)>262144:raise HostError('source-unavailable')
    child=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True)
    deadline=time.monotonic()+timeout;first=True
    try:
        while True:
            try:
                output,_=child.communicate(input=encoded if first else None,timeout=min(.2,max(.001,deadline-time.monotonic())))
                if len(output)>4_500_000 or child.returncode:raise HostError('source-unavailable')
                return json.loads(output)
            except subprocess.TimeoutExpired as error:
                first=False
                if len(error.output or b'')>4_500_000 or time.monotonic()>=deadline or cancel is not None and cancel():raise HostError('source-unavailable')
    finally:
        if child.poll() is None:
            try:
                if os.name=='posix':os.killpg(child.pid,signal.SIGKILL)
                else:child.kill()
            except ProcessLookupError:pass
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:raise HostError('worker-still-running') from None


def info(value):
    return {key:getattr(value,key,0) for key in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_flags')}


def signature(value):return json.dumps([value[k] for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_flags')],separators=(',',':'))


def availability(root,paths,*,expected=None):
    """Metadata only; negative observations never certify content is clear."""
    if (os.name!='posix' or os.open not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd
            or not all(hasattr(os,key) for key in ('O_DIRECTORY','O_NOFOLLOW'))):
        return {'capability':'descriptor-metadata-unsupported','entries':[]}
    if type(paths) is not list or not 1<=len(paths)<=25:raise ValueError()
    from leakguard_core.sources import FilesystemBoundary,AcquisitionError
    boundary=FilesystemBoundary(root);entries=[]
    if expected is not None and [boundary.identity.device,boundary.identity.inode]!=expected:raise ValueError()
    for text in paths:
        if type(text) is not str or len(text)>4096:raise ValueError()
        path=Path(text)
        if not path.is_absolute() or path==root or not path.is_relative_to(root):raise ValueError()
        descriptor=None;state='unavailable';metadata=None;parent_metadata=None
        try:
            descriptor=boundary.directory_fd(path.parent)
            if descriptor is None:raise AcquisitionError('source-unavailable')
            parent=os.fstat(descriptor);parent_metadata=info(parent)
            try:
                value=os.stat(path.name,dir_fd=descriptor,follow_symlinks=False)
                metadata=info(value)
                state='present' if stat.S_ISREG(value.st_mode) and not getattr(value,'st_flags',0)&0x40000000 else 'unavailable'
            except FileNotFoundError:state='absent'
            boundary.check(path.parent,directory=True)
            current=path.parent.lstat()
            if (current.st_dev,current.st_ino,current.st_mode)!=(parent.st_dev,parent.st_ino,parent.st_mode):
                state='unavailable';metadata=None;parent_metadata=None
        except (OSError,AcquisitionError):state='unavailable';metadata=None;parent_metadata=None
        finally:
            if descriptor is not None:os.close(descriptor)
        entries.append({'path':text,'status':state,'info':metadata,'parent_info':parent_metadata})
    boundary.check(root,directory=True)
    if expected is not None:
        value=root.lstat()
        if [value.st_dev,value.st_ino]!=expected:raise ValueError()
    return {'capability':'descriptor-metadata','entries':entries}


def main():
    try:
        raw=sys.stdin.buffer.read(262145)
        if len(raw)>262144:raise ValueError()
        req=json.loads(raw);root=Path(req['root']);path=Path(req.get('path',req['root']))
        if not root.is_absolute() or not path.is_relative_to(root) or len(str(path))>4096:raise ValueError()
        operation=req['op']
        if req.get('expected') is not None:
            check=root.lstat()
            if [check.st_dev,check.st_ino]!=req['expected']:raise ValueError()
        if operation=='probe':
            value=root.lstat()
            if not stat.S_ISDIR(value.st_mode):raise ValueError()
            with os.scandir(root):pass
            result={'status':'available','info':info(value)}
        elif operation=='enumerate':
            from leakguard_host.navigation import _scoped_scandir
            value=path.lstat();before=info(value);old=req.get('cursor');resume=old['entries'] if old and old['signature']==signature(before) else 0
            limit=min(1000,req.get('limit',1000));deadline=time.monotonic()+1.5;position=0;prefix=hashlib.sha256();entries=[];complete=True
            with _scoped_scandir(path,root,value) as iterator:
                for entry in iterator:
                    if time.monotonic()>deadline or len(entries)>=limit:complete=False;break
                    position+=1;prefix.update(os.fsencode(entry.name)+b'\0')
                    if position<=resume:
                        if position==resume and prefix.hexdigest()!=old['prefix']:position=0;prefix=hashlib.sha256();complete=False;break
                        continue
                    try:metadata=info(entry.stat(follow_symlinks=False))
                    except OSError:metadata=None
                    entries.append({'name':entry.name,'info':metadata})
            after=info(path.lstat())
            result={'info':before,'entries':entries,'position':position,'prefix':prefix.hexdigest(),'complete':complete,'stable':signature(before)==signature(after)}
        elif operation=='availability':
            result=availability(root,req['paths'],expected=req.get('expected'))
        elif operation=='scan':
            from leakguard_core.api import ScanConfig,Scanner
            from leakguard_core.models import ScanLimits,ScanPolicy
            from leakguard_core.scan_store import MemoryScanStore
            from leakguard_core.sources import FilesystemBoundary,ScopedFileInput
            paths=req['paths']
            if type(paths) is not list or not 1<=len(paths)<=100 or any(not Path(p).is_relative_to(root) for p in paths):raise ValueError()
            values=req['config'];config=ScanConfig.from_mapping(values);boundary=FilesystemBoundary(root)
            limits=ScanLimits(deadline_seconds=8,max_files=100,max_file_bytes=values['max_file_bytes'],max_report_bytes=4_000_000,detector_timeout_seconds=5)
            with Scanner.open(config=config,store=MemoryScanStore(config=values)) as scanner:
                report=scanner.scan_within(root,[Path(p) for p in paths],policy=ScanPolicy.inventory(),limits=limits,use_cache=False)
            result={'report':report.to_json()}
        else:raise ValueError()
        encoded=json.dumps(result,ensure_ascii=True,separators=(',',':'))
        if len(encoded)>4_500_000:raise ValueError()
        sys.stdout.write(encoded);return 0
    except Exception:return 2

if __name__=='__main__':raise SystemExit(main())
