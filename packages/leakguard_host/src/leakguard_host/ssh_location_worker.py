"""Fixed, isolated stdlib helper sent over existing authenticated SSH.

This file is executed as supplied code, never imported from a remote repository.
It installs nothing, changes no files, and writes only bounded pipe responses.
"""
import base64,hashlib,json,os,pathlib,platform,signal,stat,sys,time


def signature(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns,getattr(info,'st_flags',0)]
def metadata(info):return dict(zip(('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_flags'),signature(info)))
def expired(signum,frame):raise TimeoutError()

def main():
 signal.signal(signal.SIGALRM,expired);signal.alarm(8)
 try:
  import resource
  if sys.platform=='linux':resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
  resource.setrlimit(resource.RLIMIT_CPU,(10,10))
  raw=sys.stdin.buffer.read(262145)
  if len(raw)>262144:raise ValueError()
  req=json.loads(raw);operation=req['op'];root=pathlib.Path(req.get('root') or str(pathlib.Path.home()))
  if not root.is_absolute() or '..' in root.parts or len(str(root))>4096:raise ValueError()
  machine_path=pathlib.Path('/etc/machine-id');machine=hashlib.sha256(machine_path.read_bytes() if machine_path.is_file() else platform.node().encode()).hexdigest()
  root_info=root.lstat()
  if not stat.S_ISDIR(root_info.st_mode):raise ValueError()
  identity={'machine':machine,'device':root_info.st_dev,'inode':root_info.st_ino}
  if req.get('expected') is not None and req['expected']!=identity:raise RuntimeError('source-changed')
  flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|getattr(os,'O_NONBLOCK',0)
  root_fd=os.open(root,flags)
  if signature(os.fstat(root_fd))[:3]!=signature(root_info)[:3]:os.close(root_fd);raise RuntimeError('source-changed')
  def directory(path):
   path=pathlib.Path(path)
   if not path.is_absolute() or '..' in path.parts or len(str(path))>4096:raise ValueError()
   relative=path.relative_to(root)
   if len(relative.parts)>128:raise ValueError()
   fd=os.dup(root_fd)
   try:
    for part in relative.parts:
     child=os.open(part,flags,dir_fd=fd);os.close(fd);fd=child
     if os.fstat(fd).st_dev!=root_info.st_dev:raise OSError('mount-boundary')
    return fd
   except BaseException:os.close(fd);raise
  def file_info(path,read=False,maximum=0):
   path=pathlib.Path(path);parent=directory(path.parent);fd=None
   try:
    preliminary=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
    if not stat.S_ISREG(preliminary.st_mode):raise ValueError()
    if preliminary.st_dev!=root_info.st_dev:return {'path':str(path),'status':'unsupported','reason':'mount-boundary'}
    if getattr(preliminary,'st_flags',0)&0x40000000 or path.name.endswith('.icloud'):return {'path':str(path),'status':'remote-only','signature':signature(preliminary)}
    if read and preliminary.st_size>maximum:return {'path':str(path),'status':'unsupported','signature':signature(preliminary)}
    fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NONBLOCK',0),dir_fd=parent);before=os.fstat(fd)
    if signature(before)!=signature(preliminary):return {'path':str(path),'status':'changed'}
    if not stat.S_ISREG(before.st_mode):raise ValueError()
    if getattr(before,'st_flags',0)&0x40000000 or path.name.endswith('.icloud'):return {'path':str(path),'status':'remote-only','signature':signature(before)}
    if not read:return {'path':str(path),'status':'available','signature':signature(before)}
    if before.st_size>maximum:return {'path':str(path),'status':'unsupported','signature':signature(before)}
    with os.fdopen(fd,'rb') as stream:fd=None;data=stream.read(maximum+1);after=os.fstat(stream.fileno())
    current=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
    if len(data)>maximum or signature(before)!=signature(after) or signature(before)!=signature(current):return {'path':str(path),'status':'changed'}
    return {'path':str(path),'status':'available','signature':signature(before),'sha256':hashlib.sha256(data).hexdigest(),'data':base64.b64encode(data).decode('ascii')}
   except PermissionError:return {'path':str(path),'status':'inaccessible'}
   except (OSError,ValueError):return {'path':str(path),'status':'inaccessible'}
   finally:
    if fd is not None:os.close(fd)
    os.close(parent)
  try:
   if operation=='probe':result={'status':'available','home':str(pathlib.Path.home()),'identity':identity,'info':metadata(root_info),'python':sys.executable,'python_version':platform.python_version(),'connection':os.environ.get('SSH_CONNECTION','').split(),'identity_method':'machine-id' if machine_path.is_file() else 'hostname-and-SSH-host-trust'}
   elif operation=='enumerate':
    path=pathlib.Path(req['path']);fd=directory(path)
    try:
     before=os.fstat(fd);old=req.get('cursor');resume=old['entries'] if old and old['signature']==signature(before) else 0;position=0;prefix=hashlib.sha256();entries=[];complete=True;deadline=time.monotonic()+3
     with os.scandir(fd) as iterator:
      for entry in iterator:
       if len(entries)>=min(1000,req.get('limit',1000)) or time.monotonic()>=deadline:complete=False;break
       position+=1;prefix.update(os.fsencode(entry.name)+b'\0')
       if position<=resume:
        if position==resume and prefix.hexdigest()!=old['prefix']:position=0;prefix=hashlib.sha256();complete=False;break
        continue
       try:value=metadata(entry.stat(follow_symlinks=False))
       except OSError:value=None
       entries.append({'name':entry.name,'info':value})
     # The one-shot browse path cannot retain a replay iterator. Report a
     # bounded timeout instead of returning the same cursor indefinitely.
     if resume and position and position<=resume and not entries and not complete:raise TimeoutError()
     result={'status':'available','identity':identity,'info':metadata(before),'entries':entries,'position':position,'prefix':prefix.hexdigest(),'complete':complete,'stable':signature(before)==signature(os.fstat(fd))}
    finally:os.close(fd)
   elif operation in {'read','check'}:
    paths=req['paths']
    if type(paths) is not list or not 1<=len(paths)<=25:raise ValueError()
    maximum=min(20971520,req.get('max_file_bytes',20971520));remaining=32*1024*1024;entries=[]
    for path in paths:
     if remaining<=0:break
     try:item=file_info(path,read=operation=='read',maximum=min(maximum,remaining))
     except (OSError,ValueError):item={'path':path,'status':'inaccessible'}
     if item.get('data'):remaining-=len(item['data'])*3//4
     entries.append(item)
    result={'status':'available','identity':identity,'entries':entries}
   else:raise ValueError()
  finally:os.close(root_fd)
  result={'version':1,**result};encoded=json.dumps(result,ensure_ascii=True,separators=(',',':'))
  if len(encoded)>48_000_000:raise ValueError()
  sys.stdout.write(encoded);return 0
 except PermissionError:sys.stdout.write('{"version":1,"status":"permission-denied"}');return 0
 except TimeoutError:sys.stdout.write('{"version":1,"status":"timeout"}');return 0
 except RuntimeError:sys.stdout.write('{"version":1,"status":"source-changed"}');return 0
 except Exception:sys.stdout.write('{"version":1,"status":"unavailable"}');return 0

if __name__=='__main__':raise SystemExit(main())
