"""Bounded VM directory access reusing the existing SSH transport."""
from __future__ import annotations
import json
from urllib.parse import quote,unquote
from pathlib import Path,PurePosixPath
from .ssh import SSHRunner,_exchange,_target,_remote_path
from .errors import HostError


def uri(target,path):
 if not str(path).startswith('/') or '..' in PurePosixPath(path).parts:raise HostError('remote-path-invalid')
 return 'ssh://'+_target(target)+quote(str(path),safe='/')

def remote_path(source,path):
 prefix='ssh://'+source['ssh_target']
 if not path.startswith(prefix+'/'):raise HostError('remote-path-invalid')
 value=unquote(path[len(prefix):],errors='strict')
 if not PurePosixPath(value).is_relative_to(PurePosixPath(source['remote_root'])):raise HostError('outside-root')
 if '\x00' in value or '..' in PurePosixPath(value).parts:raise HostError('remote-path-invalid')
 return value


class SSHLocations:
 def __init__(self,*,runner=None):self.runner=runner or SSHRunner(port=None)
 def request(self,target,request,*,python='/usr/bin/python3',cancel=None):
  if len(json.dumps(request))>262144:raise HostError('remote-limit-invalid')
  script=Path(__file__).with_name('ssh_location_worker.py').read_text()
  if len(script)>100000:raise HostError('ssh-worker-invalid')
  command=self.runner._command(target,python,script,isolated=True)
  output=_exchange(command,json.dumps(request,ensure_ascii=True,separators=(',',':')).encode(),timeout=10,maximum=48_000_000 if request['op']=='read' else 1_500_000,cancel=cancel)
  try:
   result=json.loads(output)
   if type(result) is not dict or result.get('version')!=1:raise ValueError()
   if result.get('status')!='available':raise HostError({'permission-denied':'permission-denied','source-changed':'source-changed','timeout':'ssh-timeout'}.get(result.get('status'),'source-unavailable'))
   return result
  except HostError:raise
  except Exception:raise HostError('remote-report-invalid') from None
 def probe(self,target,root=None,*,python='/usr/bin/python3',expected=None,cancel=None):return self.request(target,{'op':'probe','root':root,'expected':expected},python=python,cancel=cancel)
 def browse(self,target,path=None,*,root=None,cursor=None):
  probe=self.probe(target,root)
  selected=path or root or probe['home'];base=root or probe['home']
  result=self.request(target,{'op':'enumerate','root':base,'path':selected,'expected':probe['identity'],'cursor':cursor,'limit':100})
  info=result['info'];sig=[info[k] for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_flags')]
  return {'target':_target(target),'path':selected,'root':base,'identity':probe['identity'],'entries':[{'name':e['name'],'path':str(PurePosixPath(selected)/e['name']),'kind':'directory' if e['info'] and __import__('stat').S_ISDIR(e['info']['st_mode']) else 'other'} for e in result['entries']],'next_cursor':None if result['complete'] else {'signature':sig,'entries':result['position'],'prefix':result['prefix']}}
