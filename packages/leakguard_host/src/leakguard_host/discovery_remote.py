"""VM metadata queue and Mac-side scanning of version-checked SSH snapshots."""
from __future__ import annotations
import base64,hashlib,json,stat,time
from dataclasses import replace
from pathlib import PurePosixPath
from leakguard_core.api import Scanner
from leakguard_core.models import BytesInput,SourceRef,SourceKind,ScanLimits,ScanPolicy,CoverageState,CoverageIssue,ErrorCode
from leakguard_core.scan_store import MemoryScanStore
from .ssh_locations import SSHLocations,uri,remote_path
from .discovery import _Evidence,_priority
from .errors import HostError
from .ssh import SSHRunner


def sig(info):return [info[k] for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_flags')]


class RemoteDiscovery:
 def __init__(self,owner):self.owner=owner;self.store=owner.store;self.config=owner.config;self.client=SSHLocations()
 def _request(self,source,op,**kwargs):
  cancel=kwargs.pop('cancel',None)
  return SSHLocations(runner=SSHRunner(port=source.get('ssh_port'))).request(source['ssh_target'],{'op':op,'root':source['remote_root'],'expected':source.get('remote_identity'),**kwargs},python=source.get('ssh_python','/usr/bin/python3'),cancel=cancel)
 def _excluded(self,path,source,settings):
  return any(path==p or path.startswith(p.rstrip('/')+'/') for p in source['exclusions'])
 def tick(self,source,job,settings,*,cancel):
  if 'inventory_generation' not in job:
   job.update(inventory_generation=int(time.time_ns()//1000),inventory_cursor=0,content_cursor=0,inventory_complete=False,unknown_descendants=0,metadata_enumerated=0,new_findings=0)
   self.store.inventory_put([(source['root'],source['id'],'directory',None,'enumerating',0,job['inventory_generation'],0,None,None)])
  identity=self.owner.identity(settings)
  identity['policy_id']=hashlib.sha256(json.dumps([identity['policy_id'],source.get('remote_identity'),source.get('remote_python_version')],sort_keys=True).encode()).hexdigest()
  if job.get('inventory_identity')!=identity:
   previous=job.get('inventory_identity') or source.get('inspection_identity');job['inventory_identity']=identity;source['inspection_identity']=identity
   if previous is not None and previous!=identity:job['invalidate_cursor']=0
  if job.get('invalidate_cursor',256)<256:
   for index in range(job['invalidate_cursor'],min(256,job['invalidate_cursor']+8)):self.store.invalidate_location(source,index)
   job['invalidate_cursor']+=8;return {'scanned':0,'inventory_complete':False}
  if job.get('refresh_requested') and job.get('inventory_complete') and job.get('refresh_cursor',256)>=256:
   job.update(inventory_generation=int(self.owner.clock()*1_000_000),inventory_complete=False,refresh_requested=False,refresh_cursor=0,reconcile_cursor=0,unknown_descendants=0,reconciliation_started_at=self.owner.clock())
  if job.get('refresh_cursor',256)<256:
   start=job['refresh_cursor']
   for index in range(start,min(256,start+8)):self.store.queue_reconciliation(source,job['inventory_generation'],index)
   job['refresh_cursor']=start+8
  if not job.get('inventory_complete') and not cancel():
   rows,cursor=self.store.inventory_page(source['id'],'directory','enumerating',cursor=job['inventory_cursor'],limit=1,prefer_priority=job['slices']%10!=0);job['inventory_cursor']=cursor
   if not rows:
    if job.get('refresh_cursor',256)>=256:job['inventory_complete']=True
   else:
    row=rows[0];path=row[0]
    if self._excluded(path,source,settings):self.store.inventory_set(path,'excluded',detail='unknown-descendants');job['unknown_descendants']+=1
    else:
     try:
      result=self._request(source,'enumerate',path=remote_path(source,path),cursor=json.loads(row[8]) if row[8] else None,limit=1000,cancel=cancel)
      info=result['info'];physical=f"{source['id']}:{source['remote_identity']['machine']}:{info['st_dev']}:{info['st_ino']}"
      if not self.store.physical_visit(physical,job['inventory_generation'],path):self.store.inventory_set(path,'alias',detail='physical-directory-already-enumerated')
      else:
       entries=[]
       for entry in result['entries']:
        child=uri(source['ssh_target'],str(PurePosixPath(remote_path(source,path))/entry['name']));value=entry['info'];detail=None
        if len(child)>4096:
         child=source['root'].rstrip('/')+'/[path-limit-'+hashlib.sha256(child.encode()).hexdigest()[:20]+']';kind='unknown';state='unsupported';detail='remote-path-length-limit; unknown-descendants'
        elif value is None:kind='unknown';state='inaccessible';detail='metadata-unreadable'
        else:
         mode=value['st_mode'];kind='directory' if stat.S_ISDIR(mode) else 'file' if stat.S_ISREG(mode) else 'symlink' if stat.S_ISLNK(mode) else 'special';state='enumerating' if kind=='directory' else 'pending' if kind=='file' else 'excluded'
         actual=PurePosixPath(remote_path(source,child));lower=str(actual).lower()
         if self._excluded(child,source,settings):state='excluded';detail='operator-exclusion; unknown-descendants' if kind=='directory' else 'operator-exclusion'
         elif kind=='directory' and value['st_dev']!=source['remote_identity']['device']:state='excluded';detail='mount-boundary; unknown-descendants'
         elif kind=='file' and value['st_dev']!=source['remote_identity']['device']:state='unsupported';detail='mount-boundary'
         elif kind=='file' and (value['st_flags']&0x40000000 or actual.name.endswith('.icloud')):state='remote-only';detail='placeholder-not-hydrated'
         elif kind=='file' and (actual.suffix.lower() in {'.lgv','.lgo','.lgbak','.keychain','.keychain-db','.kdbx','.kdb','.gpg','.pgp'} or actual.name in {'Login Data','Cookies','key4.db','cert9.db'} or '/.ssh/' in lower and actual.name.startswith('id_')):state='protected';detail='protected-store-inventory-only'
        entries.append((child,source['id'],kind,json.dumps(sig(value)) if value else None,state,_priority(PurePosixPath(child)),job['inventory_generation'],value['st_size'] if value else 0,None,detail))
       self.store.inventory_put(entries);job['metadata_enumerated']+=len(entries)
       if not result['stable']:self.store.inventory_set(path,'enumerating',detail='changed-during-enumeration')
       elif result['complete']:self.store.inventory_set(path,'enumerated',detail='remote-metadata-only',signature=json.dumps(sig(info)))
       else:self.store.inventory_set(path,'enumerating',cursor=json.dumps({'signature':sig(info),'entries':result['position'],'prefix':result['prefix']}),signature=json.dumps(sig(info)))
     except HostError as error:
      if error.code in {'permission-denied','source-unavailable'}:self.store.inventory_set(path,'inaccessible',detail='unknown-descendants');job['unknown_descendants']+=1
      else:raise
  scanned=0
  if settings['new_content']=='inspect' and not cancel():
   rows,cursor=self.store.inventory_page(source['id'],'file',('pending','changed'),cursor=job['content_cursor'],limit=job.get('content_batch_limit',25),prefer_priority=job['slices']%10!=0);job['content_cursor']=cursor
   admitted=[];total=0
   for row in rows:
    if self._excluded(row[0],source,settings):self.store.inventory_set(row[0],'excluded',detail='operator-exclusion');continue
    if row[7]>self.config.to_mapping()['max_file_bytes']:self.store.inventory_set(row[0],'unsupported',detail='file-size-limit');continue
    if total+row[7]>32*1024*1024:break
    admitted.append(row);total+=row[7]
   if admitted:
    fetched=self._request(source,'read',paths=[remote_path(source,r[0]) for r in admitted],max_file_bytes=self.config.to_mapping()['max_file_bytes'],cancel=cancel)
    snapshots={};inputs=[]
    for item in fetched['entries']:
     logical=uri(source['ssh_target'],item['path'])
     if item['status']!='available':self.store.inventory_set(logical,item['status'] if item['status'] in {'unsupported','remote-only','inaccessible'} else 'changed',detail='remote-acquisition-'+item['status']);continue
     data=base64.b64decode(item['data'],validate=True)
     if len(data)>self.config.to_mapping()['max_file_bytes'] or hashlib.sha256(data).hexdigest()!=item['sha256']:raise HostError('remote-report-invalid')
     snapshots[logical]={'signature':item['signature'],'sha256':item['sha256']};inputs.append(BytesInput(data,logical))
    if inputs:
     owner=self.store
     class Temporary(MemoryScanStore):
      def material_snapshot(self,**kwargs):return owner.material_snapshot(**kwargs)
     transient=Temporary(config=self.config.to_mapping());limits=ScanLimits(8,25,max_file_bytes=self.config.to_mapping()['max_file_bytes'],max_report_bytes=4_000_000,detector_timeout_seconds=5)
     try:
      with self.owner.scanner_factory(config=self.config,store=transient) as scanner:report=scanner.scan(inputs,policy=ScanPolicy.inventory(),limits=limits,use_cache=False,cancel=cancel)
     except Exception:
      transient.close()
      if cancel():return {'scanned':0,'inventory_complete':False}
      self._retry_missing(admitted,set(),job)
      return {'scanned':0,'inventory_complete':False}
     checked=self._request(source,'check',paths=[remote_path(source,path) for path in snapshots],cancel=cancel) if not cancel() else {'entries':[]}
     checks={uri(source['ssh_target'],x['path']):x for x in checked['entries']};job['last_slice_issues']=sorted({x.code.value for x in report.issues});job['last_slice_results']=len(report.results)
     observed=set()
     for original in report.results:
      logical=original.source.path;snapshot=snapshots[logical];current=checks.get(logical);valid=current and current.get('status')=='available' and current.get('signature')==snapshot['signature'];reference=SourceRef(SourceKind.FILESYSTEM,logical)
      observed.add(logical)
      identity=replace(original.identity,context_id=hashlib.sha256(json.dumps([original.identity.context_id,source['remote_identity'],snapshot['signature']],sort_keys=True).encode()).hexdigest(),cache_eligible=False)
      findings=tuple(replace(f,source=reference,id=hashlib.sha256(('ssh-snapshot-v1:'+logical+':'+f.id).encode()).hexdigest()) for f in original.findings)
      result=replace(original,source=reference,identity=identity,findings=findings)
      if not valid:result=replace(result,coverage=CoverageState.INCOMPLETE,last_verified_at=None,issues=(*result.issues,CoverageIssue(ErrorCode.INPUT_CHANGED,reference,required=True)))
      bucket=self.store._partitions.bucket(logical,'e')
      with self.store.partition(bucket) as child:
       view=_Evidence(child,self.store);generation=view.reserve(reference);view.record_result(result,generation=generation);job['new_findings']+=view.new_findings
      state='inspected' if result.coverage is CoverageState.COMPLETE else 'unsupported' if result.coverage is CoverageState.OMITTED else 'inspection-error'
      if state=='inspected' and any(x.omission_id for x in result.issues):state='inspected-with-omissions'
      self.store.inventory_set(logical,state,detail=json.dumps({'digest':snapshot['sha256'],'remote_signature':snapshot['signature'],'runtime':result.identity.runtime_id,'policy':result.identity.policy_id,'observed_at':result.observed_at.isoformat(),'issues':sorted({x.code.value for x in result.issues}),'transport':'ssh','checked_after_scan':bool(valid)}));scanned+=1
     if not cancel():self._retry_missing([r for r in admitted if r[0] in snapshots],observed,job)
     inputs.clear();snapshots.clear();transient.close()
  if job.get('inventory_complete') and job.get('reconcile_cursor',0)<256:
   start=job.get('reconcile_cursor',0)
   for index in range(start,min(256,start+8)):self.store.reconcile_location(source,job['inventory_generation'],index)
   job['reconcile_cursor']=start+8
  job['files_scanned']+=scanned
  return {'scanned':scanned,'inventory_complete':job.get('inventory_complete',False) and job.get('reconcile_cursor',0)>=256}

 def _retry_missing(self,rows,observed,job):
  missing=[row for row in rows if row[0] not in observed]
  if missing:job['content_batch_limit']=max(1,job.get('content_batch_limit',25)//2)
  for row in missing:
   try:previous=json.loads(row[9] or '{}')
   except (ValueError,TypeError):previous={}
   attempts=int(previous.get('attempts',0))+1 if isinstance(previous,dict) else 1
   self.store.inventory_set(row[0],'inspection-error' if attempts>=3 and job['content_batch_limit']==1 else row[4],detail=json.dumps({'attempts':attempts,'issues':['remote-inspection-no-result']}))
