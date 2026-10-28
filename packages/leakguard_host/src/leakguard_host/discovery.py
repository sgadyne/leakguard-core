"""Bounded metadata discovery and content admission for current-user locations.

Enumeration never opens file content. Only explicit, fully local regular files
enter the scanner; encrypted stores, cloud placeholders, links and special files
retain honest inventory states. Recurrence walks every descendant again.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import replace
import hashlib,json,os,stat,time
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager
from leakguard_core.api import Scanner, ScanConfig
from leakguard_core.models import ScanLimits,ScanPolicy
from . import navigation


def _sig(info):
    return json.dumps([info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns,getattr(info,'st_flags',0)],separators=(',',':'))


def _bucket(path,kind='i'):
    return kind+hashlib.sha256(str(path).encode('utf-8','surrogatepass')).hexdigest()[:2]


def _priority(path):
    name=str(path).lower()
    if any(x in name for x in ('.env','.ssh','.aws','.config','credentials','password','token','history','secrets','keychain')):return 0
    if path.name.lower() in {'.codex','.claude','.kube','.docker','.azure','.gcloud'}:return 0
    if any(part.lower() in {'.cache','caches','.tmp','node_modules','site-packages','__pycache__'} for part in path.parts):return 200
    if path.suffix.lower() in {'.json','.yaml','.yml','.toml','.conf','.ini','.txt','.log','.md','.csv','.xml','.plist'}:return 10
    if path.name.lower() in {'users','projects','work','src','code','opt','documents','desktop','downloads','.local'}:return 20
    if '/library/' in name or '/documents/' in name or '/desktop/' in name:return 20
    return 100


class _Evidence:
    def __init__(self,child,owner):self.child,self.owner=child,owner;self.new_findings=0;self.deadline=None
    def set_deadline(self,deadline):self.deadline=deadline
    def __getattr__(self,name):
        method=getattr(self.child,name)
        def invoke(*args,**kwargs):
            with self.owner._mutex:
                self.child.set_deadline(self.deadline)
                return method(*args,**kwargs)
        return invoke
    def material_snapshot(self,**kwargs):return self.owner.material_snapshot(**kwargs)
    def record_result(self,result,**kwargs):
        with self.owner._mutex:return self._record_result(result,**kwargs)
    def _record_result(self,result,**kwargs):
        self.child.set_deadline(self.deadline)
        previous={row[0] for row in self.child.conn.execute('SELECT finding_id FROM finding_state WHERE path=?',(result.source.path,))}
        self.new_findings+=sum(f.id not in previous for f in result.findings)
        scan_id=self.child.record_result(result,**kwargs)
        # The inventory retains compact per-version inspection evidence. Clean
        # machine files need no duplicate multi-kilobyte core result/history.
        # Any file with finding history retains full transition semantics.
        path=result.source.path
        conn=self.child.conn
        historical=conn.execute('SELECT 1 FROM finding_state WHERE path=? LIMIT 1',(path,)).fetchone()
        if not historical and not result.findings:
            with conn:
                keys=conn.execute('SELECT DISTINCT input_key FROM input_scans WHERE path=?',(path,)).fetchall()
                conn.execute('DELETE FROM scan_cache WHERE scan_id IN (SELECT scan_id FROM input_scans WHERE path=?)',(path,))
                conn.execute('DELETE FROM input_scans WHERE path=?',(path,))
                for key, in keys:
                    conn.execute('DELETE FROM current_inputs WHERE input_key=?',(key,))
                    conn.execute('DELETE FROM source_anchors WHERE input_key=?',(key,))
                conn.execute('DELETE FROM locations WHERE path=?',(path,))
        return scan_id
    def record_report(self,report,**kwargs):
        with self.owner._mutex:return self._record_report(report,**kwargs)
    def _record_report(self,report,**kwargs):
        self.child.set_deadline(self.deadline)
        self.child.record_report(report,**kwargs)
        with self.child.conn:
            self.child.conn.execute('DELETE FROM scan_runs WHERE run_id<>?',(report.run_id,))


class DiscoveryCoordinator:
    def __init__(self,store,config,*,scanner_factory=Scanner.open,clock=time.time):
        self.store,self.config,self.scanner_factory=store,config,scanner_factory
        self._iterators={}
        self.clock=clock

    def identity(self,settings):
        fixed=ScanLimits(deadline_seconds=10,max_files=100)
        with self.scanner_factory(config=self.config,store=self.store) as scanner:
            identity=scanner.work_identity(policy=ScanPolicy.inventory(),limits=fixed)
        artifacts=[]
        for path in sorted(Path(__file__).parent.glob('*.py')):
            data=path.read_bytes()
            if len(data)>1_000_000:raise ValueError('host-implementation-limit')
            artifacts.append((path.name,hashlib.sha256(data).hexdigest()))
        identity['policy_id']=hashlib.sha256(json.dumps([identity['policy_id'],artifacts,self.store.implementation_identity() if callable(getattr(self.store,'implementation_identity',None)) else None,settings['exclusions']],sort_keys=True).encode()).hexdigest()
        return identity

    def close(self):
        for iterator in self._iterators.values():iterator.close()
        self._iterators.clear()

    def begin(self,source,job):
        generation=int(time.time_ns()//1000)
        job.update(inventory_generation=generation,inventory_cursor=0,content_cursor=0,inventory_complete=False,unknown_descendants=0,metadata_enumerated=0,new_findings=0)
        root=Path(source['root']);seeds=[root]
        if source.get('automatic'):
            home=Path.home()
            seeds += [p for p in (home,home/'.config',home/'.ssh',home/'Documents',home/'Desktop',home/'Downloads',home/'Library') if p.is_relative_to(root) and p.is_dir()]
        self.store.inventory_put([(str(p),source['id'],'directory',None,'enumerating',0 if p==Path.home() else _priority(p),generation,0,None,None) for p in seeds])

    def _excluded(self,path,source,settings):
        for item in [*source.get('exclusions',[]),*settings['exclusions']]:
            if path==Path(item) or path.is_relative_to(Path(item)):return True
        # APFS data aliases are reached through canonical firmlinks, once.
        if source.get('automatic') and (path==Path('/Volumes') or path.is_relative_to('/System/Volumes') or path==Path('/dev')):return True
        return False

    def _enumerate(self,source,job,settings,cancel,deadline):
        generation=job['inventory_generation'];seen=0
        while seen<5000 and time.monotonic()<deadline and not cancel():
            rows,cursor=self.store.inventory_page(source['id'],'directory','enumerating',cursor=job['inventory_cursor'],limit=1,prefer_priority=job['slices']%10!=0)
            job['inventory_cursor']=cursor
            if not rows:
                job['empty_directory_pages']=job.get('empty_directory_pages',0)+1
                if job['empty_directory_pages']>=32:
                    if job.get('refresh_cursor',256)>=256:job['inventory_complete']=True
                    return
                continue
            job['empty_directory_pages']=0
            row=rows[0];path=Path(row[0]);old_cursor=json.loads(row[8]) if row[8] else None
            if self._excluded(path,source,settings):
                self.store.inventory_set(str(path),'excluded',detail='unknown-descendants');job['unknown_descendants']+=1;continue
            try:
                mounted=None
                if source['kind']=='mounted':
                    from .mounted_worker import call
                    mounted=call({'op':'enumerate','root':source['root'],'path':str(path),'cursor':old_cursor,'expected':source.get('active_root_identity'),'limit':min(1000,5000-seen)},cancel=cancel)
                    info=SimpleNamespace(**mounted['info'])
                else:info=path.lstat()
                if not stat.S_ISDIR(info.st_mode):
                    self.store.inventory_set(str(path),'changed',detail='directory-replaced');continue
                physical=f'{source["id"]}:{info.st_dev}:{info.st_ino}'
                if not self.store.physical_visit(physical,generation,str(path)):
                    self.store.inventory_set(str(path),'alias',detail='physical-directory-already-enumerated');continue
                signature=_sig(info)
                resume=old_cursor['entries'] if old_cursor and old_cursor['signature']==signature else 0
                prefix=hashlib.sha256();position=0;entries=[];exhausted=True
                @contextmanager
                def entries_for_directory():
                    if mounted is None:
                        with navigation._scoped_scandir(path,Path(source['root']),info) as iterator:yield iterator
                    else:
                        class Entry:
                            def __init__(self,item):self.name=item['name'];self.item=item
                            def stat(self,**kwargs):
                                if self.item['info'] is None:raise OSError()
                                return SimpleNamespace(**self.item['info'])
                        yield iter(Entry(item) for item in mounted['entries'])
                if mounted is not None:
                    # Prefix replay has already been bounded and verified in
                    # the isolated worker; count only newly returned entries.
                    resume=0
                    position=mounted['position']-len(mounted['entries'])
                with entries_for_directory() as iterator:
                    for entry in iterator:
                        if mounted is None and (cancel() or time.monotonic()>=deadline or seen>=5000):
                            exhausted=False;break
                        position+=1
                        if mounted is None:prefix.update(os.fsencode(entry.name)+b'\0')
                        if position<=resume:
                            if position==resume and prefix.hexdigest()!=old_cursor['prefix']:
                                resume=0;position=0;prefix=hashlib.sha256();exhausted=False;break
                            continue
                        seen+=1;child=path/entry.name
                        if len(str(child))>4096:
                            marker=str(Path(source['root'])/('[path-limit-'+hashlib.sha256(str(child).encode('utf-8','surrogatepass')).hexdigest()[:20]+']'))
                            entries.append((marker,source['id'],'unknown',None,'unsupported',100,generation,0,None,'path-length-limit; unknown-descendants'));continue
                        try:
                            value=entry.stat(follow_symlinks=False);kind='directory' if stat.S_ISDIR(value.st_mode) else 'file' if stat.S_ISREG(value.st_mode) else 'symlink' if stat.S_ISLNK(value.st_mode) else 'special'
                            state='enumerating' if kind=='directory' else 'pending' if kind=='file' else 'excluded';detail=None
                            if self._excluded(child,source,settings):state='excluded';detail='unknown-descendants' if kind=='directory' else 'operator-exclusion'
                            elif source.get('automatic') and kind=='directory' and value.st_dev not in source.get('local_devices',[info.st_dev]):state='excluded';detail='mount-boundary-unknown-descendants'
                            elif kind=='file' and (getattr(value,'st_flags',0)&0x40000000 or entry.name.endswith('.icloud')):state='remote-only';detail='cloud-placeholder-not-hydrated'
                            elif kind=='file' and (child.suffix.lower() in {'.lgv','.lgo','.lgbak','.keychain','.keychain-db','.kdbx','.gpg','.pgp'} or child.name in {'Login Data','Cookies','Trust Tokens','key4.db','cert9.db'} or any(p.endswith('.lgo.parts') for p in child.parts)):state='protected';detail='encrypted-store-inventory-only'
                            entries.append((str(child),source['id'],kind,_sig(value),state,_priority(child),generation,value.st_size,None,detail))
                        except OSError:
                            entries.append((str(child),source['id'],'unknown',None,'inaccessible',100,generation,0,None,'metadata-unreadable'))
                self.store.inventory_put(entries)
                if mounted is not None:
                    exhausted=mounted['complete'];position=mounted['position']
                stable=mounted['stable'] if mounted is not None else _sig(path.lstat())==signature
                if not stable or position<resume:
                    self.store.inventory_set(str(path),'enumerating',detail='changed-during-enumeration')
                elif exhausted:
                    self.store.inventory_set(str(path),'enumerated',detail='metadata-only',signature=signature)
                else:
                    self.store.inventory_set(str(path),'enumerating',cursor=json.dumps({'signature':signature,'entries':position,'prefix':mounted['prefix'] if mounted is not None else prefix.hexdigest()}),signature=signature)
                job['metadata_enumerated']+=len(entries)
            except PermissionError:
                self.store.inventory_set(str(path),'inaccessible',detail='unknown-descendants-permission-needed');job['unknown_descendants']+=1
            except (OSError,navigation.HostError):
                self.store.inventory_set(str(path),'inaccessible',detail='unknown-descendants-unreadable');job['unknown_descendants']+=1

    def tick(self,source,job,settings,*,cancel):
        if source['kind']=='ssh':
            from .discovery_remote import RemoteDiscovery
            return RemoteDiscovery(self).tick(source,job,settings,cancel=cancel)
        if 'inventory_generation' not in job:self.begin(source,job)
        identity=self.identity(settings)
        if job.get('inventory_identity')!=identity:
            previous=job.get('inventory_identity') or source.get('inspection_identity')
            job['inventory_identity']=identity
            source['inspection_identity']=identity
            if previous is not None and previous!=identity:job['invalidate_cursor']=0
        if job.get('invalidate_cursor',256)<256:
            for index in range(job['invalidate_cursor'],min(256,job['invalidate_cursor']+8)):
                self.store.invalidate_location(source,index)
            job['invalidate_cursor']+=8
            return {'scanned':0,'inventory_complete':False} 
        if job.get('refresh_requested') and job.get('inventory_complete') and job.get('refresh_cursor',256)>=256:
            job.update(inventory_generation=int(self.clock()*1_000_000),inventory_complete=False,refresh_requested=False,refresh_cursor=0,reconcile_cursor=0,empty_directory_pages=0,unknown_descendants=0,reconciliation_started_at=self.clock())
        if job.get('refresh_cursor',256)<256:
            start=job['refresh_cursor']
            for index in range(start,min(256,start+8)):self.store.queue_reconciliation(source,job['inventory_generation'],index)
            job['refresh_cursor']=start+8
        deadline=time.monotonic()+10
        if not job.get('inventory_complete'):self._enumerate(source,job,settings,cancel,min(deadline,time.monotonic()+2))
        scanned=0
        if settings['new_content']=='inspect' and not cancel():
            rows,cursor=self.store.inventory_page(source['id'],'file',('pending','changed'),cursor=job['content_cursor'],limit=job.get('content_batch',100),prefer_priority=job['slices']%10!=0)
            job['content_cursor']=cursor
            groups=defaultdict(list);admitted=0
            for row in rows:
                if self._excluded(Path(row[0]),source,settings):
                    self.store.inventory_set(row[0],'excluded',detail='operator-exclusion');continue
                if row[7]>self.config.to_mapping()['max_file_bytes']:
                    self.store.inventory_set(row[0],'unsupported',detail='file-size-limit');continue
                if admitted+row[7]>32*1024*1024:break
                groups[_bucket(row[0],'e')].append(row);admitted+=row[7]
            for bucket,files in groups.items():
                if cancel() or time.monotonic()>=deadline:break
                with self.store.partition(bucket) as child:
                    view=_Evidence(child,self.store)
                    with self.scanner_factory(config=self.config,store=view) as scanner:
                        limits=ScanLimits(deadline_seconds=8,max_files=100,max_file_bytes=self.config.to_mapping()['max_file_bytes'],max_report_bytes=4_000_000,detector_timeout_seconds=5)
                        identity=scanner.work_identity(policy=ScanPolicy.inventory(),limits=limits)
                        if job.get('detector_runtime')!=identity['runtime_id']:
                            # A changed resource invalidates previous inventory
                            # statuses in bounded partitions on subsequent ticks.
                            job['detector_runtime']=identity['runtime_id']
                        if source['kind']=='mounted':
                            from .mounted_worker import call
                            from leakguard_core.api import parse_report
                            if self.store.material_snapshot().identity!='no-materials':
                                for row in files:self.store.inventory_set(row[0],'unsupported',detail='registered-materials-require-local-scan')
                                continue
                            response=call({'op':'scan','root':source['root'],'paths':[r[0] for r in files],'expected':source.get('active_root_identity'),'config':self.config.to_mapping()},timeout=10,cancel=cancel)
                            report=parse_report(response['report'],max_bytes=4_500_000)
                            for result in report.results:
                                generation=view.reserve(result.source)
                                view.record_result(result,generation=generation)
                            view.record_report(report)
                        else:
                            from leakguard_core.sources import ScopedFileInput,FilesystemBoundary
                            boundary=FilesystemBoundary(source['root'])
                            report=scanner.scan_within(Path(source['root']),[Path(r[0]) for r in files],policy=ScanPolicy.inventory(),limits=limits,use_cache=True,cancel=cancel)
                        job['last_slice_issues']=sorted({i.code.value for i in report.issues})
                        job['last_slice_results']=len(report.results)
                        by_path={r[0]:r for r in files}
                        accepted={r.source.path for r in report.results}
                        if not report.results:
                            job['content_batch']=max(1,job.get('content_batch',100)//2)
                        else:job['content_batch']=min(100,job.get('content_batch',100)+10)
                        for row in files:
                            if row[0] in accepted:continue
                            try:previous=json.loads(row[9]) if row[9] else {}
                            except (ValueError,TypeError):previous={}
                            attempts=previous.get('attempts',0)+1
                            detail=json.dumps({'attempts':attempts,'issues':job['last_slice_issues'],'digest':previous.get('digest')})
                            state='inspection-error' if job.get('content_batch',100)==1 and attempts>=3 else 'pending'
                            self.store.inventory_set(row[0],state,detail=detail)
                            if state=='inspection-error':view.invalidate_scope(row[0],reason='incomplete-scan')
                        for result in report.results:
                            path=result.source.path
                            codes=sorted({i.code.value for i in result.issues})
                            try:previous=json.loads(by_path[path][9]) if by_path[path][9] else {}
                            except (ValueError,TypeError):previous={}
                            attempts=previous.get('attempts',0)
                            omitted=any(i.omission_id for i in result.issues)
                            state=('inspected-with-omissions' if omitted else 'inspected') if result.coverage.value=='complete' else 'unsupported' if result.coverage.value=='omitted' else 'inaccessible' if any(code in {'input-unreadable','source-unavailable','input-nonregular'} for code in codes) else 'pending' if attempts<2 else 'inspection-error'
                            if result.coverage.value=='incomplete':attempts+=1;job['content_batch']=max(1,job.get('content_batch',100)//2)
                            detail=json.dumps({'digest':result.content.digest if result.content else None,'runtime':result.identity.runtime_id,'policy':result.identity.policy_id,'observed_at':result.observed_at.isoformat(),'issues':sorted({i.code.value for i in result.issues}),'omissions':omitted,'attempts':attempts,'previous_failure_codes':previous.get('issues',[]),'retry_same_digest':previous.get('digest')==result.content.digest if previous.get('digest') and result.content else None})
                            self.store.inventory_set(path,state,detail=detail);scanned+=1
                        job['new_findings']+=view.new_findings
        if job.get('inventory_complete') and job.get('reconcile_cursor',0)<256:
            start=job.get('reconcile_cursor',0)
            for index in range(start,min(256,start+8)):self.store.reconcile_location(source,job['inventory_generation'],index)
            job['reconcile_cursor']=start+8
        job['files_scanned']+=scanned
        return {'scanned':scanned,'inventory_complete':job.get('inventory_complete',False) and job.get('reconcile_cursor',0)>=256}
