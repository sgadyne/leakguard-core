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
from leakguard_core.api import Scanner, ScanConfig, RuntimeSession
from leakguard_core.models import ScanLimits,ScanPolicy
from . import navigation
from .protected_paths import protected_store


def _sig(info):
    return json.dumps([info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns,getattr(info,'st_flags',0)],separators=(',',':'))


def _bucket(path,kind='i'):
    return kind+hashlib.sha256(str(path).encode('utf-8','surrogatepass')).hexdigest()[:2]


def _advance_partitions(cursor,apply):
    """Do at least the previous eight-partition slice, then use idle budget.

    Empty/small partitions need no extra scheduler/SSH round trip. Large
    partitions retain the previous minimum slice and bounded resident cache.
    """
    deadline=time.monotonic()+1
    for index in range(cursor,256):
        apply(index)
        if index-cursor>=7 and time.monotonic()>=deadline:return index+1
    return 256


def _priority(path):
    name=str(path).lower()
    leaf=path.name.lower();parts={part.lower() for part in path.parts}
    # Filename evidence outranks directory branding. In particular, the name
    # Password Buddy must not promote every bundled Python dependency.
    if leaf=='.env' or leaf.startswith('.env.') or leaf.endswith('.env') or 'history' in leaf or leaf in {'auth.json','credentials.json','credentials','tokens.json','token.json','.netrc','.npmrc','.pypirc'}:return 0
    if leaf in {'.ssh','.aws','.config','.codex','.claude','.kube','.docker','.azure','.gcloud'}:return 0
    if parts & {'.cache','caches','.tmp','node_modules','site-packages','__pycache__'}:return 200
    if any(x in leaf for x in ('credential','password','token','secret','keychain')):return 5
    if parts & {'credentials','secrets','passwords','keychains','.ssh','.aws','.azure','.gcloud','.kube','.config'}:return 5
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


class _DirectoryStream:
    """One bounded, scope-anchored metadata iterator; never file content.

    The durable cursor remains authoritative. An uncommitted anchor forces a
    fresh replay after any interrupted publication; at most eight streams live.
    """
    def __init__(self, context, signature, anchor, generation):
        self.context = context
        self.iterator = iter(context.__enter__())
        self.signature, self.anchor, self.generation = signature, anchor, generation
        self.position = 0
        self.prefix = hashlib.sha256()
        self.closed = False

    def close(self):
        if not self.closed:
            self.closed = True
            self.context.__exit__(None, None, None)


class DiscoveryCoordinator:
    def __init__(self,store,config,*,scanner_factory=Scanner.open,clock=time.time):
        self.store,self.config,self.scanner_factory=store,config,scanner_factory
        self._iterators={}
        self._runtime_session=None
        self._runtime_last_used=0
        self.clock=clock

    @contextmanager
    def scanner(self,store):
        """Bind a fresh publisher to this profile's prepared detector owner."""
        if self.scanner_factory != Scanner.open:
            with self.scanner_factory(config=self.config,store=store) as scanner:
                yield scanner
            return
        now=time.monotonic()
        if self._runtime_session is not None and now-self._runtime_last_used>60:
            self._runtime_session.close();self._runtime_session=None
        if self._runtime_session is None:
            self._runtime_session=RuntimeSession.open(config=self.config)
        self._runtime_last_used=now
        from leakguard_core.scan_store import StateError
        try:
            scanner=Scanner.open(config=self.config,store=store,runtime_session=self._runtime_session)
        except StateError as error:
            if error.code!='runtime-session-config-changed':raise
            self._runtime_session.close()
            self._runtime_session=RuntimeSession.open(config=self.config)
            scanner=Scanner.open(config=self.config,store=store,runtime_session=self._runtime_session)
        with scanner:
            yield scanner

    def identity(self,settings):
        fixed=ScanLimits(deadline_seconds=10,max_files=100)
        from leakguard_core.scan_policy import RuntimeIdentityError
        for attempt in range(2):
            try:
                with self.scanner(self.store) as scanner:
                    identity=scanner.work_identity(policy=ScanPolicy.inventory(),limits=fixed)
                break
            except RuntimeIdentityError:
                if self._runtime_session is None or attempt:raise
                self._runtime_session.close();self._runtime_session=None
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
        if self._runtime_session is not None:
            self._runtime_session.close();self._runtime_session=None
        sessions=getattr(self,'_ssh_directory_sessions',None)
        if sessions is not None:sessions.close()

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

    def _refresh_metadata(self,source,job):
        """Honor scheduled/manual refresh before initial backfill completes."""
        if (job.get('refresh_requested') and job.get('refresh_cursor',256)>=256
                and job.get('backfill_refresh_cursor',256)>=256):
            if job.get('inventory_complete'):
                job.update(inventory_generation=int(self.clock()*1_000_000),inventory_complete=False,
                           refresh_requested=False,refresh_cursor=0,reconcile_cursor=0,
                           empty_directory_pages=0,unknown_descendants=0,reconciliation_started_at=self.clock())
            else:
                # No new generation and no restart of unfinished directories.
                job.update(refresh_requested=False,backfill_refresh_cursor=0,
                           backfill_refresh_started_at=self.clock())
        if job.get('backfill_refresh_cursor',256)<256:
            job['backfill_refresh_cursor']=_advance_partitions(job['backfill_refresh_cursor'],
                lambda index:self.store.queue_backfill_refresh(source,index))
        if job.get('refresh_cursor',256)<256:
            job['refresh_cursor']=_advance_partitions(job['refresh_cursor'],
                lambda index:self.store.queue_reconciliation(source,job['inventory_generation'],index))

    def _discard_stream(self, key):
        stream = self._iterators.pop(key, None)
        if stream is not None:
            stream.close()

    def _directory_stream(self, key, path, root, info, signature, anchor, generation):
        stream = self._iterators.pop(key, None)
        if stream is not None and (stream.signature != signature or
                stream.anchor != anchor or stream.generation != generation):
            stream.close()
            stream = None
        if stream is not None:
            try:
                # Reopen all ancestry with O_NOFOLLOW on every slice. Matching
                # the same directory identity authorizes use of the retained fd.
                with navigation._scoped_scandir(path, root, info):
                    pass
            except BaseException:
                stream.close()
                raise
        else:
            stream = _DirectoryStream(navigation._scoped_scandir(path, root, info),
                                      signature, anchor, generation)
        while len(self._iterators) >= 8:
            self._discard_stream(next(iter(self._iterators)))
        self._iterators[key] = stream
        return stream

    def inventory_page(self,source,job,kind,status,*,limit):
        """Reserve bounded admission for refresh and oldest backlog separately.

        This diagnostic profile changes selection only; source, ancestry,
        runtime and publication checks still authorize every admitted version.
        A filtered empty page never proves inventory completion.
        """
        job['navigation_profile']={'version':'bounded-refresh-v3','cycle':10,
            'oldest_slot':0,'refresh_slot':5,'metadata_seconds':2,
            'slice_seconds':10,'max_metadata_entries':5000,
            'filtered_fallback_queries':1,'new_arrivals':'monotonic-clock',
            'known_availability_page_rows':25,'known_availability_seconds':2}
        key='inventory_cursor' if kind=='directory' else 'content_cursor'
        if job['slices']%10==5:
            refresh_key='refresh_'+key
            rows,cursor=self.store.inventory_page(source['id'],kind,status,
                cursor=job.get(refresh_key,0),limit=limit,prefer_priority=False,
                queue_class='refresh')
            job[refresh_key]=cursor
            if rows:return rows
        rows,cursor=self.store.inventory_page(source['id'],kind,status,
            cursor=job[key],limit=limit,prefer_priority=job['slices']%10 not in {0,5})
        job[key]=cursor
        return rows

    def _known_availability(self,source,job,settings,cancel):
        """Poll one bounded existing-finding page, never read file content.

        This only downgrades unavailable observations to unknown. It cannot
        resolve a finding or certify an unchanged file's content as current.
        The existing worker bounds potentially blocking filesystem metadata.
        """
        if source['kind']!='local':
            job['known_availability_capability']='unsupported-source-kind';return
        page_method=getattr(self.store,'query_findings_page',None)
        if not callable(page_method):
            job['known_availability_capability']='finding-page-unavailable';return
        page=page_method(limit=25,cursor=job.get('known_availability_cursor'))
        job['known_availability_cursor']=page.next_cursor
        paths=set();root=Path(source['root'])
        for row in page.rows:
            text=(row.get('source') or {}).get('path')
            if row.get('state')!='active' or not isinstance(text,str):continue
            path=Path(text)
            if (path==root or '..' in path.parts or not path.is_absolute() or not path.is_relative_to(root)
                    or self._excluded(path,source,settings) or protected_store(path)):continue
            paths.add(text)
        if not paths or cancel():return
        from .mounted_worker import call
        try:
            result=call({'op':'availability','root':str(root),'paths':sorted(paths),
                'expected':source.get('active_root_identity') or source.get('root_identity')},timeout=2,cancel=cancel)
            if type(result) is not dict or set(result)!={'capability','entries'}:raise navigation.HostError('source-unavailable')
            capability=result.get('capability')
            job['known_availability_capability']=capability
            if capability=='descriptor-metadata-unsupported':return
            if capability!='descriptor-metadata':raise navigation.HostError('source-unavailable')
            entries=result.get('entries')
            if (type(entries) is not list or len(entries)!=len(paths)
                    or any(type(item) is not dict or set(item)!={'path','status','info','parent_info'} or type(item.get('path')) is not str or type(item.get('status')) is not str for item in entries)
                    or {item.get('path') for item in entries}!=paths
                    or any(item.get('status') not in {'present','absent','unavailable'} for item in entries)):
                raise navigation.HostError('source-unavailable')
        except navigation.HostError:
            if cancel():return
            job['known_availability_capability']='worker-unavailable'
            entries=[{'path':path,'status':'unavailable','info':None,'parent_info':None} for path in sorted(paths)]
        observed={}
        keys=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_flags')
        def valid_metadata(value,kind):
            return (type(value) is dict and set(value)==set(keys)
                and all(type(value[k]) is int for k in keys) and value['st_size']>=0
                and (stat.S_ISDIR(value['st_mode']) if kind=='directory' else stat.S_ISREG(value['st_mode'])))
        valid=all((item['parent_info'] is None or valid_metadata(item['parent_info'],'directory'))
            and (item['info'] is None or (type(item['info']) is dict and set(item['info'])==set(keys)
                and all(type(item['info'][k]) is int for k in keys) and item['info']['st_size']>=0))
            and (item['status']!='present' or valid_metadata(item['info'],'file') and item['parent_info'] is not None)
            and (item['status']!='absent' or item['info'] is None and item['parent_info'] is not None)
            for item in entries)
        if not valid:
            if cancel():return
            entries=[{'path':path,'status':'unavailable','info':None,'parent_info':None} for path in sorted(paths)]
            job['known_availability_capability']='worker-unavailable'
        for item in entries:
            if item.get('parent_info') is not None:observed[(str(Path(item['path']).parent),'directory')]=item['parent_info']
            if item['status']=='present' and item.get('info') is not None:observed[(item['path'],'file')]=item['info']
        observe=getattr(self.store,'inventory_observed',None)
        if callable(observe) and isinstance(source.get('id'),str) and type(job.get('inventory_generation')) is int:
            from .mounted_worker import signature
            for (path,kind),metadata in observed.items():
                if cancel():return
                changed=observe(path,source['id'],job['inventory_generation'],kind,signature(metadata),metadata['st_size'])
                if changed:job['known_availability_changed']=job.get('known_availability_changed',0)+1
        job['known_availability_checked']=job.get('known_availability_checked',0)+len(entries)
        for item in entries:
            if cancel():break
            if item['status']=='present':continue
            with self.store.partition(_bucket(item['path'],'e')) as child:
                child.set_deadline(None)
                child.record_event(item['path'],'deleted' if item['status']=='absent' else 'changed')
            job['known_availability_unknown']=job.get('known_availability_unknown',0)+1

    def _enumerate(self,source,job,settings,cancel,deadline):
        generation=job['inventory_generation'];seen=0
        while seen<5000 and time.monotonic()<deadline and not cancel():
            rows=self.inventory_page(source,job,'directory','enumerating',limit=1)
            if not rows:
                job['empty_directory_pages']=job.get('empty_directory_pages',0)+1
                if job['empty_directory_pages']>=32:
                    if job.get('refresh_cursor',256)>=256 and job.get('backfill_refresh_cursor',256)>=256:job['inventory_complete']=True
                    return
                continue
            job['empty_directory_pages']=0
            row=rows[0];path=Path(row[0]);old_cursor=json.loads(row[8]) if row[8] else None
            refresh=row[9] in {'metadata-refresh-during-backfill','metadata-version-refresh-during-backfill'}
            stream_key=(source['id'],str(path))
            if self._excluded(path,source,settings):
                self._discard_stream(stream_key)
                self.store.inventory_set(str(path),'excluded',detail='unknown-descendants');job['unknown_descendants']+=1;continue
            try:
                mounted=None;stream=None
                if source['kind']=='mounted':
                    from .mounted_worker import call
                    mounted=call({'op':'enumerate','root':source['root'],'path':str(path),'cursor':old_cursor,'expected':source.get('active_root_identity'),'limit':min(1000,5000-seen)},cancel=cancel)
                    info=SimpleNamespace(**mounted['info'])
                else:info=path.lstat()
                if not stat.S_ISDIR(info.st_mode):
                    self._discard_stream(stream_key)
                    self.store.inventory_set(str(path),'changed',detail='directory-replaced');continue
                physical=f'{source["id"]}:{info.st_dev}:{info.st_ino}'
                if not self.store.physical_visit(physical,generation,str(path)):
                    self._discard_stream(stream_key)
                    self.store.inventory_set(str(path),'alias',detail='physical-directory-already-enumerated');continue
                signature=_sig(info)
                resume=old_cursor['entries'] if old_cursor and old_cursor['signature']==signature else 0
                entries=[];exhausted=False;mismatch=False
                if mounted is None:
                    stream=self._directory_stream(stream_key,path,Path(source['root']),info,
                                                  signature,row[8],generation)
                    iterator=stream.iterator;position=stream.position;prefix=stream.prefix
                    # Any exception before successful inventory publication must
                    # invalidate this in-memory cursor on the next attempt.
                    stream.anchor=object()
                else:
                    class Entry:
                        def __init__(self,item):self.name=item['name'];self.item=item
                        def stat(self,**kwargs):
                            if self.item['info'] is None:raise OSError()
                            return SimpleNamespace(**self.item['info'])
                    iterator=iter(Entry(item) for item in mounted['entries'])
                    resume=0;position=mounted['position']-len(mounted['entries']);prefix=None
                while mounted is not None or not (cancel() or time.monotonic()>=deadline or seen>=5000):
                    try:entry=next(iterator)
                    except StopIteration:
                        exhausted=True;break
                    position+=1
                    if stream is not None:
                        stream.position=position
                        prefix.update(os.fsencode(entry.name)+b'\0')
                    if position<=resume:
                        if position==resume and prefix.hexdigest()!=old_cursor['prefix']:
                            mismatch=True;break
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
                        elif kind=='file' and protected_store(child):state='protected';detail='encrypted-store-inventory-only'
                        elif refresh and kind in {'file','directory'}:detail='content-refresh-during-backfill' if kind=='file' else row[9]
                        entries.append((str(child),source['id'],kind,_sig(value),state,_priority(child),generation,value.st_size,None,detail))
                    except OSError:
                        entries.append((str(child),source['id'],'unknown',None,'inaccessible',100,generation,0,None,'metadata-unreadable'))
                self.store.inventory_put(entries)
                if mounted is not None:
                    exhausted=mounted['complete'];position=mounted['position']
                stable=mounted['stable'] if mounted is not None else _sig(path.lstat())==signature
                if not stable or mismatch:
                    self._discard_stream(stream_key)
                    self.store.inventory_set(str(path),'enumerating',detail=row[9] if refresh else 'changed-during-enumeration')
                    if refresh:job['refresh_metadata_restarts']=job.get('refresh_metadata_restarts',0)+1
                elif position<resume:
                    # Prefix replay may itself take several bounded slices.
                    # Keep the durable prefix until it has been fully verified.
                    self.store.inventory_set(str(path),'enumerating',cursor=row[8],signature=signature,detail=row[9] if refresh else 'metadata-prefix-replay')
                    stream.anchor=row[8]
                elif exhausted:
                    self._discard_stream(stream_key)
                    self.store.inventory_set(str(path),'enumerated',detail='metadata-only',signature=signature)
                else:
                    saved=json.dumps({'signature':signature,'entries':position,'prefix':mounted['prefix'] if mounted is not None else prefix.hexdigest()})
                    self.store.inventory_set(str(path),'enumerating',cursor=saved,signature=signature,detail=row[9] if refresh else None)
                    if stream is not None:stream.anchor=saved
                job['metadata_enumerated']+=len(entries)
            except PermissionError:
                self._discard_stream(stream_key)
                self.store.inventory_set(str(path),'inaccessible',detail='unknown-descendants-permission-needed');job['unknown_descendants']+=1
            except (OSError,navigation.HostError):
                self._discard_stream(stream_key)
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
            if previous is not None and previous!=identity:job.update(invalidate_cursor=0,priority_cursor=0,policy_resets=job.get('policy_resets',0)+1)
        if job.get('invalidate_cursor',256)<256:
            job['invalidate_cursor']=_advance_partitions(job['invalidate_cursor'],lambda index:self.store.invalidate_location(source,index))
            return {'scanned':0,'inventory_complete':False} 
        if job.get('priority_cursor',256)<256:
            job['priority_cursor']=_advance_partitions(job['priority_cursor'],lambda index:self.store.reprioritize_location(source,index,_priority))
            return {'scanned':0,'inventory_complete':False}
        self._refresh_metadata(source,job)
        deadline=time.monotonic()+10
        self._known_availability(source,job,settings,cancel)
        if not job.get('inventory_complete'):self._enumerate(source,job,settings,cancel,min(deadline,time.monotonic()+2))
        scanned=0
        if settings['new_content']=='inspect' and not cancel():
            rows=self.inventory_page(source,job,'file',('pending','changed'),limit=job.get('content_batch',100))
            groups=defaultdict(list);admitted=0
            for row in rows:
                if self._excluded(Path(row[0]),source,settings):
                    self.store.inventory_set(row[0],'excluded',detail='operator-exclusion');continue
                if protected_store(Path(row[0])):
                    self.store.inventory_set(row[0],'protected',detail='encrypted-store-inventory-only');continue
                if row[7]>self.config.to_mapping()['max_file_bytes']:
                    self.store.inventory_set(row[0],'unsupported',detail='file-size-limit');continue
                if admitted+row[7]>32*1024*1024:break
                groups[_bucket(row[0],'e')].append(row);admitted+=row[7]
            for bucket,files in groups.items():
                if cancel() or time.monotonic()>=deadline:break
                with self.store.partition(bucket) as child:
                    view=_Evidence(child,self.store)
                    with self.scanner(view) as scanner:
                        limits=ScanLimits(deadline_seconds=8,max_files=100,max_file_bytes=self.config.to_mapping()['max_file_bytes'],max_report_bytes=4_000_000,detector_timeout_seconds=5)
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
            job['reconcile_cursor']=_advance_partitions(job.get('reconcile_cursor',0),lambda index:self.store.reconcile_location(source,job['inventory_generation'],index))
        job['files_scanned']+=scanned
        return {'scanned':scanned,'inventory_complete':job.get('inventory_complete',False) and job.get('reconcile_cursor',0)>=256}
