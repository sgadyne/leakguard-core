#!/usr/bin/env python3
"""Count local simulated SSH-directory protocol trips and pipe bytes.

No SSH network, real home, or host machine-id is read. A new temporary fixture
contains ten empty files; the worker receives a synthetic machine-id override.
"""
import argparse,hashlib,json,os,pathlib,subprocess,sys,tempfile,time
from unittest.mock import patch

import leakguard_host
from leakguard_host import ssh_directory_session as session_module

class CountOS:
    def __init__(self):self.read_bytes=0;self.write_bytes=0
    def __getattr__(self,name):return getattr(os,name)
    def read(self,fd,n):
        data=os.read(fd,n);self.read_bytes+=len(data);return data
    def write(self,fd,data):
        count=os.write(fd,data);self.write_bytes+=count;return count

class LocalRunner:
    port=None
    def __init__(self,machine):self.machine=machine;self.starts=0
    def _command(self,target,python,script,*,isolated):
        assert isolated
        self.starts+=1
        prelude = f'''import pathlib
_real_is_file = pathlib.Path.is_file
_real_open = pathlib.Path.open
_machine = pathlib.Path({str(self.machine)!r})
def _is_file(path):
    return _real_is_file(_machine) if str(path) == "/etc/machine-id" else _real_is_file(path)
def _open(path, *args, **kwargs):
    return _real_open(_machine, *args, **kwargs) if str(path) == "/etc/machine-id" else _real_open(path, *args, **kwargs)
pathlib.Path.is_file = _is_file
pathlib.Path.open = _open
'''
        return [sys.executable,'-I','-S','-B','-c',prelude+script]

def cursor(page):
    keys=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_flags')
    return {'signature':[page['info'][key] for key in keys],
            'entries':page['position'],'prefix':page['prefix']}

def measure(root,machine,restart):
    runner=LocalRunner(machine);sessions=session_module.DirectorySessions()
    counter=CountOS();seen=[];pages=0;empty=0;cursor_value=None;processes=[];started=time.perf_counter_ns()
    try:
        with patch.object(session_module,'os',counter):
            while pages<20:
                req={'op':'enumerate','root':str(root),'path':str(root),
                     'cursor':cursor_value,'limit':2}
                page=sessions.request(runner,'synthetic',req,python='/usr/bin/python3')
                pages+=1
                for value in sessions._sessions.values():
                    process=value['process']
                    if process not in processes:processes.append(process)
                assert page['stable'] and page['session_capability']=='retained-linux'
                names=[entry['name'] for entry in page['entries']]
                empty+=int(not names)
                assert not set(names)&set(seen)
                seen.extend(names);cursor_value=cursor(page)
                if restart and pages==2:
                    sessions.close()
                    assert all(process.returncode is not None for process in processes)
                if page['complete']:break
            else:raise AssertionError('synthetic page bound exceeded')
    finally:sessions.close()
    assert all(process.returncode is not None for process in processes)
    assert set(seen)=={f'fixture-{i:02}.txt' for i in range(10)}
    assert len(seen)==10 and pages==6 and empty==1
    assert runner.starts==(2 if restart else 1) and counter.write_bytes>0 and counter.read_bytes>0
    return {'restart_after_page_two':restart,'requests':pages,'nonempty_pages':pages-empty,
            'empty_terminal_pages':empty,'worker_start_attempts':runner.starts,
            'client_pipe_request_bytes':counter.write_bytes,'client_pipe_response_bytes':counter.read_bytes,
            'wall_ns':time.perf_counter_ns()-started,'all_owned_workers_reaped':True,
            'names_sha256':hashlib.sha256(json.dumps(sorted(seen),separators=(',',':')).encode()).hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args()
    output={'synthetic_only':True,'transport':'local-process-simulation-no-ssh',
            'tool_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            'host_origin':str(pathlib.Path(leakguard_host.__file__).resolve()),
            'session_module_sha256':hashlib.sha256(pathlib.Path(session_module.__file__).read_bytes()).hexdigest(),
            'python':sys.version.split()[0],'file_count':10,'page_limit':2,'samples':[]}
    for _ in range(3):
        with tempfile.TemporaryDirectory(prefix='leakguard-ssh-sim-') as tmp:
            base=pathlib.Path(tmp);root=base/'fixture';root.mkdir()
            machine=base/'synthetic-machine-id';machine.write_bytes(b'synthetic-machine-id')
            for i in range(10):(root/f'fixture-{i:02}.txt').touch()
            paired=[measure(root,machine,False),measure(root,machine,True)]
            assert paired[0]['names_sha256']==paired[1]['names_sha256']
            output['samples'].append(paired)
    with a.output.open('x',encoding='utf-8') as f:json.dump(output,f,indent=2,sort_keys=True);f.write('\n')

if __name__=='__main__':main()
