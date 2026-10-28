from pathlib import Path
import os
from leakguard_host.mounted_worker import call

def test_mount_probe_and_metadata_pagination_are_readonly(tmp_path):
 for i in range(21):(tmp_path/f'file-{i}').write_text('synthetic metadata only')
 result=call({'op':'probe','root':str(tmp_path)})
 assert result['status']=='available'
 cursor=None;seen=[]
 for _ in range(10):
  result=call({'op':'enumerate','root':str(tmp_path),'path':str(tmp_path),'cursor':cursor,'limit':5})
  seen += [e['name'] for e in result['entries']]
  if result['complete']:break
  from leakguard_host.mounted_worker import signature
  cursor={'signature':signature(result['info']),'entries':result['position'],'prefix':result['prefix']}
 assert len(seen)==len(set(seen))==21
