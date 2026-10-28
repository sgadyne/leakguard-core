from pathlib import Path
from leakguard_host.discovery import _priority
from leakguard_vault import EncryptedScanStore


def test_credential_filenames_outrank_runtime_branding_and_dependency_caches():
    credential=Path('/Users/example/projects/service/operator.env')
    runtime=Path('/Users/example/Applications/Password Buddy.app/Contents/Resources/python/smtplib.py')
    cached=Path('/Users/example/Library/Application Support/Password Buddy/runtime/site-packages/password_prompt.py')
    assert _priority(credential)==0
    assert _priority(Path('/Users/example/.codex/auth.json'))==0
    assert _priority(runtime)>_priority(credential)
    assert _priority(cached)==200
    assert _priority(Path('/Users/example/.cache/service/.env'))==0


def test_partial_reweight_checkpoint_reopens_without_dropping_pending_files(tmp_path):
    path=tmp_path/'observations.lgo';phrase='synthetic-priority-recovery-passphrase'
    source={'id':'this-mac','root':'/'}
    credential='/Users/example/projects/service/operator.env'
    rows=[(f'/Users/example/Applications/Password Buddy.app/Contents/Resources/python/module{i}.py',source['id'],'file','sig','pending',0,1,20,None,None) for i in range(200)]
    rows.append((credential,source['id'],'file','sig','pending',100,1,20,None,None))
    store=EncryptedScanStore.create(path,phrase);store.inventory_put(rows)
    for index in range(128):store.reprioritize_location(source,index,_priority)
    store.checkpoint();store.close();store=EncryptedScanStore.open(path,phrase)
    for index in range(128,256):store.reprioritize_location(source,index,_priority)
    store.checkpoint();store.close();store=EncryptedScanStore.open(path,phrase)
    assert store.inventory_counts()=={'pending':201}
    admitted,_=store.inventory_page(source['id'],'file','pending',limit=1)
    assert admitted[0][0]==credential
    store.close()
