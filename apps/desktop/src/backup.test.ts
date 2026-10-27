import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {publishBackup} from './backup.ts';

test('backup is published privately and cannot replace an earlier recovery copy',async()=>{
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'buddy-backup-test-'));
  try {
    const target=path.join(directory,'recovery.lgbak');
    await publishBackup(target,Buffer.from('synthetic encrypted backup one'));
    assert.equal((await fs.stat(target)).mode & 0o777,0o600);
    await assert.rejects(publishBackup(target,Buffer.from('synthetic encrypted backup two')),/backup-already-exists/);
    assert.equal(await fs.readFile(target,'utf8'),'synthetic encrypted backup one');
    assert.deepEqual(await fs.readdir(directory),['recovery.lgbak']);
  } finally { await fs.rm(directory,{recursive:true,force:true}); }
});

test('publication failures never report success or replace a prior backup',async()=>{
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'buddy-backup-fault-'));
  try {
    const prior=path.join(directory,'prior.lgbak');
    await fs.writeFile(prior,'prior recovery');
    const linkFailure={...fs,link:async()=>{throw new Error('synthetic link failure');}} as typeof fs;
    await assert.rejects(publishBackup(path.join(directory,'new.lgbak'),Buffer.from('ciphertext'),linkFailure));
    assert.equal(await fs.readFile(prior,'utf8'),'prior recovery');
    assert.deepEqual(await fs.readdir(directory),['prior.lgbak']);
    const dirSyncFailure={...fs,open:async (...args:Parameters<typeof fs.open>)=>{
      const handle=await fs.open(...args);
      if(args[0]===directory)return new Proxy(handle,{get(target,key){
        if(key==='sync')return async()=>{throw new Error('synthetic directory sync failure');};
        const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;
      }});
      return handle;
    }} as typeof fs;
    await assert.rejects(publishBackup(path.join(directory,'published.lgbak'),Buffer.from('ciphertext'),dirSyncFailure));
    assert.equal(await fs.readFile(prior,'utf8'),'prior recovery');
    assert.equal(await fs.readFile(path.join(directory,'published.lgbak'),'utf8'),'ciphertext');
  } finally {await fs.rm(directory,{recursive:true,force:true});}
});
