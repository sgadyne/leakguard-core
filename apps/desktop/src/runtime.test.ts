import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {canonicalDataDirectory,cleanEnvironment,verifiedResource} from './runtime.ts';

test('manifest-selected interpreter validates link hash and final regular file bytes',async()=>{
  const root=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'buddy-resource-check-')));
  const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
  try{
    await fs.writeFile(path.join(root,'python3.11'),'synthetic interpreter');
    await fs.symlink('python3.11',path.join(root,'python3'));
    const manifest={files:[
      {path:'python3',mode:0o777,sha256:sha('python3.11'),linkTarget:'python3.11'},
      {path:'python3.11',mode:0o755,sha256:sha('synthetic interpreter')},
    ]};
    assert.equal(await verifiedResource(root,'python3',manifest),path.join(root,'python3'));
    await fs.writeFile(path.join(root,'python3.11'),'changed');
    await assert.rejects(verifiedResource(root,'python3',manifest));
    await fs.symlink(os.tmpdir(),path.join(root,'escape'));
    await assert.rejects(verifiedResource(root,'escape',manifest));
  }finally{await fs.rm(root,{recursive:true,force:true});}
});
test('symlinked profile roots are rejected and developer injection is not inherited',async()=>{
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'buddy-profile-check-'));
  try{
    const real=path.join(root,'real');await fs.mkdir(real);
    const link=path.join(root,'link');await fs.symlink(real,link);
    await assert.rejects(canonicalDataDirectory(link));
    process.env.PYTHONPATH='/synthetic/developer/checkout';
    process.env.LEAKGUARD_CONFIG='/synthetic/legacy/config';
    const env=cleanEnvironment('/synthetic/desktop/state','/synthetic/desktop/config');
    assert.equal(env.PYTHONPATH,undefined);
    assert.equal(env.LEAKGUARD_CONFIG,'/synthetic/desktop/config');
  }finally{delete process.env.PYTHONPATH;delete process.env.LEAKGUARD_CONFIG;await fs.rm(root,{recursive:true,force:true});}
});
