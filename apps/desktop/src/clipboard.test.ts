import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ClipboardOwner} from './clipboard.ts';

test('lock waits for and clears a native write that finishes late',async()=>{
  let value='';
  let release!:()=>void;
  let started!:()=>void;
  const writeStarted=new Promise<void>(resolve=>{started=resolve;});
  const writeRelease=new Promise<void>(resolve=>{release=resolve;});
  const owner=new ClipboardOwner({
    readText:async()=>value,
    writeText:async text=>{started();await writeRelease;value=text;},
    clear:()=>{value='';},
  });
  const copying=owner.copy('synthetic secret');
  await writeStarted;
  const locking=owner.clear();
  release();
  assert.deepEqual(await copying,{copied:false});
  await locking;
  assert.equal(value,'');
});
test('conditional clear preserves another applications clipboard replacement',async()=>{
  let value='';
  const owner=new ClipboardOwner({readText:async()=>value,writeText:async text=>{value=text;},clear:()=>{value='';}});
  assert.deepEqual(await owner.copy('owned synthetic secret'),{copied:true});
  value='new user clipboard';
  await owner.clear();
  assert.equal(value,'new user clipboard');
});
