import {test} from 'node:test';
import assert from 'node:assert/strict';
import {Control} from './control.ts';

test('private control ready/bootstrap/shutdown keeps token out of origin',async()=>{
  const source=`
    process.stdout.write(JSON.stringify({type:'ready',protocol:1,origin:'http://127.0.0.1:18732',pid:process.pid,apiVersion:1})+'\\n');
    require('readline').createInterface({input:process.stdin}).on('line',line=>{
      const value=JSON.parse(line);
      const result=value.op==='bootstrap'?{token:'synthetic_private_bootstrap_token'}:value.op==='shutdown'?{stopped:true}:{locked:true};
      process.stdout.write(JSON.stringify({id:value.id,ok:true,result})+'\\n',()=>{if(value.op==='shutdown')process.exit(0)});
    });
  `;
  const control=new Control(process.execPath,['-e',source],{cwd:process.cwd(),env:{}});
  const ready=await control.ready;
  assert.equal(ready.origin,'http://127.0.0.1:18732');
  assert.ok((await control.request('bootstrap')).token);
  assert.equal((await control.request('shutdown')).stopped,true);
  await control.exited;
  assert.equal(control.hasExited,true);
});

test('ready deadline reports failure and retains the owned process for safe EOF stop',async()=>{
  const source=`require('readline').createInterface({input:process.stdin}).on('close',()=>process.exit(0));`;
  const control=new Control(process.execPath,['-e',source],{cwd:process.cwd(),env:{}},5);
  await assert.rejects(control.ready,/backend-ready-timeout/);
  assert.equal(control.hasExited,false);
  control.closeControl();
  await control.exited;
  assert.equal(control.hasExited,true);
});
