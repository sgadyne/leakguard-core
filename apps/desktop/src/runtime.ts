import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { failure, inside } from './policy.ts';

export type Runtime = {python:string; stateDir:string; config:string; runtimeId:string};
type Manifest = {
  schemaVersion:number; protocolVersion:number; target:string; runtimeId:string;
  pythonExecutable:string; files:{path:string;sha256:string;mode:number;linkTarget?:string}[];
};
export function cleanEnvironment(stateDir?:string,config?:string):NodeJS.ProcessEnv {
  const env:NodeJS.ProcessEnv={};
  const names=['HOME','USERPROFILE','HOMEDRIVE','HOMEPATH','APPDATA','LOCALAPPDATA','PROGRAMDATA',
    'SYSTEMROOT','SystemRoot','WINDIR','COMSPEC','TEMP','TMP','TMPDIR','PATH','PATHEXT',
    'LANG','LC_ALL','LC_CTYPE','TZ','DISPLAY','WAYLAND_DISPLAY','XDG_RUNTIME_DIR','DBUS_SESSION_BUS_ADDRESS',
    'XDG_CONFIG_HOME','XDG_DATA_HOME','XDG_CACHE_HOME'];
  for(const name of names) if(process.env[name]!==undefined) env[name]=process.env[name];
  if(stateDir) env.LEAKGUARD_STATE_DIR=stateDir;
  if(config) env.LEAKGUARD_CONFIG=config;
  return env;
}
export async function canonicalDataDirectory(input:string):Promise<string> {
  if(!path.isAbsolute(input) || input.includes('\0')) throw failure('profile-path-invalid');
  try {
    if((await fs.lstat(input)).isSymbolicLink()) throw failure('profile-path-invalid');
  }catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT') throw error;}
  await fs.mkdir(input,{recursive:true,mode:0o700});
  const canonical=await fs.realpath(input);
  for(const sub of ['profile','profile/state','runtimes']){
    const candidate=path.join(canonical,sub);
    try{if((await fs.lstat(candidate)).isSymbolicLink())throw failure('profile-path-invalid');}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  }
  return canonical;
}
async function resourcePath(root:string,relative:string):Promise<string> {
  if(typeof relative!=='string' || !relative || relative.includes('\\') || relative.includes('\0') ||
     path.posix.isAbsolute(relative) || relative.split('/').some(part=>!part || part==='.' || part==='..')) throw failure('resource-manifest-invalid');
  const candidate=await fs.realpath(path.join(root,relative));
  if(!inside(root,candidate))throw failure('resource-path-invalid');
  return candidate;
}
export async function verifiedResource(root:string,relative:string,manifest:Pick<Manifest,'files'>):Promise<string> {
  const file=await resourcePath(root,relative);
  const entry=manifest.files.find(entry=>entry.path===relative);
  if(!entry || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw failure('resource-manifest-invalid');
  const original=path.join(root,relative);
  const info=await fs.lstat(original);
  if(info.isSymbolicLink()){
    const target=await fs.readlink(original);
    if(target!==entry.linkTarget || path.isAbsolute(target) ||
       createHash('sha256').update(target).digest('hex')!==entry.sha256)throw failure('resource-integrity-failed');
    const resolvedRelative=path.relative(root,file).split(path.sep).join('/');
    const resolved=manifest.files.find(candidate=>candidate.path===resolvedRelative);
    if(!resolved || resolved.linkTarget || !/^[a-f0-9]{64}$/.test(resolved.sha256) ||
       createHash('sha256').update(await fs.readFile(file)).digest('hex')!==resolved.sha256)throw failure('resource-integrity-failed');
  }else{
    if(!info.isFile() || entry.linkTarget ||
       createHash('sha256').update(await fs.readFile(file)).digest('hex')!==entry.sha256)throw failure('resource-integrity-failed');
  }
  return original;
}
export async function prepareRuntime(resourcesInput:string,dataDir:string,onProgress:(stage:string)=>void):Promise<Runtime> {
  const resources=await fs.realpath(resourcesInput);
  const raw=await fs.readFile(path.join(resources,'desktop-manifest.json'));
  if(raw.length>16*1024*1024)throw failure('resource-manifest-invalid');
  const manifest=JSON.parse(raw.toString('utf8')) as Manifest;
  const expectedTarget=process.platform==='darwin' && process.arch==='arm64'?'macos-arm64':
    process.platform==='win32' && process.arch==='x64'?'windows-x86_64':
    process.platform==='linux' && process.arch==='x64'?'linux-x86_64':'unsupported';
  if(manifest.schemaVersion!==1 || manifest.protocolVersion!==1 || manifest.target!==expectedTarget ||
     !/^[a-f0-9]{64}$/.test(manifest.runtimeId) || !Array.isArray(manifest.files)) throw failure('resource-manifest-invalid');
  const python=await verifiedResource(resources,manifest.pythonExecutable,manifest);
  const bootstrap=await verifiedResource(resources,'bootstrap.py',manifest);
  return new Promise((resolve,reject)=>{
    const child=spawn(python,['-I','-B','-X','utf8',bootstrap,'--resources',resources,'--data-dir',dataDir],
      {cwd:dataDir,env:cleanEnvironment(),stdio:['ignore','pipe','pipe'],windowsHide:true,shell:false});
    let buffer=Buffer.alloc(0);let receipt:Runtime|undefined;let code:string|undefined;let invalid=false;
    // Preparation owns its subprocess until exit. A timeout is reported but
    // never used as authority to abandon a writer or launch another installer.
    const timer=setTimeout(()=>onProgress('preparation-taking-longer'),10*60_000);
    child.stderr.on('data',()=>{});
    child.stdout.on('data',(chunk:Buffer)=>{
      if(buffer.length+chunk.length>32*1024){invalid=true;return;}
      buffer=Buffer.concat([buffer,chunk]);
      let end:number;
      while((end=buffer.indexOf(10))>=0){
        const line=buffer.subarray(0,end);buffer=buffer.subarray(end+1);
        try{
          if(line.length>16*1024)throw failure('preparation-protocol-invalid');
          const message=JSON.parse(line.toString('utf8'));
          if(message.type==='progress' && ['copying-runtime','installing-backend','checking-runtime'].includes(message.stage)) onProgress(message.stage);
          else if(message.type==='error' && typeof message.code==='string' && /^[a-z][a-z0-9-]{0,79}$/.test(message.code))code=message.code;
          else if(message.type==='runtime-ready' && message.protocol===1 && !receipt){
            if(message.runtimeId!==manifest.runtimeId || message.stateDir!==path.join(dataDir,'profile','state') ||
               message.config!==path.join(dataDir,'profile','state','config.json') || typeof message.python!=='string' ||
               !path.isAbsolute(message.python) || !inside(path.join(dataDir,'runtimes',manifest.runtimeId),message.python))throw failure('preparation-receipt-invalid');
            receipt={python:message.python,stateDir:message.stateDir,config:message.config,runtimeId:message.runtimeId};
          }else throw failure('preparation-protocol-invalid');
        }catch{invalid=true;}
      }
    });
    child.on('error',()=>{clearTimeout(timer);reject(failure('preparation-start-failed'));});
    child.on('exit',async exitCode=>{
      clearTimeout(timer);
      try{
        if(exitCode!==0 || invalid || buffer.length || !receipt || code) throw failure(code || 'preparation-failed');
        const runtimeRoot=await fs.realpath(path.join(dataDir,'runtimes',manifest.runtimeId));
        if(!inside(runtimeRoot,await fs.realpath(receipt.python)) ||
           await fs.realpath(receipt.stateDir)!==receipt.stateDir ||
           await fs.realpath(receipt.config)!==receipt.config)throw failure('preparation-receipt-invalid');
        resolve(receipt);
      }catch(error){reject(error);}
    });
  });
}
