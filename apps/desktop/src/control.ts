import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { exactOrigin, failure } from './policy.ts';

type Operation='bootstrap'|'status'|'lock-credentials'|'shutdown';
type Ready={type:'ready'; protocol:1; origin:string; pid:number; apiVersion:1};
type Pending={resolve:(value:any)=>void; reject:(error:Error)=>void; timer:NodeJS.Timeout};
const LIMIT=16*1024;
const safeCode=(value:unknown): string => typeof value==='string' && /^[a-z][a-z0-9-]{0,79}$/.test(value) ? value : 'backend-unavailable';

export class Control {
  readonly child:ChildProcessWithoutNullStreams;
  readonly ready:Promise<Ready>;
  readonly exited:Promise<void>;
  private readyResolve!:(value:Ready)=>void;
  private readyReject!:(error:Error)=>void;
  private exitResolve!:()=>void;
  private buffer=Buffer.alloc(0);
  private sequence=0;
  private pending=new Map<number,Pending>();
  private closed=false;
  private receivedReady=false;
  private readyTimer:NodeJS.Timeout;
  onUnavailable:(code:string)=>void=()=>{};
  constructor(python:string,args:string[],options:{cwd:string;env:NodeJS.ProcessEnv},readyTimeout=60_000) {
    this.ready=new Promise((resolve,reject)=>{this.readyResolve=resolve;this.readyReject=reject;});
    this.exited=new Promise(resolve=>{this.exitResolve=resolve;});
    this.readyTimer=setTimeout(()=>this.unavailable('backend-ready-timeout'),readyTimeout);
    this.child=spawn(python,args,{...options,stdio:['pipe','pipe','pipe'],windowsHide:true,shell:false});
    this.child.stdout.on('data',(chunk:Buffer)=>this.consume(chunk));
    // Drain but never log stderr: third-party failures can contain source data.
    this.child.stderr.on('data',()=>{});
    this.child.on('error',()=>this.unavailable('backend-start-failed'));
    this.child.on('close',()=>{
      this.closed=true; this.unavailable('backend-exited'); this.exitResolve();
    });
    this.child.stdin.on('error',()=>this.unavailable('backend-control-unavailable'));
  }
  private unavailable(code:string) {
    clearTimeout(this.readyTimer);
    this.readyReject(failure(code));
    for(const pending of this.pending.values()){clearTimeout(pending.timer);pending.reject(failure(code));}
    this.pending.clear();
    this.onUnavailable(code);
  }
  private consume(chunk:Buffer) {
    if(this.buffer.length+chunk.length>LIMIT*2){this.unavailable('backend-protocol-invalid');this.child.stdin.end();return;}
    this.buffer=Buffer.concat([this.buffer,chunk]);
    let end:number;
    while((end=this.buffer.indexOf(10))>=0) {
      const line=this.buffer.subarray(0,end); this.buffer=this.buffer.subarray(end+1);
      try {
        if(line.length>LIMIT) throw failure('backend-protocol-invalid');
        const message=JSON.parse(line.toString('utf8'));
        if(!message || typeof message!=='object' || Array.isArray(message)) throw failure('backend-protocol-invalid');
        if(message.type==='error'){this.unavailable(safeCode(message.code));continue;}
        if(message.type==='ready'){
          if(this.receivedReady || message.protocol!==1 || message.apiVersion!==1 || message.pid!==this.child.pid ||
             Object.keys(message).sort().join(',')!=='apiVersion,origin,pid,protocol,type') throw failure('backend-protocol-invalid');
          message.origin=exactOrigin(message.origin); clearTimeout(this.readyTimer); this.receivedReady=true; this.readyResolve(message); continue;
        }
        if(!Number.isSafeInteger(message.id) || typeof message.ok!=='boolean' ||
          Object.keys(message).some(key=>!['id','ok','result','error'].includes(key))) throw failure('backend-protocol-invalid');
        const pending=this.pending.get(message.id);
        if(!pending) continue; // A timed-out request may complete safely later.
        this.pending.delete(message.id);clearTimeout(pending.timer);
        if(message.ok) pending.resolve(message.result); else pending.reject(failure(safeCode(message.error)));
      }catch{this.unavailable('backend-protocol-invalid');this.child.stdin.end();return;}
    }
    if(this.buffer.length>LIMIT){this.unavailable('backend-protocol-invalid');this.child.stdin.end();}
  }
  request(op:Operation,timeout=60_000):Promise<any> {
    if(this.closed || !this.receivedReady || !this.child.stdin.writable) return Promise.reject(failure('backend-unavailable'));
    const id=++this.sequence;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending.delete(id);reject(failure('backend-control-timeout'));},timeout);
      this.pending.set(id,{resolve,reject,timer});
      this.child.stdin.write(JSON.stringify({id,op})+'\n',error=>{
        if(error){clearTimeout(timer);this.pending.delete(id);reject(failure('backend-control-unavailable'));}
      });
    });
  }
  closeControl():void{this.child.stdin.end();}
  get isReady():boolean{return this.receivedReady;}
  get hasExited():boolean {return this.closed;}
}
