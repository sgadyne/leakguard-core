/** Serialize native async clipboard effects and revoke delayed writes on lock. */
export interface ClipboardAPI {
  readText():Promise<string>;
  writeText(text:string):Promise<void>;
  clear():void;
}
export class ClipboardOwner {
  private generation=0;
  private owned:string|undefined;
  private tail:Promise<unknown>=Promise.resolve();
  private timer:ReturnType<typeof setTimeout>|undefined;
  private readonly api:ClipboardAPI;
  constructor(api:ClipboardAPI){this.api=api;}
  private enqueue<T>(operation:()=>Promise<T>):Promise<T>{
    const result=this.tail.then(operation,operation);
    this.tail=result.catch(()=>{});
    return result;
  }
  private async clearOwned(){
    const value=this.owned;this.owned=undefined;
    if(value!==undefined && await this.api.readText()===value)this.api.clear();
  }
  clear():Promise<void>{
    this.generation++;
    if(this.timer)clearTimeout(this.timer);
    this.timer=undefined;
    return this.enqueue(async()=>{try{await this.clearOwned();}catch{}});
  }
  copy(text:string):Promise<{copied:boolean}>{
    const generation=this.generation;
    return this.enqueue(async()=>{
      if(generation!==this.generation)return {copied:false};
      if(this.timer)clearTimeout(this.timer);
      this.timer=undefined;
      try{
        await this.clearOwned();
        if(generation!==this.generation)return {copied:false};
        this.owned=text;
        await this.api.writeText(text);
        if(generation!==this.generation){await this.clearOwned();return {copied:false};}
        if(await this.api.readText()!==text){this.owned=undefined;return {copied:false};}
        if(generation!==this.generation){await this.clearOwned();return {copied:false};}
        this.timer=setTimeout(()=>{void this.clear();},30_000);
        return {copied:true};
      }catch{
        try{await this.clearOwned();}catch{}
        return {copied:false};
      }
    });
  }
}
