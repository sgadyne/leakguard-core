export class ScanNotices {
  private counts=new Map<string,number>();
  findings(events:{id:string;count:number}[]):boolean {
    let added=false;
    for(const e of events){const previous=this.counts.get(e.id)||0;this.counts.set(e.id,e.count);if(e.count>previous)added=true;}
    if(this.counts.size>512){const keep=new Set(events.map(e=>e.id));for(const id of this.counts.keys())if(!keep.has(id))this.counts.delete(id);}
    return added;
  }
  private states=new Map<string,string>();
  update(events:{id:string;state:string}[]):'attention'|'completed'|undefined {
    let attention=false, completed=false;
    for(const event of events){
      if(this.states.get(event.id)===event.state)continue;
      this.states.set(event.id,event.state);
      if(['failed','paused','backoff'].includes(event.state))attention=true;
      if(event.state==='completed')completed=true;
    }
    // Bound memory while retaining current jobs. The backend sends newest first.
    if(this.states.size>512){const keep=new Set(events.map(e=>e.id));for(const id of this.states.keys())if(!keep.has(id))this.states.delete(id);}
    return attention?'attention':completed?'completed':undefined;
  }
}
