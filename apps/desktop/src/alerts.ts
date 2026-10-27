export type AlertSnapshot = {finding_revision:number|null; failed:boolean; paused:boolean; offline:boolean;
  stale:boolean; stale_warning:boolean; capacity_warning:boolean; pending:boolean; last_completed_at:string|null};
export type AlertKind = 'finding'|'failed'|'paused'|'offline'|'stale'|'locked'|'scheduler'|'capacity'|'backend';
export class AlertTracker {
  private revision:number|null=null;
  private wasUnlocked=false;
  private active=new Set<AlertKind>();
  update(unlocked:boolean, scheduler:string, snapshot:AlertSnapshot|null):AlertKind[] {
    const next=new Set<AlertKind>();
    if(!unlocked){
      if(this.wasUnlocked)next.add('locked');
      this.revision=null;
    }else if(snapshot){
      if(snapshot.finding_revision!==null){
        if(this.revision!==null && snapshot.finding_revision>this.revision)next.add('finding');
        this.revision=snapshot.finding_revision;
      }else this.revision=null;
      if(snapshot.failed)next.add('failed');
      if(snapshot.capacity_warning)next.add('capacity');
      if(snapshot.paused)next.add('paused');
      if(snapshot.offline)next.add('offline');
      if(snapshot.stale || snapshot.stale_warning)next.add('stale');
      if(scheduler==='stopped')next.add('scheduler');
    }
    this.wasUnlocked=unlocked;
    const result=[...next].filter(item=>item==='finding'||!this.active.has(item));
    this.active=next;
    return result;
  }
  reset(){this.revision=null;this.wasUnlocked=false;this.active.clear();}
}
