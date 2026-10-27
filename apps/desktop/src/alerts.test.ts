import {test} from 'node:test';
import assert from 'node:assert/strict';
import {AlertTracker,type AlertSnapshot} from './alerts.ts';
const base:AlertSnapshot={finding_revision:9,failed:false,paused:false,offline:false,stale:false,stale_warning:false,capacity_warning:false,pending:false,last_completed_at:null};
test('alerts baseline existing findings, deduplicate status and rebaseline after lock or restore',()=>{
 const tracker=new AlertTracker();
 assert.deepEqual(tracker.update(true,'running',base),[]);
 assert.deepEqual(tracker.update(true,'running',{...base,finding_revision:10,stale_warning:true}),['finding','stale']);
 assert.deepEqual(tracker.update(true,'running',{...base,finding_revision:10,stale:true}),[]);
 assert.deepEqual(tracker.update(true,'running',{...base,finding_revision:1}),[]);
 assert.deepEqual(tracker.update(false,'stopped',null),['locked']);
 assert.deepEqual(tracker.update(true,'running',{...base,finding_revision:20}),[]);
 assert.deepEqual(tracker.update(true,'running',{...base,finding_revision:21,failed:true}),['finding','failed']);
});
