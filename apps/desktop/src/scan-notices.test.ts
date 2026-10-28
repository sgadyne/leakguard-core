import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ScanNotices} from './scan-notices.ts';
test('completed scans notify once; failure and restart pause take priority',()=>{
 const n=new ScanNotices();
 assert.equal(n.update([{id:'a',state:'running'}]),undefined);
 assert.equal(n.update([{id:'a',state:'completed'}]),'completed');
 assert.equal(n.update([{id:'a',state:'completed'}]),undefined);
 assert.equal(n.update([{id:'b',state:'backoff'},{id:'c',state:'completed'}]),'attention');
 assert.equal(n.update([{id:'b',state:'backoff'},{id:'c',state:'completed'}]),undefined);
 assert.equal(n.update([{id:'b',state:'running'}]),undefined);
 assert.equal(n.update([{id:'b',state:'completed'}]),'completed');
 assert.equal(new ScanNotices().update([{id:'d',state:'paused'}]),'attention');
});
test('new findings notify only when their durable count advances',()=>{
 const n=new ScanNotices();
 assert.equal(n.findings([{id:'a',count:0}]),false);
 assert.equal(n.findings([{id:'a',count:1}]),true);
 assert.equal(n.findings([{id:'a',count:1}]),false);
 assert.equal(n.findings([{id:'a',count:2}]),true);
 assert.equal(n.findings([{id:'a',count:0}]),false);
});
