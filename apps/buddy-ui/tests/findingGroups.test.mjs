import assert from 'node:assert/strict';
import {groupFindings} from '../src/findingGroups.ts';
const row = (id, rule, severity, extra={}) => ({id,rule,severity,source_id:'s',path:'/a',part_id:'text',start_line:7,end_line:7,...extra});
const inputs = [row('a','literal-password','info'),row('b','credential-password','block'),row('c','other','review'),
  row('d','literal-password','review',{start_line:8,end_line:8}),row('e','other','info',{path:'/b'}),
  row('f','other','info',{part_id:undefined}),row('g','other','block',{part_id:undefined})];
const groups=groupFindings(inputs);
assert.equal(groups.length,5);
assert.deepEqual(groups[0].findings.map(x=>x.id),['a','b','c']);
assert.deepEqual(groups[0].rules,['literal-password','credential-password','other']);
assert.equal(groups[0].severity,'block');
assert.equal(groupFindings([row('a','a','review'),row('b','b','mystery')])[0].severity,'mystery');
assert.equal(groupFindings([row('a','a','mystery'),row('b','b','block')])[0].severity,'block');
assert.equal(groups.flatMap(g=>g.findings).length,inputs.length);
