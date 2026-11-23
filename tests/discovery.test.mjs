import test from 'node:test';
import assert from 'node:assert/strict';
import {readChallenge,challengeUrl,visitSource,acquisitionCounts} from '../dist/discovery.js';
test('shared challenge round-trips dataset, language and exercise without private state',()=>{
 const url=challengeUrl('https://siem-query-playground.vercel.app',{dataset:'capture',lang:'forti',exercise:9,query:'PRIVATE',email:'private@example.test'});
 assert.deepEqual(readChallenge(new URL(url).search,['capture']),{dataset:'capture',lang:'forti',exercise:9});
 assert.ok(!url.includes('PRIVATE'));assert.ok(!url.includes('email'));assert.equal(visitSource(new URL(url).search),'community');
});
test('untrusted challenge links cannot select arbitrary datasets or exercises',()=>{
 for(const search of ['?dataset=../secret&lang=shell&exercise=0','?dataset=missing&lang=<script>&exercise=11','?exercise=1.5','?exercise=-1','?exercise=']){
  assert.deepEqual(readChallenge(search,['capture']),{dataset:null,lang:null,exercise:null});
 }
 assert.deepEqual(readChallenge('?dataset=capture&lang=kql&exercise=1',['capture']),{dataset:'capture',lang:'kql',exercise:0});
});
test('acquisition records only allowlisted channel labels',()=>{
 assert.equal(visitSource('?utm_source=LinkedIn&utm_campaign=private@example.test'),'linkedin');
 for(const search of ['','?utm_source=private@example.test','?utm_source=__proto__','?utm_source=https://private.example'])assert.equal(visitSource(search),'direct');
});
test('new and historical visitor paths aggregate once without losing totals',()=>{
 const counts=acquisitionCounts(['visitors/linkedin/a.json','visitors/linkedin/b.json','visitors/community/c.json','visitors/direct/d.json','visitors/oldhash.json']);
 assert.equal(counts.reduce((sum,c)=>sum+c.visitors,0),5);assert.equal(counts.find(c=>c.source==='linkedin').visitors,2);assert.equal(counts.find(c=>c.source==='unattributed').visitors,1);
});
