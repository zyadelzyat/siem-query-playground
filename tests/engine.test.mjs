import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {LANGS,execute,equivalent} from '../dist/engine.js';
import {createLessons,grade} from '../dist/lessons.js';
import {SCRATCH_INPUT,prepareScratch} from '../dist/scratch.js';
import {COMMANDS,DOCS,referenceMarkdown} from '../dist/reference.js';
const manifest=JSON.parse(readFileSync(new URL('../dist/datasets/manifest.json',import.meta.url)));
for(const meta of manifest.datasets)test(`${meta.id}: all 40 solutions, cross-language equivalence, grading`,()=>{
 const {rows}=JSON.parse(gunzipSync(readFileSync(new URL(`../dist/datasets/${meta.file}`,import.meta.url))));
 assert.equal(rows.length,meta.count);assert.equal(new Set(rows.map(r=>r.id)).size,meta.count);
 assert.equal(rows.reduce((max,r)=>r.time>max?r.time:max,''),meta.clock);
 const lessons=createLessons(meta),clock=Date.parse(meta.clock);
 for(let i=0;i<lessons.length;i++){
  const results=LANGS.map(l=>execute(lessons[i].solution(l),l,rows,clock));
  for(const result of results)assert.ok(result.rows.length>0,`Empty reference result: ${meta.id}, lesson ${i+1}`);
  for(let j=1;j<results.length;j++){
   // Projection and aggregate column names differ. Values should agree.
   const values=r=>r.rows.map(row=>JSON.stringify(Object.values(row))).sort();
   if([0,1,2,8,9].includes(i))assert.deepEqual(results[j].rows.map(r=>r.event_id).sort((a,b)=>a-b),results[0].rows.map(r=>r.event_id).sort((a,b)=>a-b));
   if([4,5,6,7].includes(i))assert.deepEqual(values(results[j]),values(results[0]));
  }
 }
 // Correct and incorrect grading on actual records, including hidden subset checks.
 for(const l of LANGS){assert.ok(grade(lessons[6].solution(l),l,lessons[6],rows,clock));assert.equal(grade(lessons[0].solution(l),l,lessons[4],rows,clock),false);}
});
const clock=Date.parse('2022-01-01T12:00:00Z');
const fixture=[{id:1,time:new Date(clock-600000).toISOString(),code:1,eventType:'Sysmon:1',user:'DOMAIN\\User',ip:'',host:'host1',channel:'Sysmon',process:'cmd.exe',command:'echo test',raw:'{"CommandLine":"PowerShell"}'},{id:2,time:new Date(clock-600001).toISOString(),code:2,eventType:'Sysmon:2',user:'',ip:'',host:'host2',channel:'Sysmon',process:'',command:'',raw:'OTHER'}];
test('relative times include the exact boundary in each language',()=>{
 const queries={spl:"index=lab | where _time >= '2022-01-01T11:50:00.000Z'",kql:'LabEvents | where TimeGenerated >= ago(10m)',aql:'SELECT * FROM events LAST 10 MINUTES',forti:'SELECT * FROM fsiem.events WHERE phRecvTime >= now()-600'};
 for(const l of LANGS)assert.deepEqual(execute(queries[l],l,fixture,clock).rows.map(r=>r.event_id),[1]);
});
test('boolean precedence, escaped backslashes, NOT, IN, and literal pipes',()=>{
 const query='LabEvents | where (EventID == 1 or EventID == 2) and NOT (Account == "")';assert.equal(execute(query,'kql',fixture,clock).rows.length,1);
 assert.equal(execute('LabEvents | where Account == "DOMAIN\\\\User"','kql',fixture,clock).rows.length,1);
 assert.equal(execute('LabEvents | where EventID in (1, 2)','kql',fixture,clock).rows.length,2);
 assert.equal(execute('index=lab | where user="literal|pipe"','spl',fixture,clock).rows.length,0);
});
test('source searches are case-insensitive and preserve originals',()=>{
 assert.equal(execute('index=lab | search _raw="*powershell*"','spl',fixture,clock).rows[0]._raw,fixture[0].raw);
 assert.equal(execute("SELECT * FROM events WHERE payload ILIKE '%powershell%'",'aql',fixture,clock).rows.length,1);
});
test('missing values remain empty, not synthetic identities',()=>{
 for(const l of LANGS){const result=execute(createLessons({count:2,targetType:'Sysmon:1',targetUser:'',huntTerm:'powershell',clock:new Date(clock).toISOString(),threshold:0})[0].solution(l),l,fixture,clock);assert.equal(result.rows.length,2);assert.ok(!Object.values(result.rows[1]).includes('unknown'));}
});
test('unsupported grammar, unknown fields and executable text are rejected',()=>{
 for(const [q,l] of [['LabEvents | join LabEvents','kql'],['index=lab | where missing=1','spl'],['SELECT * FROM wrong','aql'],['SELECT * FROM events; DROP TABLE events','aql'],['LabEvents | where EventID == 1; alert(1)','kql'],['SELECT * FROM events ORDER BY sourceip WHERE eventid=1','aql'],['index=lab | where (EventCode=1','spl'],['index=lab | stats sum(EventCode)','spl'],['LabEvents | fields Account','kql']])assert.throws(()=>execute(q,l,fixture,clock));
});
test('zero-count aggregations, aliases, distinct and duplicate-aware grading',()=>{
 assert.deepEqual(execute('LabEvents | where EventID == 9999 | summarize total=count()','kql',fixture,clock).rows,[{total:0}]);
 assert.equal(execute('LabEvents | distinct Computer','kql',fixture,clock).rows.length,2);
 assert.deepEqual(execute('SELECT sourceip AS ip FROM events LIMIT 1','aql',fixture,clock).columns,['ip']);
 const a={columns:['x'],rows:[{x:1},{x:2},{x:1}]},b={columns:['x'],rows:[{x:1},{x:1},{x:2}]};assert.ok(equivalent(a,b));assert.equal(equivalent(a,b,true),false);assert.equal(equivalent(a,{columns:['x'],rows:[{x:1},{x:2}]}),false);
});
test('English source UI and valid dataset inventory',()=>{
 assert.equal(manifest.datasets.length,15);assert.equal(manifest.datasets.reduce((s,d)=>s+d.count,0),121606);
 for(const file of ['index.html','app.js','engine.js','lessons.js','worker.js','scratch.js','reference.js'])assert.doesNotMatch(readFileSync(new URL(`../dist/${file}`,import.meta.url),'utf8'),/\p{Script=Arabic}/u);
});
test('scratch data is separate, timezone-aware, validated and preserves entered objects',()=>{
 const {rows,meta}=prepareScratch(SCRATCH_INPUT);assert.equal(rows.length,5);assert.equal(meta.id,'scratch');assert.equal(meta.clock,'2026-01-01T12:00:00.000Z');assert.deepEqual(rows.map(r=>JSON.parse(r.raw)),SCRATCH_INPUT);
 const changed=prepareScratch([{time:'2026-01-01T12:00:00+02:00',code:'demo',user:'x',eventType:'__proto__'}]);assert.equal(changed.rows[0].time,'2026-01-01T10:00:00.000Z');assert.equal(changed.meta.eventTypes['__proto__'],1);
 for(const bad of ['{}','[]','null','bad JSON',JSON.stringify([{time:'2026-01-01T12:00:00'}]),JSON.stringify([{time:'2026-01-01T12:00:00Z',user:{}}]),JSON.stringify([{time:'2026-01-01T12:00:00Z',code:[]}]),JSON.stringify(Array.from({length:1001},()=>SCRATCH_INPUT[0]))])assert.throws(()=>prepareScratch(bad));
});
for(const operation of COMMANDS.filter(r=>r.supported))test(`cheat sheet: ${operation.title} runs in all four languages`,()=>{
 const {rows,meta}=prepareScratch(SCRATCH_INPUT),results=LANGS.map(l=>execute(operation.make(l,meta),l,rows,Date.parse(meta.clock)));
 assert.equal(new Set(results.map(r=>r.rows.length)).size,1,'Cross-language result counts differ');
 if(results[0].columns.includes('event_id'))for(const result of results.slice(1))assert.deepEqual(result.rows.map(r=>r.event_id).sort((a,b)=>a-b),results[0].rows.map(r=>r.event_id).sort((a,b)=>a-b));
});
test('cheat sheet marks native-only rows and exports all operations and official sources',()=>{
 const meta=prepareScratch(SCRATCH_INPUT).meta,markdown=referenceMarkdown(meta);assert.equal(COMMANDS.length,26);assert.equal(COMMANDS.filter(r=>r.supported).length,19);
 assert.equal(new Set(COMMANDS.map(r=>r.id)).size,COMMANDS.length);for(const d of Object.values(DOCS))assert.ok(markdown.includes(d.url));
 for(const r of COMMANDS){assert.ok(markdown.includes(r.title));if(!r.supported)for(const l of LANGS)assert.ok(r.snippets[l]);}
 assert.ok(markdown.includes('\\| stats count'));assert.ok(!markdown.includes('\\\\| stats count'));
});
