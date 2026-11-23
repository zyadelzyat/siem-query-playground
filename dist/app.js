import {community} from './community.js';
import {readChallenge,challengeUrl} from './discovery.js';
import {LANGS,META,FIELD_KEYS} from './engine.js';
import {createLessons,starter} from './lessons.js';
import {DOCS,COMMANDS,referenceMarkdown} from './reference.js';
import {SCRATCH_INPUT,prepareScratch} from './scratch.js';
const $=id=>document.getElementById(id);
const storage={get(){try{return JSON.parse(localStorage.getItem('siem-lab-v2'))||{}}catch{return {}}},set(v){try{localStorage.setItem('siem-lab-v2',JSON.stringify(v))}catch{}}};
let saved=storage.get(),lang=LANGS.includes(saved.lang)?saved.lang:'spl',exercise=Number.isInteger(saved.exercise)&&saved.exercise>=0&&saved.exercise<10?saved.exercise:0;
let drafts=saved.drafts&&typeof saved.drafts==='object'?saved.drafts:{},passed=saved.passed&&typeof saved.passed==='object'?saved.passed:{};
const guestPassed=passed;
let mode=saved.mode==='playground'?'playground':'practice',practiceDataset=saved.practiceDataset||saved.dataset||'aptsimulator_cobaltstrike',freeDataset=saved.freeDataset||'scratch';
let scratchText=typeof saved.scratchText==='string'?saved.scratchText:JSON.stringify(SCRATCH_INPUT,null,2);
try{prepareScratch(scratchText)}catch{scratchText=JSON.stringify(SCRATCH_INPUT,null,2);}
let manifest,meta,lessons=[],result=null,panel='results',rawOffset=0,busy=true,ready=false;
const worker=new Worker('./worker.js',{type:'module'}),pending=new Map();let requestId=0;
worker.onmessage=({data:m})=>{const job=pending.get(m.id);if(!job)return;pending.delete(m.id);m.error?job.reject(Error(m.error)):job.resolve(m.value);};
worker.onerror=()=>{for(const job of pending.values())job.reject(Error('The query worker failed. Reload the page to retry.'));pending.clear();feedback('The browser worker could not start. Reload the page or try a current browser.','error');};
function rpc(action,args={}){return new Promise((resolve,reject)=>{const id=++requestId;pending.set(id,{resolve,reject});worker.postMessage({id,action,...args});});}
const key=()=>`${meta.id}:${mode==='playground'?'free':exercise}:${lang}`;
function persist(){storage.set({lang,exercise,dataset:meta?.id||saved.dataset,mode,practiceDataset,freeDataset,scratchText,drafts,passed:guestPassed});}
function saveDraft(){if(ready){drafts[key()]=$('query').value;persist();}}
function lines(){$('lineNumbers').textContent=Array.from({length:$('query').value.split('\n').length},(_,i)=>i+1).join('\n');}
function feedback(message,type='info'){$('feedback').textContent=message;$('feedback').className=type;$('feedback').hidden=false;}
function setBusy(value){busy=value;for(const id of ['datasetSelect','runButton','checkButton','resetQuery','query','inspectRecord','loadSolution','practiceMode','freeMode','useExample','applyScratch','resetScratch'])$(id).disabled=busy||!ready;document.querySelectorAll('#languages button,#exerciseList button').forEach(b=>b.disabled=busy||!ready);$('nextButton').disabled=busy||!ready||exercise===9;$('exportButton').disabled=busy||!result;}
function renderNav(){
 const count=lessons.reduce((n,_,i)=>n+LANGS.filter(l=>passed[`${meta.id}:${i}:${l}`]).length,0);
 $('progressLabel').textContent=`${count} / 40`;$('progressBar').style.width=`${count/40*100}%`;
 $('exerciseList').replaceChildren(...lessons.map((ex,i)=>{
  const done=LANGS.filter(l=>passed[`${meta.id}:${i}:${l}`]).length,b=document.createElement('button');b.className=`exercise-item${i===exercise?' active':''}${done===4?' complete':''}`;b.setAttribute('aria-current',i===exercise?'step':'false');
  for(const [cl,text] of [['exercise-index',String(i+1).padStart(2,'0')],['exercise-label',ex.title],['exercise-check',done===4?'✓':`${done}/4`]]){const span=document.createElement('span');span.className=cl;span.textContent=text;b.append(span);}
  b.disabled=busy;b.onclick=()=>{if(busy)return;saveDraft();exercise=i;renderLesson();};return b;
 }));
}
function renderLanguages(){
 $('languages').replaceChildren(...LANGS.map(l=>{const b=document.createElement('button');b.textContent=META[l].name;b.className=l===lang?'active':'';b.setAttribute('role','tab');b.setAttribute('aria-selected',String(l===lang));b.disabled=busy;
  if(mode==='practice'&&passed[`${meta.id}:${exercise}:${l}`]){const s=document.createElement('span');s.textContent='✓';b.append(s);}b.onclick=()=>{if(busy)return;saveDraft();lang=l;renderLesson();};return b;}));
}
function drawTable(target,rows,columns,original=false){
 target.replaceChildren();if(!rows.length){const empty=document.createElement('div');empty.className='empty-state';empty.textContent='No records match these conditions.';target.append(empty);return;}
 const table=document.createElement('table'),head=document.createElement('thead'),tr=document.createElement('tr');
 for(const c of [...columns,...(original?['Original record']:[])]){const th=document.createElement('th');th.textContent=c;th.scope='col';tr.append(th);}head.append(tr);table.append(head);const body=document.createElement('tbody');
 for(const row of rows){const tr=document.createElement('tr');for(const c of columns){const td=document.createElement('td'),value=String(row[c]??'');td.textContent=value.length>150?value.slice(0,150)+'…':value;td.title=value.length>150?'Open the source record for its full original content.':value;tr.append(td);}if(original){const td=document.createElement('td'),button=document.createElement('button');button.className='quiet';button.textContent='Inspect';button.onclick=()=>openRaw(row.id);td.append(button);tr.append(td);}body.append(tr);}table.append(body);target.append(table);
}
function renderSchema(){
 const el=$('schemaPanel');el.replaceChildren();
 const h=t=>{const n=document.createElement('h3');n.textContent=t;el.append(n);},p=t=>{const n=document.createElement('p');n.textContent=t;el.append(n);};
 h('One capture. Four training views.');p('These are explicit educational field mappings, not imported SIEM indexes. LabEvents is a custom training table, not the Sentinel SecurityEvent table. AQL custom columns are pre-extracted for this lab; no QRadar QIDs are fabricated.');
 const names={time:'Timestamp',code:'Source event code',eventType:'Channel + event code',user:'Account',ip:'Source IP',host:'Host',channel:'Channel / provider',process:'Process path',command:'Command line',raw:'Original record'};
 const mapping=Object.entries(FIELD_KEYS).map(([k,columns])=>Object.fromEntries([['Meaning',names[k]],...LANGS.map(l=>[META[l].name,columns[l]])]));
 const wrap=document.createElement('div');wrap.className='table-wrap';drawTable(wrap,mapping,['Meaning',...LANGS.map(l=>META[l].name)]);el.append(wrap);
 h(`${META[lang].name} · supported syntax`);
 p(lang==='spl'?'index=lab · where/search · table/fields · stats count [as name] [by fields] · sort · head. Use explicit AND. _time is an ISO UTC string in this interpreter; earliest/latest are not implemented.':lang==='kql'?'LabEvents · where · project · summarize count() [by fields] · sort/order by · take/limit · distinct · ago(Nm/Nh/Nd) · datetime(constant). No join, let, bin, or extend yet.':lang==='aql'?'SELECT FROM events · WHERE · COUNT(*) · GROUP BY · HAVING · ORDER BY · LIMIT · LAST N MINUTES/HOURS/DAYS. eventname, eventid, channel, hostname, processname, and commandline are training custom columns. QIDNAME and UTF8 are not implemented.':'SELECT FROM fsiem.events · WHERE · COUNT(*) · GROUP BY · HAVING · ORDER BY · LIMIT · now()-seconds. Training eventType is channel:event-code; eventCode, eventSource, and command are normalized attributes, not a claim about your FortiSIEM deployment. user may also be read with metrics_string.value[indexOf(metrics_string.name, \'user\')].');
 const docs=document.createElement('a');docs.href=DOCS[lang].url;docs.textContent=DOCS[lang].title;docs.target='_blank';docs.rel='noopener';el.append(docs);
 if(DOCS[lang].extra){const link=document.createElement('a');link.href=DOCS[lang].extra;link.textContent=DOCS[lang].extraTitle;link.target='_blank';link.rel='noopener';el.append(document.createTextNode(' · '),link);}
 const pre=document.createElement('pre');pre.textContent=mode==='playground'?COMMANDS.find(r=>r.id==='group').make(lang,meta):lessons[exercise].solution(lang);el.append(pre);
 p('Conditions: =, ==, !=, <>, >, <, >=, <=, AND, OR, NOT, parentheses, IN. String equality is case-sensitive. contains / startswith / has are case-insensitive training operators. LIKE is case-sensitive; ILIKE is case-insensitive; only % is a wildcard. Backslashes in string literals must be doubled.');
 h('Source fidelity');p(meta.id==='scratch'?`Scratch table: ${meta.count} explicitly synthetic or user-entered rows. This table is separate from your imported evidence. The original object you entered is available in the raw field.`:`File: ${meta.sourceFile}. Format: ${meta.format}. Records: ${meta.count.toLocaleString()}. All original records are preserved. Each Linux audit line is one query row, not a reconstructed multi-line event. CSV records are exposed as JSON objects retaining all original column values.`);
 p('Windows account precedence: User, TargetUserName, SubjectUserName. Source IP precedence: IpAddress, SourceIp, SourceAddress. Process precedence: Image, NewProcessName, ProcessName, Application. Missing fields remain empty strings. No host is inferred for AWS or Linux records without a host field.');
 p(`Missing source values: ${Object.entries(meta.missing).map(([k,n])=>`${k}: ${n.toLocaleString()}`).join(' · ')}.`);
 h('Capture clock');p(`${meta.clock}. Relative time is anchored to the latest record in this dataset, never to your device clock. starttime is Unix milliseconds; phRecvTime is Unix seconds.`);
 h('Included event types');p(Object.entries(meta.eventTypes).map(([k,n])=>`${k} (${n.toLocaleString()})`).join(' · '));
 h('Scope');p('This browser interpreter supports a documented subset. Queries may need field and syntax changes in actual products. Matching source text does not establish malicious activity. No query text is sent to a server.');
}
function renderLesson(){
 persist();renderNav();renderLanguages();const ex=lessons[exercise];
 const free=mode==='playground';$('practiceSide').hidden=free;$('freeSide').hidden=!free;$('guidedChallenge').hidden=free;$('freePanel').hidden=!free;$('checkButton').hidden=free;$('shareChallenge').hidden=free;$('clearProgress').hidden=free;
 for(const [id,isActive] of [['practiceMode',!free],['freeMode',free]]){$(id).classList.toggle('active',isActive);$(id).setAttribute('aria-selected',String(isActive));}
 $('scratchOption').hidden=!free;$('scratchDetails').hidden=meta.id!=='scratch';$('scratchInput').value=scratchText;
 $('languageDocs').href=DOCS[lang].url;$('languageDocs').textContent=`${META[lang].name} docs`;$('languageDocs').title=DOCS[lang].title;
 $('exerciseBadge').textContent=`Exercise ${String(exercise+1).padStart(2,'0')}`;$('exerciseLevel').textContent=ex.level;$('challengeTitle').textContent=ex.title;$('challengeDescription').textContent=ex.desc;
 $('languageStatus').textContent=passed[key()]?'✓ Completed in this language':'';
 $('fileName').textContent=`investigation.${lang==='forti'?'sql':lang}`;
 $('query').value=typeof drafts[key()]==='string'?drafts[key()]:starter(lang);lines();$('hint').hidden=true;$('solution').hidden=true;$('feedback').hidden=true;$('hint').textContent=ex.hint;
 result=null;$('rowCount').textContent='—';$('resultMeta').textContent='Run a query to explore the evidence.';
 $('resultTable').innerHTML='<div class="empty-state"><span>⌕</span><h3>The evidence is ready.</h3><p>Run the starter query, then make it your own.</p></div>';
 renderSchema();setPanel(panel);setBusy(false);
}
function setPanel(name){panel=name;for(const n of ['results','data','schema'])$(n==='results'?'resultsPanel':`${n}Panel`).hidden=n!==name;document.querySelectorAll('[data-panel]').forEach(b=>{const active=b.dataset.panel===name;b.classList.toggle('active',active);b.setAttribute('aria-selected',String(active));});$('exportButton').hidden=name!=='results';}
function rawControls(){$('rawPage').textContent=`${rawOffset+1}–${Math.min(rawOffset+150,meta.count)} of ${meta.count.toLocaleString()}`;$('prevRaw').disabled=rawOffset===0;$('nextRaw').disabled=rawOffset+150>=meta.count;}
async function loadDataset(id,keepDraft=true){
 if(ready&&keepDraft)saveDraft();ready=false;setBusy(true);meta=id==='scratch'&&mode==='playground'?prepareScratch(scratchText).meta:manifest.datasets.find(d=>d.id===id)||manifest.datasets[0];$('datasetSelect').value=meta.id;
 feedback(`Loading ${meta.title}…`);$('datasetMeta').textContent=meta.id==='scratch'?'Preparing your scratch table…':'Loading source records…';
 try{const value=meta.id==='scratch'?await rpc('scratch',{input:scratchText}):await rpc('load',{meta});if(value.meta)meta=value.meta;ready=true;lessons=createLessons(meta);rawOffset=0;
  if(mode==='playground')freeDataset=meta.id;else practiceDataset=meta.id;
  $('captureClock').textContent=meta.clock.replace('T',' ').replace('.000Z',' UTC').replace('Z',' UTC');
  $('datasetMeta').textContent=`${meta.format} · ${value.count.toLocaleString()} records · ${Object.keys(meta.eventTypes).length} event types${meta.id==='scratch'?' · Local sample, separate from imported logs':` · ${(meta.compressedBytes/1024/1024).toFixed(2)} MB download`}`;
  $('datasetSummary').textContent=`${meta.sourceFile} · ${meta.start} to ${meta.clock}`;
  $('scenarioDescription').textContent=`${meta.title}. Investigate the source evidence, then repeat the same questions in all four languages.`;
  $('sourceCount').textContent=meta.count.toLocaleString();$('recordId').max=meta.count;$('recordId').value=1;
  drawTable($('rawTable'),value.preview,['id','time','eventType','user','ip','host','process','command'],true);rawControls();renderLesson();
 }catch(e){feedback(e.message,'error');$('datasetMeta').textContent='Dataset could not be loaded. Select a dataset to retry.';busy=false;$('datasetSelect').disabled=false;}
}
async function run(check=false){if(busy||!ready||check&&mode!=='practice')return;saveDraft();result=null;setBusy(true);const start=performance.now();
 try{result=await rpc('run',{query:$('query').value,lang});$('rowCount').textContent=result.count.toLocaleString();$('resultMeta').textContent=`${result.count.toLocaleString()} rows · ${(performance.now()-start).toFixed(1)} ms · ${META[lang].name}${result.count>150?' · Preview: first 150 rows. Export includes every result.':''}`;drawTable($('resultTable'),result.rows,result.columns);setPanel('results');$('feedback').hidden=true;
  if(check){feedback('Checking your answer against the source capture and record variations…');const correct=await rpc('grade',{query:$('query').value,lang,exercise});
   if(correct){if(community.user){const verified=await community.submit({dataset:meta.id,exercise,lang,query:$('query').value});passed=verified.progress;}else{passed[key()]=true;}persist();renderNav();renderLanguages();$('languageStatus').textContent='✓ Completed in this language';feedback('✓ Correct. Your result matches the full capture and two source-record variations. '+(community.user?'Verified progress saved to your account.':'Sign in to save verified progress and earn ranking points.') ,'success');}
   else feedback('Your query ran, but the result does not match the task. Check filters, required column names, counts, and ordering. The hint can help.');
  }
 }catch(e){if(!check||!result){result=null;$('rowCount').textContent='—';$('resultTable').replaceChildren();$('resultMeta').textContent='Query failed; the previous result has been cleared.';}feedback(e.message,'error');}finally{setBusy(false);}
}
async function openRaw(id){if(!ready||busy)return;try{const row=await rpc('raw',{recordId:Number(id)});$('rawTitle').textContent=`Original record #${row.id}`;$('rawSource').textContent=meta.sourceFile;let text=row.raw;try{text=JSON.stringify(JSON.parse(text),null,2)}catch{}$('rawContent').textContent=text;$('rawDialog').showModal();}catch(e){feedback(e.message,'error');}}
async function switchMode(next,dataset){
 if(busy||!ready)return false;saveDraft();mode=next;await loadDataset(dataset||(next==='playground'?freeDataset:practiceDataset),false);return ready;
}
function downloadText(text,name,type='text/markdown;charset=utf-8'){const url=URL.createObjectURL(new Blob([text],{type})),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function renderCheat(){
 const query=$('cheatSearch').value.trim().toLowerCase(),filter=$('cheatFilter').value,current=meta||prepareScratch(SCRATCH_INPUT).meta;
 const matches=COMMANDS.filter(r=>(filter==='all'||(filter==='runnable')===r.supported)&&[r.title,r.category,r.note,...LANGS.map(l=>r.supported?r.make(l,current):r.snippets[l])].join(' ').toLowerCase().includes(query));
 $('cheatCount').textContent=`${matches.length} of ${COMMANDS.length} operations · Examples use ${current.title}.`;
 $('cheatBody').replaceChildren(...matches.map(row=>{
  const tr=document.createElement('tr'),label=document.createElement('th');label.scope='row';
  const title=document.createElement('strong');title.textContent=row.title;const tag=document.createElement('span');tag.className=row.supported?'support-tag':'reference-tag';tag.textContent=row.supported?'Runnable here':'Native reference';const note=document.createElement('p');note.textContent=row.note;label.append(title,tag,note);tr.append(label);
  for(const l of LANGS){const td=document.createElement('td'),pre=document.createElement('pre');pre.textContent=row.supported?row.make(l,current):row.snippets[l];td.append(pre);
   if(row.supported){const button=document.createElement('button');button.className='quiet';button.textContent='Try in free query';button.setAttribute('aria-label',`Try ${row.title} in ${META[l].name}`);button.disabled=busy||!ready;
    button.onclick=async()=>{const dataset=meta.id;$('cheatDialog').close();if(mode!=='playground'&&!await switchMode('playground',dataset))return;if(busy)return;saveDraft();lang=l;renderLesson();$('query').value=row.make(l,meta);saveDraft();lines();$('query').focus();feedback('Example loaded in Free query. Run it to see the results.');};td.append(button);
   }tr.append(td);
  }return tr;
 }));
 if(!matches.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=5;td.textContent='No matching operations. Try a different search.';tr.append(td);$('cheatBody').append(tr);}
}
function openCheat(){renderCheat();$('cheatDialog').showModal();}
for(const l of LANGS){const d=DOCS[l],card=document.createElement('div'),a=document.createElement('a');a.href=d.url;a.target='_blank';a.rel='noopener';a.textContent=META[l].name;const title=document.createElement('small');title.textContent=d.title;card.append(a,title);if(d.extra){const extra=document.createElement('a');extra.href=d.extra;extra.textContent=d.extraTitle;extra.target='_blank';extra.rel='noopener';card.append(extra);}$('docsLinks').append(card);}
$('exampleSelect').replaceChildren(...COMMANDS.filter(r=>r.supported).map(r=>{const o=document.createElement('option');o.value=r.id;o.textContent=r.title;return o;}));
$('freeMode').onclick=()=>switchMode('playground');$('practiceMode').onclick=()=>switchMode('practice');
$('useExample').onclick=()=>{if(!ready||busy)return;const ex=COMMANDS.find(r=>r.id===$('exampleSelect').value);$('query').value=ex.make(lang,meta);saveDraft();lines();feedback('Example loaded. Run it, then modify it to ask your own question.');};
$('applyScratch').onclick=async()=>{if(!ready||busy)return;try{prepareScratch($('scratchInput').value);scratchText=$('scratchInput').value;await loadDataset('scratch');if(ready)feedback(`Applied ${meta.count} scratch rows. Your query draft has been kept.`,'success');}catch(e){feedback(`Scratch data was not changed: ${e.message}`,'error');}};
$('resetScratch').onclick=async()=>{if(!ready||busy)return;scratchText=JSON.stringify(SCRATCH_INPUT,null,2);await loadDataset('scratch');};
$('cheatButton').onclick=openCheat;$('sideCheatButton').onclick=openCheat;$('closeCheat').onclick=()=>$('cheatDialog').close();$('cheatSearch').oninput=renderCheat;$('cheatFilter').onchange=renderCheat;
$('downloadCheat').onclick=()=>downloadText(referenceMarkdown(meta||prepareScratch(SCRATCH_INPUT).meta),'siem-query-cheat-sheet.md');
document.querySelectorAll('[data-panel]').forEach(b=>b.onclick=()=>setPanel(b.dataset.panel));
const editor=$('query');editor.addEventListener('input',()=>{saveDraft();lines();$('feedback').hidden=true;});editor.addEventListener('scroll',()=>$('lineNumbers').scrollTop=editor.scrollTop);editor.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();run();}if(e.key==='Tab'){e.preventDefault();editor.setRangeText('  ',editor.selectionStart,editor.selectionEnd,'end');saveDraft();lines();}});
$('runButton').onclick=()=>run();$('checkButton').onclick=()=>run(true);
$('hintButton').onclick=()=>{if(ready)$('hint').hidden=!$('hint').hidden;};
$('solutionButton').onclick=()=>{if(!ready)return;$('solution').hidden=!$('solution').hidden;$('solutionCode').textContent=lessons[exercise].solution(lang);$('solutionExplanation').textContent=`${META[lang].name}: ${lessons[exercise].hint} Read the query step by step, then try rewriting it yourself.`;};
$('loadSolution').onclick=()=>{if(!ready||busy)return;editor.value=lessons[exercise].solution(lang);saveDraft();lines();editor.focus();feedback('Solution loaded. Run it to inspect the results, or check it to record completion.');};
$('resetQuery').onclick=()=>{editor.value=starter(lang);saveDraft();lines();feedback('Starter query restored.');};
$('nextButton').onclick=()=>{if(!busy&&ready&&exercise<9){saveDraft();exercise++;renderLesson();}};
$('datasetSelect').onchange=e=>loadDataset(e.target.value);
$('inspectRecord').onclick=()=>openRaw($('recordId').value);
for(const [id,delta] of [['prevRaw',-150],['nextRaw',150]])$(id).onclick=async()=>{if(busy||!ready)return;setBusy(true);try{rawOffset=Math.max(0,Math.min(Math.floor((meta.count-1)/150)*150,rawOffset+delta));drawTable($('rawTable'),await rpc('page',{offset:rawOffset}),['id','time','eventType','user','ip','host','process','command'],true);rawControls();}catch(e){feedback(e.message,'error');}finally{setBusy(false);}};
$('exportButton').onclick=async()=>{if(!result||busy)return;setBusy(true);try{const csv=await rpc('export'),url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'})),a=document.createElement('a');a.href=url;a.download=`${meta.id}-${lang}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){feedback(e.message,'error');}finally{setBusy(false);}};
$('helpButton').onclick=()=>$('helpDialog').showModal();$('closeHelp').onclick=()=>$('helpDialog').close();$('closeRaw').onclick=()=>$('rawDialog').close();
$('clearProgress').onclick=()=>{if(!ready||busy)return;if(community.user){feedback('Account progress is server-verified. Sign out to reset guest progress.');return;}if(confirm('Reset completion for this dataset? Saved queries will be kept.')){for(const k of Object.keys(passed))if(k.startsWith(meta.id+':'))delete passed[k];persist();renderNav();renderLanguages();$('languageStatus').textContent='';feedback('Dataset progress reset.');}};
document.addEventListener('siem:session',({detail})=>{if(detail.progress!==undefined){passed=detail.user?detail.progress:guestPassed;if(ready){renderNav();renderLanguages();$('languageStatus').textContent=passed[key()]?'✓ Completed in this language':'';}}});
try{const response=await fetch('./datasets/manifest.json');if(!response.ok)throw Error(`Inventory request failed (${response.status}).`);manifest=await response.json();
 const scratchOption=document.createElement('option');scratchOption.id='scratchOption';scratchOption.value='scratch';scratchOption.textContent='Scratch data · editable · no scenario';scratchOption.hidden=mode!=='playground';
 $('datasetSelect').replaceChildren(scratchOption,...manifest.datasets.map(d=>{const o=document.createElement('option');o.value=d.id;o.textContent=`${d.title} · ${d.count.toLocaleString()} records`;return o;}));
 $('inventorySummary').textContent=`${manifest.datasets.length} datasets · ${manifest.datasets.reduce((n,d)=>n+d.count,0).toLocaleString()} source records. Excluded files: ${manifest.excluded.length}. Packet captures: ${manifest.excluded.filter(x=>x.file.endsWith('.pcapng')).map(x=>x.file).join('; ')}.`;
 const linked=readChallenge(location.search,manifest.datasets.map(d=>d.id));
 if(linked.lang)lang=linked.lang;if(linked.exercise!==null)exercise=linked.exercise;
 if(linked.dataset){mode='practice';practiceDataset=linked.dataset;}
 await loadDataset(mode==='playground'?freeDataset:practiceDataset);
}catch(e){feedback(`Could not initialize the lab: ${e.message}`,'error');}



$('shareChallenge').onclick=async()=>{if(!ready||busy)return;const url=challengeUrl(location.origin,{dataset:meta.id,lang,exercise});try{await navigator.clipboard.writeText(url);feedback('Challenge link copied. It opens this dataset, exercise and language; it does not include your query or account data.','success');}catch{const a=document.createElement('a');a.href=url;a.textContent='Open this challenge link to copy or share';$('feedback').replaceChildren(a);$('feedback').hidden=false;}};
