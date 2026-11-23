import {execute} from './engine.js';
import {createLessons,grade} from './lessons.js';
import {prepareScratch} from './scratch.js';
let rows=[],meta=null,lastResult=null;
self.onmessage=async({data:m})=>{try{
 let value;
 if(m.action==='scratch'){
  const prepared=prepareScratch(m.input);rows=prepared.rows;meta=prepared.meta;lastResult=null;value={meta,count:rows.length,preview:rows.slice(0,150)};
 }else if(m.action==='load'){
  meta=null;rows=[];lastResult=null;
  if(!/^[a-z0-9_]+\.json\.gz$/.test(m.meta.file))throw Error('Invalid dataset path.');
  const response=await fetch(`./datasets/${m.meta.file}`);if(!response.ok)throw Error(`Dataset request failed (${response.status}).`);
  if(!self.DecompressionStream)throw Error('This browser needs gzip DecompressionStream support. Please use a current browser.');
  const payload=await new Response(response.body.pipeThrough(new DecompressionStream('gzip'))).json();
  if(payload.rows.length!==m.meta.count)throw Error('Dataset record count does not match its manifest.');
  rows=payload.rows;meta=m.meta;value={count:rows.length,preview:rows.slice(0,150)};
 }else{
  if(!meta)throw Error('Select and load a dataset first.');
  if(m.action==='run'){lastResult=null;lastResult=execute(m.query,m.lang,rows,Date.parse(meta.clock));value={rows:lastResult.rows.slice(0,150),columns:lastResult.columns,count:lastResult.rows.length};}
  else if(m.action==='grade'){if(meta.id==='scratch')throw Error('Scratch queries are not graded.');value=grade(m.query,m.lang,createLessons(meta)[m.exercise],rows,Date.parse(meta.clock));}
  else if(m.action==='raw'){const r=rows.find(r=>r.id===m.recordId);if(!r)throw Error('Record ID is outside this dataset.');value=r;}
  else if(m.action==='page')value=rows.slice(m.offset,m.offset+150);
  else if(m.action==='export'){
   if(!lastResult)throw Error('Run a query before exporting.');
   const cell=v=>'"'+String(v??'').replace(/"/g,'""')+'"';
   value='\uFEFF'+[lastResult.columns,...lastResult.rows.map(r=>lastResult.columns.map(c=>r[c]))].map(r=>r.map(cell).join(',')).join('\r\n');
  }else throw Error('Unknown action.');
 }
 self.postMessage({id:m.id,value});
 }catch(error){self.postMessage({id:m.id,error:error.message});}
};
