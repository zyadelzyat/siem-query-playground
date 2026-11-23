export const SCRATCH_INPUT=[
 {time:'2026-01-01T11:52:00Z',code:4624,user:'alice',ip:'192.0.2.10',host:'lab-01',channel:'Security',command:'interactive logon'},
 {time:'2026-01-01T11:56:00Z',code:4625,user:'bob',ip:'192.0.2.20',host:'lab-02',channel:'Security',command:'failed logon'},
 {time:'2026-01-01T11:58:00Z',code:4625,user:'alice',ip:'192.0.2.20',host:'lab-01',channel:'Security',command:'failed logon'},
 {time:'2026-01-01T11:59:00Z',code:1,user:'alice',ip:'',host:'lab-01',channel:'Sysmon',process:'powershell.exe',command:'powershell -NoProfile'},
 {time:'2026-01-01T12:00:00Z',code:4624,user:'bob',ip:'192.0.2.10',host:'lab-02',channel:'Security',command:'interactive logon'}
];
export function prepareScratch(input){
 const source=typeof input==='string'?JSON.parse(input):input;
 if(!Array.isArray(source)||!source.length||source.length>1000)throw Error('Scratch data must be a JSON array with 1–1,000 objects.');
 const rows=source.map((r,i)=>{
  if(!r||typeof r!=='object'||Array.isArray(r))throw Error(`Scratch row ${i+1} must be an object.`);
  if(!Number.isFinite(Date.parse(r.time))||!/(Z|[+-]\d\d:\d\d)$/.test(r.time||''))throw Error(`Scratch row ${i+1} needs a valid time with Z or a timezone offset.`);
  for(const k of ['user','ip','host','channel','process','command','eventType'])if(r[k]!==undefined&&typeof r[k]!=='string')throw Error(`Scratch row ${i+1}: ${k} must be a string.`);
  if(r.code!==undefined&&!(typeof r.code==='string'||typeof r.code==='number'&&Number.isFinite(r.code)))throw Error(`Scratch row ${i+1}: code must be text or a finite number.`);
  return {id:i+1,time:new Date(r.time).toISOString(),code:r.code??'',eventType:r.eventType||`${r.channel||'Scratch'}:${r.code??''}`,user:r.user||'',ip:r.ip||'',host:r.host||'',channel:r.channel||'',process:r.process||'',command:r.command||'',raw:JSON.stringify(r)};
 });
 const eventTypes=Object.create(null);for(const r of rows)eventTypes[r.eventType]=(eventTypes[r.eventType]||0)+1;
 const meta={id:'scratch',title:'Scratch data · no scenario',sourceFile:'Browser-local scratch data',format:'Editable sample JSON',count:rows.length,
  start:rows.reduce((v,r)=>v<r.time?v:r.time,rows[0].time),clock:rows.reduce((v,r)=>v>r.time?v:r.time,rows[0].time),compressedBytes:0,
  targetType:rows[0].eventType,targetUser:rows.find(r=>r.user)?.user||'',huntTerm:'logon',threshold:0,eventTypes,
  missing:Object.fromEntries(['user','ip','host','process','command'].map(k=>[k,rows.filter(r=>!r[k]).length]))};
 return {rows,meta};
}
