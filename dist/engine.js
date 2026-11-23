// Deliberately bounded interpreter. Never evaluates user input as JavaScript.
export const LANGS = ['spl','kql','aql','forti'];
export const META = {
 spl:{name:'Splunk SPL',table:'index=lab'},
 kql:{name:'Sentinel KQL',table:'LabEvents'},
 aql:{name:'QRadar AQL',table:'events'},
 forti:{name:'FortiSIEM SQL',table:'fsiem.events'}
};
export const FIELD_KEYS={
 time:{spl:'_time',kql:'TimeGenerated',aql:'starttime',forti:'phRecvTime'},
 code:{spl:'EventCode',kql:'EventID',aql:'eventid',forti:'eventCode'},
 eventType:{spl:'event_type',kql:'EventType',aql:'eventname',forti:'eventType'},
 user:{spl:'user',kql:'Account',aql:'username',forti:'user'},
 ip:{spl:'src_ip',kql:'IpAddress',aql:'sourceip',forti:'srcIpAddrV4'},
 host:{spl:'host',kql:'Computer',aql:'hostname',forti:'reptDevName'},
 channel:{spl:'source',kql:'Channel',aql:'channel',forti:'eventSource'},
 process:{spl:'process_path',kql:'ProcessName',aql:'processname',forti:'procName'},
 command:{spl:'command_line',kql:'CommandLine',aql:'commandline',forti:'command'},
 raw:{spl:'_raw',kql:'RawEvent',aql:'payload',forti:'rawEventMsg'}
};
export function platformRows(data,lang){return data.map(r=>{
 const row={event_id:r.id};for(const [key,names] of Object.entries(FIELD_KEYS))row[names[lang]]=key==='time'?(lang==='aql'?Date.parse(r.time):lang==='forti'?Date.parse(r.time)/1000:r.time):(r[key]??'');return row;
 });}
const err=s=>{throw Error(s)};
export function splitOutside(s,delimiter){
 let parts=[],start=0,quote=null,depth=0;
 for(let i=0;i<s.length;i++){
  const c=s[i];
  if(quote){if(c===quote&&s[i-1]!=='\\')quote=null;continue;}
  if(c==='"'||c==="'"){quote=c;continue;}
  if(c==='('||c==='[')depth++;
  if(c===')'||c===']')depth--;
  if(depth===0&&c===delimiter){parts.push(s.slice(start,i).trim());start=i+1;}
 }
 if(quote||depth!==0)err('Unclosed parenthesis or quotation mark.');
 parts.push(s.slice(start).trim());return parts;
}
function clean(s,lang,CLOCK){
 s=s.replace(/;\s*$/,'');
 s=s.replace(/metrics_string\.value\s*\[\s*indexOf\s*\(\s*metrics_string\.name\s*,\s*['"]user['"]\s*\)\s*\]/g,'user');
 s=s.replace(/datetime\(\s*(['"]?)([\dT:Z.+-]+)\1\s*\)/gi,(_,q,d)=>JSON.stringify(new Date(d).toISOString()));
 s=s.replace(/ago\(\s*(\d+)\s*([mhd])\s*\)/gi,(_,n,u)=>JSON.stringify(new Date(CLOCK-n*({m:60000,h:3600000,d:86400000}[u])).toISOString()));
 s=s.replace(/now\(\)\s*-\s*(\d+)/gi,(_,n)=>String((lang==='forti'?CLOCK/1000:CLOCK)-Number(n)));
 s=s.replace(/now\(\)/gi,String(lang==='forti'?CLOCK/1000:CLOCK));
 return s;
}
function tokens(s){
 const out=[];const re=/\s*(?:("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(>=|<=|!=|==|<>|=|>|<|\(|\)|,)|(-?\d+(?:\.\d+)?)|([A-Za-z_][\w.]*))/gy;
 let i=0;
 while(i<s.length){if(!s.slice(i).trim())break;re.lastIndex=i;const m=re.exec(s);if(!m)err(`Unsupported syntax near: ${s.slice(i,i+25)}`);i=re.lastIndex;
  if(m[1])out.push({type:'value',value:m[1].slice(1,-1).replace(/\\(['"\\])/g,'$1')});
  else if(m[3])out.push({type:'value',value:Number(m[3])});
  else out.push({type:m[4]?'word':'op',value:m[4]||m[2]});
 }return out;
}
function predicate(s,fields,lang){
 const ts=tokens(s);let p=0;
 const peek=v=>String(ts[p]?.value).toLowerCase()===v;
 const take=()=>ts[p++]||err('Incomplete condition.');
 const operand=()=>{const t=take();if(t.type==='value')return ()=>t.value;
  if(t.type!=='word')err('Expected a field name or literal value.');
  if(!fields.has(t.value))err(`Unknown field ${t.value}. Check Fields & syntax.`);
  return row=>row[t.value];};
 const atom=()=>{
  if(peek('(')){p++;const fn=or();if(!peek(')'))err('Unclosed condition parenthesis.');p++;return fn;}
  if(peek('not')){p++;const fn=atom();return r=>!fn(r);}
  const left=operand(),op=String(take().value).toLowerCase();
  if(op==='in'){if(!peek('('))err('IN requires a parenthesized list.');p++;const list=[operand()];while(peek(',')){p++;list.push(operand());}if(!peek(')'))err('Incomplete IN list.');p++;return r=>list.some(f=>f(r)===left(r));}
  if(!['=','==','!=','<>','>','<','>=','<=','contains','has','startswith','like','ilike'].includes(op))err(`Unsupported operator: ${op}.`);
  const right=operand();return r=>{const a=left(r),b=right(r);
   if(['contains','has','startswith','like','ilike'].includes(op)){
    let x=String(a),y=String(b);if(op!=='like'){x=x.toLowerCase();y=y.toLowerCase();}
    if(op==='has')return x.split(/\W+/).includes(y);
    if(op==='startswith')return x.startsWith(y);
    if(op==='contains')return x.includes(y);
    return new RegExp('^'+y.split('%').map(z=>z.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('.*')+'$').test(x);
   }
   if(op==='='&&lang.startsWith('spl')&&typeof b==='string'&&b.includes('*'))return new RegExp('^'+b.split('*').map(z=>z.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('.*')+'$',lang==='spl-search'?'i':'').test(String(a));
   if(lang==='spl-search'&&op==='='&&typeof a==='string'&&typeof b==='string')return a.toLowerCase()===b.toLowerCase();
   if(op==='='||op==='==')return a===b;if(op==='!='||op==='<>')return a!==b;
   if(op==='>')return a>b;if(op==='<')return a<b;if(op==='>=')return a>=b;return a<=b;
  };
 };
 const and=()=>{let a=atom();while(peek('and')){p++;const b=atom(),prev=a;a=r=>prev(r)&&b(r);}return a;};
 const or=()=>{let a=and();while(peek('or')){p++;const b=and(),prev=a;a=r=>prev(r)||b(r);}return a;};
 const fn=or();if(p!==ts.length)err(`Unexpected token ${ts[p].value}. Use explicit AND between conditions.`);return fn;
}
function selectFields(s,fields){return splitOutside(s,',').map(x=>{if(!/^[A-Za-z_]\w*$/.test(x)||!fields.has(x))err(`Unknown field or unsupported expression: ${x}.`);return x;});}
function aggregate(rows,groups,name,fields){
 for(const g of groups)if(!fields.has(g))err(`Unknown grouping field: ${g}.`);
 const buckets=new Map();for(const row of rows){const k=JSON.stringify(groups.map(g=>row[g]));if(!buckets.has(k))buckets.set(k,{...Object.fromEntries(groups.map(g=>[g,row[g]])),[name]:0});buckets.get(k)[name]++;}
 if(!groups.length&&!rows.length)return [{[name]:0}];return [...buckets.values()];
}
function order(rows,s,fields,lang){
 const keys=splitOutside(s,',').map(part=>{let m=part.trim().match(/^([+-]?)(\w+)(?:\s+(asc|desc))?$/i);if(!m)err('Unsupported sort expression.');if(!fields.has(m[2]))err(`Unknown sort field: ${m[2]}.`);return {key:m[2],desc:m[1]==='-'||m[3]?.toLowerCase()==='desc'||(lang==='kql'&&!m[3]&&m[1]!=='+')};});
 return [...rows].sort((a,b)=>{for(const k of keys){const x=a[k.key],y=b[k.key];const c=x<y?-1:x>y?1:0;if(c)return k.desc?-c:c;}return 0;});
}
export function execute(query,lang,data,clock){
 const CLOCK=clock??Math.max(...data.map(r=>Date.parse(r.time)));
 if(!LANGS.includes(lang))err('Unknown language.');if(query.length>10000)err('Query exceeds the 10,000 character limit.');
 let rows=platformRows(data,lang),fields=new Set(['event_id',...Object.values(FIELD_KEYS).map(m=>m[lang])]);
 const source=clean(query.trim(),lang,CLOCK);if(!source)err('Write a query first.');
 if(lang==='spl'||lang==='kql'){
  const parts=splitOutside(source,'|');const base=parts.shift();
  if(lang==='kql'){if(base!=='LabEvents')err('Start with LabEvents.');}
  else{const m=base.match(/^(?:search\s+)?index=lab(?:\s+(.+))?$/i);if(!m)err('Start with index=lab.');if(m[1])rows=rows.filter(predicate(m[1],fields,'spl-search'));}
  for(const part of parts){let m;
   if(m=part.match(/^(where|search)\s+(.+)$/i)){if(lang==='kql'&&m[1].toLowerCase()==='search')err('Use where for field conditions in this KQL subset.');rows=rows.filter(predicate(m[2],fields,lang==='spl'&&m[1].toLowerCase()==='search'?'spl-search':lang));}
   else if(m=part.match(/^(?:table|fields|project)\s+(.+)$/i)){
    if(lang==='spl'&&/^project\b/i.test(part)||lang==='kql'&&/^(table|fields)\b/i.test(part))err('Use table/fields in SPL or project in KQL.');
    const names=selectFields(lang==='spl'?m[1].replace(/\s*,\s*|\s+/g,','):m[1],fields);rows=rows.map(r=>Object.fromEntries(names.map(n=>[n,r[n]])));fields=new Set(names);
   }else if(m=part.match(/^stats\s+count(?:\s+as\s+(\w+))?(?:\s+by\s+(.+))?$/i)){
    if(lang!=='spl')err('Use summarize in KQL.');const groups=m[2]?selectFields(m[2].replace(/\s*,\s*|\s+/g,','),fields):[];const name=m[1]||'count';rows=aggregate(rows,groups,name,fields);fields=new Set([...groups,name]);
   }else if(m=part.match(/^summarize\s+(?:(\w+)\s*=\s*)?count\(\)(?:\s+by\s+(.+))?$/i)){
    if(lang!=='kql')err('Use stats in SPL.');const groups=m[2]?selectFields(m[2],fields):[];const name=m[1]||'count_';rows=aggregate(rows,groups,name,fields);fields=new Set([...groups,name]);
   }else if(m=part.match(/^(?:sort(?:\s+by)?|order\s+by)\s+(.+)$/i))rows=order(rows,m[1],fields,lang);
   else if(m=part.match(/^(head|take|limit)\s+(\d+)$/i)){if(lang==='spl'&&m[1].toLowerCase()!=='head'||lang==='kql'&&m[1].toLowerCase()==='head')err('Use head in SPL or take/limit in KQL.');rows=rows.slice(0,Number(m[2]));}
   else if(m=part.match(/^distinct\s+(.+)$/i)){
    if(lang!=='kql')err('distinct is only supported in KQL here.');const names=selectFields(m[1],fields);rows=[...new Map(rows.map(r=>{const o=Object.fromEntries(names.map(n=>[n,r[n]]));return [JSON.stringify(o),o];})).values()];fields=new Set(names);
   }else err(`Unsupported command: ${part}. Check Fields & syntax.`);
  }
 }else{
  // Recognize clauses only outside quoted strings / parentheses.
  const masked=source.split('');let quote=null,depth=0;
  for(let i=0;i<source.length;i++){const c=source[i];if(quote){masked[i]=' ';if(c===quote&&source[i-1]!=='\\')quote=null;}else if(c==='"'||c==="'"){quote=c;masked[i]=' ';}else if(c==='('){depth++;masked[i]=' ';}else if(c===')'){depth--;masked[i]=' ';}else if(depth)masked[i]=' ';}
  if(quote||depth)err('Unclosed parenthesis or quotation mark.');
  const matches=[...masked.join('').matchAll(/\b(SELECT|FROM|WHERE|GROUP\s+BY|HAVING|ORDER\s+BY|LIMIT|LAST)\b/gi)];const clauses={};let prev=-1;
  const sequence=['SELECT','FROM','WHERE','GROUP BY','HAVING','ORDER BY','LIMIT','LAST'];
  for(let i=0;i<matches.length;i++){const m=matches[i],key=m[0].toUpperCase().replace(/\s+/g,' '),pos=sequence.indexOf(key);if(pos<=prev)err('SQL clauses are out of order.');if(i===0&&m.index!==0)err('Start with SELECT.');prev=pos;clauses[key]=source.slice(m.index+m[0].length,matches[i+1]?.index||source.length).trim();}
  if(!clauses.SELECT||clauses.FROM!==META[lang].table)err(`Use SELECT ... FROM ${META[lang].table}.`);
  if(clauses.LAST){if(lang!=='aql')err('LAST is only supported in AQL.');const m=clauses.LAST.match(/^(\d+)\s+(MINUTES?|HOURS?|DAYS?)$/i);if(!m)err('Expected: LAST 10 MINUTES');const duration=Number(m[1])*({m:60000,h:3600000,d:86400000}[m[2][0].toLowerCase()]);rows=rows.filter(r=>r.starttime>=CLOCK-duration&&r.starttime<=CLOCK);}
  if(clauses.WHERE)rows=rows.filter(predicate(clauses.WHERE,fields,lang));
  const selections=splitOutside(clauses.SELECT,',').map(x=>{const m=x.match(/^(.*?)(?:\s+AS\s+(\w+))?$/i);return {expr:m[1].trim(),alias:m[2]};});
  const counts=selections.filter(x=>/^COUNT\(\*\)$/i.test(x.expr));if(counts.length>1)err('Only one count aggregation is supported.');
  if(counts.length||clauses['GROUP BY']){
   if(!counts.length)err('Use COUNT(*) with GROUP BY in this version.');const groups=clauses['GROUP BY']?selectFields(clauses['GROUP BY'],fields):[];
   for(const x of selections)if(!/^COUNT\(\*\)$/i.test(x.expr)&&!groups.includes(x.expr))err('Every selected non-aggregate field must be in GROUP BY.');
   const name=counts[0].alias||'count';rows=aggregate(rows,groups,name,fields);fields=new Set([...groups,name]);
   if(clauses.HAVING)rows=rows.filter(predicate(clauses.HAVING.replace(/COUNT\(\*\)/gi,name),fields,lang));
   if(clauses['ORDER BY'])rows=order(rows,clauses['ORDER BY'].replace(/COUNT\(\*\)/gi,name),fields,lang);
   rows=rows.map(r=>Object.fromEntries(selections.map(x=>{const isCount=/^COUNT\(\*\)$/i.test(x.expr);return [x.alias||(isCount?name:x.expr),r[isCount?name:x.expr]];})));
   fields=new Set(selections.map(x=>x.alias||(/^COUNT\(\*\)$/i.test(x.expr)?name:x.expr)));
  }else{
   if(clauses.HAVING)err('HAVING requires an aggregation.');
   if(clauses['ORDER BY'])rows=order(rows,clauses['ORDER BY'],fields,lang);
   if(clauses.SELECT!=='*'){for(const x of selections)selectFields(x.expr,fields);rows=rows.map(r=>Object.fromEntries(selections.map(x=>[x.alias||x.expr,r[x.expr]])));fields=new Set(selections.map(x=>x.alias||x.expr));}
  }
  if(clauses.LIMIT){if(!/^\d+$/.test(clauses.LIMIT))err('LIMIT requires a nonnegative integer.');rows=rows.slice(0,Number(clauses.LIMIT));}
 }
 return {rows,columns:[...fields]};
}
export function equivalent(actual,expected,ordered=false){
 const a=[...actual.columns].sort(),b=[...expected.columns].sort();if(JSON.stringify(a)!==JSON.stringify(b))return false;
 const normalize=r=>JSON.stringify(a.map(k=>r[k]));let x=actual.rows.map(normalize),y=expected.rows.map(normalize);if(!ordered){x.sort();y.sort();}return JSON.stringify(x)===JSON.stringify(y);
}
