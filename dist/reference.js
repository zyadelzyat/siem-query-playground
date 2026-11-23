import {FIELD_KEYS,META} from './engine.js';
import {starter} from './lessons.js';
export const DOCS={
 spl:{title:'Splunk SPL command reference',url:'https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/quick-reference/command-quick-reference'},
 kql:{title:'Microsoft Kusto Query Language reference',url:'https://learn.microsoft.com/en-us/kusto/query/'},
 aql:{title:'IBM QRadar AQL documentation',url:'https://www.ibm.com/docs/en/qsip/7.5.0?topic=aql-ariel-query-language-in-qradar-user-interface',extra:'https://www.ibm.com/docs/en/SSKMKU/pdf/b_qradar_aql.pdf',extraTitle:'Full AQL guide (PDF)'},
 forti:{title:'FortiSIEM Advanced Search SQL',url:'https://docs.fortinet.com/document/fortisiem/7.5.0/user-guide/704751/overview',extra:'https://clickhouse.com/docs/sql-reference',extraTitle:'ClickHouse SQL reference'}
};
const f=(key,l)=>FIELD_KEYS[key][l],literal=v=>"'"+String(v).replace(/\\/g,'\\\\').replace(/'/g,"\\'")+"'";
const filter=(l,p)=>l==='spl'||l==='kql'?`${starter(l)}\n| where ${p}`:`${starter(l)}\nWHERE ${p}`;
const eq=(l,key,v)=>`${f(key,l)} ${l==='kql'?'==':'='} ${literal(v)}`;
const group=(l,tail='')=>l==='spl'?`${starter(l)}\n| stats count as total by ${f('host',l)}${tail}`:l==='kql'?`${starter(l)}\n| summarize total=count() by ${f('host',l)}${tail}`:`SELECT ${f('host',l)}, COUNT(*) AS total\nFROM ${META[l].table}\nGROUP BY ${f('host',l)}${tail}`;
const row=(id,title,category,note,make)=>({id,title,category,note,make,supported:true});
const ref=(id,title,category,note,snippets)=>({id,title,category,note,snippets,supported:false});
export const COMMANDS=[
 row('read','Read all events','Read','These are the lab training tables. Use your actual index/table names in production.',l=>starter(l)),
 row('equal','Filter: equals','Filter','String equality is case-sensitive in where / WHERE. Values below come from the selected dataset.',(l,m)=>filter(l,eq(l,'eventType',m.targetType))),
 row('not-equal','Filter: not equal','Filter','Exclude a value using != or <>.',(l,m)=>filter(l,`${f('eventType',l)} != ${literal(m.targetType)}`)),
 row('and','Combine with AND','Filter','Both conditions must hold.',(l,m)=>filter(l,`${eq(l,'eventType',m.targetType)} ${l==='kql'?'and':'AND'} ${f('host',l)} != ''`)),
 row('or','Combine with OR','Filter','Either condition may hold. Use parentheses when mixing AND and OR.',(l,m)=>filter(l,`(${eq(l,'eventType',m.targetType)} ${l==='kql'?'or':'OR'} ${eq(l,'user',m.targetUser)})`)),
 row('not','Negate a condition','Filter','NOT applies to the parenthesized condition.',(l,m)=>filter(l,`${l==='kql'?'not':'NOT'} (${eq(l,'eventType',m.targetType)})`)),
 row('in','Match a list: IN','Filter','The list contains source event-type labels.',(l,m)=>filter(l,`${f('eventType',l)} ${l==='kql'?'in':'IN'} (${Object.keys(m.eventTypes).slice(0,2).map(literal).join(', ')})`)),
 row('range','Numeric comparison','Filter','Example: include record IDs 1 through 5. This avoids assuming numeric event codes in AWS/Linux data.',l=>filter(l,`event_id >= 1 ${l==='kql'?'and':'AND'} event_id <= 5`)),
 row('text','Search source text','Text','Case-insensitive substring search. SPL search wildcards and SQL LIKE wildcards have different syntax.',(l,m)=>l==='spl'?`${starter(l)}\n| search _raw=${literal('*'+m.huntTerm+'*')}`:filter(l,`${f('raw',l)} ${l==='kql'?'contains':'ILIKE'} ${literal(l==='kql'?m.huntTerm:'%'+m.huntTerm+'%')}`)),
 row('prefix','Match an account prefix','Text','Case-insensitive here. Wildcard/escaping rules differ; these examples use a source account prefix.',(l,m)=>{const prefix=(m.targetUser||'alice').slice(0,2);return l==='spl'?`${starter(l)}\n| search user=${literal(prefix+'*')}`:filter(l,`${f('user',l)} ${l==='kql'?'startswith':'ILIKE'} ${literal(l==='kql'?prefix:prefix+'%')}`);}),
 row('project','Choose columns','Shape','Return only the record ID and host.',l=>l==='spl'||l==='kql'?`${starter(l)}\n| ${l==='spl'?'table':'project'} event_id, ${f('host',l)}`:`SELECT event_id, ${f('host',l)} FROM ${META[l].table}`),
 row('count','Count all rows','Aggregate','The output column is named total.',l=>l==='spl'?`${starter(l)}\n| stats count as total`:l==='kql'?`${starter(l)}\n| summarize total=count()`:`SELECT COUNT(*) AS total FROM ${META[l].table}`),
 row('group','Count by a field','Aggregate','Empty hosts form their own group in this training schema.',l=>group(l)),
 row('having','Filter after aggregation','Aggregate','where after stats/summarize corresponds to HAVING in SQL.',l=>group(l,l==='spl'||l==='kql'?'\n| where total > 1':'\nHAVING COUNT(*) > 1')),
 row('sort-asc','Sort ascending','Order','Row order is deterministic because event_id is unique.',l=>l==='spl'?`${starter(l)}\n| sort +event_id`:l==='kql'?`${starter(l)}\n| sort by event_id asc`:`${starter(l)} ORDER BY event_id ASC`),
 row('sort-desc','Sort descending','Order','Specify direction explicitly to avoid different defaults.',l=>l==='spl'?`${starter(l)}\n| sort -event_id`:l==='kql'?`${starter(l)}\n| sort by event_id desc`:`${starter(l)} ORDER BY event_id DESC`),
 row('limit','Limit returned rows','Order','Without sorting first, the selected rows are not a reliable top-N ranking.',l=>l==='spl'?`${starter(l)}\n| head 5`:l==='kql'?`${starter(l)}\n| take 5`:`${starter(l)} LIMIT 5`),
 row('top','Top groups by count','Order','Sort counts descending and host ascending for tie-breaking, then keep five.',l=>group(l,l==='spl'?`\n| sort -total, +host\n| head 5`:l==='kql'?`\n| sort by total desc, Computer asc\n| take 5`:'\nORDER BY total DESC, '+f('host',l)+' ASC LIMIT 5')),
 row('time','Last ten minutes','Time','The browser lab uses the capture clock, not wall time. SPL uses an ISO comparison here; native Splunk normally uses earliest/latest.',(l,m)=>l==='aql'?`${starter(l)} LAST 10 MINUTES`:filter(l,`${f('time',l)} >= ${l==='kql'?'ago(10m)':l==='forti'?'now()-600':literal(new Date(Date.parse(m.clock)-600000).toISOString())}`)),
 ref('distinct','Distinct values / deduplicate','Shape','Native reference. Only KQL distinct is currently implemented here; the complete row has no Try buttons.',{spl:'| dedup host | table host',kql:'| distinct Computer',aql:'SELECT hostname FROM events GROUP BY hostname',forti:'SELECT DISTINCT reptDevName FROM fsiem.events'}),
 ref('sum','Sum numeric values','Aggregate','Native reference only. Replace value with a parsed numeric field.',{spl:'| stats sum(value) as total',kql:'| summarize total=sum(value)',aql:'SELECT SUM(value) AS total FROM events',forti:'SELECT sum(value) AS total FROM fsiem.events'}),
 ref('avg','Average numeric values','Aggregate','Native reference only. Missing-value and numeric-conversion behavior can differ.',{spl:'| stats avg(value) as average',kql:'| summarize average=avg(value)',aql:'SELECT AVG(value) AS average FROM events',forti:'SELECT avg(value) AS average FROM fsiem.events'}),
 ref('min','Minimum value','Aggregate','Native reference only. Compare compatible data types.',{spl:'| stats min(value) as minimum',kql:'| summarize minimum=min(value)',aql:'SELECT MIN(value) AS minimum FROM events',forti:'SELECT min(value) AS minimum FROM fsiem.events'}),
 ref('max','Maximum value','Aggregate','Native reference only.',{spl:'| stats max(value) as maximum',kql:'| summarize maximum=max(value)',aql:'SELECT MAX(value) AS maximum FROM events',forti:'SELECT max(value) AS maximum FROM fsiem.events'}),
 ref('rename','Rename an output column','Shape','Native reference only. SQL AS aliases are supported here; pipeline rename/project aliases are not.',{spl:'| rename host as machine',kql:'| project machine=Computer',aql:'SELECT hostname AS machine FROM events',forti:'SELECT reptDevName AS machine FROM fsiem.events'}),
 ref('distinct-count','Count distinct values','Aggregate','Native reference only. KQL dcount is approximate; FortiSIEM/ClickHouse uniqExact is exact. Compare accuracy requirements before translating.',{spl:'| stats dc(host) as unique_hosts',kql:'| summarize unique_hosts=dcount(Computer)',aql:'SELECT UNIQUECOUNT(hostname) AS unique_hosts FROM events',forti:'SELECT uniqExact(reptDevName) AS unique_hosts FROM fsiem.events'})
];
export function referenceMarkdown(meta){
 const escape=s=>s.replace(/\|/g,'\\|').replace(/\n/g,'<br>');
 return '# SIEM query language cheat sheet\n\nExamples use the lab training schema. Native reference rows are not executable in the browser subset.\n\n'+Object.entries(DOCS).map(([k,d])=>`- [${META[k].name}: ${d.title}](${d.url})${d.extra?` · [${d.extraTitle}](${d.extra})`:''}`).join('\n')+'\n\n| Operation | Lab support | Splunk SPL | Sentinel KQL | QRadar AQL | FortiSIEM SQL | Notes |\n| --- | --- | --- | --- | --- | --- | --- |\n'+COMMANDS.map(r=>'| '+[r.title,r.supported?'Runnable':'Reference only',...['spl','kql','aql','forti'].map(l=>r.supported?r.make(l,meta):r.snippets[l]),r.note].map(escape).join(' | ')+' |').join('\n')+'\n';
}
