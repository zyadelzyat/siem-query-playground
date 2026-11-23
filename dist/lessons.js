import {META,FIELD_KEYS,execute,equivalent} from './engine.js';
const literal=v=>typeof v==='number'?String(v):"'"+String(v).replace(/\\/g,'\\\\').replace(/'/g,"\\'")+"'";
export const starter=l=>META[l].table.includes('index=')?META[l].table:l==='kql'?META[l].table:`SELECT * FROM ${META[l].table}`;
const filter=(l,p)=>l==='spl'||l==='kql'?`${starter(l)}\n| where ${p}`:`${starter(l)}\nWHERE ${p}`;
const field=(key,l)=>FIELD_KEYS[key][l];
const eq=(key,value,l)=>`${field(key,l)} ${l==='kql'?'==':'='} ${literal(value)}`;
const count=(l,p,g,tail='')=>l==='spl'?`${filter(l,p)}\n| stats count as total${g?` by ${g}`:''}${tail}`:l==='kql'?`${filter(l,p)}\n| summarize total=count()${g?` by ${g}`:''}${tail}`:`SELECT ${g?g+', ':''}COUNT(*) AS total\nFROM ${META[l].table}\nWHERE ${p}${g?'\nGROUP BY '+g:''}${tail}`;
export function createLessons(meta){
 const target=l=>eq('eventType',meta.targetType,l),all=l=>`${field('eventType',l)} != ""`;
 const hunt=l=>l==='spl'?`${starter(l)}\n| search _raw=${literal(`*${meta.huntTerm}*`)}`:filter(l,`${field('raw',l)} ${l==='kql'?'contains':'ILIKE'} ${literal(l==='kql'?meta.huntTerm:`%${meta.huntTerm}%`)}`);
 const focus=meta.targetUser?'user':'eventType',focusValue=meta.targetUser||meta.targetType;
 const windowStart=new Date(Date.parse(meta.clock)-600000).toISOString();
 return [
  {title:'Explore the evidence',level:'Foundations',desc:`Return all ${meta.count.toLocaleString()} records from this dataset, with all available fields.`,hint:'Start with index=lab in SPL, LabEvents in KQL, or SELECT * FROM the SQL table.',solution:starter},
  {title:'Isolate an event type',level:'Foundations',desc:`Return every record whose normalized event type is ${meta.targetType}. Keep all fields.`,hint:'Use event_type (SPL), EventType (KQL), eventname (AQL), or eventType (FortiSIEM). These labels preserve the source channel and event code.',solution:l=>filter(l,target(l))},
  {title:meta.targetUser?'Follow an account':'Follow an event',level:'Foundations',desc:`Return every record with ${meta.targetUser?'account':'event type'} equal to ${focusValue}. Keep all fields.`,hint:'Use equality and quote string values. Account values are taken from the source, not invented.',solution:l=>filter(l,eq(focus,focusValue,l))},
  {title:'Keep the useful columns',level:'Foundations',desc:`Filter to ${meta.targetType}, then return only event_id, the timestamp, and the normalized event type. Column order does not matter.`,hint:'Use table in SPL, project in KQL, or list the columns in SELECT.',solution:l=>l==='spl'||l==='kql'?`${filter(l,target(l))}\n| ${l==='spl'?'table':'project'} event_id, ${field('time',l)}, ${field('eventType',l)}`:`SELECT event_id, ${field('time',l)}, ${field('eventType',l)}\nFROM ${META[l].table}\nWHERE ${target(l)}`},
  {title:'Measure the activity',level:'Aggregation',desc:`Count all records with event type ${meta.targetType}. Name the count column total.`,hint:'stats count as total / summarize total=count() / COUNT(*) AS total.',solution:l=>count(l,target(l))},
  {title:'Build an event profile',level:'Aggregation',desc:'Count all records by normalized event type. Return the event type and a count named total.',hint:'Use by or GROUP BY. This separates overlapping numeric event IDs from different channels.',solution:l=>count(l,all(l),field('eventType',l))},
  {title:'Find the top five',level:'Aggregation',desc:'Return the five most frequent event types with a count named total. Sort total descending, then event type ascending to break ties. If fewer than five types exist, return them all.',hint:'Sort after aggregation. Finish with head 5, take 5, or LIMIT 5.',ordered:true,solution:l=>count(l,all(l),field('eventType',l),l==='spl'?`\n| sort -total, +${field('eventType',l)}\n| head 5`:l==='kql'?`\n| sort by total desc, ${field('eventType',l)} asc\n| take 5`:`\nORDER BY total DESC, ${field('eventType',l)} ASC\nLIMIT 5`)},
  {title:'Apply a threshold',level:'Investigation',desc:`Count records by event type, then return only groups with total > ${meta.threshold}. Keep the event type and total columns.`,hint:'Filter after aggregation with where, or use HAVING COUNT(*) in SQL.',solution:l=>count(l,all(l),field('eventType',l),l==='spl'||l==='kql'?`\n| where total > ${meta.threshold}`:`\nHAVING COUNT(*) > ${meta.threshold}`)},
  {title:'Work a time window',level:'Investigation',desc:`Return all records in the last 10 minutes of this capture. The window starts at ${windowStart} (inclusive) and ends at ${meta.clock}. Keep all fields.`,hint:'Time is anchored to the latest source event. KQL: ago(10m). AQL: LAST 10 MINUTES. FortiSIEM: phRecvTime >= now()-600. SPL: compare _time to the displayed ISO timestamp.',solution:l=>l==='aql'?`${starter(l)} LAST 10 MINUTES`:filter(l,`${field('time',l)} >= ${l==='kql'?'ago(10m)':l==='forti'?'now()-600':literal(windowStart)}`)},
  {title:'Search the original record',level:'Investigation',desc:`Find every record containing “${meta.huntTerm}” anywhere in the original record, ignoring case. Keep all fields. This is a text hunt, not a verdict that every match is malicious.`,hint:'SPL: search _raw="*term*". KQL: RawEvent contains. AQL / FortiSIEM: ILIKE with % wildcards.',solution:hunt}
 ];
}
export function grade(query,lang,lesson,rows,clock){
 // Verify original source data, a deterministic subset, and duplicated real records.
 // These are local correctness checks, not a secure exam or newly fabricated logs.
 const variants=[rows,rows.filter((_,i)=>i%3!==0),[...rows.filter((_,i)=>i%5!==0),...rows.slice(0,Math.min(11,rows.length))]];
 for(const data of variants){const actual=execute(query,lang,data,clock),expected=execute(lesson.solution(lang),lang,data);if(!equivalent(actual,expected,lesson.ordered))return false;}return true;
}
