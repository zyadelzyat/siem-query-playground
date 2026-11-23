export const SOURCES=['linkedin','community','reddit','facebook','github'];
export function visitSource(search){const value=new URLSearchParams(search).get('utm_source')?.toLowerCase();return SOURCES.includes(value)?value:'direct';}
export function readChallenge(search,ids){
 const params=new URLSearchParams(search),dataset=params.get('dataset'),lang=params.get('lang'),exercise=params.get('exercise');
 return {dataset:ids.includes(dataset)?dataset:null,lang:['spl','kql','aql','forti'].includes(lang)?lang:null,exercise:/^[1-9]$|^10$/.test(exercise||'')?Number(exercise)-1:null};
}
export function challengeUrl(origin,{dataset,lang,exercise}){
 const url=new URL('/',origin);url.search=new URLSearchParams({dataset,lang,exercise:String(exercise+1),utm_source:'community',utm_medium:'challenge_share'});return url.href;
}
export function acquisitionCounts(paths){const counts={};for(const path of paths){const candidate=path.split('/')[1],source=SOURCES.includes(candidate)||candidate==='direct'?candidate:'unattributed';counts[source]=(counts[source]||0)+1;}return Object.entries(counts).sort((a,b)=>b[1]-a[1]).map(([source,visitors])=>({source,visitors}));}
