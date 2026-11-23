export const LANGUAGES=['spl','kql','aql','forti'];
export class HttpError extends Error {constructor(status,message){super(message);this.status=status;}}
export function summarize(paths,datasets){
 const valid=new Set(datasets.map(d=>d.id)),byUser=new Map();
 for(const path of paths){
  const match=/^completed\/([a-f0-9]{64})\/([a-z0-9_]+)\/(spl|kql|aql|forti)\/([0-9])\.json$/.exec(path);
  if(!match||!valid.has(match[2]))continue;
  const [,user,dataset,lang,exercise]=match;
  if(!byUser.has(user))byUser.set(user,{points:0,progress:{},scenarios:0,paths:0,scenarioIds:[]});
  const item=byUser.get(user),key=`${dataset}:${exercise}:${lang}`;if(!item.progress[key]){item.progress[key]=true;item.points++;}
 }
 for(const item of byUser.values())for(const dataset of datasets){
  let complete=false;
  for(const lang of LANGUAGES)if(Array.from({length:10},(_,i)=>item.progress[`${dataset.id}:${i}:${lang}`]).every(Boolean)){item.paths++;complete=true;}
  if(complete){item.scenarios++;item.scenarioIds.push(dataset.id);}
 }
 return byUser;
}
export function publicBoard(users,scores){
 return users.map(user=>({id:user.id,alias:user.alias,points:scores.get(user.id)?.points||0,scenarios:scores.get(user.id)?.scenarios||0,paths:scores.get(user.id)?.paths||0}))
 .sort((a,b)=>b.points-a.points||b.scenarios-a.scenarios||a.id.localeCompare(b.id)).map((user,i)=>({...user,rank:i+1}));
}
export function assertAdmin(user,email){if(!user)throw new HttpError(401,'Sign in first.');if(user.email!==email?.toLowerCase())throw new HttpError(403,'Administrator access required.');}
export async function submitAnswer({store,user,body,datasets,verify}){
 if(!user)throw new HttpError(401,'Sign in to save verified progress.');
 const {dataset,lang,exercise,query}=body;
 const meta=datasets.find(d=>d.id===dataset);
 if(!meta||!LANGUAGES.includes(lang)||!Number.isInteger(exercise)||exercise<0||exercise>9||typeof query!=='string'||!query.trim()||query.length>10000)throw new HttpError(400,'Invalid exercise or query.');
 const correct=await verify(query,lang,exercise,meta);
 if(!correct)return {correct:false};
 const created=await store.write(`completed/${user.id}/${dataset}/${lang}/${exercise}.json`,{at:new Date().toISOString()});
 return {correct:true,created};
}
