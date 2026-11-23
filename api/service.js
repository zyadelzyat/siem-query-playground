import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {Worker} from 'node:worker_threads';
import {store} from '../server/store.js';
import {hash,random,signed,unsign,verifyGoogle} from '../server/identity.js';
import {HttpError,summarize,publicBoard,assertAdmin,submitAnswer} from '../server/core.js';
import {SOURCES,acquisitionCounts} from '../dist/discovery.js';
const root=resolve(process.cwd(),'dist/datasets');
let datasetsPromise;
const datasets=()=>datasetsPromise??=readFile(resolve(root,'manifest.json'),'utf8').then(s=>JSON.parse(s).datasets);
const cookieOptions='; Path=/; HttpOnly; Secure; SameSite=Lax';
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(v=>v.trim().split('=').map(decodeURIComponent)).filter(a=>a.length===2));}
function setCookie(res,key,value,age){const existing=res.getHeader('Set-Cookie')||[];res.setHeader('Set-Cookie',[...existing,`${key}=${encodeURIComponent(value)}${cookieOptions}; Max-Age=${age}`]);}
function guardOrigin(req){if(req.headers.origin!==process.env.APP_ORIGIN)throw new HttpError(403,'Request origin not allowed.');}
async function currentUser(req){
 const token=cookies(req)['__Host-siem_session'];if(!token||!/^[\w-]{43}$/.test(token))return null;
 const session=await store.read(`sessions/${hash(token)}.json`);
 if(!session||session.expires<Date.now())return null;
 return store.read(`users/${session.userId}.json`);
}
async function records(){const [userPaths,completed]=await Promise.all([store.paths('users/'),store.paths('completed/')]);const users=(await Promise.all(userPaths.map(p=>store.read(p)))).filter(Boolean);return {users,scores:summarize(completed,await datasets()),completed};}
async function progress(user){return user?(summarize(await store.paths(`completed/${user.id}/`),await datasets()).get(user.id)?.progress||{}):{};}
function viewUser(user){return user?{id:user.id,alias:user.alias,name:user.name,isAdmin:user.email===process.env.ADMIN_EMAIL?.toLowerCase()}:null;}
// Terminating worker bounds execution time for arbitrary submitted queries.
function verify(query,lang,exercise,meta){return new Promise((resolve,reject)=>{
 const worker=new Worker(resolve(process.cwd(),'server/grade-worker.js'),{workerData:{query,lang,exercise,meta,root},resourceLimits:{maxOldGenerationSizeMb:384}});
 const timer=setTimeout(()=>{worker.terminate();reject(new HttpError(422,'Query took too long. Simplify it and retry.'));},8000);
 worker.once('message',message=>{clearTimeout(timer);message.error?reject(new HttpError(422,message.error)):resolve(message.correct);});
 worker.once('error',error=>{clearTimeout(timer);reject(error);});
 worker.once('exit',code=>{clearTimeout(timer);if(code!==0)reject(new HttpError(422,'Query could not be checked.'));});
});}
// Per-instance throttle limits accidental bursts; this is not a global abuse quota.
const bursts=new Map();function throttle(key,limit){const now=Date.now(),item=bursts.get(key);if(!item||item.until<now){if(bursts.size>5000)bursts.clear();bursts.set(key,{count:1,until:now+60000});return;}if(++item.count>limit)throw new HttpError(429,'Too many requests. Retry in a minute.');}
export default async function handler(req,res){
 res.setHeader('Cache-Control','private, no-store');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Content-Type','application/json; charset=utf-8');
 const send=(value,status=200)=>{res.statusCode=status;res.end(JSON.stringify(value));};
 try{
  if(!process.env.BLOB_READ_WRITE_TOKEN||!process.env.GOOGLE_CLIENT_ID||!process.env.APP_ORIGIN||!process.env.ADMIN_EMAIL)throw new HttpError(503,'Community accounts are not configured yet.');
  const action=new URL(req.url,'https://local.invalid').searchParams.get('action');
  if(!['GET','POST'].includes(req.method))throw new HttpError(405,'Method not allowed.');
  if(req.method==='POST')guardOrigin(req);
  const c=cookies(req),secret=process.env.BLOB_READ_WRITE_TOKEN;
  let body={};if(req.method==='POST'){body=req.body||{};if(typeof body==='string'){if(body.length>20000)throw new HttpError(413,'Request too large.');body=JSON.parse(body);}if(!body||typeof body!=='object'||Array.isArray(body))throw new HttpError(400,'Invalid request.');}
  if(action==='session'&&req.method==='GET'){
   const user=await currentUser(req);return send({user:viewUser(user),progress:await progress(user),clientId:process.env.GOOGLE_CLIENT_ID});
  }
  if(action==='nonce'&&req.method==='POST'){
   throttle(hash(req.headers['x-forwarded-for']||'unknown'),10);
   const nonce=`${Date.now()}:${random()}`;setCookie(res,'__Host-siem_nonce',signed(nonce,secret),600);return send({nonce:hash(nonce)});
  }
  if(action==='login'&&req.method==='POST'){
   throttle(hash(req.headers['x-forwarded-for']||'unknown'),10);
   const nonce=unsign(c['__Host-siem_nonce'],secret);
   if(!nonce||Date.now()-Number(nonce.split(':')[0])>600000||typeof body.credential!=='string'||body.credential.length>10000)throw new HttpError(401,'Sign-in expired. Try again.');
   let identity;try{identity=await verifyGoogle(body.credential,{audience:process.env.GOOGLE_CLIENT_ID,nonce:hash(nonce)});}catch{throw new HttpError(401,'Google sign-in could not be verified. Try again.');}
   const path=`users/${identity.id}.json`,old=await store.read(path);
   // Alias is pseudonymous by default. The verified email remains private.
   const profile={...identity,alias:old?.alias||`Learner-${identity.id.slice(0,8)}`,createdAt:old?.createdAt||new Date().toISOString()};
   await store.write(path,profile,true);
   const token=random();await store.write(`sessions/${hash(token)}.json`,{userId:identity.id,expires:Date.now()+7*86400000},false,7);
   setCookie(res,'__Host-siem_session',token,7*86400);setCookie(res,'__Host-siem_nonce','',0);
   return send({user:viewUser(profile),progress:await progress(profile)});
  }
  if(action==='visit'&&req.method==='POST'){
   let visitor=unsign(c['__Host-siem_visitor'],secret);
   if(!visitor||! /^[\w-]{43}$/.test(visitor)){visitor=random();const source=SOURCES.includes(body.source)?body.source:'direct';await store.write(`visitors/${source}/${hash(visitor)}.json`,{firstSeen:new Date().toISOString()});setCookie(res,'__Host-siem_visitor',signed(visitor,secret),365*86400);}
   return send({ok:true});
  }
  if(action==='leaderboard'&&req.method==='GET'){
   const {users,scores}=await records(),board=publicBoard(users,scores);
   return send({board:board.slice(0,100),learners:users.length,solvers:board.filter(u=>u.scenarios>0).length});
  }
  const user=await currentUser(req);
  if(action==='admin'&&req.method==='GET'){
   assertAdmin(user,process.env.ADMIN_EMAIL);
   const [{users,scores,completed},visits,meta]=await Promise.all([records(),store.paths('visitors/'),datasets()]);
   const board=publicBoard(users,scores),ranks=new Map(board.map(u=>[u.id,u]));
   return send({visitors:visits.length,learners:users.length,completions:completed.length,solvers:board.filter(u=>u.scenarios>0).length,
    users:users.map(u=>({...ranks.get(u.id),email:u.email,name:u.name,createdAt:u.createdAt})),acquisition:acquisitionCounts(visits),
    scenarios:meta.map(d=>({title:d.title,solvers:[...scores.values()].filter(s=>s.scenarioIds.includes(d.id)).length})),since:'2026-11-22'});
  }
  if(action==='logout'&&req.method==='POST'){
   if(c['__Host-siem_session'])await store.remove(`sessions/${hash(c['__Host-siem_session'])}.json`);
   setCookie(res,'__Host-siem_session','',0);return send({ok:true});
  }
  if(!user)throw new HttpError(401,'Sign in first.');
  if(action==='alias'&&req.method==='POST'){
   if(typeof body.alias!=='string'||! /^[\p{L}\p{N} _.-]{3,32}$/u.test(body.alias))throw new HttpError(400,'Use 3–32 letters, numbers, spaces, dots, dashes or underscores.');
   throttle(user.id,10);user.alias=body.alias.trim();if(user.alias.length<3)throw new HttpError(400,'Choose a longer display name.');await store.write(`users/${user.id}.json`,user,true);return send({user:viewUser(user)});
  }
  if(action==='submit'&&req.method==='POST'){
   throttle(user.id,20);const outcome=await submitAnswer({store,user,body,datasets:await datasets(),verify});return send({...outcome,progress:await progress(user)});
  }
  throw new HttpError(404,'Unknown action.');
 }catch(error){if(!error.status)console.error('Community API failure',error.name);send({error:error.status?error.message:'Service unavailable. Please retry.'},error.status||503);}
}
