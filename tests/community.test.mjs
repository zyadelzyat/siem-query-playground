import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {Worker} from 'node:worker_threads';
import {generateKeyPair,exportJWK,createLocalJWKSet,SignJWT} from 'jose';
import {summarize,publicBoard,assertAdmin,submitAnswer} from '../server/core.js';
import {signed,unsign,verifyGoogle} from '../server/identity.js';
import {createLessons} from '../dist/lessons.js';
const id='a'.repeat(64),other='b'.repeat(64),user={id,email:'owner@example.test',alias:'Learner-A',name:'Private name'},datasets=[{id:'capture'}];
function memory(){const data=new Map();return {data,async write(path,value){if(data.has(path))return false;data.set(path,value);return true;}};}
test('repeated and concurrent correct submissions count once',async()=>{
 const store=memory(),args={store,user,body:{dataset:'capture',lang:'spl',exercise:0,query:'index=lab'},datasets,verify:async()=>true};
 const results=await Promise.all(Array.from({length:8},()=>submitAnswer(args)));
 assert.equal(results.filter(r=>r.created).length,1);assert.equal(store.data.size,1);
 assert.equal(summarize([...store.data.keys()],datasets).get(id).points,1);
});
test('client scores and correctness claims never create a completion',async()=>{
 const store=memory();const result=await submitAnswer({store,user,body:{dataset:'capture',lang:'spl',exercise:0,query:'wrong',correct:true,points:600,userId:other},datasets,verify:async()=>false});
 assert.equal(result.correct,false);assert.equal(store.data.size,0);
});
test('anonymous and invalid submissions are rejected',async()=>{
 const args={store:memory(),user,body:{dataset:'../capture',lang:'spl',exercise:0,query:'x'},datasets,verify:async()=>{throw Error('must not run');}};
 await assert.rejects(submitAnswer({...args,user:null}),e=>e.status===401);
 for(const body of [args.body,{dataset:'capture',lang:'shell',exercise:0,query:'x'},{dataset:'capture',lang:'kql',exercise:10,query:'x'},{dataset:'capture',lang:'kql',exercise:0,query:'x'.repeat(10001)}])await assert.rejects(submitAnswer({...args,body}),e=>e.status===400);
});
test('ten exercises in a single language complete a scenario only once',()=>{
 const paths=[];for(let i=0;i<10;i++)paths.push(`completed/${id}/capture/spl/${i}.json`);
 let score=summarize(paths,datasets).get(id);assert.equal(score.scenarios,1);assert.equal(score.paths,1);
 for(let i=0;i<10;i++)paths.push(`completed/${id}/capture/kql/${i}.json`);
 score=summarize(paths,datasets).get(id);assert.equal(score.points,20);assert.equal(score.scenarios,1);assert.equal(score.paths,2);
 const partial=paths.filter(p=>!p.endsWith('/9.json'));assert.equal(summarize(partial,datasets).get(id).scenarios,0);
});
test('public leaderboard excludes private identity fields',()=>{
 const board=publicBoard([user],new Map());assert.equal(board[0].alias,'Learner-A');
 assert.deepEqual(Object.keys(board[0]).sort(),['alias','id','paths','points','rank','scenarios']);assert.ok(!JSON.stringify(board).includes(user.email));assert.ok(!JSON.stringify(board).includes(user.name));
});
test('only configured verified owner can access admin',()=>{
 assert.throws(()=>assertAdmin(null,user.email),e=>e.status===401);
 assert.throws(()=>assertAdmin({...user,email:'visitor@example.test',isAdmin:true},user.email),e=>e.status===403);
 assert.doesNotThrow(()=>assertAdmin(user,user.email));
});
test('nonce and visitor cookies reject tampering',()=>{
 const value=signed('nonce','secret');assert.equal(unsign(value,'secret'),'nonce');assert.equal(unsign(value+'x','secret'),null);assert.equal(unsign(value,'different'),null);
});
test('Google identity checks signature, audience, issuer, nonce and verified email',async()=>{
 const {publicKey,privateKey}=await generateKeyPair('RS256'),jwk=await exportJWK(publicKey);jwk.kid='test';const keys=createLocalJWKSet({keys:[jwk]});
 const make=(changes={})=>new SignJWT({email:'OWNER@example.test',email_verified:true,nonce:'nonce',sub:'google-sub',aud:'client',iss:'https://accounts.google.com',iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+300,...changes}).setProtectedHeader({alg:'RS256',kid:'test'}).sign(privateKey);
 const options={audience:'client',nonce:'nonce',keys};const identity=await verifyGoogle(await make(),options);assert.equal(identity.email,'owner@example.test');assert.equal(identity.id.length,64);
 for(const changes of [{email_verified:false},{nonce:'forged'},{aud:'another-client'},{iss:'https://evil.test'},{exp:1}])await assert.rejects(verifyGoogle(await make(changes),options));
 await assert.rejects(verifyGoogle(await make(),{...options,audience:'wrong-client'}));
});
test('server grading worker evaluates a real capture and rejects wrong results',async()=>{
 const root=resolve('dist/datasets'),meta=JSON.parse(await readFile(resolve(root,'manifest.json'),'utf8')).datasets[0];
 const check=query=>new Promise((resolve,reject)=>{const worker=new Worker(new URL('../server/grade-worker.js',import.meta.url),{workerData:{query,lang:'spl',exercise:0,meta,root}});worker.once('message',resolve);worker.once('error',reject);});
 assert.equal((await check(createLessons(meta)[0].solution('spl'))).correct,true);
 assert.equal((await check('index=lab | head 1')).correct,false);
});
