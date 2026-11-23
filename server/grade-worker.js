import {parentPort,workerData} from 'node:worker_threads';
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';
import {resolve} from 'node:path';
import {grade,createLessons} from '../dist/lessons.js';
try{
 const {query,lang,exercise,meta,root}=workerData;
 const {rows}=JSON.parse(gunzipSync(readFileSync(resolve(root,meta.file))));
 parentPort.postMessage({correct:grade(query,lang,createLessons(meta)[exercise],rows,Date.parse(meta.clock))});
}catch{parentPort.postMessage({error:'Query could not be evaluated. Check its syntax.'});}
