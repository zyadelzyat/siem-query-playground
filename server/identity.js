import {createHash,createHmac,randomBytes,timingSafeEqual} from 'node:crypto';
import {createRemoteJWKSet,jwtVerify} from 'jose';
const googleKeys=createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
export const hash=value=>createHash('sha256').update(value).digest('hex');
export const random=()=>randomBytes(32).toString('base64url');
export function signed(value,secret){return value+'.'+createHmac('sha256',secret).update(value).digest('base64url');}
export function unsign(value,secret){
 if(typeof value!=='string')return null;
 const cut=value.lastIndexOf('.'),text=value.slice(0,cut),expected=signed(text,secret);
 return value.length===expected.length&&timingSafeEqual(Buffer.from(value),Buffer.from(expected))?text:null;
}
export async function verifyGoogle(credential,{audience,nonce,keys=googleKeys}){
 const {payload}=await jwtVerify(credential,keys,{issuer:['https://accounts.google.com','accounts.google.com'],audience,algorithms:['RS256'],maxTokenAge:'10m'});
 if(payload.email_verified!==true||typeof payload.email!=='string'||!payload.sub||payload.nonce!==nonce)throw Error('Invalid Google identity');
 return {id:hash(payload.sub),email:payload.email.toLowerCase(),name:String(payload.name||'Google learner').slice(0,100)};
}
