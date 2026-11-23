import {visitSource} from './discovery.js';
export async function api(action,body){
 const response=await fetch(`/api/service?action=${encodeURIComponent(action)}`,{method:body===undefined?'GET':'POST',credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
 let data;try{data=await response.json();}catch{throw Error('Accounts are available on the hosted website.');}
 if(!response.ok)throw Error(data.error||'Request failed.');return data;
}
export const community={user:null,async submit(body){const data=await api('submit',body);if(!data.correct)throw Error('The server could not confirm this answer. Check the query and retry.');return data;}};
const el=id=>document.getElementById(id);
function text(tag,value){const node=document.createElement(tag);node.textContent=value;return node;}
function session(data){community.user=data.user;const button=el('accountButton');if(button){button.textContent=data.user?data.user.alias:'Sign in with Google';button.disabled=false;}const admin=el('adminLink');if(admin)admin.hidden=!data.user?.isAdmin;document.dispatchEvent(new CustomEvent('siem:session',{detail:data}));}
function error(message){const node=el('communityStatus');if(node){node.textContent=message;node.hidden=false;}}
let clientId,googleScript;
function loadGoogle(){return googleScript??=new Promise((resolve,reject)=>{const script=document.createElement('script');script.src='https://accounts.google.com/gsi/client';script.onload=resolve;script.onerror=()=>{googleScript=null;reject(Error('Google sign-in could not load. Check your connection or browser blocking settings.'));};document.head.append(script);});}
async function showAccount(){
 const dialog=el('accountDialog'),body=el('accountContent');body.replaceChildren();dialog.showModal();
 if(community.user){
  body.append(text('p',`Signed in as ${community.user.name}. Your verified progress is saved to your account.`));
  const label=text('label','Public display name'),input=document.createElement('input');input.maxLength=32;input.value=community.user.alias;input.id='publicAlias';label.htmlFor=input.id;
  const save=text('button','Save display name');save.className='primary';save.onclick=async()=>{save.disabled=true;try{const data=await api('alias',{alias:input.value});session({...data,progress:undefined});error('Display name updated.');dialog.close();}catch(e){error(e.message);}finally{save.disabled=false;}};
  const logout=text('button','Sign out');logout.className='quiet';logout.onclick=async()=>{try{await api('logout',{});session({user:null,progress:{}});dialog.close();}catch(e){error(e.message);}};
  body.append(label,input,save,logout);return;
 }
 body.append(text('p','Save your progress, earn a place on the leaderboard, and continue on another device. A random public display name is assigned first; you can change it after signing in. Your email is visible only to the site administrator.'));
 const googleButton=document.createElement('div');body.append(googleButton);
 const status=text('p','Loading Google sign-in…');status.setAttribute('role','status');body.append(status);
 try{
  const [nonce]=await Promise.all([api('nonce',{}),loadGoogle()]);
  google.accounts.id.initialize({client_id:clientId,nonce:nonce.nonce,callback:async response=>{
   status.textContent='Verifying your Google account…';
   try{const data=await api('login',{credential:response.credential});session(data);dialog.close();error('Signed in. New verified answers will count toward your rank. Guest progress is kept on this device.');}
   catch(e){status.textContent=e.message;}
  }});
  google.accounts.id.renderButton(googleButton,{type:'standard',theme:'outline',size:'large',text:'signin_with'});status.textContent='Use the button to choose your Google account.';
 }catch(e){status.textContent=e.message;}
}
export function table(headers,rows){const wrap=document.createElement('div');wrap.className='table-wrap';const table=document.createElement('table'),head=document.createElement('thead'),tr=document.createElement('tr');for(const title of headers)tr.append(text('th',title));head.append(tr);table.append(head);const body=document.createElement('tbody');for(const values of rows){const row=document.createElement('tr');for(const value of values)row.append(text('td',String(value)));body.append(row);}table.append(body);wrap.append(table);return wrap;}
async function showLeaderboard(){
 const dialog=el('leaderboardDialog'),body=el('leaderboardContent');dialog.showModal();body.replaceChildren(text('p','Loading…'));
 try{const data=await api('leaderboard');body.replaceChildren(text('p',`${data.learners} registered learners · ${data.solvers} learners have completed a scenario.`),text('p','1 point per verified exercise in each language. A scenario is complete after all 10 exercises in one language. Ties share the same score; their display order is stable. Solutions are available: this is practice, not a certification exam.'));
  body.append(data.board.length?table(['Rank','Learner','Points','Scenarios','Language paths'],data.board.map(u=>[u.rank,u.alias,u.points,u.scenarios,u.paths])):text('p','Be the first learner on the board.'));
 }catch(e){body.replaceChildren(text('p',e.message));}
}
for(const button of document.querySelectorAll('[data-close]'))button.onclick=()=>el(button.dataset.close).close();
if(el('accountButton'))el('accountButton').onclick=()=>showAccount().catch(e=>error(e.message));
if(el('leaderboardButton'))el('leaderboardButton').onclick=showLeaderboard;
export const communityReady=api('session').then(data=>{clientId=data.clientId;session(data);return data;}).catch(e=>{error(e.message);return {user:null,error:e.message};});
// Record one browser identifier on the public workspace; no IP address is stored.
if(el('query'))api('visit',{source:visitSource(location.search)}).catch(()=>{});
