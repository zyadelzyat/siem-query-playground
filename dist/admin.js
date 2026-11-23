import {api,table,communityReady} from './community.js';
const target=document.getElementById('adminContent'),button=document.getElementById('refreshAdmin');
function paragraph(value){const p=document.createElement('p');p.textContent=value;return p;}
let loading=false;
async function load(){if(loading)return;loading=true;button.disabled=true;try{
 const data=await api('admin');target.replaceChildren();
 const cards=document.createElement('div');cards.className='activity-cards';
 for(const [label,value] of [['Unique browsers',data.visitors],['Registered learners',data.learners],['Verified exercises',data.completions],['Scenario solvers',data.solvers]]){const card=document.createElement('div'),strong=document.createElement('strong');strong.textContent=value.toLocaleString();card.append(strong,paragraph(label));cards.append(card);}target.append(cards);
 const h2=document.createElement('h2');h2.textContent='Learners';target.append(h2,table(['Rank','Public name','Google name','Email','Points','Scenarios','Language paths','Joined'],data.users.sort((a,b)=>a.rank-b.rank).map(u=>[u.rank,u.alias,u.name,u.email,u.points,u.scenarios,u.paths,u.createdAt.slice(0,10)])));
 const channels=document.createElement('h2');channels.textContent='Where visitors found the playground';target.append(channels,paragraph('First visit per browser, based on tagged links. Direct also includes untagged traffic; unattributed means visits from before source tracking.'),table(['Source','Unique browsers'],(data.acquisition||[]).map(s=>[s.source,s.visitors])));
 const h3=document.createElement('h2');h3.textContent='Scenario completions';target.append(h3,table(['Scenario','Learners who finished'],data.scenarios.map(s=>[s.title,s.solvers])));target.append(paragraph(`Updated ${new Date().toLocaleTimeString()}. Activity is available from this release onward.`));
 }catch(e){target.replaceChildren(paragraph(e.message));}finally{loading=false;button.disabled=false;}}
button.onclick=load;document.addEventListener('siem:session',()=>load());await communityReady;await load();
