'use strict';
let setupRefreshTimer;
function stopChatSetupRefreshing(){clearTimeout(setupRefreshTimer);}
async function showChatSetup(problem=null){
  stopChatSetupRefreshing();
  const query=new URLSearchParams(activeConversation?{conversation:activeConversation.id}:{team:activeTeam});
  if(problem?.code)query.set('problem',problem.code);
  let data;
  try{data=await api('/chat/requirements?'+query);}
  catch{data={ready:false,requirements:[{code:'gateway.unverified',title:'We could not check the team’s setup',message:'The local app could not read the current settings. Try checking again. Your draft has been kept.',actions:[]}]};}
  const cards=data.requirements.map(r=>`<article class="setup-card"><h3>${esc(r.title)}</h3><p>${esc(r.message)}</p><div class="card-actions">${r.actions.map(a=>`<button type="button" class="button secondary small" data-action="setup-${esc(a.kind)}" data-name="${esc(a.target||'')}">${esc(a.label)}</button>`).join('')}</div></article>`).join('');
  openEditor(data.ready?'Your team is ready':'Set up this chat','CHAT SETUP',data.ready?'<p>Your settings are ready. Return to Chat and send your message when you are ready.</p>':cards,async()=>{if(data.ready){await renderKeepingDraft();closeEditor();}else await showChatSetup();},data.ready?'Back to chat':'Check again');
  if(data.requirements.some(r=>r.code==='gateways.updating'))setupRefreshTimer=setTimeout(()=>{if(dialog.open&&$('#dialog-kicker').textContent==='CHAT SETUP')showChatSetup().catch(()=>{});},1200);
}
async function renderKeepingDraft(){const draft=$('#message-input')?.value;await refresh();await render();if(draft!=null&&$('#message-input'))$('#message-input').value=draft;}
function preferenceValues(g){const s=g.settings;return {monthly_token_limit:s.monthly_token_limit,per_run_token_limit:s.per_run_token_limit,daily_token_limit:s.daily_token_limit,jurisdictions:s.jurisdictions,mode:s.mode,activities:s.activities,safeguarding_contact:s.safeguarding_contact};}
async function chatSetupAction(kind,target){
  stopChatSetupRefreshing();
  if(kind==='edit_draft'){closeEditor();$('#message-input')?.focus();return;}
  if(kind==='agent_tools'){await refresh();editAgent(target);return;}
  if(kind==='choose_chat'){closeEditor();await newChat();return;}
  if(kind==='reset_context'){
    const draft=$('#message-input')?.value||'';
    const id=activeConversation.id;
    openEditor('Continue without earlier context','CHAT CONTEXT','<p>Your earlier messages stay visible in this chat, but the team will not receive them in future requests. Your draft is kept. You can include an edited version of any details you still need.</p>',async()=>{
      activeConversation=await api('/conversations/'+id+'/context/reset','POST');
      closeEditor();await render();$('#message-input').value=draft;$('#message-input').focus();
    },'Continue in this chat');return;
  }
  if(kind==='sanitise'){
    const input=$('#message-input');
    const result=await api('/chat/sanitise','POST',{message:input?.value||''});
    closeEditor();if(input){input.value=result.draft;input.focus();}toast(result.message);return;
  }
  if(kind==='wait'){await showChatSetup();return;}
  if(kind==='sandbox'){await showSandboxSettings();return;}
  if(kind==='auth'){await refresh();await showConnectionAuth(target,true,()=>mcpResumeReview(target,true));return;}
  if(kind==='reconnect'){await api('/services/apply','POST');await showChatSetup();return;}
  if(kind==='discover'){await showMcpSetup(target,null,true);return;}
  if(kind==='resume'){await api('/guardrails/resume','POST');await showChatSetup();return;}
  if(kind==='secret'){await refresh();closeEditor();editSecret(target,async()=>{await showChatSetup();});return;}
  guardrailState=await api('/guardrails');
  if(kind==='tokens'){
    const g=guardrailState,s=g.settings;
    openEditor('Token allowance','CHAT TOKENS',`<p>These limits count input and output tokens. They do not require model prices or currency conversion.</p>`+field('monthly_token_limit','Monthly token allowance',s.monthly_token_limit??1000000,'number','Leave blank to switch AI responses off.')+field('per_run_token_limit','Total tokens per turn',s.per_run_token_limit,'number','Includes the complete context and follow-up model calls.')+field('daily_token_limit','Daily token allowance',s.daily_token_limit??'','number','Leave blank for the automatic daily limit.'),async form=>{
      const f=formObject(form),settings=preferenceValues(g);
      settings.monthly_token_limit=f.monthly_token_limit?Number(f.monthly_token_limit):null;
      settings.per_run_token_limit=Number(f.per_run_token_limit||50000);
      settings.daily_token_limit=f.daily_token_limit?Number(f.daily_token_limit):null;
      await api('/guardrails/settings','PUT',{revision:g.revision,settings});await showChatSetup();
    },'Save allowance');
    return;
  }
  if(kind==='technical_limits')guardEditScope('workspace');
  else if(kind==='model')guardEditModel(target);
  else if(kind==='model_settings')editModel(target);
  else if(kind==='tool'){const connection=state.catalog.find(t=>t.name===target)?.server;if(connection){await showMcpSetup(connection,null,true);return;}guardAccess(target);}
  else if(kind==='command'){await showMcpSetup(target,null,true);return;}
  else if(kind==='organisation'){
    const g=guardrailState;
    openEditor('Organisation activities','CHAT SETTINGS',['fundraising','beneficiary_data','campaigning','finance'].map(k=>checked(k,k.replaceAll('_',' '),g.settings.activities[k])).join(''),async form=>{const f=formObject(form),settings=preferenceValues(g);for(const k of Object.keys(settings.activities))settings.activities[k]=!!f[k];await api('/guardrails/settings','PUT',{revision:g.revision,settings});await showChatSetup();},'Save choices');return;
  }
  editorAfterSave=async()=>showChatSetup();
}
