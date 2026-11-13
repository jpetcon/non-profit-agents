'use strict';
function connectorSteps(step){return '<ol class="mcp-steps" aria-label="Connection setup">'+['Connect','Choose information','Choose agents'].map((s,i)=>`<li${i===step?' aria-current="step"':''}>${i+1}. ${s}</li>`).join('')+'</ol>';}
function connectorCatalogue(view){
  openEditor('Add connection','CONNECTION CATALOGUE','<p>Connect a service, choose what agents may read, then choose agents. New content stays a local draft.</p>'+field('connector_search','Search services','','search')+select('connector_category','Category',[['','All categories'],...([...new Set(view.presets.map(p=>p.category).filter(Boolean))].map(c=>[c,c]))],'')+'<div id="connector-catalogue" class="mcp-presets"></div><details class="section-space"><summary>Advanced</summary><p>Custom commands, HTTP tools and authentication registration.</p><button type="button" class="button secondary small" data-action="mcp-setup-advanced">Custom connection</button><button type="button" class="button secondary small" data-action="http-new">Create API tool</button></details>',null);
  filterConnectorCatalogue();
}
function filterConnectorCatalogue(){
  const view=mcpSetupView,el=$('#connector-catalogue');if(!view||!el)return;
  const q=($('#f-connector_search')?.value||'').toLowerCase(),category=$('#f-connector_category')?.value;
  const items=view.presets.filter(p=>(!category||p.category===category)&&[p.name,p.description,p.category].join(' ').toLowerCase().includes(q));
  el.innerHTML=items.map(p=>`<button type="button" class="card mcp-preset" data-action="mcp-setup-preset" data-name="${esc(p.id)}"><strong>${esc(p.name)}</strong><span>${esc(p.description)}</span><small>${esc(p.category||'Advanced')}</small></button>`).join('')||'<p>No matching services.</p>';
}
async function connectorNew(view){
  const p=view.presets.find(p=>p.id===view.preset);
  if(p.route==='installed'){
    openEditor('Masterbrand','EXISTING TOOLS','<p>Masterbrand is already installed. Choose its tools in the agent settings. Existing assignments are kept.</p>',null);return;
  }
  let content=connectorSteps(0)+`<p>${esc(p.description)}</p>${p.prerequisite?`<div class="subtle-box"><strong>Before connecting</strong><p>${esc(p.prerequisite)}</p></div>`:''}`+field('connector_name','Connection name',p.name);
  for(const f of p.fields||[])content+=field('connector_'+f.key,f.label,'',f.secret?'password':f.key==='server_url'||f.key==='site_url'?'url':'text',f.hint,f.required);
  if(['key','token','session','basic'].includes(p.authentication))content+=field('connector_key',p.authentication==='basic'?'Application password':p.authentication==='token'?'Access token':'API key','','password','Stored privately on this computer; never written into YAML or sent to a model.',true);
  else if(p.authentication!=='none')content+='<p>You will review the service, sign-in provider and requested permissions before opening its browser sign-in page. Provider registration may require one-time administrator setup.</p>';
  if(p.source)content+=`<a href="${esc(p.source)}" target="_blank" rel="noopener noreferrer">Provider setup instructions ↗</a>`;
  openEditor('Connect '+p.name,'GUIDED CONNECTION',content,async form=>{
    const f=formObject(form),options={},credentials={};
    for(const field of p.fields||[]){const value=f['connector_'+field.key]||'';if(value)(field.secret?credentials:options)[field.key]=value;}
    const result=await api('/connections/setup','POST',{revision:state.revision,preset:p.id,display_name:f.connector_name,options,credentials,api_key:f.connector_key||''});
    view.name=result.name;await refresh();await connectorSaved(view);
  },'Save and connect');
}
async function connectorSaved(view){
  view.catalogue=await api('/connections/'+encodeURIComponent(view.name)+'/setup');
  if(view!==mcpSetupView)return;
  const p=view.catalogue.managed,s=state.tools.mcp_servers[view.name],a=state.connection_auth?.[view.name]||{},admin=a.provider_setup&&!a.provider_setup.configured;
  const content=connectorSteps(0)+`<p>${esc(p.description)}</p>${p.prerequisite?`<p class="help">${esc(p.prerequisite)}</p>`:''}<p role="status"><strong>${admin?'Administrator setup needed':a.status==='connected'?'Ready to check connection':esc(authenticationLabels[a.status]||'Not connected')}</strong></p>${connectionSetupSummary(view.name,s)}`+(admin?'<button type="button" class="button secondary" data-action="connector-provider">Administrator setup</button>':['api_oauth','oauth'].includes(a.method)?'<button type="button" class="button secondary" data-action="connector-signin">'+(a.status==='connected'?'Reconnect':'Connect')+'</button>':'')+(['key','token','session','basic','bearer'].includes(a.method)?`<details><summary>Replace credentials</summary>${field('replacement_key','New API key or token','','password')}<button type="button" class="button secondary small" data-action="connector-key">Save and retry</button><button type="button" class="button secondary small" data-action="connector-disconnect">Disconnect</button></details>`:'')+'<p class="help">Checking reads account or permission metadata only. No reports, supporter records or model calls.</p><details><summary>Advanced</summary><p>Unknown or changed hosted MCP definitions require technical review before capability access.</p>'+(s.transport==='native'?'<p>API destinations, methods and schemas are maintained by this installation.</p>':'<button type="button" class="button secondary" data-action="connector-technical">Review hosted tools</button>')+`<button type="button" class="button danger small" data-action="mcp-delete" data-name="${esc(view.name)}">Delete connection</button></details>`;
  openEditor('Connect '+(s.display_name||p.name),'GUIDED CONNECTION',content,async()=>{
    if(['api_oauth','oauth'].includes(a.method)&&a.status!=='connected'){await showConnectionAuth(view.name,view.fromChat,()=>connectorResume(view.name,view.fromChat));return;}
    $('#form-error').textContent='Checking connection and account choices…';
    await api('/connections/'+encodeURIComponent(view.name)+'/test','POST');
    await refresh();await connectorInformation(view);
  },admin?'Check after administrator setup':'Check connection and choose information');
}
async function connectorResume(name,fromChat){await showMcpSetup(name,null,fromChat);const view=mcpSetupView;if(state.connection_auth?.[name]?.status==='connected'){await api('/connections/'+encodeURIComponent(name)+'/test','POST');await refresh();await connectorInformation(view);}}
async function connectorInformation(view){
  view.catalogue=await api('/connections/'+encodeURIComponent(view.name)+'/setup');if(view!==mcpSetupView)return;
  const c=view.catalogue;
  const resources=(c.resources||[]).map(r=>`<label class="check-option"><input type="checkbox" name="resource" value="${esc(r.id)}" ${c.selected_resources.includes(r.id)?'checked':''}><span>${esc(r.label)}</span></label>`).join('');
  const enabled=c.capabilities.filter(cap=>cap.enabled||cap.default_enabled);
  const summary='<p id="connector-read-summary">Read-only access: '+(enabled.map(cap=>esc(cap.label)).join(', ')||'no capabilities selected')+'.</p>';
  const caps=c.capabilities.map(cap=>`<label class="check-option"><input type="checkbox" name="capability" value="${esc(cap.id)}" ${cap.enabled||cap.default_enabled?'checked':''} ${cap.available?'':'disabled'}><span><b>${esc(cap.label)}</b><small>${esc(cap.description)} · ${esc(cap.data_class)} information${cap.available?'':' · Administrator review needed'}</small></span></label>`).join('');
  openEditor('Choose information','GUIDED CONNECTION',connectorSteps(1)+'<p>Maintained tools read information only. Choose the accounts or sources they may access, then choose agents.</p>'+summary+'<details><summary>Advanced — individual capabilities</summary><div class="check-grid">'+caps+'</div></details>'+(c.managed.route==='native'?'<h3>Accounts and sources</h3><p class="help">Only the selected accounts, folders or libraries may be accessed. Up to 50 choices are shown; narrow large installations with an administrator.</p><div class="check-grid">'+(resources||'<p>No accessible resources found. Reconnect or ask your administrator to check permissions.</p>')+'</div>':'')+'<p class="help">Personal information and documents still require an authorised data-processing workflow before an external model can receive them.</p>'+(c.technical_review_required?'<div class="subtle-box"><p>Some hosted definitions need administrator review. Authentication cannot approve unknown tools.</p><button type="button" class="button secondary" data-action="connector-technical">Advanced tool review</button></div>':''),async form=>{
    view.capabilities=$$('input[name="capability"]:checked',form).map(e=>e.value);view.resources=$$('input[name="resource"]:checked',form).map(e=>e.value);
    if(c.managed.route==='native'&&!view.resources.length)throw Error('Choose at least one account or source.');
    connectorAgents(view);
  },'Choose agents');
}
function connectorAgents(view){
  const caps=view.catalogue.capabilities.filter(c=>view.capabilities.includes(c.id));
  let content=connectorSteps(2)+'<p>Choose who may use each capability. Existing selections are shown; new capabilities and agents are never selected automatically.</p>';
  for(const [team,t] of Object.entries(state.agents.teams)){
    content+=`<section class="setup-card"><h3>${esc(t.display_name)}</h3><div class="check-grid">`;
    for(const agent of teamMembers(team)){
      if(caps.length>1)content+=`<div class="subtle-box"><strong>${esc(agentName(agent))}</strong>`;
      for(const cap of caps)content+=`<label class="check-option"><input type="checkbox" name="connector_agent" data-connector-cap="${esc(cap.id)}" value="${esc(agent)}" ${(state.agents.agents[agent].tools||[]).some(n=>cap.tools.includes(n))?'checked':''}><span>${esc(caps.length===1?agentName(agent):cap.label)}</span></label>`;
      if(caps.length>1)content+='</div>';
    }
    content+='</div></section>';
  }
  if(!caps.length)content+='<p>No capabilities selected. Saving will disable this connection’s tool access and keep other assignments.</p>';
  openEditor('Choose agents','GUIDED CONNECTION',content,async form=>{
    const assignments=Object.fromEntries(Object.keys(state.agents.agents).map(agent=>[agent,$$('input[name="connector_agent"]:checked',form).filter(e=>e.value===agent).map(e=>e.dataset.connectorCap)]));
    await api('/connections/'+encodeURIComponent(view.name)+'/information/complete','POST',{revision:view.catalogue.revision,configuration_hash:view.catalogue.configuration_hash,capabilities:view.capabilities,resources:view.resources,agents:[],assignments});
    const chat=view.fromChat;await saved('Connection ready. Changes connect automatically.');if(chat)await showChatSetup();
  },'Save information access');
}

async function connectorProvider(provider,back){
  if(provider==='google'){await showGoogleProviderSetup(back);return;}
  const p=await api('/providers/'+provider+'/setup');
  const sources={microsoft:'https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app',blackbaud:'https://developer.blackbaud.com/skyapi/docs/authorization',linkedin:'https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow'};
  openEditor('Administrator setup — '+provider,'PROVIDER SETUP',`<p>Register an OAuth application once in the provider’s developer console and enable the API access required by this connector. Use the same loopback callback port below in its registered redirect: <code>http://127.0.0.1:PORT/callback</code>. These settings are shared; replacing them requires affected accounts to reconnect.</p><a href="${sources[provider]}" target="_blank" rel="noopener noreferrer">Provider registration instructions ↗</a>`+field('registration_client','Application client ID','','text','',true)+field('registration_secret','Client secret','','password','Leave blank for a Microsoft public client.')+field('registration_port','Registered callback port','8766','number','Choose an unused port from 1024 to 65535.',true),async form=>{
    const f=formObject(form);await api('/providers/'+provider+'/setup','PUT',{revision:p.revision,client_id:f.registration_client,client_secret:f.registration_secret,callback_port:Number(f.registration_port)});await refresh();await back();
  },'Save administrator setup');
}
document.addEventListener('input',e=>{if(e.target.id==='f-connector_search')filterConnectorCatalogue();});
document.addEventListener('change',e=>{if(e.target.id==='f-connector_category')filterConnectorCatalogue();});
document.addEventListener('click',async e=>{
  const b=e.target.closest('[data-action^="connector-"]');if(!b)return;e.preventDefault();
  const view=mcpSetupView;if(!view)return;
  b.disabled=true;
  try{
    const action=b.dataset.action;
    if(action==='connector-provider'){const a=state.connection_auth[view.name];await connectorProvider(a.provider,()=>showMcpSetup(view.name,null,view.fromChat));}
    if(action==='connector-signin')await showConnectionAuth(view.name,view.fromChat,()=>connectorResume(view.name,view.fromChat));
    if(action==='connector-technical')await mcpReviewTools(view);
    if(action==='connector-disconnect'){await api('/connections/'+encodeURIComponent(view.name)+'/auth/disconnect','POST');await refresh();await connectorSaved(view);}
    if(action==='connector-key'){await api('/connections/'+encodeURIComponent(view.name)+'/setup/key','PUT',{revision:state.revision,api_key:$('#f-replacement_key').value});await refresh();await connectorSaved(view);}
  }catch(error){$('#form-error').textContent=error.message;}finally{b.disabled=false;}
});

document.addEventListener('change',e=>{if(e.target.name!=='capability')return;const el=$('#connector-read-summary');if(el)el.textContent='Read-only access: '+($$('input[name="capability"]:checked',dialog).map(input=>mcpSetupView.catalogue.capabilities.find(c=>c.id===input.value)?.label).join(', ')||'no capabilities selected')+'.';});
