'use strict';
let mcpSetupView=null;
function connectionSetupSummary(id,s){
  const info=state.connection_setup?.[id]||{},status=info.connection==='connected'?'Connected at last test':info.connection==='failed'?'Connection failed — retry setup':'Not tested yet';
  const method=s.auth?.type||state.connection_auth?.[id]?.method;
  const sandbox=state.sandbox;
  const local=s.transport==='stdio'&&sandbox?.enabled;
  const sandboxInfo=sandbox?.connections?.find(c=>c.name===id);
  const hasKey=s.token_env||Object.keys(s.header_secrets||{}).length||(s.env_vars||[]).length||Object.keys(s.env_secrets||{}).length;
  const authentication=['oauth','google_adc'].includes(method)?'':`<p class="help">Authentication: ${!hasKey?'No sign-in required':state.connection_auth?.[id]?.status==='connected'?'Credentials configured':'Credentials required'}</p>`;
  return `<p class="help">Connection: ${esc(status)}<br>Tool access: ${Number(info.reviewed||0)} of ${Number(info.total||0)} tools reviewed and enabled</p>${authentication}${local?`<p class="help">Local sandbox: ${sandboxInfo?.ready?'Ready':'Needs attention'}</p><button type="button" class="button ghost small" data-action="sandbox-manage">Review local tool sandbox</button>`:''}`;
}
function stopMcpSetup(){mcpSetupView=null;}
function mcpSteps(step){return `<ol class="mcp-steps" aria-label="Connection setup">${['Choose service','Connect','Review tools','Choose agents'].map((label,i)=>`<li${step===i?' aria-current="step"':''}>${i+1}. ${label}</li>`).join('')}</ol>`;}
async function showMcpSetup(name=null,preset=null,fromChat=page==='chat'){
  stopMcpAuthPolling(true);stopChatSetupRefreshing();
  const catalogue=await api('/connection-presets');
  const view=mcpSetupView={name,preset,fromChat,presets:catalogue.presets};
  if(name){await refresh();if(view!==mcpSetupView)return;if(state.tools.mcp_servers[name]?.managed){await connectorSaved(view);return;}await mcpConnectSaved(view);}
  else if(preset)await mcpConnectNew(view);
  else connectorCatalogue(view);
}
async function mcpConnectNew(view){
  const p=view.presets.find(p=>p.id===view.preset);if(!p)throw Error('Choose a service.');
  if(['native','hosted','installed'].includes(p.route)){await connectorNew(view);return;}
  view.provider=p.id==='google'?await api('/providers/google/setup'):null;
  if(view!==mcpSetupView)return;
  let content=mcpSteps(1)+`<p>${esc(p.description)}</p>`+field('setup_name','Connection name',p.id==='remote'?'':p.name,'text','A name is suggested from the server link if you leave this blank.');
  if(p.id==='remote')content+=field('setup_url','MCP server link','','url','Paste the full endpoint supplied by the service.',true)+'<button type="button" class="button secondary small" data-action="mcp-setup-check">Check link</button><p id="mcp-check-result" class="help" role="status">Checking a link sends no credentials and executes no tools.</p>'+select('setup_auth','How do you connect?',[['none','No authentication'],['oauth','Sign in through your browser'],['key','API key (bearer token)']],'none');
  if(p.id==='remote'||p.id==='brave')content+=`<div id="mcp-setup-key">${field('setup_key','API key','','password','Saved privately on this computer. Never sent to an AI model.',p.id==='brave')}</div>`;
  if(p.command)content+=`<div class="subtle-box"><strong>Runs on this computer</strong><p>Publisher: ${esc(p.publisher)}. This installs and runs a pinned package with the connection’s selected credentials.</p><a href="${esc(p.source)}" target="_blank" rel="noopener noreferrer">Publisher’s setup instructions ↗</a><details><summary>Exact package command</summary><pre class="test-output">${esc(JSON.stringify(p.command,null,2))}</pre></details>${checked('setup_confirm','I approve running this local package',false)}</div>`;
  if(p.id==='google')content+=view.provider.configured?`<p class="help">Google provider setup is ready · Project: ${esc(view.provider.project)}. Next, sign in and grant read-only Analytics access.</p>`:'<div class="subtle-box"><p>A technical administrator must register a Google OAuth desktop app and enable the Analytics APIs once for this installation. Then everyone using this installation can sign in here.</p><button type="button" class="button secondary" data-action="mcp-setup-provider">Set up Google provider</button></div>';
  content+='<details class="section-space"><summary>Advanced</summary><button type="button" class="button secondary small" data-action="mcp-setup-advanced">Custom connection settings</button></details>';
  openEditor('Connect '+p.name,'GUIDED CONNECTION',content,async form=>{
    const f=formObject(form),result=await api('/connections/setup','POST',{revision:state.revision,preset:p.id,display_name:f.setup_name,url:f.setup_url||'',authentication:p.id==='brave'?'key':f.setup_auth||'none',api_key:f.setup_key||'',confirm_local:!!f.setup_confirm});
    if(view!==mcpSetupView)return;
    view.name=result.name;await refresh();if(view!==mcpSetupView)return;
    await mcpConnectSaved(view);
    await mcpConnect(view);
  },p.id==='google'?'Save and sign in':'Connect and discover tools');
  toggleMcpSetupKey();
}
function toggleMcpSetupKey(){const selector=$('#f-setup_auth'),key=$('#mcp-setup-key');if(!selector||!key)return;key.hidden=selector.value!=='key';$('#f-setup_key').required=selector.value==='key';if(selector.value!=='key')$('#f-setup_key').value='';}
async function mcpConnectSaved(view){
  view.catalogue=await api('/connections/'+encodeURIComponent(view.name)+'/setup');
  const spec=state.tools.mcp_servers[view.name];
  if(!spec)throw Error('This connection no longer exists.');
  const auth=spec.auth?.type||state.connection_auth?.[view.name]?.method||'none',signIn=['oauth','google_adc'].includes(auth),status=state.connection_auth?.[view.name];
  if(view!==mcpSetupView)return;
  let content=mcpSteps(1)+`<p><strong>${esc(spec.display_name||view.name)}</strong></p><p>${spec.transport==='stdio'?'Runs locally on this computer':esc(spec.url)}</p>${connectionSetupSummary(view.name,spec)}<p role="status">Authentication: ${esc(authenticationLabels[status?.status]||'Not connected')}. Tool access is reviewed separately.</p>`;
  if(!spec.enabled)content+='<p>This connection is disabled. Enable it under Advanced before connecting.</p>';
  if(view.catalogue.command_review_required)content+=`<div class="subtle-box"><p>This software runs on your computer with its configured credentials. Approve the exact command before discovery.</p><pre class="test-output">${esc(JSON.stringify([spec.command,...spec.args],null,2))}</pre>${checked('setup_confirm','I approve running this local command',false)}</div>`;
  if(signIn)content+=`<p class="help">${esc(status?.message||'Sign in to connect this service.')}</p><button type="button" class="button secondary small" data-action="mcp-setup-signin">${status?.status==='connected'?'Manage sign-in':'Sign in'}</button>`;
  const brave=view.presets.find(p=>p.id==='brave'),simpleKey=auth==='bearer'||JSON.stringify([spec.command,...(spec.args||[])])===JSON.stringify(brave.command);
  if(simpleKey)content+=`<details class="section-space"><summary>Replace API key</summary>${field('replacement_key','New API key','','password','Changes this connection only; existing shared secrets are kept.')}<button type="button" class="button secondary small" data-action="mcp-setup-key">Save key and retry</button></details>`;
  if(auth==='google_adc'&&!status?.provider_setup?.configured)content+='<p class="help">You can configure Google once for this installation, or import existing user credentials in the sign-in card.</p><button type="button" class="button secondary small" data-action="mcp-setup-provider">Google provider setup</button>';
  content+='<p class="help">Connecting lists tool definitions. It does not execute tools or contact an AI model.</p><details class="section-space"><summary>Advanced</summary><button type="button" class="button secondary small" data-action="mcp-setup-advanced">Edit connection settings</button></details>';
  openEditor('Connect '+(spec.display_name||view.name),'GUIDED CONNECTION',content,async()=>mcpConnect(view),view.catalogue.tools.length?'Check connection and review tools':'Connect and discover tools');
}
async function mcpApproveCommand(view){
  if(view.catalogue?.command_review_required){
    if(!$('#f-setup_confirm')?.checked)throw Error('Approve the exact local command before connecting.');
    await api('/guardrails/connections/'+encodeURIComponent(view.name)+'/review','POST',{revision:state.revision});
    await refresh();view.catalogue.command_review_required=false;
  }
}
async function mcpConnect(view){
  await mcpApproveCommand(view);
  if(view!==mcpSetupView)return;
  const spec=state.tools.mcp_servers[view.name],method=spec.auth?.type;
  if(['oauth','google_adc'].includes(method)){
    const auth=await api('/connections/'+encodeURIComponent(view.name)+'/auth');
    if(view!==mcpSetupView)return;
    if(auth.status!=='connected'){await showConnectionAuth(view.name,view.fromChat,()=>mcpResumeReview(view.name,view.fromChat));return;}
  }
  $('#form-error').textContent='Connecting and checking tool definitions…';
  await api('/connections/'+encodeURIComponent(view.name)+'/test','POST');
  if(view!==mcpSetupView)return;
  await refresh();await mcpReviewTools(view);
}
async function mcpResumeReview(name,fromChat){
  await showMcpSetup(name,null,fromChat);
  const view=mcpSetupView,auth=await api('/connections/'+encodeURIComponent(name)+'/auth');
  if(view===mcpSetupView&&auth.status==='connected'&&view?.catalogue.tools.length)await mcpReviewTools(view);
}
async function mcpReviewTools(view){
  view.catalogue=await api('/connections/'+encodeURIComponent(view.name)+'/setup');
  if(view!==mcpSetupView)return;
  const tools=view.catalogue.tools;
  if(!tools.length)throw Error('No current tools were found. Retry connecting or check the server settings.');
  if(tools.every(t=>t.curated)&&!view.forceReview){
    view.reviews=Object.fromEntries(tools.map(t=>[t.name,{schema_hash:t.schema_hash,permission:t.permission,data_class:t.data_class,workflow:t.workflow}]));
    mcpChooseAgents(view);return;
  }
  const workflows=[['none','General research and drafting'],['fundraising','Fundraising'],['safeguarding','Safeguarding'],['campaigning','Campaigning'],['financial','Finance and grants'],['gift_aid','Gift Aid']];
  const content=mcpSteps(2)+'<p>Review what each tool actually does. Server descriptions are supplied by the service. Choosing Read is your confirmation that a tool only reads or searches.</p><p class="help">Personal information requires approved processing arrangements. Consent, charity evidence and other guardrails still apply.</p>'+tools.map((t,i)=>`<article class="setup-card"><h3>${esc(t.label||t.name)}</h3><p>${esc(t.description||'No description supplied. Leave blocked unless you can verify its behaviour.')}</p>${select('permission_'+i,'Access to '+(t.label||t.name),[['blocked','Blocked'],['read','Read'],['review','Ask before acting']],view.reviews?.[t.name]?.permission||t.permission)}${select('data_'+i,'Information accessed by '+(t.label||t.name),[['public','Public'],['personal','Personal'],['sensitive','Sensitive']],view.reviews?.[t.name]?.data_class||t.data_class)}<details><summary>Charity workflow and technical definition</summary>${select('workflow_'+i,'Workflow for '+(t.label||t.name),workflows,view.reviews?.[t.name]?.workflow||t.workflow)}<pre class="test-output">${esc(JSON.stringify({input:t.input_schema,output:t.output_schema},null,2))}</pre></details></article>`).join('');
  openEditor('Review tools','GUIDED CONNECTION',content,async form=>{
    const f=formObject(form);view.reviews=Object.fromEntries(tools.map((t,i)=>[t.name,{schema_hash:t.schema_hash,permission:f['permission_'+i],data_class:f['data_'+i],workflow:f['workflow_'+i]}]));
    mcpChooseAgents(view);
  },'Choose agents');
}
function mcpChooseAgents(view){
  const enabled=view.catalogue.tools.filter(t=>view.reviews[t.name].permission!=='blocked');
  let content=mcpSteps(3)+'<p>Choose exactly which agents can use each reviewed tool. Existing assignments to other tools are kept. No new tools are selected automatically.</p>';
  if(!enabled.length)content+='<p>All tools are blocked. You can save this choice and review them later.</p>';
  for(const [team,t] of Object.entries(state.agents.teams)){
    content+=`<section class="setup-card"><h3>${esc(t.display_name)}</h3>`;
    for(const agent of teamMembers(team))content+=`<details><summary>${esc(agentName(agent))}</summary><div class="check-grid">${enabled.map(tool=>`<label class="check-option"><input type="checkbox" data-setup-agent="${esc(agent)}" value="${esc(tool.name)}" ${(state.agents.agents[agent].tools||[]).includes(tool.name)?'checked':''}><span>${esc(tool.label||tool.name)}</span></label>`).join('')||'<p>No tools enabled.</p>'}</div></details>`;
    content+='</section>';
  }
  content+='<button type="button" class="button secondary small" data-action="mcp-setup-review">Back to tool review</button>';
  openEditor('Choose agents','GUIDED CONNECTION',content,async form=>{
    const assignments={};
    for(const agent of Object.keys(state.agents.agents))assignments[agent]=$$('input[data-setup-agent]',form).filter(el=>el.dataset.setupAgent===agent&&el.checked).map(el=>el.value);
    await api('/connections/'+encodeURIComponent(view.name)+'/setup/complete','POST',{revision:view.catalogue.revision,configuration_hash:view.catalogue.configuration_hash,reviews:view.reviews,assignments});
    const chat=view.fromChat;await saved('Tool access saved. Changes connect automatically.');if(chat)await showChatSetup();
  },'Save tool access');
}
async function showGoogleProviderSetup(back=null){
  const provider=await api('/providers/google/setup');
  openEditor('Google provider setup','PROVIDER SETUP',`<p>${provider.configured?'Google is configured for this installation. Replacing setup requires affected accounts to reconnect.':'A technical administrator completes this once. Everyday users can then sign in from the dashboard.'}</p><ol><li>Create or choose a Google Cloud project.</li><li>Enable the APIs needed by your connections: Analytics Admin/Data, Google Ads, Search Console or Drive.</li><li>Configure the OAuth consent screen and create a Desktop app OAuth client. If the app is in testing, add the intended users as test users.</li><li>Download its client JSON and choose it below.</li></ol><a href="https://github.com/googleanalytics/google-analytics-mcp#configure-credentials-" target="_blank" rel="noopener noreferrer">Official Google setup instructions ↗</a>${field('provider_project','Google Cloud project ID',provider.project,'text','Used explicitly by new Google Analytics connections.',true)}<label for="google-provider-file">OAuth desktop-client JSON</label><input id="google-provider-file" type="file" accept=".json,application/json" required><p class="help">Stored encrypted on this computer. This file is never sent to an AI model. Existing account credentials are separate.</p>${provider.configured?'<button type="button" class="button danger small" data-action="mcp-setup-provider-remove">Remove provider setup</button>':''}`,async form=>{
    await api('/providers/google/setup','PUT',{revision:provider.revision,project:formObject(form).provider_project,client_json:await authJsonFile('#google-provider-file')});
    await refresh();if(back)await back();else await saved('Google provider setup saved.');
  },provider.configured?'Replace provider setup':'Save provider setup');
}
async function mcpSetupAction(action,id){
  if(action==='show'){await showMcpSetup(id);return;}
  const view=mcpSetupView;
  if(action==='provider'){await showGoogleProviderSetup(view?()=>showMcpSetup(view.name,view.preset,view.fromChat):null);return;}
  if(action==='provider-remove'){
    const provider=await api('/providers/google/setup');
    openEditor('Remove Google provider setup?','PROVIDER SETUP','<p>Google Analytics accounts using this registration will need to reconnect. Existing account credentials will be invalidated. Other services are kept.</p>',async()=>{await api('/providers/google/setup','DELETE',{revision:provider.revision});await saved('Google provider setup removed.');},'Remove setup');return;
  }
  if(!view)return;
  if(action==='preset'){view.preset=id;await mcpConnectNew(view);}
  else if(action==='advanced'){const name=view.name;closeEditor();editMcpConnection(name);}
  else if(action==='check'){
    const result=await api('/connections/check','POST',{url:$('#f-setup_url').value});
    if(view!==mcpSetupView)return;
    $('#mcp-check-result').textContent=result.message;
    if(result.authentication==='oauth')$('#f-setup_auth').value='oauth';
    if(!$('#f-setup_name').value)$('#f-setup_name').value=new URL($('#f-setup_url').value).hostname;
    toggleMcpSetupKey();
  }else if(action==='signin'){await mcpApproveCommand(view);await showConnectionAuth(view.name,view.fromChat,()=>mcpResumeReview(view.name,view.fromChat));}
  else if(action==='key'){
    await api('/connections/'+encodeURIComponent(view.name)+'/setup/key','PUT',{revision:state.revision,api_key:$('#f-replacement_key').value});
    if(view!==mcpSetupView)return;
    view.reviews=null;await refresh();await mcpConnectSaved(view);await mcpConnect(view);
  }
  else if(action==='review'){view.forceReview=true;await mcpReviewTools(view);}
}
document.addEventListener('change',event=>{if(event.target.id==='f-setup_auth')toggleMcpSetupKey();});
