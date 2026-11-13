'use strict';
let mcpAuthTimer, mcpAuthView=null;
const authenticationLabels={not_connected:'Not connected',connecting:'Connecting',connected:'Connected',reconnect_required:'Reconnect required',failed:'Connection failed'};
function connectionAuthCard(id,s){
  const a=state.connection_auth?.[id],method=s.auth?.type||a?.method;
  if(!['oauth','google_adc','api_oauth'].includes(method))return '';
  return `<p class="help" role="status">${esc(authenticationLabels[a?.status]||'Not connected')} · ${method==='google_adc'?'Google credentials':'Browser sign-in'}</p><button class="button secondary small" data-action="connection-auth-show" data-name="${esc(id)}">${a?.status==='connected'?'Manage sign-in':a?.status==='connecting'?'Continue sign-in':'Connect'}</button>`;
}
function stopMcpAuthPolling(cancel=false){
  clearTimeout(mcpAuthTimer);
  if(cancel&&mcpAuthView){const name=mcpAuthView.name;mcpAuthView=null;api('/connections/'+encodeURIComponent(name)+'/auth/cancel','POST').catch(()=>{});}
}
async function showConnectionAuth(name,fromChat=false,onDone=null){
  stopMcpAuthPolling();
  const spec=state.tools.mcp_servers[name];
  if(!spec)throw Error('This connection is no longer configured.');
  if(spec.native&&state.connection_auth?.[name]?.method!=='api_oauth'){await showMcpSetup(name,null,fromChat);return;}
  openEditor(spec.display_name||'Connect service','CONNECTION SIGN-IN','<p role="status">Checking sign-in…</p>',null);
  mcpAuthView={name,fromChat,onDone,fingerprint:''};
  await pollMcpAuth();
}
async function pollMcpAuth(){
  const view=mcpAuthView;
  if(!view||!dialog.open||$('#dialog-kicker').textContent!=='CONNECTION SIGN-IN')return;
  clearTimeout(mcpAuthTimer);const request=view.request=(view.request||0)+1;
  try{
    const data=await api('/connections/'+encodeURIComponent(view.name)+'/auth');
    if(view!==mcpAuthView||request!==view.request)return;
    const fingerprint=JSON.stringify(data);
    if(fingerprint!==view.fingerprint){
      view.fingerprint=fingerprint;view.data=data;
      let content=`<p role="status"><strong>${esc(authenticationLabels[data.status]||'Not connected')}</strong></p><p>${esc(data.message)}</p>`;
      if(data.status==='connecting'){
        if(data.provider)content+=`<div class="subtle-box"><p><strong>Sign-in provider</strong><br>${esc(data.provider)}</p><p><strong>Requested permissions</strong></p><ul>${(data.scopes||[]).map(s=>`<li class="auth-permission">${esc(s)}</li>`).join('')||'<li>The server has not requested named permissions.</li>'}</ul><details><summary>Authentication destinations</summary><ul>${(data.destinations||[]).map(s=>`<li class="auth-permission">${esc(s)}</li>`).join('')}</ul></details></div>`;
        if(data.phase==='review')content+='<p>Continue only if this is the service and access you intended to connect.</p><button type="button" class="button" data-action="connection-auth-approve">Approve sign-in setup</button>';
        if(data.phase==='sign_in'&&data.authorization_url)content+=`<p>Complete sign-in in a new browser tab. This card will update automatically.</p><a class="button" href="${esc(data.authorization_url)}" target="_blank" rel="noopener noreferrer">Open secure sign-in ↗</a>`;
        content+='<p class="help">Sign-in expires after five minutes. Your chat and draft are kept.</p><button type="button" class="button secondary small" data-action="connection-auth-cancel">Cancel sign-in</button>';
      }else{
        if(data.method==='api_oauth'&&!data.provider_setup?.configured)content+='<div class="subtle-box"><strong>Administrator setup needed</strong><p>Register this provider once, then sign in here.</p><button type="button" class="button secondary" data-action="connection-auth-provider">Administrator setup</button></div>';
        if(data.method==='google_adc')content+=data.provider_setup?.configured?'<div class="subtle-box"><strong>Google Analytics — read only</strong><p>Provider setup is ready. Choose Connect to sign in with your Google account. You will review the provider and permissions first.</p></div>':'<div class="subtle-box"><strong>Google Analytics — read only</strong><p>An administrator can configure Google once for this installation. Your Google account needs access to the Analytics property.</p><button type="button" class="button secondary small" data-action="connection-auth-provider">Set up Google provider</button><a href="https://github.com/googleanalytics/google-analytics-mcp#configure-credentials-" target="_blank" rel="noopener noreferrer">Google setup instructions ↗</a></div><details><summary>Use a desktop-client file for this sign-in</summary><label for="google-client-file">OAuth desktop-client JSON</label><input id="google-client-file" type="file" accept=".json,application/json"><p class="help">Handled locally; never sent to an AI model.</p></details>';
        const placeholder=data.error_code==='connection.placeholder';
        content+=`<div class="card-actions">${placeholder?'':`<button type="button" class="button" data-action="connection-auth-start">${data.status==='connected'?'Reconnect':'Connect'}</button>`}${data.status==='connected'?'<button type="button" class="button secondary" data-action="connection-auth-disconnect">Disconnect</button>':''}<button type="button" class="button secondary" data-action="connection-auth-edit">Edit connection</button></div>`;
        const spec=state.tools.mcp_servers[view.name];
        if(placeholder&&/google[\s_-]*analytics|ga4/i.test([view.name,spec.display_name,spec.url].join(' ')))content+='<div class="subtle-box section-space"><p>To use Google Analytics without deploying an MCP server, set up the official read-only server on this computer.</p><button type="button" class="button" data-action="connection-auth-google-local">Set up Google Analytics locally</button></div>';
        if(data.method==='google_adc')content+='<details class="section-space"><summary>Use existing Google user credentials</summary><p>Choose the user ADC JSON created by Google Cloud sign-in. Edit scopes and external credential providers are not supported.</p><label for="google-adc-file">Google user ADC JSON</label><input id="google-adc-file" type="file" accept=".json,application/json"><button type="button" class="button secondary small" data-action="connection-auth-import">Import and connect</button></details>';
      }
      $('#editor-fields').innerHTML=content;
      currentEditor=data.status==='connecting'?null:async()=>{const chat=view.fromChat,after=view.onDone;await renderKeepingDraft();mcpAuthView=null;closeEditor();if(after)await after();else if(chat)await showChatSetup();};
      $('#save-editor').hidden=!currentEditor;$('#save-editor').textContent=data.status==='connected'&&view.onDone?'Review tools':view.fromChat?'Back to chat setup':'Done';
      if(state.connection_auth)state.connection_auth[view.name]=data;
    }
    if(data.status==='connecting')mcpAuthTimer=setTimeout(()=>pollMcpAuth(),900);
  }catch(error){if(view===mcpAuthView)$('#form-error').textContent=error.message;}
}
async function authJsonFile(id){
  const file=$(id)?.files?.[0];
  if(!file)throw Error('Choose the JSON file first.');
  if(file.size>65536)throw Error('Choose a credential JSON file smaller than 64 KB.');
  try{return JSON.parse(await file.text());}catch{throw Error('This file is not valid JSON.');}
}
async function connectionAuthAction(action,name){
  if(action==='show'){await showConnectionAuth(name);return;}
  const view=mcpAuthView;if(!view)return;
  stopMcpAuthPolling();view.request=(view.request||0)+1;
  if(action==='provider'){const {name,fromChat,onDone}=view;mcpAuthView=null;if(view.data.method==='api_oauth')await connectorProvider(view.data.provider,()=>showConnectionAuth(name,fromChat,onDone));else await showGoogleProviderSetup(()=>showConnectionAuth(name,fromChat,onDone));return;}
  if(action==='edit'||action==='google-local'){const id=view.name;mcpAuthView=null;closeEditor();editMCP(id,false,action==='google-local');return;}
  const base='/connections/'+encodeURIComponent(view.name)+'/auth/';
  if(action==='start')await api(base+'start','POST',view.data.method==='google_adc'&&!view.data.provider_setup?.configured?{client_json:await authJsonFile('#google-client-file')}:{});
  else if(action==='approve')await api(base+'approve','POST',{transaction:view.data.transaction});
  else if(action==='cancel')await api(base+'cancel','POST');
  else if(action==='disconnect')await api(base+'disconnect','POST');
  else if(action==='import')await api(base+'import','POST',{credentials:await authJsonFile('#google-adc-file')});
  view.fingerprint='';await pollMcpAuth();
}

function editMcpConnection(id=null,brave=false,google=false){
  const existing=id?state.tools.mcp_servers[id]:{};
  if(existing?.managed){showMcpSetup(id);return;}
  const s=google?{display_name:existing.display_name||'Google Analytics',enabled:existing.enabled!==false,transport:'stdio',command:'uvx',args:['--from','analytics-mcp==1.0.0','analytics-mcp'],env_vars:[],auth:{type:'google_adc',project:existing.auth?.project||''}}:id?existing:brave?{display_name:'Brave Search',transport:'stdio',command:'npx',args:['-y','@brave/brave-search-mcp-server@2.1.4','--transport','stdio'],env_vars:['BRAVE_API_KEY']}:{};
  const revision=state.revision,a=s.auth||{},method=a.type||(s.token_env?'bearer':Object.keys(s.header_secrets||{}).length?'headers':'none');
  const templates=id&&google?'<div class="subtle-box"><p>This switches this connection to the official read-only Google Analytics server running on this computer. Review the command in Guardrails before use. Its namespace and agent assignments are kept.</p></div>':!id&&!brave&&!google?'<div class="subtle-box"><strong>Start with a guided connection</strong><div class="card-actions"><button type="button" class="button secondary small" data-action="brave-template">Brave Search</button><button type="button" class="button secondary small" data-action="google-template">Google Analytics — read only</button></div></div>':'';
  const content=templates+field('display_name','Connection name',s.display_name||id||'','text','',true)+select('transport','Connection type',[['http','Remote server (HTTP)'],['stdio','Local server (stdio)']],s.transport||'http')+`<div id="mcp-http">${field('url','Server address',s.url||'','url','Use the full MCP endpoint, for example https://example.org/mcp.')}</div>`+select('mcp_authentication','Authentication',[['none','No authentication / local environment'],['bearer','Bearer token'],['headers','Secret headers'],['oauth','Browser sign-in (OAuth)'],['google_adc','Google credentials — read only']],method)+`<div id="mcp-bearer">${select('token_env','Bearer token',secretOptions(),s.token_env||'')}</div><div id="mcp-headers"><details${method==='headers'?' open':''}><summary>Secret headers</summary>${field('header_secrets','Header references',Object.entries(s.header_secrets||{}).map(([k,v])=>`${k}: ${v}`).join('\n'),'textarea','One header per line: X-API-Key: MY_SECRET_NAME')}</details></div><div id="mcp-oauth"><p>Save this connection, then choose Connect to review its permissions and sign in through your browser.</p><details><summary>OAuth client registration & advanced settings</summary><p class="help">Leave these blank when the server supports automatic client registration. Some providers require you to register an application first.</p>${field('oauth_client_id','OAuth client ID',a.client_id||'')}${select('oauth_client_secret','OAuth client secret',secretOptions(),a.client_secret_env||'')}${field('oauth_metadata','Client metadata document',a.client_metadata_url||'','url','Optional public HTTPS client metadata URL.')}${field('oauth_scopes','Requested permissions',(a.scopes||[]).join('\n'),'textarea','One scope per line. The server may request permissions for you to review.')}${field('oauth_callback_port','Callback port',a.callback_port||'','number','Optional fixed port for a pre-registered redirect URI. Otherwise an available loopback port is used.')}</details></div><div id="mcp-google">${field('google_project','Google Cloud project ID',a.project||'','text','The project where you enabled the Analytics Admin and Analytics Data APIs.')}<p class="help">After saving, choose Connect to sign in with Google or import user application credentials. Analytics write tools stay disabled.</p></div><div id="mcp-stdio">${field('command','Command',s.command||'','text','For example, npx or uvx. Runs directly without a shell.')}${field('args','Arguments',(s.args||[]).join('\n'),'textarea','One argument per line; spaces in a line stay within that argument.')}${field('env_vars','Required secret names',(s.env_vars||[]).join('\n'),'textarea','Only these saved secrets are passed to the local server.')}${field('env_secrets','Mapped environment secrets',Object.entries(s.env_secrets||{}).map(([key,value])=>`${key}: ${value}`).join('\n'),'textarea','Optional: SERVER_VARIABLE: SAVED_SECRET_REFERENCE. Do not repeat these names above.')}<div class="subtle-box">Local MCP software runs on this computer. Review the exact command in Guardrails before testing it.</div></div><hr>${checked('enabled','Enable this connection',s.enabled!==false)}${id?`<p class="help">Namespace: ${esc(id)}. Discovered tools keep their names when you rename this connection.</p>`+deleteButton('mcp-delete',id,'Delete connection'):''}`;
  openEditor(id?'Edit connection':'Add connection','CONNECTIONS',content,async form=>{
    const f=formObject(form),lines=x=>(x||'').split('\n').map(v=>v.trim()).filter(Boolean),type=f.mcp_authentication;
    const spec={display_name:f.display_name,transport:f.transport,enabled:!!f.enabled,auth:{type}};
    if(f.transport==='http'){
      spec.url=f.url;spec.token_env=type==='bearer'?f.token_env:'';spec.header_secrets={};
      if(['headers','bearer','oauth'].includes(type))for(const line of lines(f.header_secrets)){const sep=line.indexOf(':');if(sep<1)throw Error('Use Header-Name: SECRET_NAME for each secret header.');spec.header_secrets[line.slice(0,sep).trim()]=line.slice(sep+1).trim();}
      if(type==='oauth')Object.assign(spec.auth,{client_id:f.oauth_client_id,client_secret_env:f.oauth_client_secret,client_metadata_url:f.oauth_metadata,scopes:lines(f.oauth_scopes),callback_port:Number(f.oauth_callback_port||0)});
    }else{
      spec.command=f.command;spec.args=f.args.split('\n').filter(v=>v.length);spec.env_vars=lines(f.env_vars);spec.env_secrets={};for(const line of lines(f.env_secrets)){const sep=line.indexOf(':');if(sep<1)throw Error('Use SERVER_VARIABLE: SAVED_SECRET_REFERENCE for each environment mapping.');spec.env_secrets[line.slice(0,sep).trim()]=line.slice(sep+1).trim();}
      if(type==='google_adc')spec.auth.project=f.google_project;
    }
    const result=await api('/connections'+(id?'/'+id:''),id?'PUT':'POST',{revision,spec});
    await saved('Connection saved. Saved changes connect automatically.');
    if(['oauth','google_adc','api_oauth'].includes(type))await showConnectionAuth(result.name,page==='chat');
  });
  toggleMcpAuthentication();
}
function toggleMcpAuthentication(){
  const transport=$('#f-transport')?.value,selector=$('#f-mcp_authentication');if(!selector)return;
  for(const option of selector.options)option.hidden=transport==='http'?option.value==='google_adc':['bearer','headers','oauth'].includes(option.value);
  if(selector.selectedOptions[0].hidden)selector.value='none';
  const method=selector.value;
  for(const [id,visible] of Object.entries({'mcp-http':transport==='http','mcp-stdio':transport==='stdio','mcp-bearer':method==='bearer','mcp-headers':transport==='http'&&['headers','bearer','oauth'].includes(method),'mcp-oauth':method==='oauth','mcp-google':method==='google_adc'}))$('#'+id).hidden=!visible;
}
