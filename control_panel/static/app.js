'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const paths = {
  overview:'M3 10l9-7 9 7v10H3z M9 20v-7h6v7',
  teams:'M9 3h6v6H9z M3 15h6v6H3z M15 15h6v6h-6z M12 9v3 M6 15v-3h12v3',
  agents:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75',
  models:'M6 6h12v12H6z M9 9h6v6H9z M9 3v3 M15 3v3 M9 18v3 M15 18v3 M3 9h3 M3 15h3 M18 9h3 M18 15h3',
  tools:'M9 7V3 M15 7V3 M6 7h12v5a6 6 0 0 1-12 0z M12 18v4',
  brand:'M12 21S2 15 2 8a5 5 0 0 1 10-1 5 5 0 0 1 10 1c0 7-10 13-10 13z',
  guardrails:'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3z M8 12l3 3 5-6',
  secrets:'M5 10h14v11H5z M8 10V7a4 4 0 0 1 8 0v3 M12 14v3',
  chat:'M21 11a9 9 0 0 1-9 9H3l2-5a9 9 0 1 1 16-4z M8 10h8 M8 14h5',
  spark:'M12 2l3 7 7 3-7 3-3 7-3-7-7-3z',
  server:'M4 3h16v7H4z M4 14h16v7H4z M7 6h.01 M7 17h.01',
  arrow:'M5 12h14 M13 6l6 6-6 6'
};
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${paths[name] || paths.spark}"/></svg>`;
const pages = {overview:['Overview','Check your team’s setup and service status.'],teams:['Teams','Create teams for different projects and manage their agents.'],agents:['Agents','Set each agent’s instructions, model, and tools.'],models:['Models','Add models, choose providers, and connect their API keys.'],tools:['Tools & Connections','Manage the tools and services your agents can use.'],brand:['Masterbrand','Keep your organisation’s strategy, audience, and writing guidelines in one place.'],guardrails:['Guardrails','Manage gateway policies, spending and action approvals.'],secrets:['Secrets','Add or replace API keys, passwords, and connection tokens.'],chat:['Chat','Work with a team or test an individual agent.']};
let activeTeam = '';
let state, csrf = '', page = 'overview', activeConversation = null, streaming = false, toastTimer, currentEditor = null;
let polling = false, operationError = '', renderVersion = 0;
let editorAfterSave = null;
const main = $('#main'), dialog = $('#editor');
function toast(message) { $('#toast').textContent = message; $('#toast').classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => $('#toast').classList.remove('show'), 6000); }
async function api(url, method = 'GET', body) {
  const res = await fetch('/api' + url, {method, credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body: method === 'GET' ? undefined : JSON.stringify(body ?? {})});
  const data = await res.json(); if (!res.ok) {const error=new Error(data.error || 'This action could not be completed.');error.issue=data.issue;error.requirements=data.requirements;throw error;} return data;
}
async function refresh() { state = await api('/state'); if(!state.agents.teams[activeTeam])activeTeam=state.agents.default_team; navigation(); }
function agentName(id) { return state.agents.agents[id]?.display_name || id.replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase()); }
function teamName(id=activeTeam) { return state.agents.teams[id]?.display_name||'Previous team'; }
function teamRoot(id=activeTeam) { return state.agents.teams[id]?.root; }
function branchMembers(id) { const result=[],seen=new Set();function collect(name){if(seen.has(name)||!state.agents.agents[name])return;seen.add(name);result.push(name);state.agents.agents[name].sub_agents.forEach(collect);}collect(id);return result; }
function teamMembers(id=activeTeam) { return branchMembers(teamRoot(id)); }
function teamForAgent(id) { return Object.keys(state.agents.teams).find(team=>teamMembers(team).includes(id))||state.agents.default_team; }
function teamsPage() {
  return `${heading('<button class="button" data-action="team-new">＋ New team</button>')}<div class="notice"><p>Each team has its own coordinator, specialists, and conversations. Models, tools, secrets, and Masterbrand are shared across your workspace.</p></div><div class="grid three">${Object.entries(state.agents.teams).map(([id,t])=>{const members=teamMembers(id),n=members.length-1;return `<article class="card team-card ${id===activeTeam?'selected':''}"><div class="card-top"><div class="card-icon">${icon('agents')}</div><span class="tag">${id===state.agents.default_team?'Default team':id===activeTeam?'Selected team':'Team'}</span></div><h2>${esc(t.display_name)}</h2><p class="description">${esc(t.description||'No team description added.')}</p><div class="tag-list"><span class="tag">1 coordinator</span><span class="tag">${n} specialist${n===1?'':'s'}</span></div><p class="team-summary section-space">Led by ${esc(agentName(t.root))}</p><div class="card-actions"><button class="button secondary small" data-action="team-agents" data-name="${esc(id)}">View agents</button><button class="button ghost small" data-action="team-chat" data-name="${esc(id)}">Chat with team ↗</button></div><div class="card-bottom"><span>${id===activeTeam?'Current team':'Switch at any time'}</span><div class="card-actions"><button class="button ghost small" data-action="team-edit" data-name="${esc(id)}">Edit team</button><button class="button danger small" data-action="team-delete" data-name="${esc(id)}" ${Object.keys(state.agents.teams).length===1?'disabled':''}>Delete team</button></div></div>${Object.keys(state.agents.teams).length===1?'<p class="help section-space">Keep at least one team. Create another team before deleting this one.</p>':''}</article>`;}).join('')}</div>`;
}
function editTeam(id=null) {
  const t=id?state.agents.teams[id]:{},revision=state.revision;
  const instruction="Coordinate this team's work. Delegate tasks to the appropriate specialists and combine their findings. Ask for clarification when needed. Never invent tool results.";
  const content=field('display_name','Team name',t.display_name||'','text','For example, Fundraising or Campaigns.',true)+field('description','Team purpose',t.description||'','textarea','What should this team help people accomplish?')+(id?`<div class="subtle-box"><strong>Coordinator: ${esc(agentName(t.root))}</strong><p>Edit its instructions, model, and tools in Agents.</p><button type="button" class="button secondary small" data-action="team-coordinator" data-name="${esc(t.root)}">Edit coordinator</button></div>`:field('coordinator_name','Coordinator name','','text','Leave blank to use the team name.')+field('instruction','Coordinator instructions',instruction,'textarea','This agent will supervise the specialists you add.',true)+select('model','Coordinator model',Object.keys(state.models).map(k=>[k,modelName(k)]),Object.keys(state.models)[0]))+checked('default','Use this team by default',id===state.agents.default_team)+`<p class="help">The default team is selected when you open the app. Teams share your workspace’s models, tools, secrets, and Masterbrand.</p>`+(id?(Object.keys(state.agents.teams).length>1?deleteButton('team-delete',id,'Delete team and its agents'):'<p class="help">Keep at least one team. Create another team before deleting this one.</p>'):'');
  openEditor(id?'Edit team':'New team','TEAMS',content,async form=>{
    const f=formObject(form),body={revision,team:{display_name:f.display_name,description:f.description},default:!!f.default};
    if(!id)body.coordinator={display_name:f.coordinator_name||f.display_name+' coordinator',description:f.description,instruction:f.instruction,models:[f.model]};
    const result=await api('/teams'+(id?'/'+id:''),id?'PUT':'POST',body);if(!id)activeTeam=result.name;
    await saved(id?'Team updated. New conversations will use these settings.':'Team created. Open Agents to add its specialists.');
  });
  if(id===state.agents.default_team)$('[name="default"]',dialog).disabled=true;
}
function updateAgentTeam() {
  const team=$('#f-agent_team').value;
  $('#f-parent').innerHTML=teamMembers(team).map(id=>`<option value="${esc(id)}">${esc(agentName(id))}</option>`).join('');
  $('#f-parent').value=teamRoot(team);
}
function updateChatTeam() {
  const team=$('#f-chat_team').value;
  $('#f-agent').innerHTML=teamMembers(team).map(id=>`<option value="${esc(id)}">${esc(agentName(id))}${id===teamRoot(team)?' · Coordinator':''}</option>`).join('');
  $('#f-agent').value=teamRoot(team);
}
const badge = status => `<span class="badge ${esc(status)}">${esc(({needs_setup:'Needs setup',external:'Running · external',running:'Running',starting:'Starting…',stopped:'Stopped',failed:'Needs attention'})[status] || status)}</span>`;
function navigation() {
  $('#nav').innerHTML = Object.entries(pages).map(([id,[label]])=>`<a href="#${id}" class="${id===page?'active':''}" ${id===page?'aria-current="page"':''}>${icon(id)}<span>${label}</span>${id==='agents'?`<span class="nav-count">${teamMembers().length}</span>`:''}</a>`).join('');
  $('#crumb').textContent = pages[page][0];
  $('#workspace-name').textContent=teamName();
  const switcher=$('#team-switcher'), options=Object.entries(state.agents.teams).map(([id,t])=>`<option value="${esc(id)}">${esc(t.display_name)}</option>`).join('');
  if(switcher.dataset.options!==options){switcher.innerHTML=options;switcher.dataset.options=options;}
  switcher.value=activeTeam;switcher.disabled=streaming;
  $('#sidebar-services').innerHTML = state.services.map(s=>`<div class="tiny-service"><span>${s.name==='inference'?'Inference':'Tools'}</span><span>${esc(({running:'Connected',external:'External',starting:'Starting…',needs_setup:'Needs setup',failed:'Attention',stopped:'Stopped'})[s.status])}</span></div>`).join('');
}
function heading(action = '') { const [title,sub] = pages[page]; return `<div class="page-heading"><div><p class="eyebrow">YOUR WORKSPACE</p><h1>${title}</h1><p>${sub}</p></div>${action}</div>`; }
function pendingNotice() { const sync=state.synchronisation;const notice=sync?.state==='attention'?`<div class="notice warn"><p>${esc(sync.message)}</p><button class="button small" data-action="apply">Retry connection</button></div>`:state.services_busy||state.services.some(s=>s.pending)?'<div class="notice"><p>Saved changes are connecting automatically. Chat will be ready when the gateways reconnect.</p></div>':'';return `<div id="gateway-sync-notice">${notice}</div>`; }
function setupSteps() {
  const missing = state.secrets.filter(s=>!s.configured), brand = !!(state.brand.organisation_name && state.brand.mission);
  return [{done:missing.length===0,label:'Add connection keys',detail:missing.length?`${missing.length} connection ${missing.length===1?'key is':'keys are'} missing.`:'All required keys have saved values.',href:'secrets'}, {done:brand,label:'Add organisation details',detail:'Set your organisation’s name and mission in Masterbrand.',href:'brand'},{done:state.services.every(s=>['running','external'].includes(s.status)),label:'Start the gateways',detail:'Start both gateways in the background.',href:'overview'},{done:!!state.hasChats,label:'Start your first chat',detail:'Send a message to your team or an individual agent.',href:'chat'}];
}
function serviceCards() { return state.services.map(s=>`<div class="service-row"><div class="card-icon">${icon(s.name==='inference'?'spark':'server')}</div><div class="info"><h3>${esc(s.label)}</h3><p>${esc(s.detail)}</p><div class="service-actions">${['running','external'].includes(s.status)?`${s.managed?`<button class="button secondary small" data-action="service" data-name="${s.name}" data-operation="restart">Restart</button><button class="button ghost small" data-action="service" data-name="${s.name}" data-operation="stop">Stop</button>`:''}`:`<button class="button secondary small" data-action="service" data-name="${s.name}" data-operation="start" ${s.status==='starting'?'disabled':''}>${s.status==='starting'?'Starting…':'Start gateway'}</button>`}<button class="button ghost small" data-action="logs" data-name="${s.name}">Diagnostics</button></div></div>${badge(s.status)}</div>`).join(''); }
function overview() {
  const agents = Object.entries(state.agents.agents).filter(([id])=>teamMembers().includes(id)), steps=setupSteps(), complete=steps.filter(s=>s.done).length, running=state.services.filter(s=>['running','external'].includes(s.status)).length;
  return `${heading('<a href="#chat" class="button">Open chat <span aria-hidden="true">↗</span></a>')}${pendingNotice()}<div class="hero"><div><p class="eyebrow">CURRENT TEAM</p><h2>${esc(teamName())}</h2><p>Edit agents, connect tools, and review the settings this team uses.</p><a href="#agents" class="button secondary small">View agents <span aria-hidden="true">→</span></a></div><div class="hero-art" aria-hidden="true"><div class="orbit"></div><div class="orbit second"></div><div class="seed">✳</div><div class="orbit-dot"></div></div></div><div class="stats"><div class="card stat"><div class="stat-label">AGENTS IN THIS TEAM</div><div class="number">${agents.length.toString().padStart(2,'0')}</div><div class="stat-detail">Coordinator and specialists</div></div><div class="card stat"><div class="stat-label">AVAILABLE TOOLS</div><div class="number">${state.catalog.length.toString().padStart(2,'0')}</div><div class="stat-detail">Shared across all teams</div></div><div class="card stat"><div class="stat-label">GATEWAYS ONLINE</div><div class="number">${running}<span class="muted"> / 2</span></div><div class="stat-detail">${running===2?'Both gateways are running':'Check gateway status below'}</div></div></div><div class="overview-grid"><div class="stack"><section class="card"><div class="section-head"><h2>Team agents</h2><a href="#agents">View all →</a></div>${agents.slice(0,4).map(([id,a])=>`<div class="agent-mini"><div class="card-icon">${icon(id===teamRoot()?'spark':'agents')}</div><div><h3>${esc(agentName(id))}</h3><p>${esc(a.description || a.instruction.slice(0,85))}</p></div><span class="tag ${id===teamRoot()?'root':''}">${id===teamRoot()?'Coordinator':'Specialist'}</span></div>`).join('')}</section><section class="card"><div class="section-head"><h2>Gateway status</h2><span class="count-label">LIVE STATUS</span></div><div id="service-cards">${serviceCards()}</div></section></div><div class="stack"><section class="card flat"><div class="section-head"><h2>Setup checklist</h2><span class="count-label">${complete} of 4</span></div><p>${complete===steps.length?'All setup steps are complete.':'Complete these steps to set up your workspace.'}</p><div class="progress-track" aria-label="Setup ${complete} of 4 complete"><div class="progress-fill progress-${complete*25}"></div></div><ul class="checklist">${steps.map((s,i)=>`<li><span class="check-circle ${s.done?'done':''}">${s.done?'✓':i+1}</span><div><a href="#${s.href}">${esc(s.label)}</a><p>${esc(s.detail)}</p></div></li>`).join('')}</ul></section><section class="card flat"><p class="eyebrow">MASTERBRAND</p><h2>${esc(state.brand.organisation_name || 'Add your organisation')}</h2><p>${esc(state.brand.mission || 'Add your mission, strategy, and writing guidelines for agents to use.')}</p><a href="#brand" class="button ghost small">Edit Masterbrand →</a></section></div></div><section class="card wide-card"><div class="section-head"><h2>Where your models run</h2><a href="#models">Manage models →</a></div><p>Routing depends on each provider and endpoint. Global routing may process data outside Europe.</p><div class="routing">${state.routing.map(r=>`<span>${esc(r.alias)} · ${esc(r.location)}</span>`).join('')}</div></section>`;
}
function agentsPage() {
  const root=teamRoot(),members=teamMembers();
  return `${heading('<button class="button" data-action="agent-new">＋ New agent</button>')}<div class="notice"><p><strong>${esc(teamName())}</strong> has its own coordinator and specialists. Choose another team in the sidebar or manage your teams.</p><a href="#teams" class="button secondary small">Manage teams</a></div><div class="grid three">${members.map(id=>{const a=state.agents.agents[id];return `<article class="card"><div class="card-top"><div class="card-icon">${icon(id===root?'spark':'agents')}</div><span class="tag ${id===root?'root':''}">${id===root?'Coordinator':'Specialist'}</span></div><h2>${esc(agentName(id))}</h2><p class="description">${esc(a.description||a.instruction.slice(0,145))}</p><div class="tag-list"><span class="tag">${esc(modelName(a.models[0]))}</span><span class="tag">${a.tools.length} tools</span>${a.sub_agents.length?`<span class="tag">${a.sub_agents.length} specialists</span>`:''}</div><div class="card-bottom"><span>${id===root?'Leads '+esc(teamName()):'Reports to '+esc(agentName(parentOf(id)))}</span><button class="button secondary small" data-action="agent-edit" data-name="${esc(id)}">Edit agent</button></div><div class="card-actions"><button class="button ghost small" data-action="agent-duplicate" data-name="${esc(id)}">Duplicate</button><button class="button ghost small" data-action="agent-test" data-name="${esc(id)}">Test in chat ↗</button></div></article>`;}).join('')}</div>`;
}
function parentOf(id) { return Object.entries(state.agents.agents).find(([,a])=>a.sub_agents.includes(id))?.[0] || teamRoot(teamForAgent(id)); }
function modelName(id) { return state.models[id]?.display_name || ({fast:'Fast & efficient',reasoning:'Deeper reasoning',backup:'Backup model'})[id] || id; }
function modelsPage() {
  return `${heading('<button class="button" data-action="model-new">＋ Add model</button>')}<div class="notice"><p>Link each model to an API key for its provider. Saved changes connect automatically while chat is idle. Models used by agents must support tool calling.</p></div><div class="grid three">${state.model_catalog.map(m=>`<article class="card model-card"><div class="card-top"><div class="card-icon">${icon('spark')}</div><span class="badge ${m.configured?'running':'needs_setup'}">${m.configured?'Key saved':'Needs key'}</span></div><p class="eyebrow">${esc(state.providers[m.provider]?.label || 'Advanced deployment')}</p><h2>${esc(m.display_name)}</h2><p class="model-identifier">${esc(m.model || 'Deployment unavailable')}</p><div class="model-secret"><span class="muted">Private key</span><strong>${esc(m.secret || (m.provider==='ollama_chat'?'Not required':'Configured outside this editor'))}</strong></div><div class="tag-list"><span class="tag">${esc(m.location)}</span><span class="tag">${m.used_by.length} agents</span></div><p class="help section-space">${m.used_by.length?'Used by '+esc(m.used_by.join(', ')):'Ready to assign in Agents.'}</p><div class="card-actions">${m.editable?`<button class="button secondary small" data-action="model-edit" data-name="${esc(m.id)}">Edit model</button>`:'<span class="help">Manage advanced routing in YAML.</span>'}${m.secret?`<button class="button ghost small" data-action="model-key" data-name="${esc(m.id)}">${m.configured?'Replace key':'Add key'}</button>`:''}${!m.used_by.length?`<button class="button ghost small" data-action="model-delete" data-name="${esc(m.id)}">Delete</button>`:''}</div></article>`).join('')}</div><section class="card wide-card"><h2>Choose a model your provider offers</h2><p>Enter the exact model ID from your provider. OpenRouter IDs include the publisher, such as <code>publisher/model-name</code>.</p><p class="help">Saving settings does not contact a provider or verify access. “Key saved” means a value is stored, not that it has been verified. To test access, send a message in Chat once the gateways are ready; requests may incur charges. API endpoints do not by themselves guarantee where a provider processes data.</p><a href="https://docs.litellm.ai/docs/providers" target="_blank" rel="noopener noreferrer">Provider documentation ↗</a></section>`;
}
function editModel(id=null,draft=null) {
  const m=draft || (id?state.model_catalog.find(item=>item.id===id):null) || {display_name:'',provider:'openrouter',model:'',secret:'OPENROUTER_API_KEY',api_base:'https://openrouter.ai/api/v1'};
  const revision=state.revision;
  const names=new Set(state.secrets.filter(s=>!['LITELLM_MASTER_KEY','LITELLM_PROXY_API_KEY'].includes(s.name)).map(s=>s.name));
  Object.values(state.providers).forEach(p=>{if(p.secret)names.add(p.secret);});if(m.secret)names.add(m.secret);
  const secretChoices=[['','No key (local Ollama only)'],...[...names].sort().map(name=>[name,name+(state.secrets.find(s=>s.name===name)?.configured?' · configured':' · missing value')]),['__new__','Use another secret name…']];
  openEditor(id?'Edit model':'Add model','MODELS',field('display_name','Name',m.display_name,'text','The name users will see when choosing an agent’s model.',true)+select('provider','Provider',Object.entries(state.providers).map(([key,p])=>[key,p.label]),m.provider)+field('model_id','Model ID',m.model,'text','Use the provider’s exact ID, e.g. gpt-6.1-terra.',true)+select('model_secret','Private key',secretChoices,m.secret||'')+`<div id="custom-model-secret" hidden>${field('model_secret_name','Secret name','','text','Use an uppercase name such as MY_PROVIDER_API_KEY.')}</div><div class="model-key-status" id="model-key-status" role="status"></div><button type="button" class="button secondary small" data-action="model-secret-edit">Add or replace this key</button><details class="section-space"><summary>Endpoint & advanced details</summary>${field('model_api_base','API base address',m.api_base||'','url','Leave blank to use the provider default. Custom compatible providers require an address.')}<p class="help">${id?'Internal identifiers stay the same, so your agents keep their assignments.':'Identifiers are generated automatically.'} Existing provider routing options are preserved when the provider stays the same. Switching providers resets those options.</p></details><div class="subtle-box section-space">Saved changes reconnect the inference gateway automatically. Updated models are used in new conversations.</div>`,async form=>{
    const f=formObject(form);
    await api('/models'+(id?'/'+id:''),id?'PUT':'POST',{revision,model:{display_name:f.display_name,provider:f.provider,model:f.model_id,secret:f.model_secret==='__new__'?f.model_secret_name:f.model_secret,api_base:f.model_api_base}});
    await saved('Model saved. Connecting automatically; choose it in Agents or start a new chat when ready.');
  });
  dialog.dataset.modelId=id||'';
  $('#f-model_api_base').required=m.provider==='custom';
  if(m.provider==='custom')$('#f-model_api_base').closest('details').open=true;
  updateModelSecretStatus();
}
function modelDraft() { const f=formObject($('#editor-form'));return {display_name:f.display_name,provider:f.provider,model:f.model_id,secret:f.model_secret==='__new__'?f.model_secret_name:f.model_secret,api_base:f.model_api_base}; }
function updateModelSecretStatus() {
  if(!$('#f-model_secret'))return;
  const name=$('#f-model_secret').value==='__new__'?$('#f-model_secret_name').value:$('#f-model_secret').value;
  $('#custom-model-secret').hidden=$('#f-model_secret').value!=='__new__';
  const configured=state.secrets.find(s=>s.name===name)?.configured;
  $('#model-key-status').textContent=name?(configured?'A value is stored for this key. Its provider access has not been verified.':'This key has no saved value yet. Add it here or later in Secrets.'):'Local Ollama can run without a key.';
  $('[data-action="model-secret-edit"]').disabled=!name;
}
async function modelSecret(id) {
  const m=state.model_catalog.find(item=>item.id===id);
  editSecret(m.secret);
}
let toolsAdvancedOpen=false;
document.addEventListener('toggle',e=>{if(e.target.id==='tools-advanced')toolsAdvancedOpen=e.target.open;},true);
const connectionStatusLabels={setup_needed:'Setup needed',ready_to_assign:'Ready to assign',ready:'Ready',disabled:'Disabled',needs_attention:'Needs attention'};
function savedConnectionCard(id,s,providerName=''){
  const info=state.connections.find(c=>c.id===id)||{};
  let status=info.status||'setup_needed';
  if(s.enabled!==false&&s.transport==='stdio'&&state.sandbox?.enabled&&!state.sandbox.connections?.find(c=>c.name===id)?.ready)status='needs_attention';
  return `<section class="subtle-box section-space" data-connection-id="${esc(id)}"><div class="section-head"><h3>${s.display_name===providerName?'Connection: ':''}${esc(s.display_name||id.replaceAll('_',' ').toUpperCase())}</h3><span class="tag">${esc(connectionStatusLabels[status])}</span></div><p>${s.transport==='native'?'Read-only API connection':s.transport==='stdio'?'Runs locally on your computer':'MCP connection'}</p>${connectionSetupSummary(id,s)}${connectionAuthCard(id,s)}<div class="card-actions"><button class="button secondary small" data-action="mcp-setup-show" data-name="${esc(id)}">Continue setup</button><button class="button secondary small" data-action="mcp-test" data-name="${esc(id)}">Test & discover tools</button><button class="button ghost small" data-action="mcp-edit" data-name="${esc(id)}">Edit connection</button></div></section>`;
}
function maintainedServiceCard(entry){
  const p=entry.preset,installed=p.route==='installed';
  return `<article class="card" data-service-id="${esc(p.id)}"><div class="card-top"><div class="card-icon">${icon(installed?'brand':'tools')}</div>${!entry.connection_ids.length?`<span class="tag">${installed?'Installed':'Setup needed'}</span>`:''}</div><h2>${esc(p.name)}</h2><p class="description">${esc(p.description)}</p>${installed?'<div class="card-actions"><a class="button secondary small" href="#brand">Configure Masterbrand</a><a class="button ghost small" href="#agents">Manage agent assignments</a></div>':entry.connection_ids.map(id=>savedConnectionCard(id,state.tools.mcp_servers[id],p.name)).join('')+`<div class="card-actions section-space"><button class="button secondary small" data-action="service-setup" data-name="${esc(p.id)}">${entry.connection_ids.length?'Add another account':'Set up'}</button></div>`}</article>`;
}
function toolsPage(){
  const entries=state.available_connections||[],mapped=new Set(entries.flatMap(e=>e.connection_ids)),custom=Object.entries(state.tools.mcp_servers).filter(([id])=>!mapped.has(id));
  const categories=[...new Set(entries.map(e=>e.preset.category))];
  return `${heading('')}${pendingNotice()}<div class="section-head"><h2>Connections</h2><button class="button secondary small" data-action="mcp-new">＋ Add connection</button></div><p>Built-in services are included. Set up the ones you use, select their accounts or folders, then choose agents. Services you have not assigned do not block Chat.</p>${categories.map(category=>`<section class="section-space"><h2>${esc(category)}</h2><div class="grid two">${entries.filter(e=>e.preset.category===category).map(maintainedServiceCard).join('')}</div></section>`).join('')}<details id="tools-custom" class="section-space" ${custom.length?'open':''}><summary>Advanced — custom connections</summary><button class="button secondary small" data-action="service-custom">Add custom connection</button>${custom.map(([id,s])=>savedConnectionCard(id,s)).join('')||'<p>No custom connections configured.</p>'}</details><details id="tools-advanced" class="section-space" ${toolsAdvancedOpen?'open':''}><summary>Advanced — individual tools and API settings</summary><button class="button secondary small" data-action="http-new">Create API tool</button><div class="section-head section-space"><h2>Available tools</h2><span class="count-label">${state.catalog.length} tools</span></div><div class="grid three">${state.catalog.map(t=>`<article class="card"><div class="card-top"><div class="card-icon">${icon(t.kind==='Python'?'brand':t.kind==='API'?'server':'tools')}</div><span class="tag">${esc(t.kind || 'MCP')}</span></div><h3>${esc(t.label)}</h3><p class="description">${esc(t.description || 'Available to your agents.')}</p><div class="card-bottom"><span>${t.enabled===false?'Disabled':t.server?'MCP tool':t.kind==='Python'?'Installed Python tool':'Custom API tool'}</span>${t.kind==='API'?`<button class="button secondary small" data-action="http-edit" data-name="${esc(t.name)}">Edit tool</button>`:'<span class="tag">Selectable in agents</span>'}</div></article>`).join('')}</div></details>`;
}
function brandPage() { const b=state.brand; return `${heading()}<div class="brand-layout"><form id="brand-form" class="card"><div class="section-head"><h2>Organisation details</h2><span class="tag">Available on the next tool call</span></div>${field('organisation_name','Organisation name',b.organisation_name,'text','The name your agents should use.')}${field('mission','Mission',b.mission,'textarea','Describe what your organisation works to achieve.')}${field('values','Values',b.values.join('\n'),'textarea','List one value per line.')}${field('strategy','Strategy',b.strategy,'textarea','Describe your priorities and plans.')}${field('target_audience','Target audience',b.target_audience,'textarea','Who do you serve, reach, or want to engage?')}${field('brand_voice','Brand voice',b.brand_voice,'textarea','Describe your tone, language, and communication guidelines.')}<button class="button" type="submit">Save Masterbrand</button><p class="help section-space">Agents with Masterbrand tools can read these details. Empty fields are reported as not configured.</p></form><aside class="card brand-aside"><div class="big-symbol" aria-hidden="true">✳</div><p class="eyebrow">WRITING GUIDANCE</p><h3>What to include</h3><p>Describe your organisation, who you want to reach, and how you want to communicate. Include examples of language to use or avoid.</p><hr><h3>When changes take effect</h3><p>Saved changes are available the next time an agent calls a Masterbrand tool. You don’t need to restart a gateway.</p><span class="tag">Saved on this device</span></aside></div>`; }
function secretsPage() { return `${heading('<button class="button" data-action="secret-new">＋ Add secret</button>')}${pendingNotice()}<div class="notice"><p><strong>Saved values are hidden.</strong> Keys and tokens are stored in the .env file on this computer. They are used to authenticate requests to your providers and connections, and are never sent back to this browser.</p></div><div class="grid two">${state.secrets.map(s=>`<article class="card secret-card"><div class="card-icon">${icon('secrets')}</div><div class="info"><h3>${s.local_gateway?'Local gateway connection':esc(s.name.replaceAll('_',' ').replace(/\bAPI\b/g,'API'))}</h3><p>${esc(s.used_by.join(' · ') || 'Available for your connections')}</p><span class="secret-name">${s.local_gateway?'One password for the master and client keys':esc(s.name)}</span><div class="card-actions"><button class="button secondary small" data-action="secret-edit" data-name="${esc(s.name)}">${s.configured?'Replace':'Add value'}</button>${!s.used_by.length?`<button class="button ghost small" data-action="secret-delete" data-name="${esc(s.name)}">Delete</button>`:''}</div></div><span class="badge ${s.configured?'running':'needs_setup'}">${s.configured?'Configured':'Missing'}</span></article>`).join('')}</div><p class="help section-space">This version uses plaintext .env storage, protected by file permissions. Avoid sharing that file or adding it to source control.</p>`; }
function field(name,label,value='',type='text',help='',required=false) { return `<div class="field"><label for="f-${name}">${esc(label)}</label>${type==='textarea'?`<textarea id="f-${name}" name="${name}" ${required?'required':''}>${esc(value)}</textarea>`:`<input id="f-${name}" name="${name}" type="${type}" value="${esc(value)}" ${required?'required':''} ${type==='password'?'autocomplete="new-password"':''}>`}${help?`<small>${esc(help)}</small>`:''}</div>`; }
function select(name,label,options,value='',help='') { return `<div class="field"><label for="f-${name}">${esc(label)}</label><select id="f-${name}" name="${name}">${options.map(([key,text])=>`<option value="${esc(key)}" ${key===value?'selected':''}>${esc(text)}</option>`).join('')}</select>${help?`<small>${esc(help)}</small>`:''}</div>`; }
function checked(name,label,value=true) { return `<label class="check-option"><input name="${name}" type="checkbox" ${value?'checked':''}><span>${esc(label)}</span></label>`; }
function openEditor(title,kicker,content,save,label='Save changes') {
  editorAfterSave=null;
  currentEditor = save; $('#dialog-title').textContent=title; $('#dialog-kicker').textContent=kicker; $('#editor-fields').innerHTML=content; $('#form-error').textContent=''; $('#save-editor').textContent=label; $('#save-editor').hidden=!save; dialog.showModal();
}
function closeEditor() { stopMcpSetup();stopMcpAuthPolling(true);stopChatSetupRefreshing();editorAfterSave=null;dialog.close(); $('#editor-fields').replaceChildren(); currentEditor=null; }
function formObject(form) { return Object.fromEntries(new FormData(form)); }
function deleteButton(action,id,label='Delete') { return `<hr><button type="button" class="button danger small" data-action="${action}" data-name="${esc(id)}">${label}</button>`; }
async function saved(message) { const after=editorAfterSave;await renderKeepingDraft();closeEditor();if(after)await after();toast(message); }
function editAgent(id=null,duplicate=false) {
  const old=id?state.agents.agents[id]:{},team=id?teamForAgent(id):activeTeam,root=id===teamRoot(team)&&!duplicate,models=old.models||[Object.keys(state.models)[0]],revision=state.revision;
  const name=id?agentName(id)+(duplicate?' copy':''):'';
  const excluded=id&&!duplicate?branchMembers(id):[];
  const parents=teamMembers(team).filter(k=>!excluded.includes(k));
  const teamField=root?`<div class="subtle-box">Coordinator of ${esc(teamName(team))}. Each team keeps its own coordinator.</div>`:select('agent_team','Team',Object.entries(state.agents.teams).map(([k,t])=>[k,t.display_name]),team);
  const content=field('display_name','Name',name,'text','The name shown in agent lists and chat.',true)+field('description','Purpose',old.description||'','textarea','When should the coordinator use this agent?')+field('instruction','Instructions',old.instruction||'','textarea','What should this agent do, and when should it ask for help?',true)+teamField+`<div class="field-grid">${select('model','Model preference',Object.keys(state.models).map(k=>[k,modelName(k)]),models[0])}${root?'':select('parent','Supervising agent',parents.map(k=>[k,agentName(k)]),duplicate||!id?teamRoot(team):parentOf(id))}</div>${old.sub_agents?.length&&!root?'<p class="help">Moving this agent to another team also moves its specialists.</p>':''}<label>Tools</label><p class="help">Tools and connections are shared across the workspace. Choose what this agent can use.</p><div class="check-grid">${state.catalog.map(t=>`<label class="check-option"><input type="checkbox" name="tool" value="${esc(t.name)}" ${(old.tools||[]).includes(t.name)?'checked':''}><span><b>${esc(t.label)}</b><small>${esc(t.kind||'MCP')}${t.enabled===false?' · disabled':''}</small></span></label>`).join('')}</div><details><summary>Advanced settings</summary><p class="help">Identifier: ${id&&!duplicate?esc(id):'Created automatically and kept stable.'}</p><label>Fallback models</label><div class="check-grid">${Object.keys(state.models).map(k=>`<label class="check-option"><input type="checkbox" name="fallback" value="${esc(k)}" ${models.slice(1).includes(k)?'checked':''}>${esc(modelName(k))}</label>`).join('')}</div>${select('mode','Agent mode',[['','Standard conversation'],['single_turn','Single turn specialist'],['task','Task']],old.mode||'')}</details>${id&&!duplicate&&!root?deleteButton('agent-delete',id,'Delete agent'):''}`;
  openEditor(duplicate?'Duplicate agent':id?'Edit agent':'New agent','AGENTS',content,async form=>{
    const f=formObject(form),fd=new FormData(form),target=f.agent_team||team;
    await api('/agents'+(id&&!duplicate?'/'+id:''),id&&!duplicate?'PUT':'POST',{revision,team:target,parent:f.parent,agent:{display_name:f.display_name,description:f.description,instruction:f.instruction,models:[f.model,...fd.getAll('fallback').filter(k=>k!==f.model)],tools:fd.getAll('tool'),mode:f.mode||null}});
    activeTeam=target;await saved('Agent saved. New conversations will use these settings.');
  });
}
let rowCounter=0;
function inputRow(item={}) { const n=++rowCounter; return `<div class="row-editor input-row"><div class="row-heading"><span>Input parameter</span><button type="button" class="icon-button" data-action="row-remove" aria-label="Remove input">×</button></div><div class="field-grid">${field('input_name_'+n,'Name',item.name||'','text','',true)}${select('input_type_'+n,'Type',['string','number','integer','boolean','object','array'].map(v=>[v,v]),item.type||'string')}</div><div class="field-grid">${select('input_location_'+n,'Send in',[['query','Query string'],['path','URL path'],['body','JSON body']],item.location||'query')}${field('input_description_'+n,'Description',item.description||'')}</div>${checked('input_required_'+n,'Required',item.required!==false)}</div>`; }
function secretOptions() { return [['','No secret'],...state.secrets.map(s=>[s.name,s.local_gateway?'Local gateway password':s.name])]; }
function headerRow(item={}) { const n=++rowCounter; return `<div class="row-editor header-row"><div class="row-heading"><span>Request header</span><button type="button" class="icon-button" data-action="row-remove" aria-label="Remove header">×</button></div>${field('header_name_'+n,'Header name',item.name||'','text','For example, Authorization or X-API-Key',true)}<div class="field-grid">${select('header_secret_'+n,'Use a saved secret',secretOptions(),item.secret||'')}${field('header_prefix_'+n,'Prefix',item.prefix||'','text','For example, Bearer followed by a space')}</div>${field('header_value_'+n,'Or a non-sensitive fixed value',item.value||'','text','Use secret references for API keys and tokens.')}</div>`; }
function rowValues(form,cls) { return $$(cls,form).map(row=>{const result={}; $$('input,select',row).forEach(el=>{const key=el.name.replace(/^(input|header)_/,'').replace(/_\d+$/,''); result[key]=el.type==='checkbox'?el.checked:el.value;});return result;}); }
function editHTTP(id=null) {
  const s=id?state.tools.http_tools[id]:{}, revision=state.revision;
  const content=field('display_name','Tool name',s.display_name||'','text','Choose a readable name, such as Find supporters.',true)+field('description','What does it do?',s.description||'','textarea','Agents use this description to decide when to call the tool.',true)+`<div class="field-grid">${select('method','Method',['GET','POST','PUT','PATCH','DELETE','HEAD'].map(k=>[k,k]),s.method||'GET')}${field('url','API address',s.url||'','text','For path inputs, use /people/{person_id}.',true)}</div><label>Inputs</label><p class="help">Define the values your agent can supply.</p><div id="input-rows">${(s.inputs||[]).map(inputRow).join('')}</div><button type="button" class="button secondary small" data-action="input-add">＋ Add input</button><hr><label>Headers & authentication</label><div id="header-rows">${(s.headers||[]).map(headerRow).join('')}</div><button type="button" class="button secondary small" data-action="header-add">＋ Add header</button><hr>${checked('enabled','Enable this tool',s.enabled!==false)}${id?`<details><summary>Test this tool</summary><p class="help">Sends a real request using the last saved settings. Include input values as JSON.</p>${field('test_arguments','Input values','{}','textarea')}<button type="button" class="button secondary small" data-action="http-test" data-name="${id}">Send test request</button><pre id="test-output" class="test-output" hidden></pre></details>`+deleteButton('http-delete',id,'Delete tool'):''}`;
  openEditor(id?'Edit API tool':'Create API tool','TOOLS',content,async form=>{const f=formObject(form);await api('/http-tools'+(id?'/'+id:''),id?'PUT':'POST',{revision,spec:{display_name:f.display_name,description:f.description,method:f.method,url:f.url,inputs:rowValues(form,'.input-row'),headers:rowValues(form,'.header-row'),enabled:!!f.enabled}});await saved('API tool saved. Connecting automatically; review its access in Guardrails before use.');});
}
function editMCP(id=null,brave=false,google=false) { editMcpConnection(id,brave,google); }
function toggleTransport() { toggleMcpAuthentication(); }
function editSecret(name=null,onSaved=null) {
  const local=name==='LITELLM_MASTER_KEY', revision=state.revision;
  const content=(name?`<p class="help">${local?'Updates both local master and client keys. Use a password beginning with sk-.':esc(name)}</p>`:field('name','Secret name','','text','Use a name such as CRM_API_KEY.',true))+field('value',name?'New value':'Secret value','','password','Existing values are never loaded into this form.',true);
  openEditor(name?'Replace secret':'Add secret','SECRETS',content,async form=>{const f=formObject(form);await api('/secrets/'+encodeURIComponent(name||f.name),'PUT',{revision,value:f.value});form.reset();if(onSaved){closeEditor();await refresh();await onSaved();}else await saved('Secret saved on this device. Gateways reconnect automatically.');});
}
function chatUnavailable() {
  const unavailable=state.services.filter(s=>!['running','external','starting'].includes(s.status));
  if(unavailable.length)return 'This team needs a connection check. You can fix it here in Chat.';
  const starting=state.services.filter(s=>s.status==='starting');
  if(state.services_busy||starting.length)return `${starting.length?starting.map(s=>s.label).join(' and '):'Gateways'} connecting automatically… You can write your message while you wait.`;
  if(state.synchronisation?.state==='attention')return 'A connection needs attention. Review the setup here in Chat.';
  if(state.services.some(s=>s.pending))return 'Saved changes are connecting automatically. Your draft will be kept.';
  return '';
}
function updateChatReadiness() {
  const notice=$('#chat-readiness'),send=$('#send-message');
  if(!notice||!send)return;
  const reason=chatUnavailable();
  notice.hidden=!reason;
  $('p',notice).textContent=reason;
  send.disabled=streaming;
  $('#message-input').disabled=!!activeConversation?.outdated||streaming;
  $$('.prompts button').forEach(button=>button.disabled=streaming);
}
async function chatPage() {
  const conversations=(await api('/conversations')).conversations;state.hasChats=!!conversations.length;
  if(activeConversation)activeConversation=await api('/conversations/'+activeConversation.id);
  const c=activeConversation;
  return `${heading()}<div class="chat-layout"><aside class="conversation-list" aria-label="Conversations"><button class="button secondary small" data-action="chat-new">＋ New conversation</button>${conversations.map(item=>`<button class="conversation-link ${c?.id===item.id?'active':''}" data-action="chat-open" data-name="${item.id}">${esc(item.title)}<small>${esc(item.team_name||'Previous team')} · ${esc(item.agent_name||agentName(item.agent))}</small></button>`).join('')}</aside><section class="chat-main" aria-label="Agent conversation"><div class="chat-top"><div><h2>${c?esc(c.agent_name||agentName(c.agent)):esc(teamName())}</h2><small>${c?esc(c.team_name||'Previous team')+' · Conversation saved locally':'Choose the team coordinator or an individual specialist.'}</small></div>${c?`<button class="button ghost small" data-action="chat-delete" data-name="${c.id}">Delete chat</button>`:''}</div>${c?.outdated?'<div class="notice warn chat-stale"><p>This conversation’s original team or agent is no longer available.</p><button class="button small" data-action="chat-new">Choose another team</button></div>':''}<div class="chat-messages" id="chat-messages" role="log" aria-label="Messages" aria-live="polite">${c?.messages.length?renderMessages(c.messages):`<div class="chat-welcome"><div class="card-icon">${icon('spark')}</div><h2>What shall we work on?</h2><p>Talk to ${esc(teamName())}, or start a conversation with an individual specialist.</p><div class="prompts"><button data-action="prompt" data-message="What is the charity’s strategy?">What is the charity’s strategy? ↗</button><button data-action="prompt" data-message="How can this team help me?">What can this team help with? ↗</button></div></div>`}</div><div class="chat-compose"><div id="chat-readiness" class="notice warn" role="status" hidden><p></p><button class="button secondary small" type="button" data-action="chat-setup">Review setup</button></div><form id="chat-form"><label class="skip" for="message-input">Your message</label><textarea id="message-input" name="message" rows="1" placeholder="Type a message…" maxlength="32000" ${c?.outdated?'disabled':''} required></textarea><button type="submit" class="button" id="send-message" ${c?.outdated?'disabled':''}>Send ↗</button><button type="button" class="button secondary" data-action="chat-cancel" id="stop-message" hidden>Stop</button></form><small>Responses use your configured provider and may incur charges. Check sources and important details.</small></div></section></div>`;
}
function renderMessages(messages) { let html='', activities=[];const flush=()=>{if(activities.length){html+=`<details class="activity"><summary>Agent activity · ${activities.length} steps</summary>${activities.map(a=>`<p>${esc(a.label)}</p>`).join('')}</details>`;activities=[];}};for(const m of messages){if(m.type==='activity'){activities.push(m);continue;}flush();html+=messageHTML(m);}flush();return html; }
function messageHTML(m) { if(m.type==='notice'&&m.issue?.code==='response.truncated')return `<article class="message notice"><h3>${esc(m.issue.title)}</h3><p>${esc(m.issue.message)}</p></article>`;if(m.type==='error'){const p=m.issue||{code:'provider.failed',title:'Chat needs attention',message:'Review the setup below before trying again.'};return `<article class="message error"><h3>${esc(p.title)}</h3><p>${esc(p.message)}</p><button class="button secondary small" data-action="chat-setup" data-code="${esc(p.code)}">Review setup</button></article>`;} if(m.type==='answer')return `<article class="message answer"><div class="author">${esc(m.agent?agentName(m.agent):'Your team')}</div><div class="markdown">${m.html||esc(m.text)}</div></article>`;return `<article class="message ${esc(m.type)}"><div class="text">${esc(m.text)}</div></article>`; }
async function newChat(agent=null) {
  if(streaming)throw Error('Stop the current response before starting a new conversation.');
  if(!agent){
    openEditor('Start a conversation','CHAT',select('chat_team','Team',Object.entries(state.agents.teams).map(([id,t])=>[id,t.display_name]),activeTeam)+select('data_class','Conversation data class',guardClasses,'public','Personal and sensitive data need approved workflows.')+select('agent','Who would you like to talk to?',teamMembers().map(k=>[k,agentName(k)+(k===teamRoot()?' · Coordinator':'')]),teamRoot()),async form=>{
      const f=formObject(form);activeConversation=await api('/conversations','POST',{agent:f.agent,team:f.chat_team,data_class:f.data_class});activeTeam=f.chat_team;history.replaceState(null,'','#chat');page='chat';await render();closeEditor();$('#message-input')?.focus();
    },'Start conversation');return;
  }
  activeTeam=teamForAgent(agent);activeConversation=await api('/conversations','POST',{agent,team:activeTeam});history.replaceState(null,'','#chat');page='chat';await render();
}
async function render() {
  const version=++renderVersion,target=page;
  navigation();
  let html;
  if(page==='guardrails')main.innerHTML=heading()+'<div class="card" role="status">Loading your organisation’s choices…</div>';
  try {
    html=page==='overview'?overview():page==='teams'?teamsPage():page==='agents'?agentsPage():page==='models'?modelsPage():page==='tools'?toolsPage():page==='brand'?brandPage():page==='guardrails'?await guardrailsPage():page==='secrets'?secretsPage():await chatPage();
  } catch(error) {
    if(version!==renderVersion||target!==page)return;
    main.innerHTML=heading()+'<section class="card"><h2>We could not load these settings</h2><p>Your saved choices are still safe. Try loading the page again.</p><button class="button" data-action="page-retry">Try again</button></section>';
    return;
  }
  if(version!==renderVersion||target!==page)return;
  main.innerHTML=html;
  if(page==='guardrails')await pollGuardrails();
  if(page==='brand') $('#brand-form').dataset.revision=state.revision;
  if(page==='chat') { updateChatReadiness();const messages=$('#chat-messages');messages.scrollTop=messages.scrollHeight; }
  document.title=`${pages[page][0]} · Kindred`;
}
async function sendMessage(prompt) {
  if(streaming)return;
  const query=new URLSearchParams(activeConversation?{conversation:activeConversation.id}:{team:activeTeam});
  let setup;
  try{setup=await api('/chat/requirements?'+query);}catch(error){await showChatSetup();return;}
  if(!setup.ready){await showChatSetup();return;}
  if(!activeConversation){const draft=$('#message-input').value;activeConversation=await api('/conversations','POST',{team:activeTeam});await render();$('#message-input').value=draft;}
  const list=$('#chat-messages');
  $('#send-message').hidden=true;$('#stop-message').hidden=false;$('#message-input').disabled=true;streaming=true;
  let partial=null,activity=null,problem=null,answered=false;
  const scroll=()=>list.scrollTop=list.scrollHeight;
  try {
    const res=await fetch(`/api/conversations/${activeConversation.id}/messages`,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({message:prompt})});
    if(!res.ok){const failure=await res.json();problem=failure.issue||failure.requirements?.[0]||{code:'provider.failed'};throw Error('setup');}
    $('.chat-welcome',list)?.remove();list.insertAdjacentHTML('beforeend',messageHTML({type:'user',text:prompt}));$('#message-input').value='';
    const reader=res.body.getReader(), decoder=new TextDecoder();let buffer='';
    while(true){const {value,done}=await reader.read();if(done)break;buffer+=decoder.decode(value,{stream:true});let split;while((split=buffer.indexOf('\n\n'))>=0){const frame=buffer.slice(0,split);buffer=buffer.slice(split+2);if(!frame.startsWith('data: '))continue;const e=JSON.parse(frame.slice(6));
      if(e.type==='activity'){if(!activity){activity=document.createElement('details');activity.className='activity';const s=document.createElement('summary');s.textContent='Agent activity';activity.append(s);list.append(activity);}const p=document.createElement('p');p.textContent=e.label;activity.append(p);}
      else if(e.type==='delta'){if(!partial){partial=document.createElement('article');partial.className='message answer';const div=document.createElement('div');div.className='text';partial.append(div);list.append(partial);}$('.text',partial).textContent+=e.text;}
      else if(e.type==='answer'){answered=true;partial?.remove();partial=null;list.insertAdjacentHTML('beforeend',messageHTML(e));activity=null;}
      else if(e.type==='error'||e.type==='notice'){partial?.remove();partial=null;if(e.type==='error')problem=e.issue||{code:'provider.failed'};list.insertAdjacentHTML('beforeend',messageHTML(e));}scroll();
    }}
  } catch(error) {problem=problem||{code:'provider.failed'};}
  finally{streaming=false;$('#send-message').hidden=false;$('#stop-message').hidden=true;activeConversation=await api('/conversations/'+activeConversation.id);updateChatReadiness();if(problem&&!answered)$('#message-input').value=prompt;$('#message-input').focus();scroll();if(problem)await showChatSetup(problem);}
}
function confirmTeamDelete(id) {
  if(Object.keys(state.agents.teams).length===1)throw Error('Keep at least one team. Create another team before deleting this one.');
  const revision=state.revision, count=teamMembers(id).length, isDefault=id===state.agents.default_team;
  const content=`<p>This removes ${esc(teamName(id))} and its ${count} agent${count===1?'':'s'}, including the coordinator. Saved conversations will remain readable in Chat.</p><p>Shared models, tools, secrets, and Masterbrand will be kept.</p>`+(isDefault?select('replacement_default','New default team',[['','Choose a team…'],...Object.entries(state.agents.teams).filter(([name])=>name!==id).map(([name,t])=>[name,t.display_name])],'','This team will be selected when you open the app.'): '');
  if(dialog.open)closeEditor();
  openEditor(`Delete “${teamName(id)}”?`,'DELETE TEAM',content,async form=>{
    const body={revision};
    if(isDefault)body.replacement_default=formObject(form).replacement_default;
    await api('/teams/'+encodeURIComponent(id),'DELETE',body);
    if(activeConversation?.team===id)activeConversation=null;
    await saved('Team deleted. Saved conversations are still available in Chat.');
  },'Delete team');
  if(isDefault)$('#f-replacement_default',dialog).required=true;
}
async function confirmDelete(kind,id) {
  if(kind==='team'){confirmTeamDelete(id);return;}
  const mapping={team:['team','/teams/'],model:['model','/models/'],agent:['agent','/agents/'],http:['API tool','/http-tools/'],mcp:['connection','/connections/'],secret:['secret','/secrets/'],chat:['conversation','/conversations/']}, [label,url]=mapping[kind], revision=state.revision;
  if(dialog.open)closeEditor();
  openEditor(`Delete this ${label}?`,'REMOVE',`<p>This removes the ${label} from this workspace. ${kind==='chat'?'Its saved messages will be deleted.':kind==='team'?'Its coordinator and specialists will be removed. Saved conversations stay readable.':'Items still used by agents or connections must be unassigned first.'}</p>`,async()=>{await api(url+encodeURIComponent(id),'DELETE',{revision});if(kind==='chat'||kind==='team')activeConversation=null;await saved(`${label[0].toUpperCase()+label.slice(1)} deleted.`);},'Delete');
}
document.addEventListener('click',async event=>{
  const button=event.target.closest('[data-action]');if(!button)return;
  const action=button.dataset.action,id=button.dataset.name;
  try {
    if(action.startsWith('mcp-setup-')){button.disabled=true;await mcpSetupAction(action.slice(10),id);return;}
    if(action.startsWith('connection-auth-')){button.disabled=true;await connectionAuthAction(action.slice(16),id);return;}
    if(action==='google-template'){closeEditor();editMCP(null,false,true);return;}
    if(action.startsWith('setup-')){await chatSetupAction(action.slice(6),id);return;}
    if(action==='chat-setup'){await showChatSetup(button.dataset.code?{code:button.dataset.code}:null);return;}
    if(action==='page-retry'){await render();return;}
    if(action.startsWith('sandbox-')){await sandboxAction(action,id);return;}
    if(action.startsWith('guard-')){await guardrailsAction(action,id);return;}
    if(action==='service-setup'){await showMcpSetup(null,id);return;}
    if(action==='service-custom'){await showMcpSetup(null,'remote');return;}
    if(action==='agent-new')editAgent();else if(action==='agent-edit')editAgent(id);else if(action==='agent-duplicate')editAgent(id,true);else if(action==='agent-test')await newChat(id);
    else if(action==='http-new')editHTTP();else if(action==='http-edit')editHTTP(id);else if(action==='mcp-new')await showMcpSetup();else if(action==='mcp-edit')editMCP(id);else if(action==='brave-template'){closeEditor();await showMcpSetup(null,'brave');}
    else if(action==='team-new')editTeam();else if(action==='team-edit')editTeam(id);else if(action==='team-agents'){activeTeam=id;activeConversation=null;page='agents';location.hash='agents';await render();}else if(action==='team-chat'){activeTeam=id;activeConversation=null;await newChat(teamRoot());}else if(action==='team-coordinator'){closeEditor();editAgent(id);}
    else if(action==='secret-new')editSecret();else if(action==='secret-edit')editSecret(id);
    else if(action==='model-new')editModel();else if(action==='model-edit')editModel(id);else if(action==='model-key')await modelSecret(id);
    else if(action==='model-secret-edit'){const draft=modelDraft(),modelId=dialog.dataset.modelId||null;if(!/^[A-Z][A-Z0-9_]{0,79}$/.test(draft.secret))throw Error('Enter a secret name such as MY_PROVIDER_API_KEY.');closeEditor();editSecret(draft.secret,async()=>{editModel(modelId,draft);toast('Private key saved. Finish saving your model to link it.');});}
    else if(action.endsWith('-delete'))await confirmDelete(action.split('-')[0],id);
    else if(action==='input-add')$('#input-rows').insertAdjacentHTML('beforeend',inputRow());else if(action==='header-add')$('#header-rows').insertAdjacentHTML('beforeend',headerRow());else if(action==='row-remove')button.closest('.row-editor').remove();
    else if(action==='service'){button.disabled=true;const result=await api(`/services/${id}/${button.dataset.operation}`,'POST');toast(result.message);await pollServices();}
    else if(action==='apply'){button.disabled=true;toast((await api('/services/apply','POST')).message);}
    else if(action==='logs'){const data=await api(`/services/${id}/logs`);openEditor('Connection diagnostics','SERVICES',`<pre class="test-output">${esc(data.text)}</pre>`,null);}
    else if(action==='mcp-test'){button.disabled=true;button.textContent='Connecting…';if(['oauth','google_adc'].includes(state.tools.mcp_servers[id]?.auth?.type)&&(await api('/connections/'+encodeURIComponent(id)+'/auth')).status!=='connected'){await showConnectionAuth(id);return;}const data=await api(`/connections/${id}/test`,'POST');await refresh();await render();toast(data.message);}
    else if(action==='http-test'){button.disabled=true;const args=JSON.parse($('#f-test_arguments').value);const data=await api(`/http-tools/${id}/test`,'POST',{arguments:args});$('#test-output').textContent=JSON.stringify(data.result,null,2);$('#test-output').hidden=false;}
    else if(action==='chat-new')await newChat();else if(action==='chat-open'){if(streaming)throw Error('Stop the current response before switching conversations.');activeConversation=await api('/conversations/'+id);if(state.agents.teams[activeConversation.team])activeTeam=activeConversation.team;await render();}
    else if(action==='chat-cancel')await api('/chat/cancel','POST');
    else if(action==='prompt'){await sendMessage(button.dataset.message);}
  }catch(error){if(dialog.open)$('#form-error').textContent=error.message;else toast(error.message);}
  finally{if(button.isConnected){button.disabled=false;if(action==='mcp-test')button.textContent='Test & discover tools';}}
});
$('#editor-form').addEventListener('submit',async event=>{event.preventDefault();if(!currentEditor)return;$('#save-editor').disabled=true;$('#form-error').textContent='';try{await currentEditor(event.target);}catch(error){$('#form-error').textContent=error.message;}finally{$('#save-editor').disabled=false;}});
$('#close-editor').addEventListener('click',closeEditor);$('#cancel-editor').addEventListener('click',closeEditor);dialog.addEventListener('cancel',()=>{stopMcpSetup();stopMcpAuthPolling(true);stopChatSetupRefreshing();editorAfterSave=null;$('#editor-fields').replaceChildren();currentEditor=null;});
document.addEventListener('change',event=>{if(event.target.id==='f-agent_team')updateAgentTeam();if(event.target.id==='f-chat_team')updateChatTeam();if(event.target.id==='team-switcher'){if(streaming){event.target.value=activeTeam;toast('Stop the current response before switching teams.');return;}activeTeam=event.target.value;activeConversation=null;render().catch(error=>toast(error.message));}if(['f-transport','f-mcp_authentication'].includes(event.target.id))toggleTransport();if(event.target.id==='f-model_secret')updateModelSecretStatus();if(event.target.id==='f-provider'){const provider=state.providers[event.target.value];$('#f-model_secret').value=provider.secret;$('#f-model_id').value='';$('#f-model_api_base').value=provider.api_base;$('#f-model_api_base').required=event.target.value==='custom';if(event.target.value==='custom')$('#f-model_api_base').closest('details').open=true;updateModelSecretStatus();}});
document.addEventListener('input',event=>{if(event.target.id==='f-model_secret_name')updateModelSecretStatus();});
document.addEventListener('submit',async event=>{
  if(event.target.id==='brand-form'){event.preventDefault();const form=event.target,btn=$('button[type=submit]',form);btn.disabled=true;try{const f=formObject(form);f.values=f.values.split('\n').map(v=>v.trim()).filter(Boolean);await api('/masterbrand','PUT',{revision:form.dataset.revision,brand:f});await refresh();form.dataset.revision=state.revision;toast('Masterbrand saved. Your team can use it on the next tool call.');}catch(error){toast(error.message);}finally{btn.disabled=false;}}
  if(event.target.id==='chat-form'){event.preventDefault();try{await sendMessage($('#message-input').value.trim());}catch(error){toast(error.message);}}
});
document.addEventListener('keydown',event=>{if(event.target.id==='message-input'&&event.key==='Enter'&&!event.shiftKey){event.preventDefault();$('#chat-form').requestSubmit();}});
$('#menu').addEventListener('click',()=>{document.body.classList.toggle('menu-open');$('#menu').setAttribute('aria-expanded',document.body.classList.contains('menu-open'));});
window.addEventListener('hashchange',async()=>{if(!state)return;const target=location.hash.slice(1);if(!pages[target])return;if(streaming){toast('Stop the current response before leaving chat.');history.replaceState(null,'','#chat');return;}page=target;document.body.classList.remove('menu-open');$('#menu').setAttribute('aria-expanded','false');await render();main.focus();});
async function pollServices() {if(!state||polling)return;polling=true;try{const next=await api('/services');state.services=next.services;state.services_busy=next.services_busy;state.synchronisation=next.synchronisation;navigation();const notice=$('#gateway-sync-notice');if(notice)notice.outerHTML=pendingNotice();if(page==='chat')updateChatReadiness();if(next.operation_error&&next.operation_error!==operationError)toast(next.operation_error);operationError=next.operation_error||'';if(page==='overview'&&!dialog.open){const c=$('#service-cards');if(c)c.innerHTML=serviceCards();const stat=$$('.stats .stat')[2],running=state.services.filter(s=>['running','external'].includes(s.status)).length;if(stat){$('.number',stat).innerHTML=`${running}<span class="muted"> / 2</span>`;$('.stat-detail',stat).textContent=running===2?'Both gateways are running':'Check gateway status below';}}}catch{}finally{polling=false;} }
async function boot() {
  try {
    const token=new URLSearchParams(location.hash.slice(1)).get('pair');
    if(token){history.replaceState(null,'',location.pathname);csrf=(await api('/pair','POST',{token})).csrf;}else csrf=(await api('/session')).csrf;
    await refresh();state.hasChats=!!(await api('/conversations')).conversations.length;page=pages[location.hash.slice(1)]?location.hash.slice(1):'overview';await render();await pollGuardrails();setInterval(pollServices,5000);setInterval(pollGuardrails,2000);
  }catch(error){main.innerHTML=`<div class="loading"><div class="brandmark">k·</div><h1>Connect your browser</h1><p>${esc(error.message)}</p><p class="help">Use the private pairing link printed by <code>uv run python -m control_panel</code>.<br>If it has expired, restart the local app.</p></div>`;}
}
boot();
