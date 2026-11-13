'use strict';
let sandboxPollTimer;
const sandboxLabels={off:'Off',setup_needed:'Setup needed',applying:'Applying',ready:'Ready',needs_attention:'Needs attention'};
function sandboxStatus(d){
  return `<p><strong>${esc(sandboxLabels[d.state]||'Needs attention')}</strong> · Saved choice: ${d.enabled?'On':'Off'}${d.support==='experimental'?' · Experimental on Windows':''}</p>${d.experimental_message?`<p class="help">${esc(d.experimental_message)}</p>`:''}${d.checks.map(c=>`<p class="help">${esc(c.message)}</p>`).join('')}${d.jobs.filter(j=>j.state==='running'||j.state==='failed').slice(-1).map(j=>`<p role="status">${esc(j.message)}</p>`).join('')}`;
}
function sandboxContents(d){
  return `<p>Restricts local MCP connections and PDF extraction. The rest of the app, including online API connections and installed Python tools, keeps its current execution model. Data and action checks stay active in both modes.</p>${checked('sandbox_enabled','Sandbox local tools',d.enabled)}<p class="help">Off uses the current execution path. On blocks a local operation if its sandbox cannot start. Installation alone does not turn this switch on.</p><div data-sandbox-status aria-live="polite">${sandboxStatus(d)}</div><div class="card-actions"><button type="button" class="button secondary small" data-action="sandbox-setup" ${d.busy?'disabled':''}>Set up sandbox</button><button type="button" class="button secondary small" data-action="sandbox-check" ${d.busy?'disabled':''}>Check again</button></div><details class="section-space"><summary>Advanced — custom connection access</summary><p>Exact command approval and tool access review are still required. Additional paths and destinations are never inferred from model requests.</p>${d.connections.map(c=>`<article class="subtle-box"><h3>${esc(c.label)}</h3><p>${esc(c.profile==='custom'?(c.message||'Reviewed custom sandbox access'):'Maintained sandbox profile')}${d.enabled&&!c.ready?' · Needs attention':''}</p>${c.profile==='custom'?`<button type="button" class="button secondary small" data-action="sandbox-profile" data-name="${esc(c.name)}">Review sandbox access</button>`:''}</article>`).join('')}</details>`;
}
async function sandboxCard(){
  const d=await api('/sandbox');
  return `<section class="card section-space"><h2>Local tool sandbox</h2><form id="sandbox-settings-form" data-revision="${esc(d.revision)}">${sandboxContents(d)}<button class="button section-space" type="submit">Save sandbox choice</button></form></section>`;
}
async function showSandboxSettings(){
  const d=await api('/sandbox');
  openEditor('Local tool sandbox','SANDBOX',sandboxContents(d),async form=>{
    await api('/sandbox','PUT',{revision:d.revision,enabled:!!formObject(form).sandbox_enabled});
    closeEditor();await refresh();toast('Sandbox choice saved. Gateways reconnect automatically.');
  },'Save sandbox choice');
}
async function pollSandbox(){
  clearTimeout(sandboxPollTimer);
  if(!$('[data-sandbox-status]'))return;
  try{
    const d=await api('/sandbox');
    $$('[data-sandbox-status]').forEach(el=>el.innerHTML=sandboxStatus(d));
    $$('[data-action="sandbox-setup"],[data-action="sandbox-check"]').forEach(el=>el.disabled=d.busy);
    // Keep unsaved form fields and their revision intact while polling.
    if(d.jobs.some(j=>j.state==='running')||d.state==='applying')sandboxPollTimer=setTimeout(pollSandbox,1000);
  }catch{}
}
async function sandboxAction(action,id){
  if(action==='sandbox-manage'){await showSandboxSettings();return;}
  const d=await api('/sandbox');
  if(action==='sandbox-profile'){
    const c=d.connections.find(c=>c.name===id);if(!c)throw Error('Reload the saved connection before reviewing access.');
    const p=c.access||{};
    openEditor('Sandbox access · '+c.label,'LOCAL TOOL ACCESS','<p>Grant only the files and public services this command needs. Private application files and directories containing them cannot be granted.</p>'+field('read_paths','Additional read paths',(p.read_paths||[]).join('\n'),'textarea','One existing absolute path per line.')+field('write_paths','Additional write paths',(p.write_paths||[]).join('\n'),'textarea','One existing absolute path per line. Temporary storage is provided automatically.')+field('destinations','Allowed destinations',(p.destinations||[]).join('\n'),'textarea','One exact public hostname:port per line. No wildcard or local destinations.'),async form=>{
      const f=formObject(form),lines=s=>String(s||'').split('\n').map(s=>s.trim()).filter(Boolean);
      await api('/sandbox/connections/'+encodeURIComponent(id),'PUT',{revision:d.revision,profile:{configuration_hash:c.configuration_hash,read_paths:lines(f.read_paths),write_paths:lines(f.write_paths),destinations:lines(f.destinations)}});
      closeEditor();await refresh();toast('Sandbox access saved. Connecting automatically.');
    },'Save sandbox access');return;
  }
  const operation=action==='sandbox-setup'?'setup':'check';
  const start=async(confirmWindows=false)=>{
    const fresh=await api('/sandbox');
    await api('/sandbox/'+operation,'POST',{revision:fresh.revision,confirm_windows:confirmWindows});
    toast(operation==='setup'?'Sandbox setup started.':'Local sandbox checks started.');
    await pollSandbox();
  };
  if(operation==='setup'&&d.platform==='win32'){
    openEditor('Set up Windows sandbox','SANDBOX SETUP','<p>This creates a dedicated Kindred sandbox account and Windows firewall filters. Windows will ask for administrator approval. Your full user profile will not be shared, unrestricted loopback stays disabled, and other applications’ SRT installations will not be replaced.</p><p>Windows support is experimental. Turning sandboxing off later retains this installation.</p>'+checked('confirm_windows','Allow the described account and firewall setup',false),async form=>{
      if(!formObject(form).confirm_windows)throw Error('Confirm the described Windows setup to continue.');
      await start(true);await showSandboxSettings();await pollSandbox();
    },'Set up sandbox');
  }else await start();
}
document.addEventListener('submit',async event=>{
  if(event.target.id!=='sandbox-settings-form')return;
  event.preventDefault();
  const form=event.target,button=$('button[type="submit"]',form);button.disabled=true;
  try{await api('/sandbox','PUT',{revision:form.dataset.revision,enabled:!!formObject(form).sandbox_enabled});await saved('Sandbox choice saved. Connecting automatically.');}
  catch(error){toast(error.message);}finally{if(button.isConnected)button.disabled=false;}
});
