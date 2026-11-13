"""Default service availability is local metadata, never an access grant."""
from connectors.registry import catalogue
from control_panel.services import Services
from guardrails.policy import digest
from guardrails.settings import load_settings, compile_settings, ANALYTICS_COMMAND
from tests.test_connector_setup import create
from tools.mcp_auth import binding


def test_default_services_are_local_and_do_not_rewrite_configuration(client, app, monkeypatch):
    store=app.state.store
    paths=[store.tools_path,store.agents_path,store.policy_path,store.env_path]
    before={p:p.read_bytes() if p.exists() else None for p in paths}
    def forbidden(*args,**kwargs):raise AssertionError('Browsing services must not dispatch anything')
    monkeypatch.setattr('asyncio.create_subprocess_exec',forbidden)
    monkeypatch.setattr('httpx.AsyncClient.send',forbidden)
    monkeypatch.setattr('httpx2.AsyncClient.send',forbidden)
    state=client.get('/api/state').json()
    entries={e['preset']['id']:e for e in state['available_connections']}
    assert set(entries)=={p['id'] for p in catalogue() if p['route']!='custom'}
    assert entries['brave']['connection_ids']==['brave']
    assert entries['masterbrand']['connection_ids']==[]
    assert entries['google_ads']['connection_ids']==[]
    assert before=={p:p.read_bytes() if p.exists() else None for p in paths}


def test_service_identity_supports_multiple_accounts_and_last_deletion(client,app):
    first,second=create(client),create(client)
    def matched():
        return next(e for e in client.get('/api/state').json()['available_connections'] if e['preset']['id']=='web')['connection_ids']
    assert matched()==[first,second]
    for name in (first,second):
        result=client.request('DELETE','/api/connections/'+name,json={'revision':app.state.store.revision()})
        assert result.status_code==200,result.text
    assert matched()==[]


def complete_web(client,name,*,capabilities=None,assignments=None):
    view=client.get(f'/api/connections/{name}/setup').json()
    body={'revision':view['revision'],'configuration_hash':view['configuration_hash'],'capabilities':['pages'] if capabilities is None else capabilities,'resources':['public_https'],'agents':[], 'assignments':assignments or {}}
    return client.post(f'/api/connections/{name}/information/complete',json=body)


def test_defaults_are_suggestions_until_sources_and_agents_are_saved(client,app):
    name=create(client)
    store=app.state.store
    original=store.agents()
    view=client.get(f'/api/connections/{name}/setup').json()
    assert view['capabilities'][0]['default_enabled'] and not view['capabilities'][0]['enabled']
    assert view['selected_resources']==[] and name+'_fetch_page' not in load_settings(store.root).access
    assert client.post(f'/api/connections/{name}/test',json={}).status_code==200
    view=client.get(f'/api/connections/{name}/setup').json()
    body={'revision':view['revision'],'configuration_hash':view['configuration_hash'],'capabilities':['pages'],'resources':[],'agents':[]}
    assert client.post(f'/api/connections/{name}/information/complete',json=body).status_code==400
    assert complete_web(client,name).status_code==200
    assert store.agents()==original
    state=client.get('/api/state').json()
    assert next(c for c in state['connections'] if c['id']==name)['status']=='ready_to_assign'
    assert complete_web(client,name,assignments={'strategy_agent':['pages']}).status_code==200
    state=client.get('/api/state').json()
    assert next(c for c in state['connections'] if c['id']==name)['status']=='ready'
    assert name+'_fetch_page' not in state['agents']['agents']['influencer_search_agent']['tools']


def test_explicit_disabled_capabilities_and_narrower_access_survive_reopening(client,app):
    name=create(client)
    assert client.post(f'/api/connections/{name}/test',json={}).status_code==200
    assert complete_web(client,name).status_code==200
    store=app.state.store
    settings=load_settings(store.root)
    settings.access[name+'_fetch_page'].approved_data_classes=[]
    store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
    assert complete_web(client,name).status_code==200
    assert app.state.chat.guardrails.policy().tools[name+'_fetch_page'].approved_data_classes==[]
    assert complete_web(client,name,capabilities=[]).status_code==200
    cap=client.get(f'/api/connections/{name}/setup').json()['capabilities'][0]
    assert not cap['enabled'] and not cap['default_enabled']


def test_unassigned_missing_credentials_do_not_block_selected_branch(client,app,monkeypatch):
    store=app.state.store
    store.write_secrets({'BRAVE_API_KEY':None})
    monkeypatch.delenv('BRAVE_API_KEY',raising=False)
    tools=store.tools()
    tools['http_tools']['unused_api']={'description':'Unassigned API','url':'https://unused.service.co.uk','headers':[{'name':'Authorization','secret':'UNCONFIGURED_API_KEY'}]}
    store.save(store.tools_path,tools)
    ready=client.get('/api/chat/requirements?agent=strategy_agent').json()
    assert not any(r['code'] in {'model.secret','tools.missing','connection.auth_required'} for r in ready['requirements']),ready
    blocked=client.get('/api/chat/requirements?agent=influencer_search_agent').json()
    assert not blocked['ready']
    assert any(r['code']=='model.secret' for r in blocked['requirements'])
    assert any(a['kind']=='agent_tools' for r in blocked['requirements'] for a in r['actions'])
    assert not any('UNCONFIGURED_API_KEY'==a.get('target') for r in blocked['requirements'] for a in r['actions'])


def test_native_secret_changes_still_change_gateway_fingerprint(client,app):
    name=create(client,'meta_ads',api_key='private-before-rotation')
    store=app.state.store
    services=Services(store)
    before=services.fingerprint('tools')
    reference=store.tools()['mcp_servers'][name]['native']['secret_refs']['api_key']
    store.write_secrets({reference:'private-after-rotation'})
    assert services.fingerprint('tools')!=before


def test_default_suggestions_do_not_invalidate_authentication(client,app):
    name=create(client)
    spec=app.state.store.tools()['mcp_servers'][name]
    original=binding(spec,app.state.store.secret)
    spec['managed'].pop('default_capabilities')
    assert binding(spec,app.state.store.secret)==original


def test_connection_cards_report_failed_disabled_and_stale_setup(client,app):
    name=create(client)
    store=app.state.store
    def status():return next(c for c in client.get('/api/state').json()['connections'] if c['id']==name)['status']
    assert status()=='setup_needed'
    app.state.authentication.vault.record_check(name,store.tools()['mcp_servers'][name],'failed')
    assert status()=='needs_attention'
    config=store.tools();config['mcp_servers'][name]['enabled']=False
    store.save(store.tools_path,config)
    assert status()=='disabled'
    config['mcp_servers'][name]['enabled']=True
    config['mcp_servers'][name]['managed']['revision']='old-definition'
    store.save(store.tools_path,config)
    assert status()=='needs_attention'


def test_assigned_unknown_tool_cannot_make_a_connection_look_ready(client,app):
    name=create(client)
    assert client.post(f'/api/connections/{name}/test',json={}).status_code==200
    assert complete_web(client,name).status_code==200
    store=app.state.store
    agents=store.agents();agents['agents']['strategy_agent']['tools'].append(name+'_old_tool')
    store.save(store.agents_path,agents)
    state=client.get('/api/state').json()
    assert next(c for c in state['connections'] if c['id']==name)['status']=='needs_attention'


def test_pinned_analytics_has_only_maintained_read_defaults(store):
    config=store.tools()
    spec={'transport':'stdio','command':ANALYTICS_COMMAND[0],'args':ANALYTICS_COMMAND[1:],'auth':{'type':'google_adc','project':'charity'}}
    config['mcp_servers']['analytics']=spec
    store.save(store.tools_path,config)
    settings=load_settings(store.root)
    settings.approved_connections['analytics']=digest(spec)
    tools=[{'name':'analytics_'+name,'server':'analytics','description':name,'input_schema':{'type':'object'},'output_schema':None,'configuration_hash':digest(spec)} for name in ('run_report','create_property_annotation')]
    store.remember_catalog('analytics',tools)
    policy=compile_settings(store.root,settings)
    assert policy.tools['analytics_run_report'].classification=='read'
    assert 'analytics_create_property_annotation' not in policy.tools
    spec['args']=['--from','analytics-mcp==2.0.0','analytics-mcp']
    config['mcp_servers']['analytics']=spec
    store.save(store.tools_path,config)
    assert 'analytics_run_report' not in compile_settings(store.root,settings).tools
