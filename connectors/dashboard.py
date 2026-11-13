"""Preset setup owns configuration; account discovery never executes tools."""
import asyncio
import secrets
import time
from urllib.parse import urlsplit

from fastapi import Request
from pydantic import Field

from control_panel.store import Conflict, slug
from guardrails.policy import Strict, canonical, digest, PolicyDenied
from guardrails.settings import load_settings, bind_access
from tools.definitions import MCPSpec
from tools.mcp_auth import AuthenticationRequired
from .registry import catalogue, preset, managed_check, hosted_url, hosted_read_allowed, capability_tools, resources_bound
from .auth import provider_name, provider_status
from .native import NativeClient


def create(store, runtime, data, p):
    updates = {}
    with store.edit(data.revision):
        config = store.tools()
        base = slug(data.display_name or p['name']).replace('_', '')[:32] or 'connection'
        name, index = base, 2
        used = set().union(*(set(config[s]) for s in ['mcp_servers','custom_tools','http_tools']))
        while name in used or any(name.startswith(n+'_') or n.startswith(name+'_') for n in config['mcp_servers']):
            name, index = base+str(index), index+1
        spec = {'display_name':data.display_name.strip() or p['name'], 'enabled':True, 'managed':{'preset':p['id'],'revision':p['revision'],'default_capabilities':[c['id'] for c in p['capabilities']]}}
        credentials = dict(data.credentials)
        if data.api_key:
            if 'api_key' in credentials:raise ValueError('Enter the API key once.')
            credentials['api_key'] = data.api_key
        if p['route'] == 'native':
            required = {f['key'] for f in p['fields'] if f['secret'] and f['required']}
            if p['authentication'] in {'key','token','session','basic'}:required.add('api_key')
            if set(credentials) != required:raise ValueError('Enter the credentials requested by this service.')
            refs = {}
            for key, value in credentials.items():
                if not value or len(value)>16384 or any(ord(c)<33 or ord(c)==127 for c in value):raise ValueError('Use a credential without whitespace or control characters.')
                reference = 'MCP_'+name.upper()+'_'+secrets.token_hex(6).upper()
                refs[key], updates[reference] = reference, value
            spec.update(transport='native',native={'provider':p['id'],'options':data.options,'secret_refs':refs,'resources':[],'capabilities':[]})
        else:
            allowed = {f['key'] for f in p['fields']}
            if set(data.options)-allowed:raise ValueError('Use the preset’s supported settings.')
            url = data.options.get('server_url') or data.url or p['url']
            if p['id']=='contentful' and data.options.get('region')=='eu':url='https://mcp.eu.contentful.com/mcp'
            hosted_url(p,url)
            spec.update(transport='http',url=url,auth={'type':'bearer' if p['authentication']=='key' else 'oauth'})
            if p['authentication']=='key':
                if set(credentials)!={'api_key'} or not credentials['api_key'] or any(ord(c)<33 for c in credentials['api_key']):raise ValueError('Enter the service’s MCP token.')
                ref='MCP_'+name.upper()+'_'+secrets.token_hex(6).upper()
                spec['token_env'],updates[ref]=ref,credentials['api_key']
            elif credentials:raise ValueError('Browser sign-in does not accept an API key.')
        config['mcp_servers'][name]=MCPSpec.model_validate(spec).model_dump(exclude_none=True)
        store.save_with_new_secrets({store.tools_path:config},updates)
        if spec.get('native') and not provider_name(spec):
            from tools.mcp_auth import CredentialVault
            CredentialVault(store.root).reset(name,config['mcp_servers'][name],store.secret).change(lambda record:record.update(connected=True),status='connected')
    runtime.invalidate_pending()
    return {'name':name,'revision':store.revision(),'message':'Connection saved. Connect, choose information and choose agents.'}


def view(store,runtime,authentication,name,spec):
    from control_panel.mcp_setup import connection_view
    p=managed_check(spec)
    tools=connection_view(store,runtime,name)['tools']
    native=spec.get('native') or {}
    choices=[]
    if native:
        try:
            record=authentication.vault.handle(name,spec,store.secret).read()
            snapshot=record.get('resource_choices',{})
            if snapshot.get('binding')==digest([native['provider'],native['options']]):choices=snapshot.get('values',[])
        except AuthenticationRequired:pass
    caps=[]
    policy=runtime.policy()
    settings=load_settings(store.root)
    def reviewed(tool,cap):
        rule=policy.tools.get(tool['name'])
        levels=['public','personal','sensitive']
        return bool(rule and rule.classification=='read' and rule.schema_hash==tool['schema_hash'] and rule.configuration_hash==digest(spec) and resources_bound(rule) and levels.index(rule.source_data_class)>=levels.index(cap['data_class']))
    for cap in p['capabilities']:
        matching=[t for t in tools if t.get('capability')==cap['id']] if native else [t for t in tools if t['name'][len(name)+1:] in capability_tools(p,cap['id']) and reviewed(t,cap)]
        caps.append({**cap,'tools':[t['name'] for t in matching],'available':bool(matching),'enabled':cap['id'] in native.get('capabilities',[]) if native else any(t['name'] not in settings.blocked_tools for t in matching)})
    usable={t for c in caps for t in c['tools']}
    defaults = (spec.get('managed') or {}).get('default_capabilities') or []
    for cap in caps:
        cap['default_enabled'] = not native.get('resources') and cap['available'] and cap['id'] in defaults and not any(t in settings.blocked_tools for t in cap['tools'])
    return {'managed':p,'resources':choices,'selected_resources':native.get('resources',[]),'capabilities':caps,'technical_review_required':not native and any(t['name'] not in usable for t in tools)}


async def discover_resources(store,runtime,authentication,name,spec):
    async with asyncio.timeout(35):
        choices=await NativeClient(name,spec,store.root,runtime.policy(),store.secret).resources()
    if any(s in canonical(choices) for s in runtime.secret_values()):
        raise PolicyDenied('data.secret','The service disclosed a credential in account metadata. The result was withheld.')
    if len(choices)>50 or len({c['id'] for c in choices})!=len(choices):raise ValueError('The service returned ambiguous account choices.')
    with store.lock:
        if store.tools()['mcp_servers'].get(name)!=spec:raise Conflict('The connection changed. Connect again.')
        handle=authentication.vault.handle(name,spec,store.secret)
        if handle.generation is None:handle=authentication.vault.reset(name,spec,store.secret)
        handle.change(lambda data:data.update(resource_choices={'binding':digest([spec['native']['provider'],spec['native']['options']]),'values':choices,'checked':time.time()}))
    return choices


class Complete(Strict):
    revision:str
    configuration_hash:str
    capabilities:list[str]=Field(max_length=12)
    resources:list[str]=Field(max_length=50)
    agents:list[str]=Field(max_length=500)
    assignments:dict[str,list[str]]|None=Field(default=None,max_length=500)


class Registration(Strict):
    revision:str
    client_id:str=Field(min_length=1,max_length=1024)
    client_secret:str=Field(default='',max_length=16384)
    callback_port:int=Field(ge=1024,le=65535)


class DeleteRegistration(Strict):
    revision:str


def connection_preset(spec):
    """Recognise maintained identity without treating names as evidence."""
    identifier = (spec.get('managed') or {}).get('preset')
    if identifier:
        try:
            return preset(identifier)
        except ValueError:
            return None
    from guardrails.settings import curated_connection, ANALYTICS_COMMAND
    if curated_connection(spec):
        return preset('brave')
    if spec.get('transport')=='stdio' and [spec.get('command'), *spec.get('args', [])]==ANALYTICS_COMMAND and (spec.get('auth') or {}).get('type')=='google_adc':
        return preset('google')
    return None


def available_connections(store):
    saved = store.tools()['mcp_servers']
    matches = {name: connection_preset(spec) for name, spec in saved.items()}
    return [{'preset':p, 'connection_ids':[name for name, match in matches.items() if match and match['id']==p['id']]} for p in catalogue() if p['route']!='custom']


def normalised_connections(store,authentication,summaries):
    result=[]
    agents = store.agents()['agents']
    for name,spec in store.tools()['mcp_servers'].items():
        p = connection_preset(spec)
        stale = False
        try:
            if spec.get('managed'):
                managed_check(spec)
        except ValueError:
            stale = True
        auth=authentication.status(name) if spec.get('enabled',True) else {'status':'disabled'}
        summary=summaries.get(name,{})
        assigned = [agent for agent, detail in agents.items() if any(t.startswith(name+'_') for t in detail['tools'])]
        assigned_tools = {t for agent in assigned for t in agents[agent]['tools'] if t.startswith(name+'_')}
        status = 'setup_needed'
        if not spec.get('enabled', True):
            status = 'disabled'
        elif stale or summary.get('connection')=='failed' or auth.get('status')=='failed':
            status = 'needs_attention'
        elif summary.get('connection')=='connected' and assigned_tools-set(summary.get('reviewed_tools', [])):
            status = 'needs_attention'
        elif auth.get('status')=='connected' and summary.get('connection')=='connected' and summary.get('reviewed',0)>0:
            status = 'ready' if assigned else 'ready_to_assign'
        result.append({'id':name,'name':spec.get('display_name') or name,'route':p['route'] if p else 'mcp','preset':p['id'] if p else None,'category':p['category'] if p else 'Advanced','authentication':auth,'connection':summary.get('connection','not_connected'),'reviewed':summary.get('reviewed',0),'total':summary.get('total',0),'capabilities':p['capabilities'] if p else [],'status':status,'assigned_agents':assigned})
    return result


def install_routes(app,store,authentication,runtime,response,idle):
    from control_panel.mcp_setup import payload,connection_view

    @app.get('/api/providers/{provider}/setup')
    async def registration(provider:str):
        return response(provider_status(authentication.vault,provider))

    @app.put('/api/providers/{provider}/setup')
    async def registration_update(provider:str,request:Request):
        idle();provider_status(authentication.vault,provider)
        if provider=='google':raise ValueError('Use the Google desktop-client setup.')
        data=await payload(request,Registration)
        if provider in {'blackbaud','linkedin'} and not data.client_secret:
            raise ValueError('This provider requires the registered application’s client secret.')
        if any(ord(c)<33 or ord(c)==127 for c in data.client_id+data.client_secret):raise ValueError('Use registration values without whitespace or control characters.')
        pending=[name for name,t in authentication.transactions.items() if (t.handle.spec.get('native') and provider_name(t.handle.spec)==provider)]
        authentication.vault.save_provider(provider,data.model_dump(exclude={'revision'}),data.revision)
        for name in pending:await authentication.cancel(name)
        return response(provider_status(authentication.vault,provider))

    @app.delete('/api/providers/{provider}/setup')
    async def registration_delete(provider:str,request:Request):
        idle();provider_status(authentication.vault,provider)
        if provider=='google':raise ValueError('Use the Google setup removal action.')
        data=await payload(request,DeleteRegistration)
        authentication.vault.save_provider(provider,None,data.revision)
        for name,t in list(authentication.transactions.items()):
            if t.handle.spec.get('native') and provider_name(t.handle.spec)==provider:await authentication.cancel(name)
        return response(provider_status(authentication.vault,provider))

    @app.post('/api/connections/{name}/information/complete')
    async def complete(name:str,request:Request):
        idle();data=await payload(request,Complete)
        with store.edit(data.revision):
            config=store.tools();spec=config['mcp_servers'].get(name)
            if not spec or digest(spec)!=data.configuration_hash:raise Conflict('Connection settings changed. Review information access again.')
            p=managed_check(spec)
            if not p:raise ValueError('Use Advanced review for custom connections.')
            current=view(store,runtime,authentication,name,spec)
            caps={c['id']:c for c in current['capabilities']}
            if len(set(data.capabilities))!=len(data.capabilities) or set(data.capabilities)-set(caps) or any(not caps[c]['available'] for c in data.capabilities):raise ValueError('Choose available reviewed capabilities only. Unknown hosted definitions need Advanced review.')
            if spec.get('native'):
                handle=authentication.vault.handle(name,spec,store.secret)
                snapshot=handle.read().get('resource_choices',{})
                if time.time()-snapshot.get('checked',0)>1800:raise Conflict('Account choices expired. Check the connection again.')
                if not data.resources or set(data.resources)-{r['id'] for r in current['resources']} or len(set(data.resources))!=len(data.resources):raise ValueError('Choose information from the connected account list.')
                spec['native']['resources']=data.resources;spec['native']['capabilities']=data.capabilities
                MCPSpec.model_validate(spec)
            elif data.resources:raise ValueError('Hosted resources are restricted by their reviewed tool rules.')
            settings=load_settings(store.root);policy=runtime.policy()
            definitions=connection_view(store,runtime,name)['tools']
            approved=[]
            for definition in definitions:
                enabled=definition.get('capability') in data.capabilities if spec.get('native') else any(definition['name'] in caps[c]['tools'] for c in data.capabilities)
                if not enabled:continue
                key=definition['name'];previous=policy.tools.get(key)
                if spec.get('native'):
                    definition={**definition,'configuration_hash':digest(spec)}
                    source=definition['data_class']
                    if previous and previous.classification != 'read':
                        raise ValueError('Keep this tool’s existing action restriction. Changes need Advanced review.')
                    if previous and ['public','personal','sensitive'].index(previous.source_data_class)>['public','personal','sensitive'].index(source):source=previous.source_data_class
                    rule=bind_access(definition,permission='read',data_class=source,workflow=previous.charity_workflow if previous else 'none',previous=previous)
                    if previous:
                        rule.approved_data_classes = [value for value in rule.approved_data_classes if value in previous.approved_data_classes]
                    settings.access[key]=rule;settings.blocked_tools=[t for t in settings.blocked_tools if t!=key]
                else:
                    settings.blocked_tools=[t for t in settings.blocked_tools if t!=key]
                approved.append(key)
            # Disabling a capability blocks previously assigned tools too; it never
            # deletes unrelated assignments or silently assigns newly added agents.
            connection_tools={d['name'] for d in definitions}
            settings.blocked_tools=sorted(set(settings.blocked_tools)|(connection_tools-set(approved)))
            agents=store.agents()
            if len(set(data.agents))!=len(data.agents) or set(data.agents)-set(agents['agents']):raise ValueError('Choose existing agents.')
            selections=data.assignments if data.assignments is not None else {agent:data.capabilities for agent in data.agents}
            if data.assignments is not None and data.agents:
                raise ValueError('Choose one explicit assignment format.')
            if set(selections)-set(agents['agents']) or any(len(chosen)!=len(set(chosen)) or set(chosen)-set(data.capabilities) for chosen in selections.values()):
                raise ValueError('Assign only the chosen capabilities to existing agents.')
            for agent,detail in agents['agents'].items():
                old=detail['tools']
                chosen_tools={tool for cap in selections.get(agent,[]) for tool in caps[cap]['tools']}
                detail['tools']=[t for t in old if t not in connection_tools]+[tool for tool in approved if tool in chosen_tools]
            store.save_many({store.tools_path:config,store.policy_path:settings.model_dump(mode='json',exclude_none=True),store.agents_path:store.validate_agents(agents)})
            if spec.get('native'):
                authentication.vault.record_check(name,spec,'connected')
        runtime.invalidate_pending()
        return response({'revision':store.revision(),'message':'Information access saved. Changes connect automatically.'})
