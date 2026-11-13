"""Read-only Chat setup checks and trusted targets for the local repair cards."""
from agents.config import AppConfig
from guardrails.policy import digest
from guardrails.settings import definitions

from .issues import issue


def chat_requirements(store, chat, statuses, *, conversation=None, team=None, agent=None, busy=False, problem=None):
    config = AppConfig.model_validate(store.agents())
    data_class = "public"
    result = []
    if conversation:
        saved = chat.get(conversation)
        team, agent, data_class = saved['team'], saved['agent'], saved.get('data_class') or 'public'
        if saved['outdated']:
            return [issue('conversation.outdated',actions=[{'kind':'choose_chat','label':'Choose an available team'}])]
    team = team or (config.team_for_agent(agent) if agent else config.default_team)
    if team not in config.teams:
        raise ValueError('Choose an existing team.')
    agent = agent or config.teams[team].root
    if agent not in config.team_members(team):
        raise ValueError('Choose an agent from this team.')
    selected = []
    def collect(name):
        selected.append(name)
        for child in config.agents[name].sub_agents:collect(child)
    collect(agent)
    runtime = chat.guardrails
    try:
        policy = runtime.policy()
        usage = runtime.summary()
    except Exception:
        return [issue('policy.invalid')]
    if usage['stopped']:
        result.append(issue('runtime.stopped',actions=[{'kind':'resume','label':'Resume agent work'}]))
    if not policy.token_limits.monthly:
        result.append(issue('tokens.setup',actions=[{'kind':'tokens','label':'Set token allowance'}]))
    for period, code in [('today','tokens.day'),('month','tokens.month')]:
        current = usage['usage'][period]
        if current['limit'] is not None and current['used_tokens'] >= current['limit']:
            result.append(issue(code,actions=[{'kind':'tokens','label':'Review token allowance'}]))
    models = store.yaml('inference/litellm-config.yml')['model_list']
    aliases = {store.models()[name]['model_type'] for member in selected for name in config.agents[member].models}
    secrets, model_secrets = set(), set()
    for entry in models:
        params = entry['litellm_params']
        key = params.get('api_key','')
        if key.startswith('os.environ/'):
            secrets.add(key.split('/',1)[1])
            if entry['model_name'] in aliases:model_secrets.add(key.split('/',1)[1])
        if entry['model_name'] in aliases:
            rule = policy.models.get(entry['model_name'])
            if not rule or rule.deployment_hash != digest(params):
                result.append(issue('model.unreviewed',actions=[{'kind':'model','target':entry['model_name'],'label':'Review '+entry['model_name']}]))
            elif data_class not in rule.approved_data_classes or (data_class != 'public' and not (rule.purpose and rule.provider_terms_reference and rule.transfer_reference)):
                result.append(issue('data.destination',actions=[{'kind':'model','target':entry['model_name'],'label':'Review data handling'}]))
    connections = store.tools()['mcp_servers']
    assigned_tools = {name for member in selected for name in config.agents[member].tools}
    affected = set()
    for name, spec in connections.items():
        if not spec.get('enabled',True) or not any(tool.startswith(name+'_') for tool in assigned_tools):continue
        secrets.update(spec.get('env_vars',[]));secrets.update(spec.get('header_secrets',{}).values())
        secrets.update(spec.get('env_secrets',{}).values())
        if spec.get('token_env'):secrets.add(spec['token_env'])
        keys = [*spec.get('env_vars',[]), *spec.get('env_secrets',{}).values(), *spec.get('header_secrets',{}).values(), *([spec['token_env']] if spec.get('token_env') else [])]
        if any(not store.secret(key) for key in keys):
            affected.update(member for member in selected if any(tool.startswith(name+'_') for tool in config.agents[member].tools))
    for name, spec in store.tools()['http_tools'].items():
        if spec.get('enabled',True) and name in assigned_tools:
            keys = [h['secret'] for h in spec.get('headers',[]) if h.get('secret')]
            secrets.update(keys)
            if any(not store.secret(key) for key in keys):
                affected.update(member for member in selected if name in config.agents[member].tools)
    for name in sorted(secrets):
        if not store.secret(name):
            result.append(issue('model.secret',actions=[{'kind':'secret','target':name,'label':'Add '+name.replace('_',' ')}]))
    known = {d['name']:d for d in definitions(store.root)}
    auth_checked = set()
    sandbox_checked = set()
    for member in selected:
        for name in config.agents[member].tools:
            sources = [key for key in connections if name.startswith(key+'_')]
            if policy.sandbox.enabled and len(sources) == 1 and sources[0] not in sandbox_checked:
                source = sources[0]
                sandbox_checked.add(source)
                if connections[source].get('transport') == 'stdio':
                    from sandboxing.runtime import installation, connection_profile
                    from guardrails.policy import PolicyDenied
                    try:
                        installation(store.root)
                        connection_profile(store.root, policy, source, connections[source])
                    except PolicyDenied as error:
                        affected.add(member)
                        result.append(issue(error.rule, actions=[{'kind':'sandbox','label':'Review local tool sandbox'}]))
            if len(sources) == 1 and sources[0] not in auth_checked:
                source = sources[0]
                auth_checked.add(source)
                authentication = getattr(store, 'authentication', None)
                if authentication and connections[source].get('enabled', True):
                    status = authentication.status(source)
                    if status['method'] in {'oauth', 'google_adc', 'api_oauth', 'key', 'token', 'session', 'basic'} and status['status'] != 'connected':
                        result.append(issue('connection.auth_required', actions=[{'kind':'auth','target':source,'label':'Sign in to '+(connections[source].get('display_name') or source)}]))
            if any(r['code']=='connection.auth_required' and any(a.get('target') in sources for a in r['actions']) for r in result):
                affected.add(member)
            definition, rule = known.get(name), policy.tools.get(name)
            limits = policy.effective({'team':team,'agent':member},tool=name)
            if not definition:
                affected.add(member)
                sources = [key for key in connections if name.startswith(key+'_')]
                if len(sources)==1:
                    source=sources[0];spec=connections[source]
                    approved = spec.get('transport')!='stdio' or [spec['command'],*spec.get('args',[])] in policy.stdio_commands
                    result.append(issue('tools.missing',actions=[{'kind':'discover' if approved else 'command','target':source,'label':('Test ' if approved else 'Review ')+(spec.get('display_name') or source)+' connection'}]))
                else:
                    result.append(issue('tools.missing'))
            elif not rule or rule.schema_hash != definition['schema_hash'] or rule.configuration_hash != definition['configuration_hash'] or (limits.allowed_tools is not None and name not in limits.allowed_tools):
                affected.add(member)
                result.append(issue('tool.unreviewed' if not rule else 'tool.changed',actions=[{'kind':'tool','target':name,'label':'Review '+name.replace('_',' ')}]))
            if rule and rule.charity_workflow not in {'none','safeguarding'}:
                activity = 'finance' if rule.charity_workflow in {'financial','gift_aid'} else rule.charity_workflow
                if not policy.profile.get('activities',{}).get(activity,True):
                    result.append(issue('activity.disabled',actions=[{'kind':'organisation','label':'Review organisation activities'}]))
    # A missing assigned tool stays a blocker. Let users either finish setup or
    # edit that agent's assignments, without losing or resending their draft.
    for requirement in result:
        if requirement['code'].startswith('sandbox.') or requirement['code'] in {'tools.missing','connection.auth_required','tool.unreviewed','tool.changed','model.secret'}:
            requirement['actions'].extend({'kind':'agent_tools','target':member,'label':'Edit '+(config.agents[member].display_name or member)+' tools'} for member in selected if member in affected)
    if busy or any(s['status']=='starting' for s in statuses):
        result.append(issue('gateways.updating',actions=[{'kind':'wait','label':'Check connection status'}]))
    elif any(s['status'] not in {'running','external'} or s.get('pending') for s in statuses) and not any(r['code']=='model.secret' for r in result):
        result.append(issue('gateway.unverified',actions=[{'kind':'reconnect','label':'Connect gateways'}]))
    if problem and not result:
        actions = []
        if problem['code'].startswith('sandbox.'):
            actions = [{'kind':'sandbox','label':'Review local tool sandbox'}]
        if problem['code'] in {'data.personal', 'data.payment', 'data.field', 'data.pattern', 'data.secret', 'data.credential'}:
            actions = [{'kind':'edit_draft','label':'Edit my draft'}]
            if problem['code'] in {'data.personal', 'data.payment'}:
                actions.insert(0, {'kind':'sanitise','label':'Remove detected details'})
        elif problem['code'] in {'data.history','inference.history','inference.tool_history'}:
            actions = [{'kind':'reset_context','label':'Continue without earlier context'}]
        elif problem['code'] == 'data.output':
            actions = [{'kind':'edit_draft','label':'Refine my request'}]
        if problem['code'].startswith('tokens.'):
            actions = [{'kind':'tokens','label':'Review token allowance'}]
        elif problem['code'].startswith(('model.','provider.')):
            actions = [{'kind':'model','target':entry['model_name'],'label':'Review '+entry['model_name']} for entry in models if entry['model_name'] in aliases]
        if problem['code']=='provider.credentials':
            actions=[{'kind':'secret','target':name,'label':'Replace '+name.replace('_',' ')} for name in sorted(model_secrets)]
        if problem['code']=='provider.failed':
            actions=[{'kind':'model_settings','target':name,'label':'Edit '+(spec.get('display_name') or name)+' model'} for name,spec in store.models().items() if spec['model_type'] in aliases]
        if problem['code']=='model.limits':
            actions=[{'kind':'technical_limits','label':'Review output limits'}]
        if problem['code']=='gateway.unverified':
            actions=[{'kind':'reconnect','label':'Connect gateways'}]
        if problem['code']=='activity.disabled':
            actions=[{'kind':'organisation','label':'Review organisation activities'}]
        if problem['code'] in {'tools.missing','tool.changed','inference.tool_schema'}:
            actions=[{'kind':'discover','target':name,'label':'Test '+(spec.get('display_name') or name)+' connection'} for name,spec in connections.items() if spec.get('enabled',True)]
        result.append({**problem,'actions':actions})
    seen=set()
    return [r for r in result if not ((key:= (r['code'],str(r['actions']))) in seen or seen.add(key))]
