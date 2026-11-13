"""Guided setup uses real MCP discovery and deterministic policy, never models."""
import asyncio
import json

from fastmcp import FastMCP
import httpx
import pytest

from control_panel.mcp_setup import check_connection
from control_panel.store import Conflict
from guardrails.policy import PolicyDenied, digest
from guardrails.runtime import Runtime
from guardrails.settings import load_settings
from tools.definitions import MCPSpec
from tools.mcp_auth import AuthenticationRequired, CredentialVault, GOOGLE_TOKEN


CLIENT = {"installed": {"client_id": "test.apps.googleusercontent.com", "client_secret": "private-once-only-google-client", "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": GOOGLE_TOKEN}}


def setup(client, **values):
    return client.post('/api/connections/setup', json={"revision": client.get('/api/state').json()['revision'], "preset": "remote", "url": "https://reports.charity-tools.co.uk/mcp", **values})


def discovered(client, app, monkeypatch):
    result = setup(client)
    assert result.status_code == 201, result.text
    name = result.json()['name']
    remote = FastMCP('Fake tools')
    @remote.tool
    def report() -> str:
        pytest.fail('Setup must not execute a tool')
    @remote.tool
    def send() -> str:
        pytest.fail('Setup must not execute a tool')
    monkeypatch.setattr('tools.gateway.mcp_transport', lambda *a, **k: remote)
    found = client.post('/api/connections/'+name+'/test', json={})
    assert found.status_code == 200, found.text
    view = client.get('/api/connections/'+name+'/setup').json()
    assert len(view['tools']) == 2
    body = {"revision": view['revision'], "configuration_hash": view['configuration_hash'], "reviews": {t['name']: {"schema_hash": t['schema_hash'], "permission": "blocked", "data_class": "public", "workflow": "none"} for t in view['tools']}, "assignments": {}}
    return name, view, body


def test_presets_and_explicit_local_consent(client, app):
    presets = client.get('/api/connection-presets').json()['presets']
    assert {'google', 'brave', 'remote'} <= {p['id'] for p in presets}
    before = app.state.store.revision()
    response = setup(client, preset='brave', api_key='private-new-brave-key')
    assert response.status_code == 400 and 'Confirm' in response.json()['error']
    assert before == app.state.store.revision()
    response = setup(client, preset='brave', confirm_local=True, api_key='private-new-brave-key')
    assert response.status_code == 201, response.text
    name = response.json()['name']
    store = app.state.store
    spec = store.tools()['mcp_servers'][name]
    reference = spec['env_secrets']['BRAVE_API_KEY']
    assert reference.startswith('MCP_') and store.secret(reference) == 'private-new-brave-key'
    assert store.secret('BRAVE_API_KEY') == 'private-brave-test-key'
    assert [spec['command'], *spec['args']] in app.state.chat.guardrails.policy().stdio_commands
    assert 'private-new-brave-key' not in store.tools_path.read_text()
    assert 'private-new-brave-key' not in client.get('/api/state').text
    assert load_settings(store.root).approved_connections[name] == digest(spec)
    for agent in store.agents()['agents'].values():
        assert not any(t.startswith(name+'_') for t in agent['tools'])


def test_remote_key_and_validation_do_not_change_legacy_secrets(client, app):
    result = setup(client, authentication='key', api_key='private-remote-service-key')
    assert result.status_code == 201
    name, store = result.json()['name'], app.state.store
    spec = store.tools()['mcp_servers'][name]
    assert spec['auth']['type'] == 'bearer'
    assert store.secret(spec['token_env']) == 'private-remote-service-key'
    assert 'private-remote-service-key' not in client.get('/api/state').text
    for values in [{"api_key": "unexpected"}, {"authentication": "key", "api_key": "line\nbreak"}, {"url": "https://user:password@tools.charity.org/mcp"}, {"url": "https://tools.charity.org/mcp?token=secret"}, {"url": "https://example.org/mcp"}, {"command": "sh"}]:
        revision = store.revision()
        response = setup(client, **values)
        assert response.status_code == 400, response.text
        assert store.revision() == revision


def test_generated_names_never_create_ambiguous_connection_prefixes(client, app):
    for label in ['Brave Search', 'Brave', 'Brave', 'Brave archive']:
        response = setup(client, display_name=label)
        assert response.status_code == 201, response.text
    names = list(app.state.store.tools()['mcp_servers'])
    assert not any(a.startswith(b+'_') for a in names for b in names if a != b)


def test_replacing_key_is_scoped_and_never_overwrites_a_shared_secret(client, app):
    store = app.state.store
    original = store.secret('BRAVE_API_KEY')
    response = client.put('/api/connections/brave/setup/key', json={'revision': store.revision(), 'api_key': 'private-replacement-brave-key'})
    assert response.status_code == 200, response.text
    spec = store.tools()['mcp_servers']['brave']
    assert spec['env_vars'] == []
    assert store.secret(spec['env_secrets']['BRAVE_API_KEY']) == 'private-replacement-brave-key'
    assert store.secret('BRAVE_API_KEY') == original
    assert 'private-replacement-brave-key' not in client.get('/api/state').text
    oauth = setup(client, authentication='oauth').json()['name']
    before = store.revision()
    response = client.put('/api/connections/'+oauth+'/setup/key', json={'revision': before, 'api_key': 'private-not-oauth'})
    assert response.status_code == 400 and before == store.revision()


def test_discovery_review_and_assignment_are_separate_and_atomic(client, app, monkeypatch):
    name, view, body = discovered(client, app, monkeypatch)
    assert all(t['permission'] == 'blocked' for t in view['tools'])
    assert not any(t.startswith(name+'_') for t in app.state.chat.guardrails.policy().tools)
    tool = name+'_report'
    body['reviews'][tool]['permission'] = 'read'
    body['assignments'] = {'strategy_agent': [tool]}
    original = app.state.store.agents()['agents']['strategy_agent']['tools']
    result = client.post('/api/connections/'+name+'/setup/complete', json=body)
    assert result.status_code == 200, result.text
    assert app.state.store.agents()['agents']['strategy_agent']['tools'] == original+[tool]
    policy = app.state.chat.guardrails.policy()
    assert policy.tools[tool].classification == 'read'
    assert name+'_send' in load_settings(app.state.store.root).blocked_tools
    # Other agents were not changed or assigned automatically.
    assert not any(tool in s['tools'] for a, s in app.state.store.agents()['agents'].items() if a != 'strategy_agent')


@pytest.mark.parametrize('change', ['schema', 'config', 'assignment', 'blocked', 'revision'])
def test_completion_rejects_stale_or_forged_inputs_without_partial_writes(client, app, monkeypatch, change):
    name, view, body = discovered(client, app, monkeypatch)
    if change == 'schema':
        first = next(iter(body['reviews']))
        body['reviews'][first]['schema_hash'] = 'forged'
    elif change == 'config':
        body['configuration_hash'] = 'forged'
    elif change == 'assignment':
        body['assignments'] = {'strategy_agent': ['get_strategy']}
    elif change == 'blocked':
        body['assignments'] = {'strategy_agent': [name+'_send']}
    else:
        body['revision'] = 'old'
    before = app.state.store.revision()
    result = client.post('/api/connections/'+name+'/setup/complete', json=body)
    assert result.status_code in {400, 409}
    assert before == app.state.store.revision()


def test_schema_changed_after_discovery_is_rejected(client, app, monkeypatch):
    name, view, body = discovered(client, app, monkeypatch)
    store = app.state.store
    entries = [t for t in store.catalog() if t.get('server') == name]
    entries[0]['description'] = 'Changed server behaviour'
    store.remember_catalog(name, entries)
    body['revision'] = store.revision()
    result = client.post('/api/connections/'+name+'/setup/complete', json=body)
    assert result.status_code == 409


def test_failed_assignment_save_restores_tool_permissions_too(client, app, monkeypatch):
    from control_panel import store as module
    name, view, body = discovered(client, app, monkeypatch)
    tool = name+'_report'
    body['reviews'][tool]['permission'] = 'read'
    body['assignments'] = {'strategy_agent': [tool]}
    before = app.state.store.revision()
    original = module.atomic_write
    def fail(path, *args, **kwargs):
        if path == app.state.store.agents_path:
            raise OSError('simulated assignment failure')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(module, 'atomic_write', fail)
    response = client.post('/api/connections/'+name+'/setup/complete', json=body)
    assert response.status_code == 400, response.text
    assert app.state.store.revision() == before
    assert tool not in app.state.chat.guardrails.policy().tools


def test_review_does_not_remove_existing_charity_controls(client, app, monkeypatch):
    name, view, body = discovered(client, app, monkeypatch)
    tool = name+'_send'
    store = app.state.store
    from guardrails.settings import bind_access
    settings = load_settings(store.root)
    definition = next(t for t in view['tools'] if t['name'] == tool)
    rule = bind_access(definition, permission='review', workflow='financial', data_class='sensitive')
    rule.classification = 'financial'
    settings.access[tool] = rule
    store.save(store.policy_path, settings.model_dump(mode='json'))
    body['revision'] = store.revision()
    body['reviews'][tool].update(permission='read')
    response = client.post('/api/connections/'+name+'/setup/complete', json=body)
    assert response.status_code == 400
    body['reviews'][tool].update(permission='review', workflow='financial', data_class='sensitive')
    response = client.post('/api/connections/'+name+'/setup/complete', json=body)
    assert response.status_code == 200, response.text
    assert app.state.chat.guardrails.policy().tools[tool].classification == 'financial'


def test_key_save_rolls_back_and_notifies_once(store, monkeypatch):
    from control_panel import store as module
    before = store.revision()
    calls = []
    store.on_change = lambda *p: calls.append(p)
    original = module.atomic_write
    def fail(path, *a, **k):
        if path == store.policy_path:
            raise OSError('simulated storage failure')
        return original(path, *a, **k)
    monkeypatch.setattr(module, 'atomic_write', fail)
    with store.edit(before), pytest.raises(ValueError, match='Previous settings'):
        store.save_with_new_secrets({store.tools_path: store.tools(), store.policy_path: load_settings(store.root).model_dump(mode='json')}, {'MCP_UNIQUE': 'private-new-transaction-key'})
    assert store.revision() == before and calls == [] and not store.secret('MCP_UNIQUE')
    monkeypatch.setattr(module, 'atomic_write', original)
    with store.edit(before):
        store.save_with_new_secrets({store.tools_path: store.tools()}, {'MCP_UNIQUE': 'private-new-transaction-key'})
    assert len(calls) == 1
    assert store.env_path.stat().st_mode & 0o777 == 0o600


def test_google_provider_setup_is_private_persistent_and_separate_from_disconnect(client, app):
    before = client.get('/api/providers/google/setup').json()
    response = client.put('/api/providers/google/setup', json={'revision': before['revision'], 'client_json': CLIENT, 'project': 'charity-project'})
    assert response.status_code == 200, response.text
    status = response.json()
    assert status['configured'] and 'client' not in response.text
    result = setup(client, preset='google', confirm_local=True)
    assert result.status_code == 201, result.text
    name, store = result.json()['name'], app.state.store
    assert store.tools()['mcp_servers'][name]['auth']['project'] == 'charity-project'
    assert client.post('/api/connections/'+name+'/auth/disconnect', json={}).status_code == 200
    assert client.get('/api/providers/google/setup').json() == status
    vault = CredentialVault(store.root)
    assert vault.provider('google')[1]['client_json'] == CLIENT
    assert b'private-once-only-google-client' not in vault.path.read_bytes()
    assert 'private-once-only-google-client' not in client.get('/api/state').text
    assert CLIENT['installed']['client_secret'] in vault.secret_values()
    # Old windows cannot replace the registration, including with a fresh secret.
    assert client.put('/api/providers/google/setup', json={'revision': '', 'client_json': CLIENT, 'project': 'another'}).status_code == 409
    assert client.request('DELETE', '/api/providers/google/setup', json={'revision': status['revision']}).status_code == 200
    assert not vault.provider('google')[1]
    assert client.put('/api/providers/google/setup', json={'revision': '', 'client_json': CLIENT, 'project': 'stale-window'}).status_code == 409


@pytest.mark.asyncio
async def test_provider_reuse_and_rotation_invalidate_pending_writers(store, monkeypatch):
    from control_panel.mcp_auth import AuthenticationManager, SignIn
    manager = AuthenticationManager(store, Runtime(store.root))
    await manager.update_provider('', {'client_json': CLIENT, 'project': 'charity-project'})
    config = store.tools()
    spec = {'transport': 'stdio', 'command': 'fake-ga4', 'auth': {'type': 'google_adc'}}
    config['mcp_servers']['ga4'] = spec
    store.save(store.tools_path, config)
    seen = []
    async def pending(transaction):
        seen.append(transaction.client_json)
        await asyncio.Event().wait()
    monkeypatch.setattr(SignIn, 'run', pending)
    try:
        await manager.start('ga4')
        await asyncio.sleep(0)
        handle = manager.transactions['ga4'].handle
        assert seen == [CLIENT]
        registration = manager.provider_status()['revision']
        # An independent process updating the provider invalidates this generation.
        CredentialVault(store.root).save_provider('google', {'client_json': CLIENT, 'project': 'changed'}, registration)
        with pytest.raises(AuthenticationRequired):
            handle.change(lambda data: data.update(connected=True))
    finally:
        await manager.close()


def test_provider_changes_keep_independent_google_user_credentials(store):
    config = store.tools()
    spec = {'transport': 'stdio', 'command': 'fake-ga4', 'auth': {'type': 'google_adc'}}
    config['mcp_servers']['imported'] = spec
    store.save(store.tools_path, config)
    vault = CredentialVault(store.root)
    handle = vault.reset('imported', spec)
    handle.change(lambda data: data.update(connected=True, google={'client_id': 'independent.apps.googleusercontent.com'}), status='connected')
    vault.save_provider('google', {'client_json': CLIENT, 'project': 'charity-project'}, '')
    assert handle.read()['connected']


def test_active_provider_secrets_outlive_retired_secret_retention(store):
    vault = CredentialVault(store.root)
    vault.save_provider('google', {'client_json': CLIENT, 'project': 'charity-project'}, '')
    with vault.db() as db:
        db.execute('UPDATE redactions SET expires=0')
    assert CLIENT['installed']['client_secret'] in CredentialVault(store.root).secret_values()
    replacement = json.loads(json.dumps(CLIENT))
    replacement['installed']['client_secret'] = 'private-replacement-provider-secret'
    vault.save_provider('google', {'client_json': replacement, 'project': 'charity-project'}, vault.provider('google')[0])
    assert CLIENT['installed']['client_secret'] in vault.secret_values()
    with vault.db() as db:
        db.execute('UPDATE redactions SET expires=0')
    values = vault.secret_values()
    assert CLIENT['installed']['client_secret'] not in values
    assert replacement['installed']['client_secret'] in values


@pytest.mark.asyncio
@pytest.mark.parametrize('status,challenge,expected', [(401, 'Bearer resource_metadata="https://untrusted.invalid/metadata"', 'oauth'), (401, 'Bearer', 'unknown'), (405, '', 'unknown'), (200, '', 'unknown')])
async def test_anonymous_check_inspects_headers_without_following_metadata(store, monkeypatch, status, challenge, expected):
    seen = []
    def respond(request):
        seen.append(request)
        assert request.method == 'GET'
        assert not request.headers.get('authorization') and not request.headers.get('cookie')
        return httpx.Response(status, headers={'WWW-Authenticate': challenge}, content=b'not tools or instructions')
    monkeypatch.setattr('control_panel.mcp_setup.transport_for', lambda *a, **k: httpx.MockTransport(respond))
    result = await check_connection('https://tools.charity.org/mcp', Runtime(store.root).policy())
    assert result['authentication'] == expected and len(seen) == 1


@pytest.mark.asyncio
async def test_anonymous_check_blocks_private_and_metadata_addresses(store):
    with pytest.raises(PolicyDenied, match='Private, reserved'):
        await check_connection('https://169.254.169.254/mcp', Runtime(store.root).policy())


def test_setup_and_provider_apis_require_csrf_and_idle(client, app):
    for path in ['/api/connections/setup', '/api/connections/check', '/api/connections/brave/setup/complete']:
        assert client.post(path, json={}, headers={'X-CSRF-Token': ''}).status_code == 403
    assert client.put('/api/providers/google/setup', json={}, headers={'X-CSRF-Token': ''}).status_code == 403
    class Busy:
        def done(self): return False
    app.state.chat.active = Busy()
    try:
        assert setup(client).status_code == 409
        assert client.put('/api/providers/google/setup', json={'revision': '', 'client_json': CLIENT, 'project': 'charity-project'}).status_code == 409
    finally:
        app.state.chat.active = None


@pytest.mark.parametrize('env', [{'PATH': 'MCP_KEY'}, {'PYTHONPATH': 'MCP_KEY'}, {'GOOGLE_APPLICATION_CREDENTIALS': 'MCP_KEY'}])
def test_environment_mapping_cannot_override_system_or_google_credentials(env):
    with pytest.raises(ValueError):
        MCPSpec.model_validate({'transport': 'stdio', 'command': 'fake', 'env_secrets': env, **({'auth': {'type': 'google_adc'}} if 'GOOGLE_APPLICATION_CREDENTIALS' in env else {})})


@pytest.mark.asyncio
async def test_real_local_transport_receives_only_mapped_secret(store, tmp_path, monkeypatch):
    import sys
    from fastmcp import Client
    from tools.gateway import mcp_transport
    backend, marker = tmp_path/'mapped_server.py', tmp_path/'environment.json'
    backend.write_text('''import json,os,sys
from pathlib import Path
from fastmcp import FastMCP
Path(sys.argv[1]).write_text(json.dumps({k:os.environ.get(k) for k in ['BRAVE_API_KEY','MCP_PRIVATE_REFERENCE','UNRELATED_API_SECRET']}))
m=FastMCP('Mapped secrets')
@m.tool
def report()->str:raise RuntimeError('Discovery must not execute tools')
m.run(transport='stdio',show_banner=False)
''')
    monkeypatch.setenv('UNRELATED_API_SECRET', 'private-unrelated-secret')
    spec = {'transport': 'stdio', 'command': sys.executable, 'args': [str(backend), str(marker)], 'env_secrets': {'BRAVE_API_KEY': 'MCP_PRIVATE_REFERENCE'}}
    policy = Runtime(store.root).policy()
    policy.stdio_commands.append([spec['command'], *spec['args']])
    async with Client(mcp_transport(spec, lambda name: 'private-mapped-secret', policy=policy), timeout=10) as client:
        assert [t.name for t in await client.list_tools()] == ['report']
    assert json.loads(marker.read_text()) == {'BRAVE_API_KEY': 'private-mapped-secret', 'MCP_PRIVATE_REFERENCE': None, 'UNRELATED_API_SECRET': None}


@pytest.mark.asyncio
async def test_a_failed_assigned_connection_cannot_hide_working_tools(store, guarded_gateway, monkeypatch):
    from fastmcp import Client
    remote = FastMCP('Working service')
    @remote.tool
    def report()->str:return 'Aggregate report'
    tools = store.tools()
    tools['mcp_servers'] = {'working': {'url': 'https://working.charity.org/mcp'}, 'broken': {'url': 'https://broken.charity.org/mcp'}}
    store.save(store.tools_path, tools)
    dispatched = []
    def transport(spec, *a, **k):
        dispatched.append(spec['url'])
        if 'broken' in spec['url']:
            raise ValueError('unavailable service')
        return remote
    monkeypatch.setattr('tools.gateway.mcp_transport', transport)
    gateway = await guarded_gateway(['working_report'])
    agents = store.agents()
    agents['agents']['strategy_agent']['tools'].append('broken_report')
    store.save(store.agents_path, agents)
    async with Client(gateway, timeout=10) as client:
        assert [t.name for t in await client.list_tools()] == ['working_report']
        assert (await client.call_tool('working_report', {})).data == 'Aggregate report'
    assert any('broken' in url for url in dispatched)
