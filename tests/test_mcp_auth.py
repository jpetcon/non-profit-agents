"""Real MCP/OAuth clients against local fake services; no account or model calls."""
import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2
import pytest
import pytest_asyncio
import uvicorn
from fastmcp import Client, FastMCP
from mcp.shared.auth import OAuthToken
from starlette.responses import JSONResponse, RedirectResponse

from control_panel.connections import discover_connection
from control_panel.mcp_auth import AuthenticationManager, SignInFailure, sign_in_failure
from guardrails.policy import PolicyDenied, Restrictions
from guardrails.runtime import Runtime
from tools.definitions import MCPSpec
from tools.gateway import mcp_transport
from tools.mcp_auth import AuthenticationRequired, CredentialVault, SavedOAuth, GOOGLE_SCOPE, GOOGLE_TOKEN, validate_google_credentials, current_access_token


def save_connection(store, name, spec):
    config = store.tools()
    config['mcp_servers'] = {name: spec}
    store.save(store.tools_path, config)


@pytest_asyncio.fixture
async def oauth_service(store):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    fake = SimpleNamespace(base=base, calls=0, refreshes=0, registrations=0, exchanges=0, revoked=0, tokens=set(), clients={}, codes={}, deny_refresh=False, bad_scope=False, headers=[])
    mcp = FastMCP('Fake OAuth tools')

    @mcp.tool
    def report() -> str:
        fake.calls += 1
        return 'Aggregate report'

    @mcp.custom_route('/.well-known/oauth-protected-resource/mcp', methods=['GET'])
    async def resource(request):
        assert not request.headers.get('authorization')
        assert not request.headers.get('x-service-key')
        return JSONResponse({'resource': base+'/mcp', 'authorization_servers': [base], 'scopes_supported': ['reports:read']})

    @mcp.custom_route('/.well-known/oauth-authorization-server', methods=['GET'])
    async def metadata(request):
        assert not request.headers.get('x-service-key')
        return JSONResponse({'issuer': base, 'authorization_endpoint': base+'/authorize', 'token_endpoint': getattr(fake, 'token_endpoint', base+'/token'), 'registration_endpoint': base+'/register', 'revocation_endpoint': base+'/revoke', 'response_types_supported': ['code'], 'code_challenge_methods_supported': ['S256'], 'scopes_supported': ['reports:read'], 'authorization_response_iss_parameter_supported': True, 'client_id_metadata_document_supported': getattr(fake, 'cimd', False)})

    @mcp.custom_route('/register', methods=['POST'])
    async def register(request):
        fake.registrations += 1
        assert not request.headers.get('authorization')
        assert not request.headers.get('x-service-key')
        data = await request.json()
        client = 'fake-client-'+str(fake.registrations)
        fake.clients[client] = data
        return JSONResponse({**data, 'client_id': client, 'token_endpoint_auth_method': 'none'}, status_code=201)

    @mcp.custom_route('/authorize', methods=['GET'])
    async def authorize(request):
        query = dict(request.query_params)
        assert query['code_challenge_method'] == 'S256'
        assert query['resource'] == base+'/mcp'
        code = 'fake-code-'+str(len(fake.codes))
        fake.codes[code] = query
        return RedirectResponse(query['redirect_uri']+'?'+urlencode({'code': code, 'state': query['state'], 'iss': base}))

    @mcp.custom_route('/token', methods=['POST'])
    async def token(request):
        data = parse_qs((await request.body()).decode())
        if data['grant_type'] == ['refresh_token']:
            fake.refreshes += 1
            await asyncio.sleep(.04)
            if fake.deny_refresh:
                return JSONResponse({'error': 'invalid_grant'}, status_code=400)
        else:
            fake.exchanges += 1
            code = fake.codes.pop(data['code'][0])
            challenge = base64.urlsafe_b64encode(hashlib.sha256(data['code_verifier'][0].encode()).digest()).decode().rstrip('=')
            assert challenge == code['code_challenge']
            assert data['redirect_uri'] == [code['redirect_uri']]
        access = 'private-fake-access-'+str(fake.exchanges)+'-'+str(fake.refreshes)
        fake.tokens.add(access)
        return JSONResponse({'access_token': access, 'refresh_token': 'private-fake-refresh-'+str(fake.refreshes), 'token_type': 'Bearer', 'expires_in': 3600, 'scope': 'reports:write' if fake.bad_scope else 'reports:read'})

    @mcp.custom_route('/revoke', methods=['POST'])
    async def revoke(request):
        fake.revoked += 1
        return JSONResponse({})

    app = mcp.http_app(path='/mcp')

    async def protected(scope, receive, send):
        if scope['type'] == 'http' and scope['path'] == '/mcp':
            headers = dict(scope['headers'])
            credential = headers.get(b'authorization', b'').decode()
            assert headers.get(b'x-service-key') == b'private-brave-test-key'
            fake.headers.append(credential)
            if credential.removeprefix('Bearer ') not in fake.tokens:
                await JSONResponse({'error': 'sign in'}, status_code=401, headers={'WWW-Authenticate': f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/mcp", scope="reports:read"'})(scope, receive, send)
                return
        await app(scope, receive, send)

    server = uvicorn.Server(uvicorn.Config(protected, host='127.0.0.1', port=port, log_level='critical', access_log=False))
    task = asyncio.create_task(server.serve())
    while not server.started:
        if task.done():
            await task
        await asyncio.sleep(.01)
    runtime = Runtime(store.root)
    policy = runtime.policy()
    policy.local_endpoints.append(base)
    store.save(store.policy_path, policy.model_dump(mode='json'))
    spec = {'display_name': 'Reports', 'transport': 'http', 'url': base+'/mcp', 'header_secrets': {'X-Service-Key': 'BRAVE_API_KEY'}, 'auth': {'type': 'oauth'}}
    save_connection(store, 'reports', spec)
    fake.runtime, fake.spec = runtime, spec
    try:
        yield fake
    finally:
        server.should_exit = True
        await task


async def wait_phase(manager, name, phase):
    async with asyncio.timeout(10):
        while True:
            status = manager.status(name)
            if status.get('phase') == phase or status['status'] == phase:
                return status
            if status['status'] == 'failed':
                raise AssertionError(status)
            await asyncio.sleep(.01)


async def sign_in(manager, name='reports'):
    await manager.start(name)
    status = await wait_phase(manager, name, 'review')
    manager.transactions[name].approve(status['transaction'])
    status = await wait_phase(manager, name, 'sign_in')
    async with httpx2.AsyncClient(trust_env=False, follow_redirects=False) as browser:
        response = await browser.get(status['authorization_url'])
        callback = await browser.get(response.headers['location'])
        assert callback.status_code == 200
    await manager.transactions[name].task
    assert manager.status(name)['status'] == 'connected', manager.transactions[name].message


@pytest.mark.asyncio
async def test_real_oauth_discovery_refresh_restart_and_scoped_gateway(store, oauth_service, guarded_gateway):
    fake = oauth_service
    manager = AuthenticationManager(store, fake.runtime)
    await sign_in(manager)
    assert fake.registrations == 1 and fake.exchanges == 1 and fake.calls == 0
    assert store.catalog()[0]['name'] == 'reports_report'
    saved_revision = store.revision()
    vault = CredentialVault(store.root)
    handle = vault.handle('reports', fake.spec)
    provider = SavedOAuth(handle)
    await provider.token_storage_adapter.set_tokens(OAuthToken(access_token='expired-private-access', refresh_token='private-fake-refresh-0', expires_in=-1, scope='reports:read'))
    # Independent objects imitate the dashboard and gateway processes sharing state.
    values = await asyncio.gather(*[current_access_token(CredentialVault(store.root).handle('reports', fake.spec), fake.runtime.policy()) for _ in range(6)])
    assert len(set(values)) == 1 and fake.refreshes == 1
    assert store.revision() == saved_revision
    restarted = AuthenticationManager(store, fake.runtime)
    assert restarted.status('reports')['status'] == 'connected'
    gateway = await guarded_gateway(['reports_report'])
    async with Client(gateway) as client:
        assert [tool.name for tool in await client.list_tools()] == ['reports_report']
        assert fake.calls == 0
        assert (await client.call_tool('reports_report')).data == 'Aggregate report'
    assert fake.calls == 1
    assert all(not value.startswith('Bearer gr_') for value in fake.headers)
    assert all(secret not in json.dumps(restarted.status('reports')) for secret in values)
    assert all(value.encode() not in vault.path.read_bytes() for value in values)
    assert stat_mode(vault.directory/'key') == 0o600
    assert stat_mode(vault.path) == 0o600
    await manager.close(); await restarted.close()


def stat_mode(path):
    return path.stat().st_mode & 0o777


@pytest.mark.asyncio
async def test_missing_auth_never_dispatches_or_opens_browser(store, oauth_service, monkeypatch):
    import webbrowser
    monkeypatch.setattr(webbrowser, 'open', lambda *a, **k: pytest.fail('Agent opened a browser'))
    with pytest.raises(AuthenticationRequired):
        await discover_connection(store, oauth_service.runtime, 'reports')
    assert oauth_service.headers == []
    assert oauth_service.calls == 0 and oauth_service.registrations == 0


@pytest.mark.asyncio
async def test_agent_without_connection_assignment_does_not_discover_it(store, oauth_service, guarded_gateway):
    manager = AuthenticationManager(store, oauth_service.runtime)
    await sign_in(manager)
    before = len(oauth_service.headers)
    gateway = await guarded_gateway(['get_strategy'])
    async with Client(gateway) as client:
        assert [tool.name for tool in await client.list_tools()] == ['get_strategy']
    assert len(oauth_service.headers) == before


@pytest.mark.asyncio
async def test_callback_state_issuer_replay_and_cancellation(store, oauth_service):
    manager = AuthenticationManager(store, oauth_service.runtime)
    await manager.start('reports')
    reviewed = await wait_phase(manager, 'reports', 'review')
    assert oauth_service.registrations == 0  # no client registration before review
    transaction = manager.transactions['reports']
    transaction.approve(reviewed['transaction'])
    status = await wait_phase(manager, 'reports', 'sign_in')
    uri = parse_qs(urlsplit(status['authorization_url']).query)['redirect_uri'][0]
    async with httpx2.AsyncClient(trust_env=False) as browser:
        assert (await browser.get(uri+'?'+urlencode({'state': 'forged', 'code': 'bad'}))).status_code == 400
        assert (await browser.get(uri+'?'+urlencode({'state': transaction.expected_state, 'code': 'bad', 'iss': 'https://other.example'}))).status_code == 400
        assert not transaction.callback.done()
        transaction.expires = time.time()-1
        assert (await browser.get(uri+'?'+urlencode({'state': transaction.expected_state, 'code': 'bad'}))).status_code == 400
    old_handle = transaction.handle
    await manager.cancel('reports')
    with pytest.raises(AuthenticationRequired):
        old_handle.change(lambda data: data.update(connected=True))
    assert oauth_service.exchanges == 0 and oauth_service.calls == 0
    assert transaction.server.is_serving() is False


@pytest.mark.asyncio
async def test_disconnect_rotation_and_changed_settings_block_old_credentials(store, oauth_service):
    manager = AuthenticationManager(store, oauth_service.runtime)
    await sign_in(manager)
    handle = manager.vault.handle('reports', oauth_service.spec)
    save_connection(store, 'reports', dict(oauth_service.spec, display_name='Renamed reports'))
    assert manager.status('reports')['status'] == 'connected'
    secret = await current_access_token(handle, oauth_service.runtime.policy())
    await manager.disconnect('reports')
    with pytest.raises(AuthenticationRequired):
        await current_access_token(handle, oauth_service.runtime.policy())
    assert oauth_service.revoked == 1
    assert secret in manager.vault.secret_values()
    assert secret not in store.redact({'error': secret})['error']
    with pytest.raises(PolicyDenied, match='data.secret'):
        oauth_service.runtime.inspect({'text': secret}, Restrictions(), identity={'data_class': 'sensitive'})
    await sign_in(manager)
    handle = manager.vault.handle('reports', oauth_service.spec)
    changed = dict(oauth_service.spec, auth={'type': 'oauth', 'scopes': ['reports:write']})
    save_connection(store, 'reports', changed)
    assert manager.status('reports')['status'] == 'reconnect_required'
    with pytest.raises(AuthenticationRequired):
        await current_access_token(handle, oauth_service.runtime.policy())
    await manager.close()


@pytest.mark.asyncio
async def test_failed_refresh_is_terminal_and_never_starts_login(store, oauth_service):
    manager = AuthenticationManager(store, oauth_service.runtime)
    await sign_in(manager)
    handle = manager.vault.handle('reports', oauth_service.spec)
    await SavedOAuth(handle).token_storage_adapter.set_tokens(OAuthToken(access_token='expired-access', refresh_token='private-fake-refresh-0', expires_in=-1, scope='reports:read'))
    oauth_service.deny_refresh = True
    before = len(oauth_service.headers)
    with pytest.raises(AuthenticationRequired):
        await discover_connection(store, oauth_service.runtime, 'reports')
    assert len(oauth_service.headers) == before
    assert oauth_service.exchanges == 1 and oauth_service.registrations == 1
    assert manager.status('reports')['status'] == 'reconnect_required'
    await manager.close()


@pytest.mark.asyncio
async def test_metadata_cannot_enable_private_authentication_destinations(store, oauth_service):
    oauth_service.token_endpoint = 'http://169.254.169.254/latest/meta-data'
    manager = AuthenticationManager(store, oauth_service.runtime)
    await manager.start('reports')
    await manager.transactions['reports'].task
    assert manager.status('reports')['status'] == 'failed'
    assert oauth_service.registrations == 0 and oauth_service.exchanges == 0


@pytest.mark.asyncio
async def test_timeout_closes_callback_and_changed_settings_cancel_pending_flow(store, oauth_service, monkeypatch):
    monkeypatch.setattr('control_panel.mcp_auth.SIGN_IN_SECONDS', .2)
    manager = AuthenticationManager(store, oauth_service.runtime)
    await manager.start('reports')
    transaction = manager.transactions['reports']
    await transaction.task
    assert manager.status('reports')['status'] == 'failed'
    assert not transaction.server.is_serving()
    monkeypatch.setattr('control_panel.mcp_auth.SIGN_IN_SECONDS', 300)
    await manager.start('reports')
    status = await wait_phase(manager, 'reports', 'review')
    save_connection(store, 'reports', dict(oauth_service.spec, url=oauth_service.base+'/different'))
    with pytest.raises(AuthenticationRequired):
        manager.transactions['reports'].approve(status['transaction'])
    await manager.close()
    assert oauth_service.registrations == 0


@pytest.mark.asyncio
async def test_repeated_connect_requests_are_all_supervised_on_shutdown(store, oauth_service, monkeypatch):
    from control_panel.mcp_auth import SignIn
    instances = []
    original = SignIn.run
    async def run(transaction):
        instances.append(transaction)
        try:
            await original(transaction)
        finally:
            # Exercise another Connect arriving while the previous task closes.
            await asyncio.sleep(.02)
    monkeypatch.setattr(SignIn, 'run', run)
    manager = AuthenticationManager(store, oauth_service.runtime)
    await asyncio.gather(*(manager.start('reports') for _ in range(4)))
    await asyncio.sleep(.05)
    await manager.close()
    assert all(transaction.task.done() for transaction in instances)
    assert all(transaction.server is None or not transaction.server.is_serving() for transaction in instances)
    assert not manager.tasks
    assert oauth_service.exchanges == 0 and oauth_service.calls == 0


@pytest.mark.asyncio
async def test_refresh_cannot_add_permissions(store, oauth_service):
    manager = AuthenticationManager(store, oauth_service.runtime)
    await sign_in(manager)
    handle = manager.vault.handle('reports', oauth_service.spec)
    await SavedOAuth(handle).token_storage_adapter.set_tokens(OAuthToken(access_token='expired-access', refresh_token='private-fake-refresh-0', expires_in=-1, scope='reports:read'))
    oauth_service.bad_scope = True
    before = len(oauth_service.headers)
    with pytest.raises(AuthenticationRequired):
        await discover_connection(store, oauth_service.runtime, 'reports')
    assert len(oauth_service.headers) == before
    assert manager.status('reports')['status'] == 'reconnect_required'


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['registered', 'cimd'])
async def test_pre_registered_clients_and_client_metadata_documents(store, oauth_service, method):
    spec = dict(oauth_service.spec)
    if method == 'registered':
        spec['auth'] = {'type': 'oauth', 'client_id': 'registered-client'}
    else:
        oauth_service.cimd = True
        spec['auth'] = {'type': 'oauth', 'client_metadata_url': 'https://app.example/oauth/client.json'}
    save_connection(store, 'reports', spec)
    manager = AuthenticationManager(store, oauth_service.runtime)
    await sign_in(manager)
    assert oauth_service.registrations == 0 and oauth_service.exchanges == 1


@pytest.mark.asyncio
async def test_disconnect_during_refresh_cannot_restore_credentials(store, oauth_service):
    manager = AuthenticationManager(store, oauth_service.runtime)
    await sign_in(manager)
    handle = manager.vault.handle('reports', oauth_service.spec)
    await SavedOAuth(handle).token_storage_adapter.set_tokens(OAuthToken(access_token='expired-access', refresh_token='private-fake-refresh-0', expires_in=-1, scope='reports:read'))
    refresh = asyncio.create_task(current_access_token(handle, oauth_service.runtime.policy()))
    async with asyncio.timeout(5):
        while not oauth_service.refreshes:
            await asyncio.sleep(.001)
    manager.vault.disconnect('reports')
    with pytest.raises(AuthenticationRequired):
        await refresh
    assert manager.status('reports')['status'] == 'not_connected'
    assert oauth_service.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('installation_setup', [False, True])
async def test_google_browser_sign_in_uses_sdk_pkce_and_discovers_without_executing(store, monkeypatch, installation_setup):
    spec = {'transport': 'stdio', 'command': 'approved-ga4-command', 'auth': {'type': 'google_adc', 'project': 'charity-project'}}
    save_connection(store, 'ga4', spec)
    runtime = Runtime(store.root)
    policy = runtime.policy();policy.stdio_commands.append([spec['command']]);store.save(store.policy_path, policy.model_dump(mode='json'))
    manager = AuthenticationManager(store, runtime)
    exchanges = []
    expected_challenge = []
    def exchange(request):
        assert str(request.url) == GOOGLE_TOKEN
        data = parse_qs(request.content.decode())
        assert data['client_secret'] == ['private-google-client']
        assert data['grant_type'] == ['authorization_code']
        challenge = base64.urlsafe_b64encode(hashlib.sha256(data['code_verifier'][0].encode()).digest()).decode().rstrip('=')
        assert challenge == expected_challenge[0]
        exchanges.append(data)
        return httpx2.Response(200, json={'access_token': 'private-google-access', 'refresh_token': 'private-google-refresh', 'expires_in': 3600, 'scope': GOOGLE_SCOPE})
    monkeypatch.setattr('tools.mcp_auth.transport_for', lambda *a, **k: httpx2.MockTransport(exchange))
    async def public(*args):
        return ['8.8.8.8']
    monkeypatch.setattr('control_panel.mcp_auth.resolve_public', public)
    fake = FastMCP('Fake GA4')
    @fake.tool
    def report()->str:
        pytest.fail('Discovery executed a tool')
    monkeypatch.setattr('tools.gateway.mcp_transport', lambda *a, **k: fake)
    registration = {'installed': {'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'private-google-client', 'auth_uri': 'https://accounts.google.com/o/oauth2/auth', 'token_uri': GOOGLE_TOKEN}}
    if installation_setup:
        await manager.update_provider('', {'client_json': registration, 'project': 'charity-project'})
        manager = AuthenticationManager(store, runtime)  # restart reuses registration
    await manager.start('ga4', None if installation_setup else registration)
    review = await wait_phase(manager, 'ga4', 'review')
    assert review['scopes'] == [GOOGLE_SCOPE] and review['provider'] == 'https://accounts.google.com'
    manager.transactions['ga4'].approve(review['transaction'])
    status = await wait_phase(manager, 'ga4', 'sign_in')
    query = parse_qs(urlsplit(status['authorization_url']).query)
    assert query['access_type'] == ['offline'] and query['prompt'] == ['consent']
    assert query['scope'] == [GOOGLE_SCOPE] and query['code_challenge_method'] == ['S256']
    expected_challenge.append(query['code_challenge'][0])
    async with httpx2.AsyncClient(trust_env=False) as browser:
        response = await browser.get(query['redirect_uri'][0]+'?'+urlencode({'code': 'google-test-code', 'state': query['state'][0]}))
        assert response.status_code == 200
    await manager.transactions['ga4'].task
    assert len(exchanges) == 1 and manager.status('ga4')['status'] == 'connected'
    assert store.catalog()[0]['name'] == 'ga4_report'
    assert 'private-google-' not in json.dumps(manager.status('ga4'))
    assert 'private-google-refresh' in manager.vault.secret_values()
    if installation_setup:
        version = manager.provider_status()['revision']
        handle = manager.transactions['ga4'].handle
        await manager.update_provider(version, {'client_json': registration, 'project': 'new-project'})
        with pytest.raises(AuthenticationRequired):
            handle.read()
        assert manager.status('ga4')['status'] != 'connected'


@pytest.mark.asyncio
async def test_google_import_validates_refresh_with_only_google_endpoint(store, monkeypatch):
    save_connection(store, 'ga4', {'transport': 'stdio', 'command': 'not-yet-reviewed', 'auth': {'type': 'google_adc'}})
    calls = []
    def exchange(request):
        calls.append(request)
        assert str(request.url) == GOOGLE_TOKEN
        data = parse_qs(request.content.decode())
        assert data['scope'] == [GOOGLE_SCOPE] and data['grant_type'] == ['refresh_token']
        return httpx2.Response(200, json={'access_token': 'private-google-import-access', 'token_type': 'Bearer', 'scope': GOOGLE_SCOPE})
    monkeypatch.setattr('tools.mcp_auth.transport_for', lambda *a, **k: httpx2.MockTransport(exchange))
    manager = AuthenticationManager(store, Runtime(store.root))
    credentials = {'type': 'authorized_user', 'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'private-client-secret', 'refresh_token': 'private-refresh-token'}
    result = await manager.import_google('ga4', credentials)
    assert len(calls) == 1 and result['status'] == 'connected'
    assert store.catalog() == []  # unapproved command was never launched


@pytest.mark.parametrize('spec', [
    {'transport': 'stdio', 'command': 'fake', 'auth': {'type': 'oauth'}},
    {'url': 'https://example.com/mcp', 'auth': {'type': 'google_adc'}},
    {'url': 'https://example.com/mcp', 'token_env': 'TOKEN', 'auth': {'type': 'oauth'}},
    {'transport': 'stdio', 'command': 'fake', 'args': ['--allow-write'], 'auth': {'type': 'google_adc'}},
    {'transport': 'stdio', 'command': 'fake', 'env_vars': ['GOOGLE_APPLICATION_CREDENTIALS'], 'auth': {'type': 'google_adc'}},
    {'url': 'http://remote.example/mcp', 'auth': {'type': 'oauth'}},
])
def test_invalid_auth_transport_combinations(spec):
    with pytest.raises(ValueError):
        MCPSpec.model_validate(spec)


@pytest.mark.parametrize('extra', [
    {'type': 'external_account', 'credential_source': {'url': 'http://169.254.169.254'}},
    {'token_uri': 'https://evil.example/token'},
    {'scopes': ['https://www.googleapis.com/auth/analytics.edit']},
    {'universe_domain': 'evil.example'},
])
def test_google_import_rejects_untrusted_providers(extra):
    with pytest.raises(ValueError):
        validate_google_credentials({'type': 'authorized_user', 'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'private-google-client', 'refresh_token': 'private-google-refresh', **extra})


@pytest.mark.asyncio
async def test_google_stdio_uses_private_request_files_and_cleans_up(store, tmp_path):
    marker = tmp_path/'observed.json'
    backend = tmp_path/'ga4.py'
    backend.write_text('''import json,os,sys
from pathlib import Path
from fastmcp import FastMCP
path=Path(os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
Path(sys.argv[1]).write_text(json.dumps({'path':str(path),'mode':path.stat().st_mode&511,'scopes':json.loads(path.read_text())['scopes'],'project':os.environ.get('GOOGLE_CLOUD_PROJECT'),'leaked':os.environ.get('UNRELATED_API_SECRET')}))
m=FastMCP('Fake GA4')
@m.tool
def report()->str:return 'Report'
m.run(transport='stdio',show_banner=False)
''')
    spec = {'transport': 'stdio', 'command': sys.executable, 'args': [str(backend), str(marker)], 'auth': {'type': 'google_adc', 'project': 'charity-project'}}
    save_connection(store, 'ga4', spec)
    vault = CredentialVault(store.root)
    handle = vault.reset('ga4', spec)
    handle.change(lambda data: data.update(connected=True, google={'type': 'authorized_user', 'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'private-google-client', 'refresh_token': 'private-google-refresh'}), status='connected')
    runtime = Runtime(store.root)
    policy = runtime.policy()
    policy.stdio_commands.append([spec['command'], *spec['args']])
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('UNRELATED_API_SECRET', 'private-unrelated')
        async with Client(mcp_transport(spec, policy=policy, root=store.root, connection='ga4')) as client:
            assert [t.name for t in await client.list_tools()] == ['report']
            observed = json.loads(marker.read_text())
            assert Path(observed['path']).exists() and observed['mode'] == 0o600
            assert observed['project'] == 'charity-project' and observed['leaked'] is None
            assert observed['scopes'] == [GOOGLE_SCOPE]
    assert not Path(observed['path']).exists()
    assert list(vault.directory.glob('adc-*.json')) == []


@pytest.mark.asyncio
async def test_google_stdio_cancellation_and_disconnect_remove_credential_files(store, tmp_path):
    backend = tmp_path/'slow_ga4.py'
    marker = tmp_path/'credential-path'
    backend.write_text('''import asyncio,os,sys
from pathlib import Path
from fastmcp import FastMCP
Path(sys.argv[1]).write_text(os.environ['GOOGLE_APPLICATION_CREDENTIALS'])
m=FastMCP('Slow fake GA4')
@m.tool
async def report()->str:
    await asyncio.sleep(60)
    return 'Report'
m.run(transport='stdio',show_banner=False)
''')
    spec = {'transport': 'stdio', 'command': sys.executable, 'args': [str(backend), str(marker)], 'auth': {'type': 'google_adc'}}
    save_connection(store, 'ga4', spec)
    vault = CredentialVault(store.root)
    policy = Runtime(store.root).policy();policy.stdio_commands.append([spec['command'], *spec['args']])
    async def operation():
        async with Client(mcp_transport(spec, policy=policy, root=store.root, connection='ga4'), timeout=65) as client:
            await client.call_tool('report')
    for cancel in [True, False]:
        handle = vault.reset('ga4', spec)
        handle.change(lambda data: data.update(connected=True, google={'type': 'authorized_user', 'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'private-google-client', 'refresh_token': 'private-google-refresh'}), status='connected')
        marker.unlink(missing_ok=True)
        task = asyncio.create_task(operation())
        async with asyncio.timeout(10):
            while not marker.exists():
                await asyncio.sleep(.01)
        credential_path = Path(marker.read_text())
        assert credential_path.exists()
        if cancel:
            task.cancel()
        else:
            vault.disconnect('ga4')
        async with asyncio.timeout(10):
            result = await asyncio.gather(task, return_exceptions=True)
        assert isinstance(result[0], BaseException)
        assert not credential_path.exists()
    assert list(vault.directory.glob('adc-*.json')) == []


def test_auth_endpoints_require_pairing_csrf_and_show_chat_repair(client, app, store):
    spec = {'display_name': 'Analytics', 'url': 'https://analytics.example-service.com/mcp', 'auth': {'type': 'oauth'}}
    save_connection(store, 'analytics', spec)
    agents = store.agents();agents['agents']['strategy_agent']['tools'] = ['analytics_report'];store.save(store.agents_path, agents)
    status = client.get('/api/connections/analytics/auth')
    assert status.json()['status'] == 'not_connected'
    forbidden = client.post('/api/connections/analytics/auth/start', json={}, headers={'X-CSRF-Token': ''})
    assert forbidden.status_code == 403
    requirements = client.get('/api/chat/requirements?agent=strategy_agent').json()['requirements']
    auth = next(r for r in requirements if r['code'] == 'connection.auth_required')
    assert auth['actions'][0]['kind'] == 'auth' and auth['actions'][0]['target'] == 'analytics'
    assert 'private-provider-test-key' not in status.text
    # Failed preflight preserves history and contacts no model (fake backend unused).
    conversation = client.post('/api/conversations', json={'agent': 'strategy_agent'}).json()
    sent = client.post('/api/conversations/'+conversation['id']+'/messages', json={'message': 'Run a report'})
    assert sent.status_code == 409
    assert client.get('/api/conversations/'+conversation['id']).json()['messages'] == []


@pytest.mark.asyncio
async def test_example_google_endpoint_reports_setup_problem_without_dispatch(store, monkeypatch):
    spec = {'display_name': 'Google Analytics', 'url': 'https://ga4-mcp.yourdomain.com/mcp', 'auth': {'type': 'oauth'}}
    save_connection(store, 'google_analytics', spec)
    manager = AuthenticationManager(store, Runtime(store.root))
    async def no_callback(*args):
        pytest.fail('An example endpoint must not start sign-in or discovery')
    monkeypatch.setattr('control_panel.mcp_auth.SignIn.listen', no_callback)
    status = manager.status('google_analytics')
    assert status['status'] == 'failed' and status['error_code'] == 'connection.placeholder'
    assert 'example server address' in status['message']
    with pytest.raises(SignInFailure, match='example server address'):
        await manager.start('google_analytics')
    assert manager.transactions == {} and store.catalog() == []
    assert store.tools()['mcp_servers']['google_analytics'] == spec


@pytest.mark.asyncio
async def test_actionable_failure_survives_restart_without_provider_details(store, oauth_service, monkeypatch):
    manager = AuthenticationManager(store, oauth_service.runtime)
    async def occupied_port(*args):
        raise OSError('Sensitive diagnostic: private-provider-test-key callback-code-example')
    monkeypatch.setattr('control_panel.mcp_auth.SignIn.listen', occupied_port)
    await manager.start('reports')
    await manager.transactions['reports'].task
    restarted = AuthenticationManager(store, oauth_service.runtime)
    status = restarted.status('reports')
    assert status['error_code'] == 'auth.callback_port'
    assert 'another callback port' in status['message']
    assert 'private-provider-test-key' not in json.dumps(status)
    assert 'callback-code-example' not in json.dumps(status)
    assert oauth_service.headers == []


@pytest.mark.parametrize('error,stage,code', [
    (PolicyDenied('network.dns', 'private diagnostic'), 'discovery', 'auth.dns'),
    (PolicyDenied('network.private', 'private diagnostic'), 'provider_review', 'auth.network'),
    (httpx2.ConnectError('private diagnostic'), 'discovery', 'auth.unreachable'),
    (TimeoutError('private diagnostic'), 'authorization', 'auth.expired'),
    (AuthenticationRequired('reports'), 'authorization', 'auth.changed'),
    (SignInFailure('auth.declined'), 'authorization', 'auth.declined'),
    (ExceptionGroup('private diagnostic', [httpx2.ConnectError('private token')]), 'discovery', 'auth.unreachable'),
    (RuntimeError('private diagnostic'), 'discovery', 'auth.failed'),
])
def test_failure_codes_do_not_depend_on_exception_text(error, stage, code):
    assert sign_in_failure(error, stage) == code
