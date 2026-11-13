"""Real Chromium workflows against temporary files and mocked providers only."""
from pathlib import Path
import socket
import threading
import time

import pytest
from playwright.sync_api import sync_playwright, expect
import uvicorn


@pytest.fixture
def browser_page(app, monkeypatch, request):
    from fastmcp import FastMCP
    remote=FastMCP('Fake search')
    @remote.tool
    def web_search(query: str) -> str:
        return 'A source for '+query
    @remote.tool
    def brave_web_search(query: str) -> str:
        return 'A source for '+query
    from tools.gateway import mcp_transport as real_transport
    monkeypatch.setattr('tools.gateway.mcp_transport',lambda spec,*args,**kwargs:real_transport(spec,*args,**kwargs) if spec.get('transport')=='native' else remote)
    if getattr(request,'param',None)=='first_run':
        store=app.state.store
        store.write_secrets({name:None for name in store.values()})
        for name in ['OPENROUTER_API_KEY','BRAVE_API_KEY','LITELLM_MASTER_KEY','LITELLM_PROXY_API_KEY']:
            monkeypatch.delenv(name,raising=False)
        for service in app.state.services.states.values():
            service.update(status='needs_setup',managed=False,detail='Add your connection keys to get started.')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='error',access_log=False))
    thread=threading.Thread(target=server.run,daemon=True)
    thread.start()
    deadline=time.monotonic()+10
    while not server.started and time.monotonic()<deadline:
        time.sleep(.05)
    assert server.started
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch()
            page=browser.new_page(viewport={'width':1440,'height':1050},reduced_motion='reduce')
            errors=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{port}/#pair=browser-pair-test')
            expect(page.get_by_role('heading',name='Overview',exact=True)).to_be_visible()
            yield page,errors
            browser.close()
    finally:
        server.should_exit=True
        thread.join(timeout=15)
        assert not thread.is_alive()


def go(page,name):
    page.locator('#nav').get_by_role('link',name=name,exact=False).click()
    expect(page.get_by_role('heading',name=name,exact=True)).to_be_visible()


@pytest.mark.parametrize('width',[390,1440])
def test_builtin_services_are_visible_without_creating_connections(browser_page,app,width):
    page,errors=browser_page
    store=app.state.store
    before={p:p.read_bytes() if p.exists() else None for p in [store.tools_path,store.agents_path,store.policy_path,store.env_path]}
    page.set_viewport_size({'width':width,'height':1000})
    if width==390:page.locator('#menu').click()
    go(page,'Tools & Connections')
    from connectors.registry import catalogue
    expect(page.locator('[data-service-id]')).to_have_count(sum(p['route']!='custom' for p in catalogue()))
    card=page.locator('[data-service-id="google_ads"]')
    expect(card.get_by_text('Setup needed',exact=True)).to_be_visible()
    card.get_by_role('button',name='Set up',exact=True).click()
    expect(page.get_by_role('heading',name='Connect Google Ads',exact=True)).to_be_visible()
    expect(page.get_by_role('dialog')).to_contain_text('administrator')
    page.locator('#close-editor').click()
    expect(page.locator('[data-service-id="masterbrand"]').get_by_role('link',name='Configure Masterbrand')).to_be_visible()
    expect(page.locator('[data-service-id="brave"] [data-connection-id="brave"]')).to_have_count(1)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    assert before=={p:p.read_bytes() if p.exists() else None for p in before}
    assert errors==[]


def test_pinned_brave_setup_uses_maintained_reads_and_keeps_manual_assignments(browser_page,app):
    page,errors=browser_page
    original=app.state.store.agents()
    go(page,'Tools & Connections')
    page.locator('[data-connection-id="brave"]').get_by_role('button',name='Continue setup',exact=True).click()
    page.get_by_role('dialog').get_by_role('button',name='Check connection and review tools',exact=True).click()
    expect(page.get_by_role('heading',name='Choose agents',exact=True)).to_be_visible()
    expect(page.locator('[data-setup-agent="strategy_agent"]:checked')).to_have_count(0)
    expect(page.locator('[data-setup-agent="influencer_search_agent"][value="brave_brave_web_search"]')).to_be_checked()
    assert app.state.store.agents()==original
    page.get_by_role('button',name='Back to tool review',exact=True).click()
    expect(page.get_by_role('heading',name='Review tools',exact=True)).to_be_visible()
    assert errors==[]


def screenshot(page,name):
    path=Path(__file__).resolve().parent.parent/'.local/qa'
    path.mkdir(parents=True,exist_ok=True)
    page.evaluate('window.scrollTo(0,0)')
    page.screenshot(path=str(path/name),full_page=True)


def test_guardrail_forms_simulation_and_emergency_stop(browser_page):
    page,errors=browser_page
    go(page,'Guardrails')
    page.get_by_label('Monthly token allowance',exact=True).fill('1000000')
    page.get_by_label('Fundraising',exact=True).check()
    page.get_by_role('button',name='Save choices',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Choices saved')
    expect(page.get_by_label('Monthly token allowance',exact=True)).to_have_value('1000000')
    expect(page.get_by_role('heading',name='Token usage',exact=True)).to_be_visible()
    assert page.get_by_label('GBP per USD',exact=True).count()==0
    page.get_by_role('button',name='Check an example',exact=True).click()
    page.get_by_label('Example',exact=True).select_option('fundraising')
    page.get_by_role('button',name='Check example',exact=True).click()
    expect(page.locator('#guard-scenario-result')).to_contain_text('charity.marketing_evidence')
    page.get_by_role('button',name='Cancel',exact=True).click()
    page.get_by_role('button',name='Emergency stop',exact=True).first.click()
    expect(page.locator('#approval-tray')).to_contain_text('Emergency stop active')
    page.get_by_role('button',name='Resume new runs',exact=True).click()
    expect(page.locator('#approval-tray')).not_to_be_visible()
    assert errors==[]


def test_automatic_reply_limits_and_explicit_overrides_survive_saves(browser_page,app):
    page,errors=browser_page
    go(page,'Guardrails')
    expect(page.get_by_text('Reply length uses the model’s supported output limit',exact=False)).to_be_visible()
    page.locator('#guard-advanced').get_by_text('Advanced overrides',exact=True).click()
    page.get_by_role('button',name='Technical limits',exact=True).click()
    cap=page.get_by_label('Maximum output tokens',exact=True)
    expect(cap).to_have_value('')
    cap.fill('75000')
    page.get_by_role('dialog').get_by_role('button',name='Save changes',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Guardrails saved')
    page.get_by_role('button',name='Save choices',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Choices saved')
    from guardrails.settings import load_settings
    assert load_settings(app.state.store.root).max_output_tokens==75000
    page.locator('#guard-advanced').get_by_text('Advanced overrides',exact=True).click()
    page.get_by_role('button',name='Technical limits',exact=True).click()
    page.get_by_label('Maximum output tokens',exact=True).fill('')
    page.get_by_role('dialog').get_by_role('button',name='Save changes',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Guardrails saved')
    page.reload()
    expect(page.get_by_role('heading',name='Guardrails',exact=True)).to_be_visible()
    assert load_settings(app.state.store.root).max_output_tokens is None
    assert errors==[]


def test_optional_sandbox_switch_setup_and_chat_draft(browser_page,app,monkeypatch):
    from sandboxing.manager import SetupError
    from unittest.mock import AsyncMock
    monkeypatch.setattr(app.state.sandbox,'setup',AsyncMock(side_effect=SetupError('Install Node.js LTS first.')))
    page,errors=browser_page
    go(page,'Guardrails')
    switch=page.get_by_label('Sandbox local tools',exact=True)
    expect(switch).not_to_be_checked()
    switch.check()
    page.get_by_role('button',name='Save sandbox choice',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Sandbox choice saved')
    expect(page.get_by_label('Sandbox local tools',exact=True)).to_be_checked()
    expect(page.locator('[data-sandbox-status]')).to_contain_text('Setup needed')
    page.get_by_role('button',name='Set up sandbox',exact=True).click()
    expect(page.locator('[data-sandbox-status]')).to_contain_text('Install Node.js LTS first.')
    go(page,'Chat')
    draft=page.get_by_placeholder('Type a message…');draft.fill('Keep this while I check sandbox setup')
    page.locator('#send-message').click()
    expect(page.get_by_role('dialog')).to_contain_text('Set up the local tool sandbox')
    page.get_by_role('button',name='Review local tool sandbox',exact=True).click()
    expect(page.get_by_role('heading',name='Local tool sandbox',exact=True)).to_be_visible()
    page.get_by_label('Sandbox local tools',exact=True).uncheck()
    page.get_by_role('button',name='Save sandbox choice',exact=True).click()
    expect(draft).to_have_value('Keep this while I check sandbox setup')
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(page.locator('.message.user')).to_have_count(0)
    assert errors==[]


def test_sandbox_custom_profile_and_experimental_windows_setup(browser_page,app,tmp_path,monkeypatch):
    import sys
    from guardrails.policy import digest
    from guardrails.settings import load_settings
    from unittest.mock import AsyncMock
    store=app.state.store
    config=store.tools()
    spec={'transport':'stdio','command':sys.executable,'args':['-m','fixture']}
    config['mcp_servers']['sandbox_fixture']=spec
    store.save(store.tools_path,config)
    documents=tmp_path/'documents';documents.mkdir()
    manager=app.state.sandbox
    status=manager.status
    def experimental(policy):
        return {**status(policy),'platform':'win32','support':'experimental','experimental_message':'Windows sandbox support is experimental.'}
    monkeypatch.setattr(manager,'status',experimental)
    setup=AsyncMock()
    monkeypatch.setattr(manager,'setup',setup)
    page,errors=browser_page
    go(page,'Guardrails')
    expect(page.locator('[data-sandbox-status]')).to_contain_text('Experimental on Windows')
    page.get_by_text('Advanced — custom connection access',exact=True).click()
    page.get_by_role('button',name='Review sandbox access',exact=True).click()
    page.get_by_label('Additional read paths',exact=True).fill(str(documents))
    page.get_by_label('Allowed destinations',exact=True).fill('api.example.org:443')
    page.get_by_role('button',name='Save sandbox access',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Sandbox access saved')
    profile=load_settings(store.root).sandbox.connections['sandbox_fixture']
    assert profile.configuration_hash==digest(spec)
    assert profile.read_paths==[str(documents)]
    assert profile.destinations==['api.example.org:443']
    page.get_by_role('button',name='Set up sandbox',exact=True).click()
    dialog=page.get_by_role('dialog')
    expect(dialog).to_contain_text('firewall filters')
    expect(dialog).to_contain_text('administrator approval')
    page.get_by_label('Allow the described account and firewall setup',exact=True).check()
    with page.expect_response(lambda response: response.request.method=='POST' and response.url.endswith('/api/sandbox/setup')) as started:
        dialog.get_by_role('button',name='Set up sandbox',exact=True).click()
    assert started.value.status==202
    expect(dialog.get_by_role('heading',name='Local tool sandbox',exact=True)).to_be_visible()
    expect(page.locator('[data-sandbox-status]').last).to_contain_text('Saved choice: Off')
    assert setup.await_count==1
    assert not load_settings(store.root).sandbox.enabled
    assert errors==[]


def test_chat_setup_card_keeps_draft_until_gateways_are_ready(browser_page,app):
    page,errors=browser_page
    services=app.state.services
    services.states['tools'].update(status='starting',detail='Starting tools')
    go(page,'Chat')
    message=page.get_by_placeholder('Type a message…')
    send=page.locator('#send-message')
    message.fill('Keep my draft while connecting')
    send.click()
    expect(page.get_by_role('dialog')).to_be_visible()
    expect(page.get_by_role('heading',name='Set up this chat',exact=True)).to_be_visible()
    expect(page.get_by_role('dialog')).to_contain_text('Connecting your changes')
    expect(message).to_have_value('Keep my draft while connecting')
    page.get_by_role('button',name='Cancel',exact=True).click()
    services.states['tools'].update(status='running',pending=False)
    page.evaluate('pollServices()')
    def reject(route):
        route.fulfill(status=409,content_type='application/json',body='{"issue":{"code":"gateway.unverified"}}')
    page.route('**/api/conversations/*/messages',reject)
    send.click()
    expect(page.get_by_role('dialog')).to_contain_text('Connect the gateways')
    expect(message).to_have_value('Keep my draft while connecting')
    expect(page.locator('.message.user')).to_have_count(0)
    page.get_by_role('button',name='Cancel',exact=True).click()
    page.unroute('**/api/conversations/*/messages',reject)
    send.click()
    expect(page.locator('.markdown')).to_contain_text('helps children')
    expect(page.locator('.message.user')).to_have_count(1)
    expect(message).to_have_value('')
    assert errors==[]


def test_google_connection_preset_and_private_import_on_mobile(browser_page, monkeypatch):
    import json
    import httpx2
    page, errors = browser_page
    def google(request):
        assert str(request.url) == 'https://oauth2.googleapis.com/token'
        return httpx2.Response(200, json={'access_token': 'private-ui-google-access', 'scope': 'https://www.googleapis.com/auth/analytics.readonly'})
    monkeypatch.setattr('tools.mcp_auth.transport_for', lambda *a, **k: httpx2.MockTransport(google))
    page.set_viewport_size({'width': 390, 'height': 844})
    page.locator('#menu').click()
    go(page, 'Tools & Connections')
    page.get_by_role('button', name='Add connection', exact=False).first.click()
    page.locator('#editor-fields summary').filter(has_text='Advanced').first.click()
    page.get_by_role('button', name='Custom connection', exact=True).click()
    page.get_by_role('button', name='Google Analytics — read only', exact=True).click()
    expect(page.get_by_label('Authentication', exact=True)).to_have_value('google_adc')
    expect(page.get_by_label('Command', exact=True)).to_have_value('uvx')
    assert 'analytics-mcp==1.0.0' in page.get_by_label('Arguments', exact=True).input_value()
    page.get_by_label('Google Cloud project ID', exact=True).fill('charity-project')
    page.get_by_role('button', name='Save changes', exact=True).click()
    expect(page.get_by_role('heading', name='Google Analytics', exact=True).last).to_be_visible()
    page.get_by_text('Use a desktop-client file for this sign-in', exact=True).click()
    expect(page.get_by_label('OAuth desktop-client JSON')).to_be_visible()
    page.get_by_text('Use existing Google user credentials', exact=True).click()
    credentials = {'type': 'authorized_user', 'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'private-ui-client-secret', 'refresh_token': 'private-ui-refresh-token'}
    page.get_by_label('Google user ADC JSON', exact=True).set_input_files({'name': 'user-adc.json', 'mimeType': 'application/json', 'buffer': json.dumps(credentials).encode()})
    page.get_by_role('button', name='Import and connect', exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('Connected')
    expect(page.get_by_role('dialog')).not_to_contain_text('private-ui-')
    page.get_by_role('button', name='Done', exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(page.get_by_role('heading', name='Google Analytics', exact=True)).to_be_visible()
    assert errors == []


@pytest.mark.parametrize('width', [390, 1440])
def test_guided_remote_setup_reviews_and_assigns_without_losing_chat(browser_page, app, width):
    import json
    page, errors = browser_page
    page.set_viewport_size({'width': width, 'height': 1000})
    if width == 390:page.locator('#menu').click()
    go(page, 'Chat')
    draft = page.get_by_placeholder('Type a message…')
    draft.fill('Keep this draft while I add reporting tools')
    page.route('**/api/connections/check', lambda route: route.fulfill(status=200, content_type='application/json', body=json.dumps({'authentication': 'unknown', 'message': 'Choose the method supplied by your service.'})))
    page.evaluate('showMcpSetup(null,null,true)')
    page.get_by_role('button', name='Another MCP server', exact=False).click()
    page.get_by_label('MCP server link', exact=True).fill('https://library.charity-tools.co.uk/mcp')
    page.get_by_role('button', name='Check link', exact=True).click()
    expect(page.get_by_label('Connection name', exact=True)).to_have_value('library.charity-tools.co.uk')
    page.get_by_label('How do you connect?', exact=True).select_option('key')
    page.get_by_label('API key', exact=True).fill('private-guided-ui-api-key')
    page.get_by_role('button', name='Connect and discover tools', exact=True).click()
    expect(page.get_by_role('heading', name='Review tools', exact=True)).to_be_visible()
    expect(page.get_by_label('Access to Web Search', exact=True)).to_have_value('blocked')
    screenshot(page, f'guided-mcp-{width}.png')
    page.get_by_label('Access to Web Search', exact=True).select_option('read')
    page.get_by_role('button', name='Choose agents', exact=True).click()
    page.get_by_text('Strategy Agent', exact=True).click()
    strategy = page.locator('#editor-fields details').filter(has=page.locator('summary', has_text='Strategy Agent'))
    expect(strategy.get_by_role('checkbox', name='Web Search', exact=True)).not_to_be_checked()
    strategy.get_by_role('checkbox', name='Web Search', exact=True).check()
    page.get_by_role('button', name='Save tool access', exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('Your team is ready')
    expect(draft).to_have_value('Keep this draft while I add reporting tools')
    expect(page.locator('.message.user')).to_have_count(0)
    assert 'private-guided-ui-api-key' not in page.content()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    config = app.state.store.agents()['agents']
    selected = [t for t in config['strategy_agent']['tools'] if t.startswith('library_')]
    assert len(selected) == 1 and selected[0].endswith('_web_search')
    assert all(selected[0] not in spec['tools'] for name, spec in config.items() if name != 'strategy_agent')
    assert errors == []


def test_guided_failed_api_key_can_be_replaced_in_the_same_card(browser_page, monkeypatch):
    from tools import gateway
    original = gateway.mcp_transport
    def transport(spec, resolve=None, **kwargs):
        if resolve and spec.get('token_env') and resolve(spec['token_env']) != 'private-correct-ui-key':
            raise ValueError('provider body must never reach the browser')
        return original(spec, resolve, **kwargs)
    monkeypatch.setattr(gateway, 'mcp_transport', transport)
    page, errors = browser_page
    go(page, 'Tools & Connections')
    page.get_by_role('button', name='Add connection', exact=False).first.click()
    page.get_by_role('button', name='Another MCP server', exact=False).click()
    page.get_by_label('MCP server link', exact=True).fill('https://reports.charity-tools.co.uk/mcp')
    page.get_by_label('How do you connect?', exact=True).select_option('key')
    page.get_by_label('API key', exact=True).fill('private-wrong-ui-key')
    page.get_by_role('button', name='Connect and discover tools', exact=True).click()
    expect(page.locator('#form-error')).to_contain_text('Connection failed')
    expect(page.get_by_role('dialog')).not_to_contain_text('provider body')
    page.get_by_text('Replace API key', exact=True).click()
    page.get_by_label('New API key', exact=True).fill('private-correct-ui-key')
    page.get_by_role('button', name='Save key and retry', exact=True).click()
    expect(page.get_by_role('heading', name='Review tools', exact=True)).to_be_visible()
    assert 'private-correct-ui-key' not in page.content()
    assert errors == []


def test_guided_google_provider_is_configured_once_and_reconnect_needs_no_file(browser_page, app):
    import json
    from tools.mcp_auth import GOOGLE_TOKEN
    page, errors = browser_page
    go(page, 'Tools & Connections')
    page.get_by_role('button', name='Add connection', exact=False).first.click()
    page.get_by_role('button', name='Google Analytics', exact=False).click()
    expect(page.get_by_role('dialog')).to_contain_text('technical administrator')
    page.get_by_role('button', name='Set up Google provider', exact=True).click()
    page.get_by_label('Google Cloud project ID', exact=True).fill('charity-project')
    registration = {'installed': {'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'private-browser-google-registration', 'auth_uri': 'https://accounts.google.com/o/oauth2/auth', 'token_uri': GOOGLE_TOKEN}}
    page.get_by_label('OAuth desktop-client JSON', exact=True).set_input_files({'name': 'client.json', 'mimeType': 'application/json', 'buffer': json.dumps(registration).encode()})
    page.get_by_role('button', name='Save provider setup', exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('Google provider setup is ready')
    expect(page.get_by_label('I approve running this local package')).not_to_be_checked()
    page.get_by_label('I approve running this local package').check()
    page.get_by_role('button', name='Save and sign in', exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('Provider setup is ready')
    expect(page.get_by_label('OAuth desktop-client JSON')).to_have_count(0)
    assert 'private-browser-google-registration' not in page.content()
    # Closing and resuming the saved connection retains provider setup.
    page.locator('#close-editor').click()
    page.evaluate('renderKeepingDraft()')
    card = page.locator('.card').filter(has=page.get_by_role('heading', name='Google Analytics', exact=True)).first
    card.get_by_role('button', name='Continue setup', exact=True).click()
    expect(page.get_by_role('dialog')).not_to_contain_text('technical administrator')
    page.get_by_role('button', name='Sign in', exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('Provider setup is ready')
    expect(page.get_by_label('OAuth desktop-client JSON')).to_have_count(0)
    assert errors == []


def test_oauth_setup_in_chat_preserves_draft_and_uses_explicit_browser_link(browser_page, app):
    import json
    page, errors = browser_page
    store = app.state.store
    tools = store.tools()
    tools['mcp_servers']['reporting'] = {'display_name': 'Reporting', 'transport': 'http', 'url': 'https://reports.example/mcp', 'auth': {'type': 'oauth'}}
    store.save(store.tools_path, tools)
    agents = store.agents();agents['agents']['strategy_agent']['tools'].append('reporting_report');store.save(store.agents_path, agents)
    page.evaluate('refresh()')
    status = {'method': 'oauth', 'status': 'not_connected', 'message': 'Sign in to connect this service.'}
    def oauth(route):
        path = urlsplit(route.request.url).path
        if path.endswith('/start'):
            status.update(status='connecting', phase='review', transaction='ui-sign-in', provider='https://login.example', scopes=['reports:read'], destinations=['https://login.example/token'])
        elif path.endswith('/approve'):
            status.update(phase='sign_in', authorization_url='https://login.example/authorize?state=test-state')
        elif path.endswith('/cancel'):
            status.update(status='not_connected')
        route.fulfill(status=200, content_type='application/json', body=json.dumps(status))
    from urllib.parse import urlsplit
    page.route('**/api/connections/reporting/auth**', oauth)
    go(page, 'Chat')
    draft = page.get_by_placeholder('Type a message…')
    draft.fill('Keep this draft while I sign in')
    page.locator('#send-message').click()
    expect(page.get_by_role('dialog')).to_contain_text('Sign in to your connection')
    page.get_by_role('button', name='Sign in to Reporting', exact=True).click()
    page.get_by_role('button', name='Connect', exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('https://login.example')
    expect(page.get_by_role('dialog')).to_contain_text('reports:read')
    page.get_by_role('button', name='Approve sign-in setup', exact=True).click()
    link = page.get_by_role('link', name='Open secure sign-in', exact=False)
    expect(link).to_have_attribute('target', '_blank')
    expect(link).to_have_attribute('rel', 'noopener noreferrer')
    expect(draft).to_have_value('Keep this draft while I sign in')
    status.update(status='connected', message='Signed in.')
    page.evaluate('pollMcpAuth()')
    page.get_by_role('button', name='Review tools', exact=True).click()
    expect(draft).to_have_value('Keep this draft while I sign in')
    expect(page.locator('.message.user')).to_have_count(0)
    assert errors == []


def test_back_to_chat_waits_for_refresh_before_closing_setup(browser_page):
    page, errors = browser_page
    go(page, 'Chat')
    message = page.get_by_placeholder('Type a message…')
    message.fill('Keep my draft during setup refresh')
    page.evaluate('showChatSetup()')
    expect(page.get_by_role('heading', name='Your team is ready', exact=True)).to_be_visible()
    # Hold the state request to make the old close-before-render race deterministic.
    page.evaluate('''() => {
      const original = api;
      window.refreshHeld = false;
      api = async (...args) => {
        if (args[0] === '/state') {
          api = original;
          window.refreshHeld = true;
          await new Promise(resolve => { window.releaseRefresh = resolve; });
        }
        return original(...args);
      };
    }''')
    page.get_by_role('button', name='Back to chat', exact=True).click()
    page.wait_for_function('window.refreshHeld')
    expect(page.get_by_role('dialog')).to_be_visible()
    expect(page.locator('.message.user')).to_have_count(0)
    page.evaluate('window.releaseRefresh()')
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(message).to_have_value('Keep my draft during setup refresh')
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_contain_text('helps children')
    assert errors == []


def test_example_google_endpoint_can_be_repaired_in_sign_in_card(browser_page, app):
    page, errors = browser_page
    store = app.state.store
    tools = store.tools()
    tools['mcp_servers']['google_analytics'] = {'display_name': 'Google Analytics', 'transport': 'http', 'url': 'https://ga4-mcp.yourdomain.com/mcp', 'auth': {'type': 'oauth'}}
    store.save(store.tools_path, tools)
    agents = store.agents();agents['agents']['strategy_agent']['tools'].append('google_analytics_run_report');store.save(store.agents_path, agents)
    page.evaluate('refresh()')
    go(page, 'Chat')
    message = page.get_by_placeholder('Type a message…')
    message.fill('Show an aggregate report')
    page.locator('#send-message').click()
    page.get_by_role('button', name='Sign in to Google Analytics', exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('example server address')
    expect(page.get_by_role('button', name='Connect', exact=True)).to_have_count(0)
    page.get_by_role('button', name='Set up Google Analytics locally', exact=True).click()
    expect(page.get_by_label('Connection type', exact=True)).to_have_value('stdio')
    expect(page.get_by_label('Authentication', exact=True)).to_have_value('google_adc')
    expect(page.get_by_label('Command', exact=True)).to_have_value('uvx')
    # Switching the form is reviewable and does not change the saved connection.
    assert store.tools()['mcp_servers']['google_analytics']['transport'] == 'http'
    page.get_by_role('button', name='Save changes', exact=True).click()
    page.get_by_text('Use a desktop-client file for this sign-in', exact=True).click()
    expect(page.get_by_label('OAuth desktop-client JSON')).to_be_visible()
    assert store.tools()['mcp_servers']['google_analytics']['transport'] == 'stdio'
    assert store.agents()['agents']['strategy_agent']['tools'][-1] == 'google_analytics_run_report'
    expect(message).to_have_value('Show an aggregate report')
    assert errors == []


def test_guardrail_mobile_access_review_and_charity_choices(browser_page):
    page,errors=browser_page
    page.set_viewport_size({'width':390,'height':844})
    page.locator('#menu').click()
    go(page,'Guardrails')
    page.get_by_label('Safeguarding contact or escalation route',exact=True).fill('Contact our safeguarding lead')
    page.get_by_label('Campaigning',exact=True).check()
    page.get_by_role('button',name='Save choices',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Choices saved')
    expect(page.get_by_label('Campaigning',exact=True)).to_be_checked()
    page.get_by_role('button',name='Review access',exact=True).first.click()
    page.get_by_label('What may this capability do?',exact=True).select_option('blocked')
    page.get_by_role('button',name='Save access',exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(page.get_by_text('Access off',exact=True)).to_be_visible()
    assert not page.locator('#guard-advanced').evaluate('(el)=>el.open')
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    assert errors==[]


def test_desktop_management_and_streamed_chat(browser_page):
    page,errors=browser_page
    screenshot(page,'desktop-overview.png')
    assert page.evaluate('localStorage.length + sessionStorage.length')==0
    go(page,'Agents')
    page.get_by_role('button',name='New agent').click()
    page.get_by_label('Name',exact=True).fill('Campaign helper')
    page.get_by_label('Purpose',exact=True).fill('Helps with thoughtful campaigns')
    page.get_by_label('Instructions',exact=True).fill('Use the charity strategy to suggest campaigns.')
    page.get_by_label('Get Strategy',exact=False).check()
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('heading',name='Campaign helper',exact=True)).to_be_visible()
    go(page,'Tools & Connections')
    page.get_by_text('Advanced — individual tools and API settings',exact=True).click()
    page.get_by_role('button',name='Create API tool').click()
    page.get_by_label('Tool name').fill('Find supporters')
    page.get_by_label('What does it do?').fill('Find people interested in the charity')
    page.get_by_label('API address').fill('https://example.org/supporters')
    page.get_by_role('button',name='Add input',exact=False).click()
    page.get_by_label('Name',exact=True).fill('topic')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('heading',name='Find supporters',exact=True)).to_be_visible()
    page.get_by_role('button',name='Test & discover tools').click()
    expect(page.get_by_role('heading',name='Web Search',exact=True)).to_be_visible()
    go(page,'Agents')
    helper=page.locator('article.card').filter(has=page.get_by_role('heading',name='Campaign helper',exact=True))
    helper.get_by_role('button',name='Edit agent',exact=True).click()
    page.get_by_role('checkbox',name='Web Search MCP',exact=True).check()
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    config=page.request.get(page.url.split('#')[0]+'api/state').json()
    assert 'brave_web_search' in config['agents']['agents']['campaign_helper']['tools']
    go(page,'Tools & Connections')
    # Create an HTTP MCP connection using forms without executing it.
    page.get_by_role('button',name='Add connection').click()
    page.locator('#editor-fields summary').filter(has_text='Advanced').first.click()
    page.get_by_role('button', name='Custom connection', exact=True).click()
    page.get_by_label('Connection name').fill('Reference library')
    page.get_by_label('Server address').fill('https://example.org/mcp')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('heading',name='Reference library',exact=True)).to_be_visible()
    go(page,'Masterbrand')
    page.get_by_label('Organisation name').fill('Kind Futures')
    page.get_by_label('Mission',exact=True).fill('Help children thrive.')
    page.get_by_label('Values',exact=True).fill('Care\nEvidence')
    page.get_by_label('Brand voice',exact=True).fill('Warm and clear')
    page.get_by_role('button',name='Save Masterbrand',exact=True).click()
    expect(page.locator('#toast')).to_contain_text('Masterbrand saved')
    go(page,'Secrets')
    page.get_by_role('button',name='Add secret',exact=False).click()
    page.get_by_label('Secret name').fill('CRM_API_KEY')
    secret='browser-private-key-should-never-return'
    page.get_by_label('Secret value').fill(secret)
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('heading',name='CRM API KEY',exact=True)).to_be_visible()
    assert secret not in page.content()
    assert page.evaluate('localStorage.length + sessionStorage.length')==0
    go(page,'Chat')
    page.get_by_placeholder('Type a message…').fill('What is our strategy?')
    page.get_by_role('button',name='Send',exact=False).click()
    expect(page.locator('.markdown')).to_contain_text('helps children')
    expect(page.locator('#stop-message')).to_be_hidden()
    expect(page.locator('.markdown').get_by_role('link',name='Source')).to_have_attribute('href','https://example.org/strategy')
    expect(page.get_by_text('Using get_strategy',exact=True)).to_be_attached()
    assert page.locator('.markdown script').count()==0
    screenshot(page,'desktop-chat.png')
    assert errors==[]


@pytest.mark.parametrize('browser_page',['first_run'],indirect=True)
def test_first_run_guidance_and_missing_secret_entry(browser_page):
    page,errors=browser_page
    expect(page.get_by_text('2 connection keys are missing.',exact=True)).to_be_visible()
    go(page,'Secrets')
    key_card=page.locator('article.card').filter(has=page.get_by_role('heading',name='OPENROUTER API KEY',exact=True))
    expect(key_card.get_by_text('Missing',exact=True)).to_be_visible()
    key_card.get_by_role('button',name='Add value',exact=True).click()
    page.get_by_label('New value',exact=True).fill('first-run-provider-private-key')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(key_card.get_by_text('Configured',exact=True)).to_be_visible()
    assert 'first-run-provider-private-key' not in page.content()
    assert errors==[]


def test_mobile_keyboard_and_reduced_motion(browser_page):
    page,errors=browser_page
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.get_by_role('button',name='Toggle navigation').click()
    page.locator('#nav').get_by_role('link',name='Agents').click()
    expect(page.get_by_role('heading',name='Agents',exact=True)).to_be_visible()
    page.get_by_role('button',name='New agent').click()
    expect(page.get_by_role('dialog')).to_be_visible()
    page.keyboard.press('Escape')
    expect(page.get_by_role('dialog')).not_to_be_visible()
    page.get_by_role('button',name='Toggle navigation').click()
    page.locator('#nav').get_by_role('link',name='Chat').click()
    page.get_by_placeholder('Type a message…').fill('Strategy please')
    page.get_by_placeholder('Type a message…').press('Enter')
    expect(page.locator('.markdown')).to_contain_text('helps children')
    expect(page.locator('#stop-message')).to_be_hidden()
    assert page.evaluate('matchMedia("(prefers-reduced-motion: reduce)").matches')
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    screenshot(page,'mobile-chat.png')
    assert errors==[]


def test_model_provider_secret_and_agent_assignment(browser_page):
    page,errors=browser_page
    go(page,'Models')
    expect(page.get_by_role('heading',name='Fast & efficient',exact=True)).to_be_visible()
    page.get_by_role('button',name='Add model',exact=False).click()
    page.get_by_label('Name',exact=True).fill('Campaign brain')
    page.get_by_label('Provider',exact=True).select_option('anthropic')
    page.get_by_label('Model ID',exact=True).fill('my-chat-model')
    expect(page.get_by_label('Private key',exact=True)).to_have_value('ANTHROPIC_API_KEY')
    expect(page.locator('#model-key-status')).to_contain_text('no saved value')
    page.get_by_role('button',name='Add or replace this key',exact=True).click()
    key='model-browser-private-value'
    page.get_by_label('New value',exact=True).fill(key)
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('heading',name='Add model',exact=True)).to_be_visible()
    expect(page.get_by_label('Name',exact=True)).to_have_value('Campaign brain')
    expect(page.get_by_label('Provider',exact=True)).to_have_value('anthropic')
    expect(page.locator('#model-key-status')).to_contain_text('value is stored')
    page.get_by_role('button',name='Save changes',exact=True).click()
    card=page.locator('article.model-card').filter(has=page.get_by_role('heading',name='Campaign brain',exact=True))
    expect(card.get_by_text('Key saved',exact=True)).to_be_visible()
    assert key not in page.content()
    assert page.evaluate('localStorage.length + sessionStorage.length')==0
    go(page,'Agents')
    coordinator=page.locator('article.card').filter(has=page.get_by_role('heading',name='Coordinator',exact=True))
    coordinator.get_by_role('button',name='Edit agent',exact=True).click()
    page.get_by_label('Model preference',exact=True).select_option(label='Campaign brain')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(coordinator.get_by_text('Campaign brain',exact=True)).to_be_visible()
    go(page,'Models')
    expect(card.get_by_text('Used by Coordinator',exact=True)).to_be_visible()
    assert card.get_by_role('button',name='Delete',exact=True).count()==0
    card.get_by_role('button',name='Edit model',exact=True).click()
    page.get_by_label('Provider',exact=True).select_option('openrouter')
    expect(page.get_by_label('Private key',exact=True)).to_have_value('OPENROUTER_API_KEY')
    page.get_by_label('Model ID',exact=True).fill('publisher/my-model')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(card.get_by_text('OpenRouter',exact=True)).to_be_visible()
    expect(card.get_by_text('Global · development',exact=True)).to_be_visible()
    page.get_by_role('button',name='Add model',exact=False).click()
    page.get_by_label('Name',exact=True).fill('Temporary model')
    page.get_by_label('Provider',exact=True).select_option('custom')
    page.get_by_label('Model ID',exact=True).fill('custom-id')
    expect(page.get_by_label('API base address',exact=True)).to_be_visible()
    page.get_by_label('API base address',exact=True).fill('https://example.org/v1')
    page.get_by_role('button',name='Save changes',exact=True).click()
    unused=page.locator('article.model-card').filter(has=page.get_by_role('heading',name='Temporary model',exact=True))
    expect(unused.get_by_text('Needs key',exact=True)).to_be_visible()
    unused.get_by_role('button',name='Delete',exact=True).click()
    page.get_by_role('dialog').get_by_role('button',name='Delete',exact=True).click()
    expect(page.get_by_role('heading',name='Temporary model',exact=True)).not_to_be_visible()
    screenshot(page,'desktop-models.png')
    page.set_viewport_size({'width':390,'height':844})
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    screenshot(page,'mobile-models.png')
    assert errors==[]


def test_multiple_teams_agents_defaults_and_saved_chats(browser_page):
    page,errors=browser_page
    go(page,'Teams')
    expect(page.get_by_role('button',name='Delete team',exact=True)).to_be_disabled()
    expect(page.get_by_text('Keep at least one team. Create another team before deleting this one.',exact=True)).to_be_visible()
    page.get_by_role('button',name='New team',exact=False).click()
    page.get_by_label('Team name',exact=True).fill('Fundraising')
    page.get_by_label('Team purpose',exact=True).fill('Build lasting support.')
    page.get_by_label('Coordinator name',exact=True).fill('Fundraising lead')
    page.get_by_role('button',name='Save changes',exact=True).click()
    card=page.locator('article.team-card').filter(has=page.get_by_role('heading',name='Fundraising',exact=True))
    expect(card).to_be_visible()
    expect(page.get_by_label('Current team',exact=True)).to_have_value('fundraising')
    card.get_by_role('button',name='View agents',exact=True).click()
    expect(page.get_by_role('heading',name='Fundraising lead',exact=True)).to_be_visible()
    expect(page.get_by_role('heading',name='Coordinator',exact=True)).not_to_be_visible()
    page.get_by_role('button',name='New agent',exact=False).click()
    page.get_by_label('Name',exact=True).fill('Grant writer')
    page.get_by_label('Instructions',exact=True).fill('Draft clear proposals.')
    expect(page.get_by_label('Team',exact=True)).to_have_value('fundraising')
    expect(page.get_by_label('Supervising agent',exact=True)).to_contain_text('Fundraising lead')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('heading',name='Grant writer',exact=True)).to_be_visible()
    page.get_by_label('Current team',exact=True).select_option('charity_team')
    expect(page.get_by_role('heading',name='Strategy Agent',exact=True)).to_be_visible()
    strategy=page.locator('article.card').filter(has=page.get_by_role('heading',name='Strategy Agent',exact=True))
    strategy.get_by_role('button',name='Edit agent',exact=True).click()
    page.get_by_label('Team',exact=True).select_option('fundraising')
    expect(page.get_by_label('Supervising agent',exact=True)).to_have_value('fundraising_coordinator')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_label('Current team',exact=True)).to_have_value('fundraising')
    expect(page.get_by_role('heading',name='Strategy Agent',exact=True)).to_be_visible()
    go(page,'Teams')
    card.get_by_role('button',name='Edit team',exact=True).click()
    page.get_by_label('Use this team by default',exact=True).check()
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    page.reload()
    expect(page.get_by_label('Current team',exact=True)).to_have_value('fundraising')
    go(page,'Chat')
    page.get_by_role('button',name='New conversation',exact=False).click()
    expect(page.get_by_label('Team',exact=True)).to_have_value('fundraising')
    page.get_by_label('Team',exact=True).select_option('charity_team')
    expect(page.get_by_label('Who would you like to talk to?',exact=True)).not_to_contain_text('Grant writer')
    page.get_by_label('Team',exact=True).select_option('fundraising')
    expect(page.get_by_label('Who would you like to talk to?',exact=True)).to_have_value('fundraising_coordinator')
    page.get_by_role('button',name='Start conversation',exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    page.get_by_placeholder('Type a message…').fill('Plan a campaign for this team')
    page.get_by_role('button',name='Send',exact=False).click()
    expect(page.locator('.markdown')).to_contain_text('helps children')
    expect(page.locator('#stop-message')).to_be_hidden()
    go(page,'Teams')
    screenshot(page,'desktop-teams.png')
    card.get_by_role('button',name='Delete team',exact=True).click()
    expect(page.get_by_role('heading',name='Delete “Fundraising”?',exact=True)).to_be_visible()
    expect(page.get_by_label('New default team',exact=True)).to_have_value('')
    page.get_by_role('button',name='Cancel',exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(card).to_be_visible()
    card.get_by_role('button',name='Delete team',exact=True).click()
    page.get_by_label('New default team',exact=True).select_option('charity_team')
    page.get_by_role('dialog').get_by_role('button',name='Delete team',exact=True).click()
    expect(page.get_by_role('heading',name='Fundraising',exact=True)).not_to_be_visible()
    expect(page.get_by_label('Current team',exact=True)).to_have_value('charity_team')
    expect(page.get_by_role('button',name='Delete team',exact=True)).to_be_disabled()
    go(page,'Chat')
    page.locator('.conversation-link').filter(has_text='Plan a campaign').click()
    expect(page.get_by_role('heading',name='Fundraising lead',exact=True)).to_be_visible()
    expect(page.get_by_text('This conversation’s original team or agent is no longer available.',exact=True)).to_be_visible()
    expect(page.locator('.markdown')).to_contain_text('helps children')
    page.set_viewport_size({'width':390,'height':844})
    page.get_by_role('button',name='Toggle navigation').click()
    page.locator('#nav').get_by_role('link',name='Teams',exact=True).click()
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    screenshot(page,'mobile-teams.png')
    assert errors==[]


def test_guardrails_load_failure_has_a_retry_and_recovers(browser_page):
    page,errors=browser_page
    def unavailable(route):route.fulfill(status=503,content_type='application/json',body='{"error":"Unavailable"}')
    page.route('**/api/guardrails',unavailable)
    go(page,'Guardrails')
    expect(page.get_by_role('heading',name='We could not load these settings')).to_be_visible()
    page.unroute('**/api/guardrails',unavailable)
    page.get_by_role('button',name='Try again',exact=True).click()
    expect(page.get_by_label('Monthly token allowance',exact=True)).to_be_visible()
    assert page.get_by_text('Refresh pricing',exact=True).count()==0
    assert errors==[]


@pytest.mark.parametrize('width',[1440,390])
def test_missing_key_is_fixed_inside_chat_without_resending(browser_page,app,width):
    page,errors=browser_page
    app.state.store.write_secrets({'OPENROUTER_API_KEY':None})
    go(page,'Chat')
    page.set_viewport_size({'width':width,'height':950})
    message=page.get_by_placeholder('Type a message…')
    message.fill('Help with our strategy')
    page.locator('#send-message').click()
    expect(page.get_by_role('heading',name='Set up this chat',exact=True)).to_be_visible()
    page.get_by_role('button',name='Add OPENROUTER API KEY',exact=True).click()
    page.get_by_label('New value',exact=True).fill('replacement-private-provider-test-key')
    page.get_by_role('button',name='Save changes',exact=True).click()
    expect(page.get_by_role('heading',name='Your team is ready',exact=True)).to_be_visible()
    assert page.locator('.message.user').count()==0
    assert 'replacement-private-provider-test-key' not in page.content()
    page.get_by_role('button',name='Back to chat',exact=True).click()
    expect(message).to_have_value('Help with our strategy')
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_contain_text('helps children')
    assert errors==[]


@pytest.mark.parametrize('width',[1440,390])
def test_reply_length_notice_preserves_answer_and_continues_only_on_send(browser_page,app,width):
    from control_panel.issues import ResponseTruncated
    page,errors=browser_page
    calls=[]
    async def backend(conversation,prompt):
        calls.append((conversation['id'],conversation['messages']))
        if len(calls)==1:
            yield {'type':'delta','text':'The first part of the answer.'}
            raise ResponseTruncated('Raw SDK text must never be shown')
        yield {'type':'answer','text':'A continuation of the saved answer.'}
    app.state.chat.backend=backend
    go(page,'Chat')
    page.set_viewport_size({'width':width,'height':950})
    message=page.get_by_placeholder('Type a message…')
    message.fill('Start a public answer')
    page.locator('#send-message').click()
    expect(page.get_by_role('heading',name='This reply reached its length limit',exact=True)).to_be_visible()
    expect(page.locator('.markdown')).to_contain_text('The first part of the answer.')
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(page.locator('.message.error')).to_have_count(0)
    expect(page.locator('#chat-messages').get_by_role('button',name='Review setup',exact=True)).to_have_count(0)
    expect(message).to_be_enabled()
    assert len(calls)==1 and 'Raw SDK text' not in page.content()
    # Reload and reopen the same saved conversation: both answer and notice
    # survive, without invoking a provider or losing the earlier context.
    page.reload()
    page.locator('[data-action="chat-open"]').first.click()
    expect(page.get_by_role('heading',name='This reply reached its length limit',exact=True)).to_be_visible()
    expect(page.locator('.markdown')).to_contain_text('The first part of the answer.')
    assert len(calls)==1
    message=page.get_by_placeholder('Type a message…')
    message.fill('Continue the answer')
    expect(message).to_have_value('Continue the answer')
    page.locator('#send-message').click()
    expect(page.locator('.markdown').last).to_contain_text('A continuation of the saved answer.')
    assert len(calls)==2 and calls[0][0]==calls[1][0]
    assert any(m.get('text')=='The first part of the answer.' for m in calls[1][1])
    expect(page.get_by_role('dialog')).not_to_be_visible()
    assert errors==[]


def test_sdk_traceback_becomes_a_setup_card_and_never_reaches_history(browser_page,app):
    page,errors=browser_page
    calls=[]
    async def failed(conversation,prompt):
        calls.append(True)
        yield {'type':'activity','label':'Checking model'}
        raise RuntimeError('Traceback (most recent call last): File "/private/secret/exception_mapping_utils.py", line 2745 private-provider-test-key model.unreviewed: configure its prices')
    app.state.chat.backend=failed
    go(page,'Chat')
    page.get_by_placeholder('Type a message…').fill('Help me plan')
    page.locator('#send-message').click()
    expect(page.get_by_role('heading',name='Set up this chat',exact=True)).to_be_visible()
    expect(page.get_by_role('dialog')).to_contain_text('Review this model')
    assert len(calls)==1
    for forbidden in ['Traceback','exception_mapping_utils','private-provider-test-key','configure its prices']:
        assert forbidden not in page.content()
    expect(page.get_by_placeholder('Type a message…')).to_have_value('Help me plan')
    page.get_by_role('button',name='Review agent-fast',exact=True).click()
    expect(page.get_by_label('Approved processing purpose',exact=True)).to_be_visible()
    assert page.get_by_label('Input USD per million tokens',exact=True).count()==0
    assert len(calls)==1
    assert errors==[]


def test_token_allowance_is_fixed_in_chat_and_requires_an_explicit_send(browser_page,app):
    from guardrails.settings import load_settings
    page,errors=browser_page
    store=app.state.store
    settings=load_settings(store.root);settings.monthly_token_limit=None
    store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
    go(page,'Chat')
    message=page.get_by_placeholder('Type a message…');message.fill('Plan a public research brief')
    page.locator('#send-message').click()
    expect(page.get_by_role('dialog')).to_contain_text('Choose a token allowance')
    page.get_by_role('button',name='Set token allowance',exact=True).click()
    page.get_by_label('Monthly token allowance',exact=True).fill('2000000')
    page.get_by_label('Total tokens per turn',exact=True).fill('100000')
    page.get_by_role('button',name='Save allowance',exact=True).click()
    expect(page.get_by_role('heading',name='Your team is ready',exact=True)).to_be_visible()
    assert app.state.chat.list()==[]
    assert store.yaml(store.policy_path)['monthly_token_limit']==2000000
    page.get_by_role('button',name='Back to chat',exact=True).click()
    expect(message).to_have_value('Plan a public research brief')
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_contain_text('helps children')
    assert errors==[]


def test_failed_setup_check_stays_in_a_card_and_keeps_the_draft(browser_page,app):
    page,errors=browser_page
    go(page,'Chat')
    def unavailable(route):route.fulfill(status=503,content_type='application/json',body='{"error":"Internal traceback that must not be displayed"}')
    page.route('**/api/chat/requirements?*',unavailable)
    message=page.get_by_placeholder('Type a message…');message.fill('Keep this unsent draft')
    page.locator('#send-message').click()
    expect(page.get_by_role('dialog')).to_contain_text('We could not check the team’s setup')
    expect(message).to_have_value('Keep this unsent draft')
    assert 'Internal traceback' not in page.content()
    assert app.state.chat.list()==[]
    page.unroute('**/api/chat/requirements?*',unavailable)
    page.get_by_role('button',name='Check again',exact=True).click()
    expect(page.get_by_role('heading',name='Your team is ready',exact=True)).to_be_visible()
    assert errors==[]


@pytest.mark.parametrize('width', [1440, 390])
@pytest.mark.parametrize('original,title,details', [
    ('Mrs. Anne Smith, 10 Acacia Lane EC1 1AA, 07891000000. How do I sign up?', 'Remove personal details before sending', ['Anne','Acacia','EC1','07891']),
    ('Here are my card details 4000056655665556 12/29 123. Plan public advertising.', 'Remove payment details before sending', ['4000056655665556','12/29','123']),
])
def test_restricted_details_are_removed_locally_without_automatic_send(browser_page, app, width, original, title, details):
    page, errors = browser_page
    calls = []
    async def backend(conversation, prompt):
        calls.append(prompt)
        yield {'type':'answer','text':'Your public request was received.'}
    app.state.chat.backend = backend
    go(page, 'Chat')
    page.set_viewport_size({'width':width,'height':950})
    message = page.get_by_placeholder('Type a message…')
    message.fill(original)
    page.locator('#send-message').click()
    expect(page.get_by_role('dialog')).to_contain_text(title)
    expect(message).to_have_value(original)
    assert calls == [] and page.locator('.message.user').count() == 0
    page.get_by_role('button',name='Remove detected details',exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    draft = message.input_value()
    assert all(part not in draft for part in details)
    assert calls == [] and page.locator('.message.user').count() == 0
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_contain_text('public request was received')
    assert calls == [draft] and errors == []


@pytest.mark.parametrize('width',[1440,390])
def test_limit_is_changed_and_same_chat_continues_with_history(browser_page,app,width):
    from guardrails.policy import PolicyDenied
    page,errors=browser_page
    calls=[]
    async def backend(conversation,prompt):
        calls.append((conversation['id'],conversation['messages']))
        if len(calls)==2:
            raise PolicyDenied('tokens.month','Monthly limit reached.')
        yield {'type':'answer','text':'A checked answer for the public campaign.'}
    app.state.chat.backend=backend
    go(page,'Chat')
    page.set_viewport_size({'width':width,'height':950})
    message=page.get_by_placeholder('Type a message…')
    message.fill('Remember our public campaign plan')
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_contain_text('checked answer')
    conversation=calls[0][0]
    message.fill('Continue with our plan')
    page.locator('#send-message').click()
    expect(page.get_by_role('dialog')).to_contain_text('Monthly token allowance reached')
    page.get_by_role('button',name='Review token allowance',exact=True).click()
    page.get_by_label('Monthly token allowance',exact=True).fill('2000000')
    page.get_by_role('button',name='Save allowance',exact=True).click()
    expect(page.get_by_role('heading',name='Your team is ready',exact=True)).to_be_visible()
    assert len(calls)==2
    page.get_by_role('button',name='Back to chat',exact=True).click()
    expect(message).to_be_enabled()
    expect(message).to_have_value('Continue with our plan')
    assert page.locator('.conversation-link').count()==1
    assert page.get_by_text('Start new chat with updated settings',exact=True).count()==0
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_have_count(2)
    assert calls[-1][0]==conversation
    assert any(m.get('text')=='Remember our public campaign plan' for m in calls[-1][1])
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    assert errors==[]


@pytest.mark.parametrize('width',[1440,390])
def test_history_context_is_reset_inside_same_visible_chat(browser_page,app,width):
    page,errors=browser_page
    calls=[]
    async def backend(conversation,prompt):
        calls.append((conversation['id'],conversation['messages']))
        yield {'type':'answer','text':'A checked public answer.'}
    app.state.chat.backend=backend
    go(page,'Chat')
    page.set_viewport_size({'width':width,'height':950})
    message=page.get_by_placeholder('Type a message…')
    message.fill('Start a public plan')
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_contain_text('checked public answer')
    conversation=calls[0][0]
    app.state.chat.append(conversation,{'type':'user','text':'Earlier record: example-person@example.org'})
    page.locator('.conversation-link').first.click()
    expect(page.locator('#chat-messages')).to_contain_text('Earlier record: example-person@example.org')
    message.fill('Continue using public information')
    page.locator('#send-message').click()
    expect(page.get_by_role('dialog')).to_contain_text('Earlier context needs attention')
    page.get_by_role('button',name='Continue without earlier context',exact=True).click()
    expect(page.get_by_role('heading',name='Continue without earlier context',exact=True)).to_be_visible()
    page.get_by_role('button',name='Continue in this chat',exact=True).click()
    expect(page.get_by_role('dialog')).not_to_be_visible()
    expect(message).to_have_value('Continue using public information')
    assert len(calls)==1 and page.locator('.conversation-link').count()==1
    expect(page.locator('#chat-messages')).to_contain_text('Earlier record: example-person@example.org')
    page.locator('#send-message').click()
    expect(page.locator('.markdown')).to_have_count(2)
    assert calls[-1][0]==conversation and 'example-person@example.org' not in str(calls[-1][1])
    assert errors==[]


@pytest.mark.parametrize('width',[390,1440])
def test_connector_catalogue_native_capabilities_and_chat_draft(browser_page,app,width):
    page,errors=browser_page
    page.set_viewport_size({'width':width,'height':1000})
    if width==390:page.locator('#menu').click()
    go(page,'Chat')
    draft=page.get_by_placeholder('Type a message…')
    draft.fill('Keep this research draft')
    page.evaluate('showMcpSetup(null,null,true)')
    page.get_by_label('Search services',exact=True).fill('Blackbaud')
    expect(page.locator('#connector-catalogue .mcp-preset')).to_have_count(2)
    page.get_by_label('Search services',exact=True).fill('web page')
    page.locator('#connector-catalogue .mcp-preset').click()
    expect(page.get_by_role('heading',name='Connect Web page retrieval',exact=True)).to_be_visible()
    page.get_by_role('button',name='Save and connect',exact=True).click()
    page.get_by_role('button',name='Check connection and choose information',exact=True).click()
    expect(page.get_by_role('heading',name='Choose information',exact=True)).to_be_visible()
    expect(page.locator('input[name="capability"]')).to_be_checked()
    page.get_by_role('checkbox',name='Public HTTPS websites',exact=True).check()
    page.get_by_role('button',name='Choose agents',exact=True).click()
    expect(page.locator('input[name="connector_agent"]:checked')).to_have_count(0)
    page.get_by_role('checkbox',name='Strategy Agent',exact=True).check()
    page.get_by_role('button',name='Save information access',exact=True).click()
    expect(page.get_by_role('dialog')).to_contain_text('Your team is ready')
    expect(draft).to_have_value('Keep this research draft')
    expect(page.locator('.message.user')).to_have_count(0)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
    assert errors==[]
