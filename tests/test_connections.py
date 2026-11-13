import asyncio
from pathlib import Path
import socket
import sys
import time

from fastapi.testclient import TestClient
from fastmcp import FastMCP
import pytest

from control_panel.app import create_app
from control_panel.connections import discover_connection
from control_panel.services import Services
from control_panel.store import Conflict
from guardrails.runtime import Runtime


def wait_until_ready(client):
    deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        result=client.get('/api/services').json()
        if not result['services_busy']:
            assert result['synchronisation']['state']=='ready',result
            return result
        time.sleep(.05)
    pytest.fail('Saved connection did not activate automatically')


def test_connection_discovery_activates_real_gateways_and_brave_preset(store,monkeypatch):
    # A local executable impersonates only the pinned package CLI. No npm
    # download, paid search or inference is needed for this end-to-end check.
    executable=store.root/'bin'/'npx'
    executable.parent.mkdir()
    marker=store.root/'tool-executed'
    executable.write_text(f'''#!{sys.executable}
from fastmcp import FastMCP
from pathlib import Path
m=FastMCP('Fake Brave')
@m.tool(name='brave_news_search')
def news(query: str) -> str:
    Path({str(marker)!r}).write_text('executed')
    return 'News'
@m.tool(name='brave_llm_context')
def context(query: str) -> str:
    Path({str(marker)!r}).write_text('executed')
    return 'Context'
@m.tool(name='send_unreviewed')
def send() -> str:
    raise RuntimeError('Unreviewed capability must remain blocked')
m.run(transport='stdio',show_banner=False)
''')
    executable.chmod(0o700)
    monkeypatch.setenv('PATH',str(executable.parent)+':'+__import__('os').environ['PATH'])
    with socket.socket() as a,socket.socket() as b:
        a.bind(('127.0.0.1',0));b.bind(('127.0.0.1',0))
        inference_port,tool_port=a.getsockname()[1],b.getsockname()[1]
    models=store.yaml('models/model_config.yml')
    models['gateway']['url']=f'http://127.0.0.1:{inference_port}'
    store.save(store.root/'models/model_config.yml',models)
    tools=store.tools();tools['gateway']['port']=tool_port
    store.save(store.tools_path,tools)
    agents=store.agents()
    for spec in agents['agents'].values():spec['tools']=[]
    agents['agents']['strategy_agent']['tools']=['brave_brave_news_search','brave_brave_llm_context']
    store.save(store.agents_path,agents)
    def service_factory(app_store):
        environment=app_store.process_environment()
        environment['PYTHONPATH']=str(Path(__file__).resolve().parent.parent)
        app_store.process_environment=lambda:environment.copy()
        return Services(app_store)
    app=create_app(store.root,auto_start=False,pairing_token='connection-test',service_factory=service_factory)
    with TestClient(app,base_url='http://127.0.0.1:8080') as client:
        pair=client.post('/api/pair',json={'token':'connection-test'})
        client.headers['X-CSRF-Token']=pair.json()['csrf']
        response=client.post('/api/connections/brave/test',json={})
        assert response.status_code==200,response.text
        assert 'automatically' in response.json()['message']
        status=wait_until_ready(client)
        assert all(s['status']=='running' and not s['pending'] for s in status['services'])
        runtime=Runtime(store.root)
        assert 'brave_send_unreviewed' not in runtime.policy().tools
        run=runtime.start_run('test-connection','charity_team')
        token=runtime.issue(run,'strategy_agent','tools')
        async def check():
            from tools.tool_registry import ToolRegistry
            registry=ToolRegistry(f'http://127.0.0.1:{tool_port}/mcp',credential_provider=lambda agent,audience:token,revision_provider=lambda:runtime.policy().revision)
            names=agents['agents']['strategy_agent']['tools']
            await registry.validate_available(names,agent='strategy_agent')
            toolset=registry.resolve(names,agent='strategy_agent')[0]
            try:assert {t.name for t in await toolset.get_tools()}==set(names)
            finally:await toolset.close()
        try:asyncio.run(check())
        finally:runtime.revoke(run)
        assert not marker.exists()
        before={name:r['pid'] for name,r in app.state.services.records.items()}
        revision=runtime.policy().revision
        # Repeating an unchanged test must not repin policy or restart services.
        assert client.post('/api/connections/brave/test',json={}).status_code==200
        assert not app.state.synchronisation.pending
        assert runtime.policy().revision==revision
        assert {name:r['pid'] for name,r in app.state.services.records.items()}==before


@pytest.mark.asyncio
async def test_discovery_does_not_save_results_for_a_changed_connection(store,monkeypatch):
    remote=FastMCP('Fake connection')
    @remote.tool
    def brave_news_search(query: str) -> str:return 'Never executed'
    def transport(*args,**kwargs):
        config=store.tools()
        config['mcp_servers']['brave']['args'].append('--changed')
        store.save(store.tools_path,config)
        return remote
    monkeypatch.setattr('tools.gateway.mcp_transport',transport)
    with pytest.raises(Conflict,match='changed during its test'):
        await discover_connection(store,Runtime(store.root),'brave')
    assert store.catalog()==[]


@pytest.mark.asyncio
async def test_startup_refreshes_older_catalog_missing_assigned_news_search(store,monkeypatch):
    from unittest.mock import AsyncMock
    from guardrails.policy import digest
    remote=FastMCP('Fake Brave')
    @remote.tool
    def brave_news_search(query: str) -> str:
        raise AssertionError('Discovery must not execute search')
    config=store.tools()
    store.remember_catalog('brave',[{'name':'brave_brave_web_search','server':'brave','description':'Web search','input_schema':{'type':'object'},'configuration_hash':digest(config['mcp_servers']['brave'])}])
    agents=store.agents()
    agents['agents']['influencer_search_agent']['tools']=['brave_brave_news_search']
    store.save(store.agents_path,agents)
    monkeypatch.setattr('tools.gateway.mcp_transport',lambda *args,**kwargs:remote)
    services=Services(store)
    services._start=AsyncMock()
    await services.start_ready()
    assert [t['name'] for t in store.catalog()]==['brave_brave_news_search']
    assert Runtime(store.root).policy().tools['brave_brave_news_search'].classification=='read'
    assert services._start.await_count==2
