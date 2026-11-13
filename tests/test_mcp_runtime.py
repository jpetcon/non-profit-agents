"""Regressions for concurrent stdio proxy sessions and missing assigned tools."""
import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import psutil
import pytest
import pytest_asyncio
import yaml

from fastmcp import Client, FastMCP
from tools.gateway import build_gateway
from tools.tool_registry import RequiredMcpToolset, ToolRegistry


@pytest_asyncio.fixture
async def stdio_gateway(tmp_path,store,guarded_gateway):
    backend=tmp_path/'fake_mcp.py'
    pids=tmp_path/'pids.txt'
    backend.write_text('''import asyncio,os,sys
from pathlib import Path
from fastmcp import FastMCP
with Path(sys.argv[1]).open('a') as f:f.write(str(os.getpid())+'\\n')
m=FastMCP('Fake backend')
@m.tool
async def probe(delay: float) -> str:
    await asyncio.sleep(delay)
    return 'ok'
if __name__=='__main__':m.run(transport='stdio',show_banner=False)
''')
    config=store.tools_path
    config.write_text(yaml.safe_dump({'gateway':{'name':'fake gateway'},'mcp_servers':{'fake':{'transport':'stdio','command':sys.executable,'args':[str(backend),str(pids)]}}}))
    return await guarded_gateway(['fake_probe']),pids


async def assert_children_closed(path):
    pids={int(pid) for pid in path.read_text().splitlines()}
    def alive(pid):
        try:return psutil.Process(pid).status()!=psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:return False
    for _ in range(40):
        if not any(alive(pid) for pid in pids):return
        await asyncio.sleep(.05)
    assert not any(alive(pid) for pid in pids),'MCP subprocesses must close with their request contexts'


@pytest.mark.asyncio
@pytest.mark.parametrize('mode',['auto','legacy'])
async def test_concurrent_stdio_calls_and_discovery_are_isolated(stdio_gateway,mode):
    gateway,pids=stdio_gateway
    async def run():
        async with Client(gateway,mode=mode,timeout=10) as client:
            assert [t.name for t in await client.list_tools()]==['fake_probe']
            results=await asyncio.gather(
                client.call_tool('fake_probe',{'delay':.7}),
                client.call_tool('fake_probe',{'delay':.05}),
                client.list_tools(),
            )
            assert all(not result.is_error for result in results[:2])
            assert [t.name for t in results[2]]==['fake_probe']
            # Later contexts must get fresh, working transports too.
            result=await client.call_tool('fake_probe',{'delay':0})
            assert not result.is_error
    await asyncio.wait_for(run(),30)
    await assert_children_closed(pids)


@pytest.mark.asyncio
async def test_cancelling_one_proxy_call_does_not_disconnect_another(stdio_gateway):
    gateway,pids=stdio_gateway
    async with Client(gateway,timeout=10) as client:
        await client.list_tools()
        cancelled=asyncio.create_task(client.call_tool('fake_probe',{'delay':5}))
        other=asyncio.create_task(client.call_tool('fake_probe',{'delay':.8}))
        await asyncio.sleep(.3)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):await cancelled
        assert not (await asyncio.wait_for(other,15)).is_error
    await assert_children_closed(pids)


@pytest.mark.asyncio
async def test_missing_tools_raise_instead_of_silently_filtering_to_empty(monkeypatch):
    parent=AsyncMock(return_value=[SimpleNamespace(name='get_strategy')])
    monkeypatch.setattr('google.adk.tools.mcp_tool.McpToolset.get_tools',parent)
    toolset=RequiredMcpToolset(['get_strategy','brave_brave_web_search'],'http://127.0.0.1:9000/mcp')
    try:
        with pytest.raises(ValueError,match='brave_brave_web_search'):
            await toolset.get_tools()
        parent.return_value.append(SimpleNamespace(name='brave_brave_web_search'))
        assert len(await toolset.get_tools())==2
        # A later loss of the same capability is also detected.
        parent.return_value=[]
        with pytest.raises(ValueError,match='Assigned tools are unavailable'):
            await toolset.get_tools()
        parent.side_effect=RuntimeError('Sensitive upstream error')
        with pytest.raises(ValueError,match='Could not load assigned tools') as error:
            await toolset.get_tools()
        assert 'Sensitive' not in str(error.value)
    finally:
        await toolset.close()


@pytest.mark.asyncio
async def test_preflight_checks_gateway_names_without_invoking_tools(monkeypatch):
    import httpx2
    from guardrails.client import tool_transport
    remote=FastMCP('Fake tool gateway')
    calls=[]
    @remote.tool
    def get_strategy() -> str:
        calls.append(True)
        return 'Strategy'
    app=remote.http_app(stateless_http=True,json_response=True)
    def transport(url,token):
        result=tool_transport(url,token)
        original=result.httpx_client_factory
        def factory(**kwargs):
            kwargs['transport']=httpx2.ASGITransport(app=app)
            return original(**kwargs)
        result.httpx_client_factory=factory
        return result
    # Replace only the network destination; keep the real Client constructor,
    # authenticated HTTP transport, handshake and discovery protocol.
    monkeypatch.setattr('guardrails.client.tool_transport',transport)
    registry=ToolRegistry('http://127.0.0.1:9000/mcp',credential_provider=lambda agent,audience:'synthetic-token')
    async with app.router.lifespan_context(app):
        await registry.validate_available(['get_strategy'],agent='strategy_agent')
        with pytest.raises(ValueError,match='brave_brave_web_search'):
            await registry.validate_available(['get_strategy','brave_brave_web_search'],agent='strategy_agent')
    assert calls==[]


@pytest.mark.asyncio
async def test_preflight_preserves_policy_denials_and_sanitises_client_errors():
    from guardrails.policy import PolicyDenied
    credential=Mock(side_effect=PolicyDenied('runtime.stopped','Emergency stop is active.'))
    registry=ToolRegistry('http://127.0.0.1:9000/mcp',credential_provider=credential)
    with pytest.raises(PolicyDenied,match='runtime.stopped: Emergency stop is active'):
        await registry.validate_available(['get_strategy'])
    credential.side_effect=TypeError('Private connection details')
    with pytest.raises(ValueError,match='Could not validate assigned tools') as error:
        await registry.validate_available(['get_strategy'])
    assert 'Private connection details' not in str(error.value) and 'unavailable' not in str(error.value)
    credential.reset_mock()
    await registry.validate_available([])
    credential.assert_not_called()


@pytest.mark.asyncio
async def test_missing_assigned_tools_stop_chat_before_any_inference(store,monkeypatch):
    from control_panel.chat import Chat
    model=Mock(side_effect=AssertionError('Inference must not be constructed'))
    validate=AsyncMock(side_effect=ValueError('Assigned tools are unavailable: brave_brave_web_search. Test the connection.'))
    monkeypatch.setattr('tools.tool_registry.ToolRegistry.validate_available',validate)
    monkeypatch.setattr('models.model_registry.Models.resolve',model)
    chat=Chat(store)
    conversation=chat.create()
    queue=chat.start(conversation['id'],'Find influencers')
    events=[]
    while True:
        event=await asyncio.wait_for(queue.get(),10)
        events.append(event)
        if event['type']=='done':break
    assert [e['type'] for e in events]==['activity','error','done']
    assert events[1]['issue']['code']=='tools.missing'
    required=validate.await_args.args[0]
    assert 'get_strategy' in required
    model.assert_not_called()
    assert [m['type'] for m in chat.get(conversation['id'])['messages']]==['user','error']
    await chat.close()


@pytest.mark.asyncio
async def test_tool_health_requires_assigned_remote_tools(store,monkeypatch):
    from control_panel.services import Services
    names=set(store.tools()['custom_tools'])
    fake=SimpleNamespace(list_tools=AsyncMock(side_effect=lambda:[SimpleNamespace(name=name) for name in names]))
    client=AsyncMock()
    client.__aenter__.return_value=fake
    monkeypatch.setattr('fastmcp.Client',lambda *args,**kwargs:client)
    services=Services(store)
    async def check_health(*args,**kwargs):
        return httpx.Response(200,json={'guardrails':1,'revision':services.guardrails.policy().revision})
    import httpx
    monkeypatch.setattr('httpx.AsyncClient.get',check_health)
    assert not await services.health('tools')
    names.add('brave_brave_web_search')
    assert await services.health('tools')
