"""An isolated stdlib fake gateway verifies real ownership and child cleanup."""
import asyncio
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace

import psutil
import pytest

from control_panel.services import Services


@pytest.mark.asyncio
async def test_real_owned_process_no_duplicates_and_child_cleanup(store,monkeypatch):
    if os.name=='nt':pytest.skip('POSIX ownership integration')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        port=sock.getsockname()[1]
    model_config=store.yaml('models/model_config.yml')
    model_config['gateway']['url']=f'http://127.0.0.1:{port}'
    store.save(store.root/'models/model_config.yml',model_config)
    bin_dir=store.root/'bin'
    bin_dir.mkdir()
    (bin_dir/'python').symlink_to(sys.executable)
    (store.root/'inference/__main__.py').write_text('''import argparse,json,subprocess,sys
from http.server import BaseHTTPRequestHandler,HTTPServer
p=argparse.ArgumentParser();p.add_argument('--config');p.add_argument('--host');p.add_argument('--port',type=int);a=p.parse_args()
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
print('child',child.pid,flush=True)
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  data=json.dumps({'guardrails':1,'revision':'POLICY_REVISION'} if self.path=='/health/liveliness' else {'data':[{'id':x} for x in ['agent-fast','agent-powerful','agent-backup']]}).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(data)
 def log_message(self,*args):pass
HTTPServer((a.host,a.port),Handler).serve_forever()
'''.replace('POLICY_REVISION',__import__('guardrails.runtime',fromlist=['Runtime']).Runtime(store.root).policy().revision))
    monkeypatch.setattr('control_panel.services.sys',SimpleNamespace(executable=str(bin_dir/'python')))
    services=Services(store)
    services.STARTUP_TIMEOUT=5
    parent=None
    children=[]
    try:
        await services.action('inference','start')
        assert services.states['inference']['status']=='running'
        parent=services.owned('inference')
        assert parent is not None
        children=parent.children(recursive=True)
        assert children
        await services.action('inference','start')
        assert services.records['inference']['pid']==parent.pid
        store.write_secrets({'OPENROUTER_API_KEY':'new-private-provider-key'})
        assert (await services.observe('inference'))['pending']
    finally:
        await services.close()
    assert not services.occupied(port)
    assert parent is not None and not parent.is_running()
    assert all(not child.is_running() or child.status()==psutil.STATUS_ZOMBIE for child in children)


@pytest.mark.asyncio
async def test_startup_timeout_stops_failed_process(store,monkeypatch):
    services=Services(store)
    services.STARTUP_TIMEOUT=0
    from unittest.mock import AsyncMock, MagicMock
    monkeypatch.setattr(services,'occupied',lambda port:False)
    monkeypatch.setattr(services,'owned',lambda name:None)
    fake=MagicMock(pid=999,returncode=None)
    identity=MagicMock()
    identity.create_time.return_value=1
    monkeypatch.setattr('psutil.Process',lambda pid:identity)
    monkeypatch.setattr('asyncio.create_subprocess_exec',AsyncMock(return_value=fake))
    services._read_log=AsyncMock()
    services._stop=AsyncMock()
    await services._start('inference')
    assert services.states['inference']['status']=='failed'
    services._stop.assert_awaited_once_with('inference',preserve_error=True)


@pytest.mark.asyncio
async def test_real_guarded_gateways_start_and_report_active_revision(store,monkeypatch):
    from unittest.mock import Mock
    from control_panel.chat import Chat
    from guardrails.policy import PolicyDenied
    from tools.tool_registry import ToolRegistry
    def unexpected_cloud_auth(*args, **kwargs):
        raise AssertionError('Local tool discovery must never request cloud credentials.')
    cloud_auth = Mock(side_effect=unexpected_cloud_auth)
    monkeypatch.setattr('google.auth.default', cloud_auth)
    # Exercise the shipped entry points with fake keys, no remote MCP connections
    # and no inference requests. Mock-only service tests cannot catch boot errors.
    environment=store.process_environment()
    environment['PYTHONPATH']=str(Path(__file__).resolve().parent.parent)
    monkeypatch.setattr(store,'process_environment',lambda:environment.copy())
    with socket.socket() as first, socket.socket() as second:
        first.bind(('127.0.0.1',0))
        second.bind(('127.0.0.1',0))
        inference_port,tool_port=first.getsockname()[1],second.getsockname()[1]
    models=store.yaml('models/model_config.yml')
    models['gateway']['url']=f'http://127.0.0.1:{inference_port}'
    store.save(store.root/'models/model_config.yml',models)
    tools=store.tools()
    tools['gateway']['port']=tool_port
    tools['mcp_servers']={}
    store.save(store.tools_path,tools)
    agents=store.agents()
    for agent in agents['agents'].values():agent['tools']=['get_strategy']
    store.save(store.agents_path,agents)
    services=Services(store)
    services.STARTUP_TIMEOUT=20
    try:
        await services.start_ready()
        assert not services.lock.locked()
        states=await services.snapshot()
        assert all(s['status']=='running' and not s['pending'] for s in states), states
        assert await services.health('inference')
        assert await services.health('tools')
        runtime=services.guardrails
        run=runtime.start_run('preflight-test','charity_team')
        token=runtime.issue(run,'strategy_agent','tools')
        credentials=Mock(return_value=token)
        registry=ToolRegistry(f'http://127.0.0.1:{tool_port}/mcp',credential_provider=credentials,revision_provider=lambda:runtime.policy().revision)
        try:
            # Overview and Chat must both work with the actual client API. Chat
            # uses agent scope; the supervisor's admin token cannot prove this.
            await registry.validate_available(['get_strategy'],agent='strategy_agent')
            credentials.assert_called_with('strategy_agent','tools')
            toolset=registry.resolve(['get_strategy'],agent='strategy_agent')[0]
            try:
                assert [tool.name for tool in await toolset.get_tools()]==['get_strategy']
                cloud_auth.assert_not_called()
            finally:
                await toolset.close()
            with pytest.raises(ValueError,match='Assigned tools are unavailable.*get_brand_voice'):
                await registry.validate_available(['get_strategy','get_brand_voice'],agent='strategy_agent')
            credentials.return_value=runtime.issue(run,'strategy_agent','tools',ttl=-1)
            with pytest.raises(PolicyDenied,match='gateway.unverified'):
                await registry.validate_available(['get_strategy'],agent='strategy_agent')
            credentials.return_value=token
            policy=store.yaml('guardrails/config.yml')
            policy['mode']='draft_only'
            store.save(store.policy_path,policy)
            with pytest.raises(PolicyDenied,match='gateway.unverified'):
                await registry.validate_available(['get_strategy'],agent='strategy_agent')
            # Failed discovery must never execute tools or reserve inference.
            with runtime.db() as db:
                assert db.execute('SELECT COUNT(*) FROM calls').fetchone()[0]==0
            await services.action('tools','stop')
            with pytest.raises(PolicyDenied,match='gateway.unverified'):
                await registry.validate_available(['get_strategy'],agent='strategy_agent')
            # Also cover the existing unscoped client interface and its safe
            # error when the HTTP endpoint cannot be reached.
            with pytest.raises(ValueError,match='Could not validate assigned tools'):
                await ToolRegistry(registry.gateway_url).validate_available(['get_strategy'])
            model=Mock(side_effect=AssertionError('Inference must not be constructed'))
            monkeypatch.setattr('models.model_registry.Models.resolve',model)
            chat=Chat(store)
            try:
                conversation=chat.create()
                queue=chat.start(conversation['id'],'Find the charity strategy')
                events=[]
                while True:
                    event=await asyncio.wait_for(queue.get(),10)
                    events.append(event)
                    if event['type']=='done':break
                assert [e['type'] for e in events]==['activity','error','done']
                assert events[1]['issue']['code']=='gateway.unverified'
                model.assert_not_called()
            finally:
                await chat.close()
        finally:
            runtime.revoke(run)
    finally:
        await services.close()
    assert not services.occupied(inference_port)
    assert not services.occupied(tool_port)
