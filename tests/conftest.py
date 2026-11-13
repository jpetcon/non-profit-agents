import asyncio
import json
from pathlib import Path
import shutil

import pytest
from fastapi.testclient import TestClient

from control_panel.app import create_app
from control_panel.store import Store

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def fake_model_capabilities(monkeypatch):
    """Provider fixtures never query a live model catalogue."""
    class FixtureLimits:
        async def resolve(self, params, endpoint, local_endpoints=()):
            return 65536
    monkeypatch.setattr('inference.app.ModelLimits', FixtureLimits)


@pytest.fixture
def workspace(tmp_path):
    for path in ['agents/config.yml', 'models/model_config.yml', 'tools/config.yml', 'inference/litellm-config.yml', 'tools/custom_tools/lib/strategy.json']:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        fixtures = {'agents/config.yml': 'agents.yml', 'tools/config.yml': 'tools.yml'}
        source = ROOT / 'tests/fixtures' / fixtures[path] if path in fixtures else ROOT / path
        shutil.copyfile(source, target)
    # Keep first-run tests independent of the user's locally edited Masterbrand.
    (tmp_path / 'tools/custom_tools/lib/strategy.json').write_text(json.dumps({'strategy':"Support children's wellbeing."}))
    (tmp_path / '.env').write_text("# unrelated comment\nOPENROUTER_API_KEY='private-provider-test-key'\nLITELLM_MASTER_KEY='sk-private-local-test-key'\nLITELLM_PROXY_API_KEY='sk-private-local-test-key'\nBRAVE_API_KEY='private-brave-test-key'\n")
    return tmp_path


class FakeServices:
    def __init__(self, store):
        self.store = store
        self.lock = asyncio.Lock()
        self.states = {name: {'name': name, 'label': name.title() + ' gateway', 'status': 'running', 'managed': True, 'pending': False, 'detail': 'Mock gateway ready'} for name in ['inference', 'tools']}

    async def snapshot(self): return list(self.states.values())
    async def observe(self, name): return self.states[name]
    async def start_ready(self): pass
    async def close(self): pass
    async def action(self, name, action): pass
    async def apply(self): return await self.snapshot()
    def logs(self, name): return 'Mock gateway ready'


async def fake_chat(conversation, prompt):
    yield {'type': 'activity', 'label': 'Using get_strategy', 'kind': 'tool'}
    yield {'type': 'delta', 'text': 'Our strategy '}
    await asyncio.sleep(.01)
    yield {'type': 'answer', 'text': 'Our **strategy** helps children. [Source](https://example.org/strategy). <script>alert(1)</script>', 'agent': 'strategy_agent'}


@pytest.fixture
def app(workspace):
    from guardrails.policy import digest
    store=Store(workspace)
    spec=store.tools()['mcp_servers']['brave']
    store.remember_catalog('brave',[{'name':'brave_brave_web_search','server':'brave','description':'Search public sources','input_schema':{'type':'object','properties':{'query':{'type':'string'}},'required':['query']},'output_schema':None,'configuration_hash':digest(spec)}])
    return create_app(workspace, auto_start=False, pairing_token='browser-pair-test', service_factory=FakeServices, chat_backend=fake_chat)


@pytest.fixture
def client(app):
    with TestClient(app, base_url='http://127.0.0.1:8080') as client:
        result = client.post('/api/pair', json={'token':'browser-pair-test'})
        assert result.status_code == 200
        client.headers.update({'X-CSRF-Token':result.json()['csrf'], 'Origin':'http://127.0.0.1:8080'})
        yield client


@pytest.fixture
def store(workspace): return Store(workspace)


@pytest.fixture
def guarded_gateway(store):
    """Approve explicit test capabilities without disabling gateway enforcement."""
    async def build(names, agent='strategy_agent'):
        from guardrails.runtime import Runtime, tool_hash
        from guardrails.policy import ToolRule, digest
        from tools.gateway import build_gateway
        from agents.config import AppConfig
        runtime=Runtime(store.root)
        config=store.tools()
        policy=runtime.policy()
        policy.stdio_commands=[[s['command'],*s.get('args',[])] for s in config['mcp_servers'].values() if s.get('transport')=='stdio']
        store.save(store.policy_path,policy.model_dump(mode='json'))
        agents=store.agents()
        agents['agents'][agent]['tools']=names
        store.save(store.agents_path,agents)
        team=AppConfig.model_validate(agents).team_for_agent(agent)
        run=runtime.start_run('test',team)
        token=runtime.issue(run,agent,'tools')
        identity=lambda:runtime.authenticate(token,'tools')
        gateway=build_gateway(store.tools_path,runtime=runtime,identity_provider=identity)
        for name in names:
            tool=await gateway.get_tool(name)
            spec=config.get('custom_tools',{}).get(name) or config.get('http_tools',{}).get(name)
            if spec is None:spec=next(s for prefix,s in config['mcp_servers'].items() if name.startswith(prefix+'_'))
            policy.tools[name]=ToolRule(classification='read',schema_hash=tool_hash(name,tool.description,tool.parameters,tool.output_schema),configuration_hash=digest(spec),input_schema=tool.parameters,output_schema=tool.output_schema)
        store.save(store.policy_path,policy.model_dump(mode='json'))
        return build_gateway(store.tools_path,runtime=runtime,identity_provider=identity)
    return build
