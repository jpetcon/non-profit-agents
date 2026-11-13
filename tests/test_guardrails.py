"""Security boundaries exercised with fake providers and real in-process MCP."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
import json
import socket

from fastapi.testclient import TestClient
from fastmcp import Client
import httpx
import pytest

from guardrails.network import permitted_url, resolve_public, transport_for
from guardrails.policy import Policy, PolicyDenied, Restrictions, ToolRule, digest
from guardrails.runtime import Runtime, periods, tool_hash
from inference.app import create_inference_app
from tools.gateway import build_gateway


def save_policy(store, policy):
    store.save(store.policy_path, policy.model_dump(mode="json"))


def identity_for(store, runtime, agent="strategy_agent", audience="tools", data_class="public"):
    from agents.config import AppConfig
    config = AppConfig.model_validate(store.agents())
    run = runtime.start_run("test", config.team_for_agent(agent), data_class)
    token = runtime.issue(run, agent, audience)
    return token, runtime.authenticate(token, audience)


def setup_model(store, *, free=False):
    runtime = Runtime(store.root)
    policy = runtime.policy()
    entry = store.yaml("inference/litellm-config.yml")["model_list"][0]
    policy.models[entry["model_name"]] = __import__("guardrails.policy", fromlist=["ModelRule"]).ModelRule(deployment_hash=digest(entry["litellm_params"]))
    save_policy(store, policy)
    return runtime, policy


def test_scoped_credentials_revocation_and_admin_separation(store):
    runtime = Runtime(store.root)
    token, identity = identity_for(store, runtime)
    assert runtime.authenticate(token, "tools")["agent"] == "strategy_agent"
    for bad in ["", "forged", token + "x"]:
        with pytest.raises(PolicyDenied): runtime.authenticate(bad, "tools")
    with pytest.raises(PolicyDenied): runtime.authenticate(token, "inference")
    with pytest.raises(PolicyDenied): runtime.assigned(runtime.authenticate(runtime.admin_token("tools"), "tools"), tool="get_strategy")
    runtime.revoke(identity["run"])
    with pytest.raises(PolicyDenied): runtime.authenticate(token, "tools")
    _, second = identity_for(store, runtime)
    runtime.stop()
    with pytest.raises(PolicyDenied): runtime.active(second)
    with pytest.raises(PolicyDenied): runtime.start_run("test", "charity_team")
    runtime.stop(False)
    with pytest.raises(PolicyDenied): runtime.active(second)


def test_restrictions_only_tighten_and_patterns_are_bounded():
    p = Policy(workspace={"allowed_tools": ["a", "b"], "max_tool_calls": 8, "blocked_fields": ["secret_field"]}, teams={"team": {"allowed_tools": ["b", "c"], "max_tool_calls": 100, "blocked_fields": []}}, agents={"agent": {"max_tool_calls": 3}})
    effective = p.effective({"team": "team", "agent": "agent"})
    assert effective.allowed_tools == ["b"] and effective.max_tool_calls == 3
    assert "secret_field" in effective.blocked_fields
    for pattern in ["(a+)+$", "a*", "a{1,}", "a{0,10}a{0,10}", "a{99999}"]:
        with pytest.raises(ValueError): Restrictions(blocked_patterns=[pattern])
    roundtrip=Policy.model_validate(p.model_dump(mode='json'))
    assert roundtrip.effective({'team':'team','agent':'agent'})==effective
    assert 'timeout_seconds' not in p.model_dump(mode='json')['teams']['team']


def test_complete_content_inspection_and_redaction(store):
    runtime = Runtime(store.root)
    for value in [{"history": ["private-provider-test-key"]}, {"tool_call": {"ni_number": "example"}}]:
        with pytest.raises(PolicyDenied): runtime.inspect(value, Restrictions())
    assert runtime.inspect({"result": "REF1234"}, Restrictions(redact_patterns=["REF[0-9]{4}"])) == ({"result": "[REDACTED]"}, True)
    with pytest.raises(PolicyDenied): runtime.inspect({"a": {"b": {"c": 1}}}, Restrictions(max_depth=2))


def test_atomic_token_limits_survive_restart_and_uncertain_usage(store):
    runtime,policy=setup_model(store)
    policy.token_limits.per_run=500
    policy.token_limits.daily=500
    save_policy(store,policy)
    _,identity=identity_for(store,runtime)
    limits=policy.effective(identity)
    def reserve(i):
        try:return Runtime(store.root).reserve(identity,'inference','agent-fast',str(i),0,limits,tokens=300)
        except PolicyDenied:return None
    with ThreadPoolExecutor(max_workers=2) as pool:calls=list(pool.map(reserve,range(2)))
    assert sum(c is not None for c in calls)==1
    restarted=Runtime(store.root)
    assert restarted.summary()['usage']['today']['reserved_tokens']==300
    restarted.settle(next(c for c in calls if c),usage={'prompt_tokens':60,'completion_tokens':40,'total_tokens':100,'completion_tokens_details':{'reasoning_tokens':20}})
    assert restarted.summary()['usage']['today']['reported_tokens']==100
    restarted.reserve(identity,'inference','agent-fast','new',0,limits,tokens=300)
    with pytest.raises(PolicyDenied,match='tokens.'):restarted.reserve(identity,'inference','agent-fast','overflow',0,limits,tokens=200)



def test_london_calendar_boundaries():
    # British summer time: July begins one hour before UTC midnight.
    instant = datetime(2026, 6, 30, 23, 30, tzinfo=timezone.utc).timestamp()
    assert periods(instant) == ("2026-07-01", "2026-07")


@pytest.mark.asyncio
async def test_network_blocks_private_mixed_dns_and_redirect_targets(monkeypatch):
    async def addresses(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)), (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", addresses)
    with pytest.raises(PolicyDenied): await resolve_public("example.org", 443)
    with pytest.raises(PolicyDenied): permitted_url("https://other.org/api", ["https://example.org/api"])
    with pytest.raises(PolicyDenied): permitted_url("https://example.org/apievil", ["https://example.org/api"])
    with pytest.raises(PolicyDenied): permitted_url("http://127.0.0.1/api", ["http://127.0.0.1/api"])
    assert permitted_url("http://127.0.0.1/api", ["http://127.0.0.1/api"], ["http://127.0.0.1/api"])


@pytest.mark.asyncio
async def test_dns_pins_socket_address_and_retains_original_origin(monkeypatch):
    import httpcore._backends.auto
    async def addresses(*args, **kwargs): return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", addresses)
    connected = []
    async def connect(self, host, port, **kwargs): connected.append((host, port));return object()
    monkeypatch.setattr(httpcore._backends.auto.AutoBackend, "connect_tcp", connect)
    transport = transport_for("https://example.org/api", ["https://example.org/api"])
    await transport._pool._network_backend.connect_tcp("example.org", 443)
    assert connected == [("93.184.216.34", 443)]
    await transport.aclose()


@pytest.mark.asyncio
async def test_approval_is_one_use_transient_and_cancellation_revokes(store):
    runtime = Runtime(store.root)
    _, identity = identity_for(store, runtime)
    rule = ToolRule(classification="publish", schema_hash="hash", input_schema={"type": "object"})
    task = asyncio.create_task(runtime.approval(identity, "publish", {"text": "private draft"}, rule, runtime.policy().revision, {"tool": "publish"}))
    await asyncio.sleep(.01)
    approval = runtime.summary()["approvals"][0]
    assert "private draft" not in runtime.path.read_bytes().decode(errors="ignore")
    assert runtime.pending_payloads[approval["id"]] == {"text": "private draft"}
    runtime.decide_approval(approval["id"], True)
    await task
    assert not runtime.pending_payloads
    with pytest.raises(PolicyDenied): runtime.decide_approval(approval["id"], True)
    task = asyncio.create_task(runtime.approval(identity, "publish", {}, rule, runtime.policy().revision, {}))
    await asyncio.sleep(.01)
    runtime.revoke(identity["run"])
    with pytest.raises(PolicyDenied): await task


def test_charity_hard_blocks_and_review(store):
    runtime = Runtime(store.root)
    policy = runtime.policy()
    policy.profile['activities']['fundraising'] = True
    policy.tools["send"] = ToolRule(classification="send", schema_hash="hash", input_schema={"type": "object"}, charity_workflow="fundraising")
    save_policy(store, policy)
    _, identity = identity_for(store, runtime)
    with pytest.raises(PolicyDenied): runtime.evaluate_tool(identity, "send", {})
    policy.charity.sender_identity = "Test charity"
    policy.charity.unsubscribe_url = "https://example.org/unsubscribe"
    from guardrails.policy import Recipient
    policy.charity.recipients["r1"] = Recipient(basis="charitable_soft_opt_in", evidence_reference="record", suppressed=False, collected_on="2025-01-01", collected_directly=True, interest_or_support=True, collection_opt_out=True, purpose_references=["charitable purpose"])
    policy.charity.registered_charity = True
    policy.charity.approved_purposes = ["charitable purpose"]
    policy.tools["send"].purpose_reference = "charitable purpose"
    save_policy(store, policy)
    args = {"recipients": ["r1"], "sender_identity": "Test charity", "unsubscribe_url": "https://example.org/unsubscribe"}
    with pytest.raises(PolicyDenied, match="soft_opt_in"): runtime.evaluate_tool(identity, "send", args)
    policy.charity.recipients["r1"].collected_on = "2026-05-01"
    save_policy(store, policy)
    assert runtime.evaluate_tool(identity, "send", args)[0].action == "require_approval"
    policy.charity.recipients["r1"].suppressed = True
    save_policy(store, policy)
    with pytest.raises(PolicyDenied, match="suppression"): runtime.evaluate_tool(identity, "send", args)


@pytest.mark.asyncio
async def test_tool_gateway_pins_assignment_and_blocks_before_dispatch(store):
    runtime = Runtime(store.root)
    token, identity = identity_for(store, runtime)
    config = store.tools()
    config["mcp_servers"] = {}
    store.save(store.tools_path, config)
    gateway = build_gateway(store.tools_path, runtime=runtime, identity_provider=lambda: runtime.authenticate(token, "tools"))
    definition = await gateway.get_tool("get_strategy")
    policy = runtime.policy()
    policy.tools = {}
    policy.tools["get_strategy"] = ToolRule(classification="read", schema_hash=tool_hash("get_strategy", definition.description, definition.parameters, definition.output_schema), input_schema=definition.parameters, output_schema=definition.output_schema, configuration_hash=digest(config["custom_tools"]["get_strategy"]))
    save_policy(store, policy)
    gateway = build_gateway(store.tools_path, runtime=runtime, identity_provider=lambda: runtime.authenticate(token, "tools"))
    async with Client(gateway) as client:
        assert [t.name for t in await client.list_tools()] == ["get_strategy"]
        result = await client.call_tool("get_strategy", {})
        assert not result.is_error
        with pytest.raises(Exception): await client.call_tool("get_brand_voice", {})
        runtime.revoke(identity["run"])
        with pytest.raises(Exception): await client.call_tool("get_strategy", {})


def test_inference_missing_credentials_and_token_limit_block_without_dispatch(store):
    calls = []
    async def provider(**kwargs): calls.append(kwargs);return {}
    runtime = Runtime(store.root)
    policy=runtime.policy();policy.token_limits.monthly=None;save_policy(store,policy)
    token, _ = identity_for(store, runtime, audience="inference")
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        payload = {"model": "agent-fast", "messages": [{"role": "user", "content": "hello"}]}
        assert client.post("/v1/chat/completions", json=payload).status_code == 403
        result = client.post("/v1/chat/completions", json=payload, headers={"Authorization": "Bearer " + token})
        assert result.status_code == 403 and "tokens.setup" in result.text
        assert client.post("/v1/embeddings", json=payload).status_code == 404
    assert calls == []


@pytest.mark.parametrize("failure", ["secret", "tool_schema", "output_schema", "routing_override", "data_class", "deployment_changed"])
def test_inference_rejection_never_releases_content(store, failure):
    runtime, policy = setup_model(store)
    calls = []
    response = {"id": "test", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": "safe"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
    if failure == "secret": response["choices"][0]["message"]["content"] = "private-provider-test-key"
    if failure == "tool_schema": response["choices"][0]["message"].update(tool_calls=[{"id": "1", "type": "function", "function": {"name": "missing", "arguments": "{}"}}])
    async def provider(**kwargs): calls.append(kwargs);return response
    token, _ = identity_for(store, runtime, audience="inference", data_class="sensitive" if failure == "data_class" else "public")
    payload = {"model": "agent-fast", "messages": [{"role": "user", "content": "hello"}], "stream": True}
    if failure == "output_schema": payload["response_format"] = {"type": "json_object"}
    if failure == "routing_override": payload["api_base"] = "https://attacker.org"
    if failure == "deployment_changed":
        config = store.yaml("inference/litellm-config.yml")
        config["model_list"][0]["litellm_params"]["api_base"] = "https://attacker.org"
        store.save(store.root / "inference/litellm-config.yml", config)
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result = client.post("/v1/chat/completions", json=payload, headers={"Authorization": "Bearer " + token})
    assert result.status_code == 403, result.text
    assert "private-provider-test-key" not in result.text and not result.text.startswith("data: ")
    if failure in {"routing_override", "data_class", "deployment_changed"}: assert not calls


def test_inference_validated_sse_usage_and_identity_stripping(store):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience="inference")
    calls = []
    async def provider(**kwargs):
        calls.append(kwargs)
        return {"id": "test", "choices": [{"index": 0, "message": {"role": "assistant", "content": "Checked output"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result = client.post("/v1/chat/completions", headers={"Authorization": "Bearer " + token}, json={"model": "agent-fast", "messages": [{"role": "user", "content": "hello"}], "stream": True, "user": "local-identity"})
    assert result.status_code == 200, result.text
    assert "Checked output" in result.text and "[DONE]" in result.text
    assert "user" not in calls[0] and token not in str(calls)
    assert runtime.summary()["usage"]["today"]["reported_tokens"] > 0


def test_dashboard_policy_conflicts_simulation_and_stop(client, store):
    original = client.get("/api/guardrails").json()
    assert original["policy"]["budgets"]["daily_gbp"] is None
    assert original["tool_definitions"]
    policy = original["policy"]
    policy["workspace"]["blocked_patterns"] = ["SENSITIVE[0-9]{4}"]
    result = client.put("/api/guardrails", json={"revision": original["revision"], "policy": policy})
    assert result.status_code == 200, result.text
    assert client.put("/api/guardrails", json={"revision": original["revision"], "policy": policy}).status_code == 409
    result = client.post("/api/guardrails/test", json={"content": "SENSITIVE1234"}).json()
    assert result["decision"]["action"] == "block"
    assert client.post("/api/guardrails/stop", json={}).status_code == 200
    assert client.get("/api/guardrails/activity").json()["stopped"]
    assert client.post("/api/guardrails/resume", json={}).status_code == 200
    assert client.post("/api/guardrails/stop", json={}, headers={"X-CSRF-Token": ""}).status_code == 403


@pytest.mark.parametrize("provider", ["openrouter", "openai", "anthropic", "gemini", "ollama_chat", "mistral", "groq", "deepseek", "together_ai"])
def test_real_litellm_uses_guarded_http_transport(store, monkeypatch, provider):
    config = store.yaml('inference/litellm-config.yml')
    config['model_list'][0]['litellm_params'] = {'model':provider+'/test-model','api_base':'https://provider.invalid/v1','api_key':'os.environ/OPENROUTER_API_KEY'}
    store.save(store.root/'inference/litellm-config.yml',config)
    runtime, _ = setup_model(store)
    token, _ = identity_for(store,runtime,audience='inference')
    requests=[]
    async def fake(request):
        requests.append(request)
        # Reaching this transport proves the provider cannot silently use its
        # own unguarded client. The 400 response is deliberately non-retriable.
        return httpx.Response(400,json={'error':{'message':'Synthetic provider response','type':'invalid_request_error'}})
    monkeypatch.setattr('inference.app.transport_for',lambda *args,**kwargs:httpx.MockTransport(fake))
    with TestClient(create_inference_app(store.root)) as client:
        result=client.post('/v1/chat/completions',json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}]},headers={'Authorization':'Bearer '+token})
    assert requests, (provider,result.text)
    assert all(token not in str(r.headers) for r in requests)
    assert len(requests)==1, 'A reserved attempt must not silently retry provider IO'


def test_external_schema_references_block_before_provider(store):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store,runtime,audience='inference')
    calls=[]
    async def provider(**kwargs):calls.append(kwargs)
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}],'response_format':{'type':'json_schema','json_schema':{'name':'test','schema':{'$ref':'http://169.254.169.254/schema'}}}})
    assert result.status_code==403 and not calls


@pytest.mark.asyncio
async def test_revocation_cancels_inflight_work(store):
    runtime=Runtime(store.root)
    _,identity=identity_for(store,runtime)
    cancelled=[]
    async def operation():
        try:await asyncio.sleep(10)
        finally:cancelled.append(True)
    task=asyncio.create_task(runtime.guarded(identity,operation(),20))
    await asyncio.sleep(.01)
    Runtime(store.root).stop()
    with pytest.raises(PolicyDenied):await asyncio.wait_for(task,1)
    assert cancelled==[True]


@pytest.mark.asyncio
async def test_real_http_mcp_authentication_and_payload_boundary(store,guarded_gateway):
    import httpx2
    from fastmcp.client.transports import StreamableHttpTransport
    from starlette.middleware import Middleware
    from guardrails.http_boundary import GatewayHTTPBoundary
    config=store.tools();config['mcp_servers']={};store.save(store.tools_path,config)
    await guarded_gateway(['get_strategy'])
    runtime=Runtime(store.root)
    token,_=identity_for(store,runtime)
    gateway=build_gateway(store.tools_path,runtime=runtime)
    app=gateway.http_app(stateless_http=True,json_response=True,middleware=[Middleware(GatewayHTTPBoundary,runtime=runtime)])
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app),base_url='http://127.0.0.1') as client:
            assert (await client.post('/mcp',json={'method':'tools/list'})).status_code==403
            result=await client.post('/mcp',content=b'x'*140000,headers={'Authorization':'Bearer '+token})
            assert result.status_code==413
        def factory(**kwargs):
            kwargs['transport']=httpx2.ASGITransport(app=app)
            return httpx2.AsyncClient(**kwargs)
        transport=StreamableHttpTransport('http://127.0.0.1/mcp',headers={'Authorization':'Bearer '+token},httpx_client_factory=factory)
        async with Client(transport) as client:
            assert [t.name for t in await client.list_tools()]==['get_strategy']
            assert not (await client.call_tool('get_strategy',{})).is_error


@pytest.mark.parametrize('secret_output',[False,True])
def test_real_litellm_streams_are_buffered_and_usage_is_authentic(store,monkeypatch,secret_output):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    def chunk(delta,finish=None,usage=None):
        return {'id':'stub','object':'chat.completion.chunk','created':1,'model':'test-model','choices':[{'index':0,'delta':delta,'finish_reason':finish}],'usage':usage}
    content='private-provider-test-key' if secret_output else 'Checked'
    frames=[chunk({'role':'assistant','content':content[:7]}),chunk({'content':content[7:]}),chunk({},'stop',{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15})]
    body=''.join('data: '+json.dumps(f)+'\n\n' for f in frames)+'data: [DONE]\n\n'
    async def fake(request):return httpx.Response(200,content=body,headers={'content-type':'text/event-stream'})
    monkeypatch.setattr('inference.app.transport_for',lambda *args,**kwargs:httpx.MockTransport(fake))
    with TestClient(create_inference_app(store.root)) as client:
        result=client.post('/v1/chat/completions',json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}],'stream':True},headers={'Authorization':'Bearer '+token})
    if secret_output:
        assert result.status_code==403 and content not in result.text
    else:
        assert result.status_code==200 and 'Checked' in result.text,result.text
    assert runtime.summary()['usage']['today']['reported_tokens']>0


@pytest.mark.asyncio
async def test_gateway_approval_prevents_side_effects_until_exact_review(store,guarded_gateway,monkeypatch):
    from guardrails.policy import ToolRule
    calls=[]
    def action() -> str:
        calls.append(True)
        return 'Published'
    monkeypatch.setattr('tools.custom_tools.master_brand.get_strategy',action)
    config=store.tools();config['mcp_servers']={};store.save(store.tools_path,config)
    await guarded_gateway(['get_strategy'])
    runtime=Runtime(store.root)
    policy=runtime.policy();policy.tools['get_strategy'].classification='publish';save_policy(store,policy)
    token,_=identity_for(store,runtime)
    gateway=build_gateway(store.tools_path,runtime=runtime,identity_provider=lambda:runtime.authenticate(token,'tools'))
    async with Client(gateway) as client:
        task=asyncio.create_task(client.call_tool('get_strategy',{}))
        for _ in range(50):
            if runtime.summary()['approvals']:break
            await asyncio.sleep(.02)
        pending=runtime.summary()['approvals'][0]
        assert calls==[] and not task.done()
        runtime.decide_approval(pending['id'],True)
        assert not (await asyncio.wait_for(task,2)).is_error
        assert calls==[True]
        # A repeated consequential action cannot dispatch again, even if its new
        # exact-action approval is granted.
        task=asyncio.create_task(client.call_tool('get_strategy',{}))
        for _ in range(50):
            if runtime.summary()['approvals']:break
            await asyncio.sleep(.02)
        runtime.decide_approval(runtime.summary()['approvals'][0]['id'],True)
        with pytest.raises(Exception):await asyncio.wait_for(task,2)
        assert calls==[True]


@pytest.mark.asyncio
async def test_client_verification_rejects_external_and_legacy_gateways(monkeypatch):
    from guardrails.client import verify_gateway
    requests=[]
    async def get(*args,**kwargs):requests.append(args);return httpx.Response(200,json={'status':'ok'})
    monkeypatch.setattr('httpx.AsyncClient.get',get)
    with pytest.raises(PolicyDenied,match='gateway.local'):
        await verify_gateway('https://external.example/v1','inference','scoped-token','revision')
    assert not requests
    with pytest.raises(PolicyDenied,match='gateway.unverified'):
        await verify_gateway('http://127.0.0.1:4000','inference','scoped-token','revision')


def test_adk_multiturn_text_history_accepts_null_optional_fields(store):
    from inference.app import InferenceHooks
    runtime,_=setup_model(store)
    _,identity=identity_for(store,runtime,audience='inference')
    data={'model':'agent-fast','messages':[{'role':'user','content':'hello'},{'role':'assistant','content':'hello back','tool_calls':None,'reasoning_content':None},{'role':'user','content':'continue'}],'tools':None,'response_format':None}
    clean,_,_,_=InferenceHooks(runtime).request(identity,data)
    assert len(clean['messages'])==3


def test_financial_evidence_binds_actual_arguments(store):
    runtime=Runtime(store.root);policy=runtime.policy()
    policy.profile['activities']['finance'] = True
    policy.charity.approved_purposes=['purpose'];policy.charity.approved_funds=['fund']
    policy.tools['pay']=ToolRule(classification='financial',schema_hash='test',input_schema={'type':'object'},purpose_reference='purpose',fund_reference='fund',recipient_reference='recipient',due_diligence_reference='checked',max_value_gbp=Decimal(10))
    save_policy(store,policy)
    _,identity=identity_for(store,runtime)
    args={'fund_id':'fund','recipient_id':'other','amount_gbp':1}
    with pytest.raises(PolicyDenied,match='financial_target'):runtime.evaluate_tool(identity,'pay',args)
    args['recipient_id']='recipient';args['amount_gbp']=11
    with pytest.raises(PolicyDenied,match='tool.value'):runtime.evaluate_tool(identity,'pay',args)
    args['amount_gbp']=1
    assert runtime.evaluate_tool(identity,'pay',args)[0].action=='require_approval'
