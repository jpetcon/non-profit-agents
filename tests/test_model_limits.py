import httpx
import pytest
from fastapi.testclient import TestClient

from guardrails.policy import Policy, Restrictions
from guardrails.settings import Settings, compile_settings
from inference.app import create_inference_app
from inference.model_limits import ModelLimits
from tests.test_guardrails import setup_model, save_policy, identity_for


def test_automatic_default_and_explicit_legacy_caps(store):
    assert Settings().max_output_tokens is None
    assert Restrictions().max_output_tokens is None
    for cap in (4096, 100000):
        settings = Settings.model_validate({'advanced': {'workspace': {'max_output_tokens': cap}}})
        assert settings.max_output_tokens == cap
        assert compile_settings(store.root, settings).workspace.max_output_tokens == cap
        settings.max_output_tokens = None
        settings = Settings.model_validate(settings.model_dump(mode='json', exclude_none=True))
        assert compile_settings(store.root, settings).workspace.max_output_tokens is None
    policy = Policy(agents={'worker': {'max_output_tokens': 9000}})
    assert policy.effective({'agent': 'worker'}).max_output_tokens == 9000


def test_partial_preferences_and_advanced_edits_share_cap(client):
    current = client.get('/api/guardrails').json()
    result = client.put('/api/guardrails/settings', json={'revision': current['revision'], 'settings': {'max_output_tokens': 50000, 'per_run_token_limit': 75000}})
    assert result.status_code == 200
    current = client.get('/api/guardrails').json()
    assert current['policy']['workspace']['max_output_tokens'] == 50000
    result = client.put('/api/guardrails/settings', json={'revision': current['revision'], 'settings': {'mode': 'draft_only'}})
    assert result.status_code == 200
    current = client.get('/api/guardrails').json()
    assert current['settings']['max_output_tokens'] == 50000
    assert current['settings']['per_run_token_limit'] == 75000
    current['policy']['workspace']['max_output_tokens'] = None
    result = client.put('/api/guardrails', json={'revision': current['revision'], 'policy': current['policy']})
    assert result.status_code == 200
    assert client.get('/api/guardrails').json()['settings']['max_output_tokens'] is None


@pytest.mark.parametrize('period', ['per_run', 'daily', 'monthly'])
def test_output_uses_model_limit_and_remaining_budgets(store, period):
    runtime, policy = setup_model(store)
    policy.token_limits.per_run = policy.token_limits.daily = policy.token_limits.monthly = 5000000
    setattr(policy.token_limits, period, 12000)
    save_policy(store, policy)
    token, identity = identity_for(store, runtime, audience='inference')
    calls = []
    async def provider(**kwargs):
        calls.append(kwargs)
        return {'id': 'test', 'choices': [{'message': {'role': 'assistant', 'content': 'Done'}, 'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 100, 'completion_tokens': 5000, 'total_tokens': 5100}}
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        for text in ('First', 'Second'):
            result = client.post('/v1/chat/completions', headers={'Authorization': 'Bearer '+token}, json={'model': 'agent-fast', 'messages': [{'role': 'user', 'content': text}]})
            assert result.status_code == 200, result.text
    assert 4096 < calls[1]['max_tokens'] < calls[0]['max_tokens'] < 12000
    assert runtime.summary()['usage']['today']['reported_tokens'] == 10200


def test_large_budget_uses_model_output_limit(store):
    runtime, policy = setup_model(store)
    policy.token_limits.per_run = policy.token_limits.daily = policy.token_limits.monthly = 5000000
    save_policy(store, policy)
    token, _ = identity_for(store, runtime, audience='inference')
    calls = []
    async def provider(**kwargs):
        calls.append(kwargs)
        return {'choices': [{'message': {'role': 'assistant', 'content': 'Done'}, 'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15}}
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result = client.post('/v1/chat/completions', headers={'Authorization': 'Bearer '+token}, json={'model': 'agent-fast', 'messages': [{'role': 'user', 'content': 'Hello'}]})
    assert result.status_code == 200, result.text
    assert calls[0]['max_tokens'] == 65536


@pytest.mark.asyncio
async def test_openrouter_catalogue_is_bounded_cached_and_prompt_free(monkeypatch):
    seen = []
    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={'data': [{'id': 'example/model', 'top_provider': {'max_completion_tokens': 100000}}]})
    def transport(endpoint, targets, local, **kwargs):
        assert targets == [endpoint] and kwargs == {'max_bytes': 8*1024*1024, 'max_requests': 1}
        return httpx.MockTransport(respond)
    monkeypatch.setattr('inference.model_limits.transport_for', transport)
    resolver = ModelLimits()
    params = {'model': 'openrouter/example/model', 'api_key': 'os.environ/SECRET'}
    for _ in range(2):
        assert await resolver.resolve(params, 'https://openrouter.ai/api/v1') == 100000
    assert len(seen) == 1 and seen[0].url.path == '/api/v1/models'
    assert not seen[0].content and 'authorization' not in seen[0].headers


@pytest.mark.asyncio
async def test_custom_endpoint_cannot_borrow_another_models_metadata():
    assert await ModelLimits().resolve({'model': 'openai/gpt-4o'}, 'https://example.org/v1') is None
    assert await ModelLimits().resolve({'model': 'openai/gpt-4o'}, 'https://api.openai.com/v1') == 16384


@pytest.mark.asyncio
@pytest.mark.parametrize('payload', [None, {'data': [{'id': 'example/model', 'top_provider': {'max_completion_tokens': True}}]}])
async def test_unavailable_or_invalid_catalogue_does_not_invent_a_cap(monkeypatch, payload):
    calls=[]
    def respond(request):
        calls.append(request)
        return httpx.Response(503) if payload is None else httpx.Response(200, json=payload)
    monkeypatch.setattr('inference.model_limits.transport_for', lambda *args, **kwargs: httpx.MockTransport(respond))
    resolver=ModelLimits()
    for _ in range(2):
        assert await resolver.resolve({'model':'openrouter/example/model'}, 'https://openrouter.ai/api/v1') is None
    assert len(calls)==1


def test_unknown_output_limit_has_actionable_error_without_dispatch(store, monkeypatch):
    class Unknown:
        async def resolve(self, *args): return None
    monkeypatch.setattr('inference.app.ModelLimits', Unknown)
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience='inference')
    calls = []
    async def provider(**kwargs): calls.append(kwargs)
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result = client.post('/v1/chat/completions', headers={'Authorization': 'Bearer '+token}, json={'model': 'agent-fast', 'messages': [{'role': 'user', 'content': 'Hello'}]})
    assert result.status_code == 403 and result.json()['error']['code'] == 'model.limits'
    assert not calls


def test_unknown_model_still_honours_a_reviewed_explicit_cap(store, monkeypatch):
    class Unknown:
        async def resolve(self, *args): return None
    monkeypatch.setattr('inference.app.ModelLimits', Unknown)
    runtime, policy = setup_model(store)
    policy.workspace.max_output_tokens=6000
    save_policy(store, policy)
    token, _ = identity_for(store, runtime, audience='inference')
    calls=[]
    async def provider(**kwargs):
        calls.append(kwargs)
        return {'choices': [{'message': {'role':'assistant','content':'Done'}, 'finish_reason':'stop'}], 'usage': {'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}}
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result=client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+token}, json={'model':'agent-fast','messages':[{'role':'user','content':'Hello'}]})
    assert result.status_code==200, result.text
    assert calls[0]['max_tokens']==6000


def test_output_limit_problem_links_to_technical_settings(client):
    result=client.get('/api/chat/requirements?problem=model.limits').json()
    problem=next(item for item in result['requirements'] if item['code']=='model.limits')
    assert problem['actions']==[{'kind':'technical_limits','label':'Review output limits'}]
