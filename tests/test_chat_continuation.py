"""Settings changes preserve a chat; current policy still controls every turn."""
import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from control_panel.chat import Chat
from guardrails.policy import PolicyDenied, digest
from guardrails.settings import load_settings


def settle(client, app):
    async def ready():
        while app.state.synchronisation.pending:
            await asyncio.sleep(.01)
    client.portal.call(asyncio.wait_for,ready(),2)


def test_raise_token_limit_and_continue_with_same_history_and_new_credentials(client,app,store):
    settings=load_settings(store.root)
    settings.monthly_token_limit=1000;settings.daily_token_limit=20
    store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
    settle(client,app)
    runtime=app.state.chat.guardrails
    attempts=[]
    async def backend(conversation,prompt):
        token=runtime.issue(app.state.chat.run_id,conversation['agent'],'inference')
        identity=runtime.authenticate(token,'inference')
        attempts.append({'conversation':conversation['id'],'run':identity['run'],'token':token,'history':conversation['messages']})
        call=runtime.reserve(identity,'inference','agent-fast',digest(prompt),0,runtime.policy().effective(identity),tokens=20)
        runtime.settle(call,usage={'prompt_tokens':10,'completion_tokens':5,'total_tokens':15})
        yield {'type':'answer','text':'A checked public answer.'}
    app.state.chat.backend=backend
    conversation=client.post('/api/conversations',json={'agent':'strategy_agent'}).json()
    url='/api/conversations/'+conversation['id']
    first=client.post(url+'/messages',json={'message':'Remember our public campaign plan'})
    assert first.status_code==200 and 'A checked public answer.' in first.text
    failed=client.post(url+'/messages',json={'message':'Continue the plan'})
    assert 'tokens.day' in failed.text
    before=client.get(url).json()['messages']
    settings.daily_token_limit=40
    store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
    settle(client,app)
    current=client.get(url).json()
    assert not current['outdated'] and current['settings_changed']
    assert client.get('/api/chat/requirements',params={'conversation':conversation['id']}).json()['ready']
    assert len(attempts)==2  # Saving settings never sends a request.
    result=client.post(url+'/messages',json={'message':'Continue with the saved plan'})
    assert result.status_code==200 and 'A checked public answer.' in result.text
    saved=client.get(url).json()
    assert saved['id']==conversation['id'] and saved['messages'][:len(before)]==before
    assert not saved['settings_changed'] and len(client.get('/api/conversations').json()['conversations'])==1
    assert any(m.get('text')=='Remember our public campaign plan' for m in attempts[-1]['history'])
    assert len({a['run'] for a in attempts})==3 and len({a['token'] for a in attempts})==3
    with pytest.raises(PolicyDenied):runtime.authenticate(attempts[0]['token'],'inference')
    assert runtime.summary()['usage']['today']['reported_tokens']==30


def test_relax_applicable_data_rule_and_continue_with_retained_context(client,app,store):
    settings=load_settings(store.root)
    from guardrails.policy import Policy
    settings.advanced=Policy(workspace={'blocked_patterns':['HOLD']})
    store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
    settle(client,app)
    conversation=client.post('/api/conversations',json={}).json()
    url='/api/conversations/'+conversation['id']
    app.state.chat.append(conversation['id'],{'type':'user','text':'HOLD earlier public reference'})
    denied=client.post(url+'/messages',json={'message':'Continue'})
    assert denied.json()['issue']['code']=='data.history'
    settings.advanced.workspace.blocked_patterns=[]
    store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
    settle(client,app)
    result=client.post(url+'/messages',json={'message':'Continue with the earlier reference'})
    assert result.status_code==200 and 'helps children' in result.text
    saved=client.get(url).json()
    assert saved['messages'][0]['text']=='HOLD earlier public reference'
    assert saved['context_after']==0


def test_context_reset_keeps_transcript_but_never_resends_earlier_payment_data(client,app):
    conversation=client.post('/api/conversations',json={}).json()
    url='/api/conversations/'+conversation['id']
    earlier='Old card details 4000056655665556 12/29 123'
    app.state.chat.append(conversation['id'],{'type':'user','text':earlier})
    denied=client.post(url+'/messages',json={'message':'Continue safely'})
    assert denied.json()['issue']['code']=='data.history'
    requirement=client.get('/api/chat/requirements',params={'conversation':conversation['id'],'problem':'data.history'}).json()
    assert requirement['requirements'][0]['actions'][0]['kind']=='reset_context'
    seen=[]
    async def backend(conversation,prompt):
        seen.extend(conversation['messages'])
        yield {'type':'answer','text':'Continuing with fresh context.'}
    app.state.chat.backend=backend
    assert client.post(url+'/context/reset',json={},headers={'X-CSRF-Token':''}).status_code==403
    reset=client.post(url+'/context/reset',json={}).json()
    assert reset['id']==conversation['id'] and reset['messages'][0]['text']==earlier
    assert reset['session_id']!=conversation['id'] and seen==[]
    result=client.post(url+'/messages',json={'message':'Continue with public information'})
    assert result.status_code==200 and 'Continuing with fresh context.' in result.text
    assert earlier not in json.dumps(seen)
    assert client.get(url).json()['messages'][0]['text']==earlier


@pytest.mark.asyncio
async def test_real_adk_history_survives_policy_change_and_resets_only_explicitly(store,monkeypatch):
    from google.adk.agents import Agent
    from google.adk.models import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    captured=[]
    class MockModel(BaseLlm):
        async def generate_content_async(self,llm_request,stream=False):
            captured.append(llm_request.model_dump(mode='json'))
            yield LlmResponse(content=types.Content(role='model',parts=[types.Part(text='Checked answer.')]))
    monkeypatch.setattr('agents.agent_factory.AgentFactory.build',lambda factory:Agent(name='mock_agent',model=MockModel(model='mock'),instruction='Reply.'))
    monkeypatch.setattr('tools.tool_registry.ToolRegistry.validate_available',AsyncMock())
    chat=Chat(store)
    conversation=chat.create()
    async def send(text):
        queue=chat.start(conversation['id'],text)
        while True:
            item=await queue.get()
            assert item['type']!='error',item
            if item['type']=='done':break
    try:
        await send('Original public context')
        settings=load_settings(store.root);settings.monthly_token_limit=2000000
        store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
        await send('Continue after changing the allowance')
        assert 'Original public context' in json.dumps(captured[-1])
        saved=chat.reset_context(conversation['id'])
        await send('New context only')
        assert 'Original public context' not in json.dumps(captured[-1])
        assert 'New context only' in json.dumps(captured[-1])
        assert chat.get(conversation['id'])['messages'][0]['text']=='Original public context'
        # Both internal sessions are removed when the user deletes the chat.
        await chat.delete(conversation['id'])
        for session_id in [conversation['id'],saved['session_id']]:
            assert await chat.sessions.get_session(app_name='non_profit_agents',user_id='local',session_id=session_id) is None
    finally:
        await chat.close()


@pytest.mark.asyncio
async def test_context_reset_cannot_race_an_active_turn(store):
    async def slow(conversation,prompt):
        yield {'type':'activity','label':'Working'}
        await asyncio.Event().wait()
    chat=Chat(store,backend=slow)
    conversation=chat.create()
    queue=chat.start(conversation['id'],'Work on a public draft')
    await queue.get()
    try:
        from control_panel.store import Conflict
        with pytest.raises(Conflict):chat.reset_context(conversation['id'])
        assert chat.get(conversation['id'])['context_after']==0
    finally:
        await chat.close()


@pytest.mark.asyncio
async def test_reset_revokes_old_credentials_and_pending_approvals(store):
    from guardrails.policy import ToolRule
    chat=Chat(store)
    conversation=chat.create()
    runtime=chat.guardrails
    run=runtime.start_run(conversation['id'],conversation['team'])
    token=runtime.issue(run,conversation['agent'],'tools')
    identity=runtime.authenticate(token,'tools')
    action=asyncio.create_task(runtime.approval(identity,'publish',{'text':'Public draft'},ToolRule(classification='publish',schema_hash='test',input_schema={'type':'object'}),runtime.policy().revision,{'tool':'publish'}))
    try:
        for _ in range(50):
            if runtime.summary()['approvals']:break
            await asyncio.sleep(.01)
        approval=runtime.summary()['approvals'][0]['id']
        chat.reset_context(conversation['id'])
        with pytest.raises(PolicyDenied):runtime.authenticate(token,'tools')
        with pytest.raises(PolicyDenied):await asyncio.wait_for(action,2)
        with pytest.raises(PolicyDenied):runtime.decide_approval(approval,True)
    finally:
        if not action.done():
            action.cancel()
            await asyncio.gather(action,return_exceptions=True)
        await chat.close()
