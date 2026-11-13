import pytest
from unittest.mock import AsyncMock


@pytest.mark.asyncio
async def test_real_adk_runner_with_mock_model_and_sqlite(store,monkeypatch):
    from google.adk.agents import Agent
    from google.adk.models import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    from control_panel.chat import Chat

    class MockModel(BaseLlm):
        async def generate_content_async(self,llm_request,stream=False):
            yield LlmResponse(content=types.Content(role='model',parts=[types.Part(text='A response from the mocked model.')]))

    monkeypatch.setattr('agents.agent_factory.AgentFactory.build',lambda factory:Agent(name='mock_agent',model=MockModel(model='mock'),instruction='Reply.'))
    monkeypatch.setattr('tools.tool_registry.ToolRegistry.validate_available',AsyncMock())
    chat=Chat(store)
    conversation=chat.create()
    events=[event async for event in chat.adk(conversation,'Hello')]
    assert any(e['type']=='answer' and 'mocked model' in e['text'] for e in events)
    session=await chat.sessions.get_session(app_name='non_profit_agents',user_id='local',session_id=conversation['id'])
    assert session is not None and len(session.events)>=2
    events=[event async for event in chat.adk(conversation,'Again')]
    assert any(e['type']=='answer' for e in events)
    await chat.close()
    # Deleting a saved chat after app restart also removes the ADK session.
    chat=Chat(store)
    await chat.delete(conversation['id'])
    assert await chat.sessions.get_session(app_name='non_profit_agents',user_id='local',session_id=conversation['id']) is None
    await chat.close()


@pytest.mark.asyncio
async def test_real_streamed_tool_call_produces_one_persisted_activity_entry(store,monkeypatch):
    from google.adk.agents import Agent
    from google.adk.models import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    from control_panel.chat import Chat
    calls=[]
    def get_strategy() -> str:
        calls.append(True)
        return 'The charity strategy.'
    class MockModel(BaseLlm):
        async def generate_content_async(self,llm_request,stream=False):
            if not calls:
                for _ in range(5):
                    yield LlmResponse(partial=True,content=types.Content(role='model',parts=[types.Part(function_call=types.FunctionCall(id='0',name='get_strategy',will_continue=True))]))
                yield LlmResponse(content=types.Content(role='model',parts=[types.Part(function_call=types.FunctionCall(id='0',name='get_strategy',args={}))]))
            else:
                yield LlmResponse(content=types.Content(role='model',parts=[types.Part(text='The charity strategy.')]))
    monkeypatch.setattr('agents.agent_factory.AgentFactory.build',lambda factory:Agent(name='mock_agent',model=MockModel(model='mock'),instruction='Retrieve the strategy.',tools=[get_strategy]))
    monkeypatch.setattr('tools.tool_registry.ToolRegistry.validate_available',AsyncMock())
    chat=Chat(store)
    conversation=chat.create()
    try:
        queue=chat.start(conversation['id'],'Get our strategy')
        while True:
            event=await queue.get()
            if event['type']=='done':break
        assert calls==[True]
        messages=chat.get(conversation['id'])['messages']
        activity=[m['label'] for m in messages if m['type']=='activity']
        assert activity.count('Using get_strategy')==1
        assert activity.count('Finished get_strategy')==1
        assert any(m['type']=='answer' for m in messages)
    finally:
        await chat.close()
