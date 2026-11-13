"""A truncated reply is retained safely and never presented as broken setup."""
import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from control_panel.chat import Chat
from control_panel.issues import ResponseTruncated, error_issue


@pytest.mark.asyncio
@pytest.mark.parametrize('content',['complete','fragments','empty'])
async def test_real_adk_length_limit_keeps_answer_and_allows_explicit_continuation(store,monkeypatch,content):
    from google.adk.agents import Agent
    from google.adk.models import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    calls=[]
    class Model(BaseLlm):
        async def generate_content_async(self,llm_request,stream=False):
            calls.append(llm_request.model_dump(mode='json'))
            if len(calls)>1:
                yield LlmResponse(content=types.Content(role='model',parts=[types.Part(text='The rest of the answer.')]))
                return
            if content=='fragments':
                yield LlmResponse(partial=True,content=types.Content(role='model',parts=[types.Part(text='The first part ')]))
                yield LlmResponse(partial=True,content=types.Content(role='model',parts=[types.Part(text='of the answer.')]))
            yield LlmResponse(
                content=types.Content(role='model',parts=[types.Part(text='The first part of the answer.')]) if content=='complete' else None,
                error_code=types.FinishReason.MAX_TOKENS,
                finish_reason=types.FinishReason.MAX_TOKENS,
                # SDK text is never used as the public explanation.
                error_message='Raw SDK error /private/path private-provider-test-key',
            )
    monkeypatch.setattr('agents.agent_factory.AgentFactory.build',lambda factory:Agent(name='mock_agent',model=Model(model='mock'),instruction='Reply.'))
    monkeypatch.setattr('tools.tool_registry.ToolRegistry.validate_available',AsyncMock())
    chat=Chat(store)
    conversation=chat.create()
    policy=chat.guardrails.policy()
    async def send(prompt):
        queue=chat.start(conversation['id'],prompt)
        events=[]
        while True:
            event=await asyncio.wait_for(queue.get(),10)
            events.append(event)
            if event['type']=='done':break
        await chat.active
        return events
    try:
        events=await send('Start the answer')
        assert len(calls)==1  # No retry or continuation can spend more tokens.
        assert not any(e['type']=='error' for e in events)
        notices=[e for e in events if e['type']=='notice']
        assert len(notices)==1 and notices[0]['issue']['code']=='response.truncated'
        answers=[e for e in events if e['type']=='answer']
        assert len(answers)==(0 if content=='empty' else 1)
        if answers:
            assert answers[0]['text']=='The first part of the answer.'
            assert events.index(answers[0])<events.index(notices[0])
        saved=chat.get(conversation['id'])['messages']
        assert saved[-1]==notices[0]
        for forbidden in ['Raw SDK error','/private/path','private-provider-test-key','provider.failed']:
            assert forbidden not in json.dumps(saved)
        assert chat.guardrails.policy().revision==policy.revision
        assert chat.run_id is None
        events=await send('Continue the answer')
        assert len(calls)==2
        assert any(e['type']=='answer' and e['text']=='The rest of the answer.' for e in events)
        if content=='complete':
            assert 'The first part of the answer.' in json.dumps(calls[-1])
        assert chat.get(conversation['id'])['messages'][:len(saved)]==saved
    finally:
        await chat.close()


@pytest.mark.asyncio
async def test_truncated_fragments_still_pass_output_secret_checks(store):
    async def backend(conversation,prompt):
        yield {'type':'delta','text':'private-provider-'}
        yield {'type':'delta','text':'test-key'}
        raise ResponseTruncated()
    chat=Chat(store,backend)
    conversation=chat.create()
    try:
        queue=chat.start(conversation['id'],'A public request')
        events=[]
        while True:
            event=await queue.get();events.append(event)
            if event['type']=='done':break
        await chat.active
        assert not any(e['type'] in {'answer','delta','notice'} for e in events)
        assert next(e for e in events if e['type']=='error')['issue']['code']=='data.secret'
        assert 'private-provider-test-key' not in json.dumps(chat.get(conversation['id']))
    finally:
        await chat.close()


def test_length_notice_uses_trusted_text_and_unrelated_errors_stay_errors():
    assert error_issue(ResponseTruncated('raw private data'))['code']=='response.truncated'
    assert 'raw private data' not in json.dumps(error_issue(ResponseTruncated('raw private data')))
    assert error_issue(ValueError('unrelated SDK failure'))['code']=='provider.failed'
