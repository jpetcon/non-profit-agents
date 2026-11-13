import asyncio
import json

import pytest

from control_panel.issues import error_issue
from guardrails.policy import PolicyDenied


def test_chat_readiness_gives_local_fix_actions_and_no_secrets(client,store,monkeypatch):
    monkeypatch.delenv('OPENROUTER_API_KEY', raising=False)
    store.write_secrets({'OPENROUTER_API_KEY':None})
    result=client.get('/api/chat/requirements?team=charity_team').json()
    key=next(r for r in result['requirements'] if r['code']=='model.secret')
    assert key['actions'][0]['kind']=='secret' and key['actions'][0]['target']=='OPENROUTER_API_KEY'
    assert 'private-brave-test-key' not in json.dumps(result)
    conversation=client.post('/api/conversations',json={}).json()
    sent=client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':'My draft'})
    assert sent.status_code==409 and sent.json()['requirements']
    assert client.get('/api/conversations/'+conversation['id']).json()['messages']==[]


def test_old_sdk_tracebacks_are_sanitised_when_history_is_read(client,app):
    conversation=client.post('/api/conversations',json={}).json()
    app.state.chat.append(conversation['id'],{'type':'error','text':'Traceback: File "/private/user/exception_mapping_utils.py" private-provider-test-key model.unreviewed: configure prices'})
    result=client.get('/api/conversations/'+conversation['id'])
    assert 'Traceback' not in result.text and 'exception_mapping_utils' not in result.text
    assert result.json()['messages'][0]['issue']['code']=='model.unreviewed'


@pytest.mark.parametrize('error,code',[(RuntimeError('Traceback: private-provider-test-key model.unreviewed: configure prices'),'model.unreviewed'),(PolicyDenied('charity.suppression','Sensitive recipient details should never render'),'charity.suppression'),(RuntimeError('Unknown provider error containing /private/path and credentials'),'provider.failed')])
def test_provider_and_policy_errors_use_a_safe_vocabulary(error,code):
    problem=error_issue(error)
    assert problem['code']==code
    assert not any(value in json.dumps(problem) for value in ['Traceback','/private','private-provider-test-key','Sensitive recipient details'])


def test_token_setup_can_be_fixed_without_price_metadata(client,store):
    preferences=client.get('/api/guardrails').json()['settings']
    preferences={k:v for k,v in preferences.items() if k not in {'version','advanced_configured'}}
    preferences['monthly_token_limit']=None
    assert client.put('/api/guardrails/settings',json={'revision':store.revision(),'settings':preferences}).status_code==200
    requirements=client.get('/api/chat/requirements').json()['requirements']
    assert any(r['code']=='tokens.setup' and r['actions'][0]['kind']=='tokens' for r in requirements)
    preferences['monthly_token_limit']=2000000
    assert client.put('/api/guardrails/settings',json={'revision':store.revision(),'settings':preferences}).status_code==200
    assert client.get('/api/guardrails').json()['policy']['token_limits']['monthly']==2000000
