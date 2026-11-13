import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from control_panel.chat import Chat
from control_panel.security import safe_markdown
from control_panel.store import Conflict


def test_large_payload_redaction_takes_one_secret_snapshot(store,monkeypatch):
    from unittest.mock import Mock
    values=Mock(wraps=store.values)
    references=Mock(wraps=store.secret_references)
    monkeypatch.setattr(store,'values',values)
    monkeypatch.setattr(store,'secret_references',references)
    payload={'tools':[{'description':'private-provider-test-key','value':'Bearer scoped-secret','number':1,'unset':None} for _ in range(1500)]}
    clean=store.redact(payload)
    assert values.call_count==1 and references.call_count==1
    assert 'private-provider-test-key' not in str(clean) and 'scoped-secret' not in str(clean)
    assert clean['tools'][0]['number']==1 and clean['tools'][0]['unset'] is None


def test_pairing_authentication_origin_and_csrf(app):
    with TestClient(app,base_url='http://127.0.0.1:8080') as client:
        assert client.get('/api/state').status_code==401
        assert client.get('/api/state',headers={'Host':'evil.example'}).status_code==403
        assert client.post('/api/pair',json={'token':'browser-pair-test'},headers={'Origin':'https://evil.example'}).status_code==403
        result=client.post('/api/pair',json={'token':'browser-pair-test'})
        assert result.status_code==200
        assert 'HttpOnly' in result.headers['set-cookie'] and 'SameSite=strict' in result.headers['set-cookie']
        assert client.post('/api/pair',json={'token':'browser-pair-test'}).status_code==400
        assert client.get('/api/state').status_code==200
        assert client.post('/api/chat/cancel',json={}).status_code==403
        csrf=result.json()['csrf']
        assert client.post('/api/chat/cancel',json={},headers={'X-CSRF-Token':csrf,'Origin':'http://127.0.0.1:8080'}).status_code==200
        assert client.post('/api/chat/cancel',json={},headers={'X-CSRF-Token':csrf,'Sec-Fetch-Site':'cross-site'}).status_code==403
        assert "script-src 'self'" in client.get('/').headers['content-security-policy']


def test_secret_values_never_returned(client,store):
    state=client.get('/api/state').json()
    key='THIS_SECRET_MUST_NOT_ESCAPE_123'
    response=client.put('/api/secrets/CRM_API_KEY',json={'revision':state['revision'],'value':key})
    assert response.status_code==200
    for url in ['/api/state','/api/services','/api/services/tools/logs','/','/static/app.js']:
        result=client.get(url)
        assert key not in result.text
        for value in store.values().values():
            assert value not in result.text
    state=client.get('/api/state').json()
    result=client.put('/api/secrets/LITELLM_MASTER_KEY',json={'revision':state['revision'],'value':'sk-new-private-local'})
    assert result.status_code==200
    assert store.secret('LITELLM_MASTER_KEY')==store.secret('LITELLM_PROXY_API_KEY')=='sk-new-private-local'
    result=client.request('DELETE','/api/secrets/BRAVE_API_KEY',json={'revision':store.revision()})
    assert result.status_code==400
    assert 'private-brave-test-key' not in result.text
    # Validation never echoes request input, including a malicious secret in a tool spec.
    result=client.post('/api/http-tools',json={'revision':store.revision(),'spec':{'display_name':'Bad','description':'bad','url':'bad','unexpected':key}})
    assert result.status_code==400 and key not in result.text


def test_markdown_is_inert():
    html=safe_markdown('<img src=x onerror=alert(1)> <script>alert(1)</script> [click](javascript:alert(1))\n\n[Source](https://example.org)')
    assert '<script' not in html and '<img' not in html and 'href="javascript:' not in html
    assert 'href="https://example.org"' in html


def test_stream_persistence_updates_and_deletion(client,store):
    conversation=client.post('/api/conversations',json={}).json()
    result=client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':'What is the strategy?'})
    assert result.status_code==200
    events=[json.loads(line[6:]) for line in result.text.splitlines() if line.startswith('data: ')]
    assert {e['type'] for e in events} >= {'activity','answer','done'}
    assert not any(e['type'] == 'delta' for e in events)
    assert '<script>' not in next(e['html'] for e in events if e['type']=='answer')
    saved=client.get('/api/conversations/'+conversation['id']).json()
    assert saved['messages'][0]['text']=='What is the strategy?'
    assert any(m['type']=='answer' for m in saved['messages'])
    config=store.agents()
    config['agents']['coordinator']['description']='Updated'
    store.save(store.agents_path,config)
    updated=client.get('/api/conversations/'+conversation['id']).json()
    assert not updated['outdated'] and updated['settings_changed']
    assert client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':'again'}).status_code==200
    assert client.request('DELETE','/api/conversations/'+conversation['id'],json={}).status_code==200
    assert client.get('/api/conversations').json()['conversations']==[]


@pytest.mark.asyncio
async def test_chat_cancellation_and_one_active_run(store):
    async def slow(conversation,prompt):
        yield {'type':'activity','label':'Started'}
        await asyncio.Event().wait()
    chat=Chat(store,slow)
    first=chat.create()
    queue=chat.start(first['id'],'Hello')
    await queue.get()
    with pytest.raises(Conflict): chat.start(first['id'],'Again')
    with pytest.raises(Conflict): await chat.delete(first['id'])
    await chat.cancel()
    assert any(m['type']=='notice' for m in chat.get(first['id'])['messages'])
    assert chat.active.done()
    await chat.close()


def test_chat_readiness_blocks_without_saving_or_dispatching(client,app):
    services=app.state.services
    conversation=client.post('/api/conversations',json={}).json()
    url='/api/conversations/'+conversation['id']
    client.portal.call(services.lock.acquire)
    try:
        assert client.get('/api/services').json()['services_busy'] is True
        assert client.get('/api/state').json()['services_busy'] is True
        assert client.post(url+'/messages',json={'message':'Keep this draft'}).status_code==409
        assert client.get(url).json()['messages']==[]
        assert app.state.chat.active is None
    finally:
        client.portal.call(services.lock.release)
    services.states['inference'].update(status='failed',detail='Port 4000 is occupied. Stop the old server.')
    result=client.post(url+'/messages',json={'message':'Keep this draft'})
    assert result.status_code==409
    assert result.json()['requirements'][0]['code']=='gateway.unverified'
    assert client.get(url).json()['messages']==[]
    services.states['inference'].update(status='running',pending=True)
    assert client.post(url+'/messages',json={'message':'Still blocked'}).status_code==409
    services.states['inference']['pending']=False
    async def settled():
        while app.state.synchronisation.pending:
            await asyncio.sleep(.01)
    client.portal.call(asyncio.wait_for,settled(),2)
    assert client.post(url+'/messages',json={'message':'Ready now'}).status_code==200
