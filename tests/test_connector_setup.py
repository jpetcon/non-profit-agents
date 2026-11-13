"""Dashboard setup remains revision checked, explicit and model-free."""
import time

import pytest

from connectors.native import NativeClient
from connectors.registry import preset
from tools.mcp_auth import CredentialVault
from guardrails.settings import load_settings
from guardrails.policy import digest


def create(client,preset='web',**extra):
    result=client.post('/api/connections/setup',json={'revision':client.get('/api/state').json()['revision'],'preset':preset,**extra})
    assert result.status_code==201,result.text
    return result.json()['name']


def test_native_setup_discovery_completion_and_assignment_isolation(client,app):
    store=app.state.store
    original=store.agents()
    name=create(client)
    spec=store.tools()['mcp_servers'][name]
    assert spec['native']['capabilities']==[] and spec['native']['resources']==[]
    assert client.post(f'/api/connections/{name}/test',json={}).status_code==200
    view=client.get(f'/api/connections/{name}/setup').json()
    assert view['resources']==[{'id':'public_https','label':'Public HTTPS websites'}]
    assert view['capabilities'][0]['available'] and not view['capabilities'][0]['enabled']
    assert view['tools'][0]['permission']=='blocked'
    body={'revision':view['revision'],'configuration_hash':view['configuration_hash'],'capabilities':['pages'],'resources':['public_https'],'agents':['strategy_agent']}
    response=client.post(f'/api/connections/{name}/information/complete',json=body)
    assert response.status_code==200,response.text
    updated=store.agents()['agents']
    assert name+'_fetch_page' in updated['strategy_agent']['tools']
    for agent,detail in original['agents'].items():
        if agent!='strategy_agent':assert updated[agent]==detail
    assert set(original['agents']['strategy_agent']['tools']) <= set(updated['strategy_agent']['tools'])
    current=client.get('/api/state').json()
    normal=next(c for c in current['connections'] if c['id']==name)
    assert normal['route']=='native' and normal['reviewed']==normal['total']==1
    assert client.post(f'/api/connections/{name}/information/complete',json=body).status_code==409


def test_generated_keys_are_private_and_account_choices_are_not_client_claims(client,app,monkeypatch):
    name=create(client,'meta_ads',api_key='private-scoped-meta-token')
    store=app.state.store
    assert 'private-scoped-meta-token' not in store.tools_path.read_text()
    assert 'private-scoped-meta-token' not in client.get('/api/state').text
    assert store.secret('BRAVE_API_KEY')=='private-brave-test-key'
    calls=[]
    async def resources(self):calls.append('metadata');return [{'id':'act_123','label':'Charity adverts'}]
    monkeypatch.setattr(NativeClient,'resources',resources)
    assert client.post(f'/api/connections/{name}/test',json={}).status_code==200
    assert calls==['metadata']
    view=client.get(f'/api/connections/{name}/setup').json()
    body={'revision':view['revision'],'configuration_hash':view['configuration_hash'],'capabilities':['reports'],'resources':['act_unselected'],'agents':[]}
    assert client.post(f'/api/connections/{name}/information/complete',json=body).status_code==400
    assert store.tools()['mcp_servers'][name]['native']['resources']==[]
    body['resources']=['act_123']
    assert client.post(f'/api/connections/{name}/information/complete',json=body).status_code==200
    assert all(name+'_read_reports' not in a['tools'] for a in store.agents()['agents'].values())
    rule=app.state.chat.guardrails.policy().tools[name+'_read_reports']
    assert rule.classification=='read'
    assert 'private-scoped-meta-token' in set(app.state.chat.guardrails.secret_values())


def test_personal_capability_cannot_be_downgraded_by_generic_setup(client,app,monkeypatch):
    name=create(client,'beacon',api_key='private-beacon-token',options={'account_id':'123'})
    async def resources(self):return [{'id':'person','label':'Supporters'}]
    monkeypatch.setattr(NativeClient,'resources',resources)
    assert client.post(f'/api/connections/{name}/test',json={}).status_code==200
    view=client.get(f'/api/connections/{name}/setup').json()
    body={'revision':view['revision'],'configuration_hash':view['configuration_hash'],'reviews':{t['name']:{'schema_hash':t['schema_hash'],'permission':'read','data_class':'public','workflow':'none'} for t in view['tools']},'assignments':{}}
    assert client.post(f'/api/connections/{name}/setup/complete',json=body).status_code==400


def test_stale_and_secret_disclosing_metadata_is_withheld(client,app,monkeypatch):
    name=create(client,'meta_ads',api_key='private-scoped-token')
    async def resources(self):return [{'id':'act_123','label':'private-scoped-token'}]
    monkeypatch.setattr(NativeClient,'resources',resources)
    result=client.post(f'/api/connections/{name}/test',json={})
    assert result.status_code!=200 and 'private-scoped-token' not in result.text
    view=client.get(f'/api/connections/{name}/setup').json()
    assert view['resources']==[]


def test_administrator_registration_is_private_revision_checked_and_isolated(client,app):
    name=create(client,'sharepoint',options={'tenant':'charity.onmicrosoft.com'})
    status=client.get(f'/api/connections/{name}/auth').json()
    assert status['method']=='api_oauth' and not status['provider_setup']['configured']
    registration=client.get('/api/providers/microsoft/setup').json()
    body={'revision':registration['revision'],'client_id':'charity-client','client_secret':'private-ms-client-secret','callback_port':8766}
    response=client.put('/api/providers/microsoft/setup',json=body)
    assert response.status_code==200,response.text
    assert 'private-ms-client-secret' not in response.text
    assert client.put('/api/providers/microsoft/setup',json=body).status_code==409
    spec=app.state.store.tools()['mcp_servers'][name]
    vault=CredentialVault(app.state.store.root)
    revision,_=vault.provider('microsoft')
    handle=vault.reset(name,spec,app.state.store.secret)
    handle.change(lambda d:d.update(provider_registration_name='microsoft',provider_registration=revision,connected=True),status='connected')
    assert client.get(f'/api/connections/{name}/auth').json()['status']=='connected'
    assert client.post(f'/api/connections/{name}/auth/disconnect',json={}).status_code==200
    assert client.get('/api/providers/microsoft/setup').json()['configured']
    assert client.get(f'/api/connections/{name}/auth').json()['status']!='connected'
    response=client.request('DELETE','/api/providers/microsoft/setup',json={'revision':revision})
    assert response.status_code==200 and not response.json()['configured']


def test_setup_protection_and_disabled_capabilities(client,app):
    name=create(client)
    before=app.state.store.revision()
    assert client.post(f'/api/connections/{name}/information/complete',json={'revision':before,'configuration_hash':'forged','capabilities':['pages'],'resources':['public_https'],'agents':[]}).status_code==409
    client.headers.pop('X-CSRF-Token')
    assert client.post('/api/connections/setup',json={'revision':before,'preset':'web'}).status_code==403
    assert before==app.state.store.revision()


def test_native_disconnect_removes_only_private_account_key_and_keeps_redaction(client,app):
    name=create(client,'meta_ads',api_key='private-disconnected-meta-key')
    store=app.state.store
    reference=store.tools()['mcp_servers'][name]['native']['secret_refs']['api_key']
    result=client.post(f'/api/connections/{name}/auth/disconnect',json={})
    assert result.status_code==200,result.text
    assert not store.secret(reference)
    assert store.secret('BRAVE_API_KEY')=='private-brave-test-key'
    assert 'private-disconnected-meta-key' in set(CredentialVault(store.root).secret_values())
    assert client.get(f'/api/connections/{name}/auth').json()['status']=='not_connected'


def test_existing_agents_do_not_inherit_other_capabilities_on_same_connection(client,app,monkeypatch):
    name=create(client,'mailchimp',api_key='private-mailchimp-key',options={'datacenter':'us21'})
    async def resources(self):return [{'id':'123','label':'Charity email'}]
    monkeypatch.setattr(NativeClient,'resources',resources)
    assert client.post(f'/api/connections/{name}/test',json={}).status_code==200
    def complete(assignments):
        view=client.get(f'/api/connections/{name}/setup').json()
        return client.post(f'/api/connections/{name}/information/complete',json={'revision':view['revision'],'configuration_hash':view['configuration_hash'],'capabilities':['reports','content'],'resources':['123'],'agents':[],'assignments':assignments})
    assert complete({'strategy_agent':['reports']}).status_code==200
    assert complete({'strategy_agent':['reports']}).status_code==200
    tools=app.state.store.agents()['agents']['strategy_agent']['tools']
    assert name+'_read_reports' in tools
    assert name+'_read_content' not in tools
    assert all(name+'_read_content' not in a['tools'] for a in app.state.store.agents()['agents'].values())
    assert complete({'strategy_agent':['audiences']}).status_code==400
