from copy import deepcopy
import json

import pytest

from control_panel.model_management import ModelDefinition, ModelManager, PROVIDERS
from control_panel.services import Services
from control_panel.store import Conflict


def payload(provider='anthropic', **updates):
    return {'display_name':'Campaign model','provider':provider,'model':'my-chat-model','secret':PROVIDERS[provider]['secret'],'api_base':PROVIDERS[provider]['api_base'],**updates}


def test_existing_models_list_without_values_or_config_changes(client,store):
    before={p:p.read_bytes() for p in store.paths}
    result=client.get('/api/models')
    assert result.status_code==200
    data=result.json()
    assert {m['id'] for m in data['models']}=={'fast','reasoning','backup'}
    fast=next(m for m in data['models'] if m['id']=='fast')
    assert fast['provider']=='openrouter' and fast['configured']
    assert fast['secret']=='OPENROUTER_API_KEY'
    assert fast['location']=='Global · development'
    for value in store.values().values():assert value not in result.text
    assert before=={p:p.read_bytes() for p in store.paths}


@pytest.mark.parametrize('provider',list(PROVIDERS))
def test_each_provider_persists_explicit_secret_reference(store,provider):
    manager=ModelManager(store)
    spec=payload(provider,api_base='https://example.org/v1' if provider=='custom' else PROVIDERS[provider]['api_base'])
    with store.edit(store.revision()):name=manager.save(None,spec)
    saved=next(m for m in manager.list() if m['id']==name)
    assert saved['provider']==provider
    assert saved['configured'] == (provider in {'openrouter','ollama_chat'})
    params=next(e['litellm_params'] for e in store.yaml('inference/litellm-config.yml')['model_list'] if e['model_name']==saved['alias'])
    assert params['model']==PROVIDERS[provider]['prefix']+'/my-chat-model'
    if spec['secret']:
        assert params['api_key']=='os.environ/'+spec['secret']
        assert spec['secret'] in Services(store).required_secrets('inference')
    else:
        assert 'api_key' not in params


def test_change_provider_preserves_alias_assignments_and_updates_required_key(client,store):
    before=store.agents()
    result=client.put('/api/models/fast',json={'revision':store.revision(),'model':payload()})
    assert result.status_code==200, result.text
    entry=next(e for e in store.yaml('inference/litellm-config.yml')['model_list'] if e['model_name']=='agent-fast')
    assert entry['litellm_params']=={'model':'anthropic/my-chat-model','api_key':'os.environ/ANTHROPIC_API_KEY'}
    assert store.models()['fast']['model_type']=='agent-fast'
    assert store.models()['fast']['display_name']=='Campaign model'
    assert store.agents()==before
    metadata={secret['name']:secret for secret in client.get('/api/state').json()['secrets']}
    assert not metadata['ANTHROPIC_API_KEY']['configured']
    assert 'Model: agent-fast' in metadata['ANTHROPIC_API_KEY']['used_by']
    assert 'ANTHROPIC_API_KEY' in Services(store).required_secrets('inference')
    assert client.request('DELETE','/api/models/fast',json={'revision':store.revision()}).status_code==400


def test_edit_same_provider_keeps_routing_options_and_other_deployments(store):
    manager=ModelManager(store)
    original=store.yaml('inference/litellm-config.yml')
    params=original['model_list'][0]['litellm_params']
    with store.edit(store.revision()):manager.save('fast',payload('openrouter',model='publisher/new-model',secret='OPENROUTER_API_KEY'))
    updated=store.yaml('inference/litellm-config.yml')
    assert updated['model_list'][0]['litellm_params']['extra_body']==params['extra_body']
    assert updated['model_list'][1:]==original['model_list'][1:]
    assert updated['general_settings']==original['general_settings']
    assert '# Temporary development setting' in (store.root/'inference/litellm-config.yml').read_text()


def test_new_model_secrets_assignment_deletion_and_conversation_revision(client,store):
    conversation=client.post('/api/conversations',json={}).json()
    response=client.post('/api/models',json={'revision':store.revision(),'model':payload(secret='TEAM_AI_KEY')})
    assert response.status_code==200
    name=response.json()['name']
    updated=client.get('/api/conversations/'+conversation['id']).json()
    assert not updated['outdated'] and updated['settings_changed']
    key='never-return-this-model-key'
    result=client.put('/api/secrets/TEAM_AI_KEY',json={'revision':store.revision(),'value':key})
    assert result.status_code==200
    state=client.get('/api/state').json()
    assert next(m for m in state['model_catalog'] if m['id']==name)['configured']
    assert key not in json.dumps(state)
    # Managed keys cannot be removed while a model uses them.
    assert client.request('DELETE','/api/secrets/TEAM_AI_KEY',json={'revision':store.revision()}).status_code==400
    spec=store.agents()['agents']['strategy_agent']
    spec.pop('sub_agents')
    spec.update(models=[name,'backup'],display_name='Strategy specialist')
    result=client.put('/api/agents/strategy_agent',json={'revision':store.revision(),'agent':spec,'parent':'coordinator'})
    assert result.status_code==200
    assert client.request('DELETE','/api/models/'+name,json={'revision':store.revision()}).status_code==400
    spec['models']=['fast','backup']
    assert client.put('/api/agents/strategy_agent',json={'revision':store.revision(),'agent':spec,'parent':'coordinator'}).status_code==200
    assert client.request('DELETE','/api/models/'+name,json={'revision':store.revision()}).status_code==200
    assert name not in store.models()
    assert not any(e['model_name']=='agent-'+name for e in store.yaml('inference/litellm-config.yml')['model_list'])


def test_conflict_and_failed_batch_rollback_leave_both_files_unchanged(store,monkeypatch):
    manager=ModelManager(store)
    revision=store.revision()
    before={p:p.read_bytes() for p in store.paths}
    from control_panel.store import atomic_write
    failed=False
    def fail_second(path,content,**kwargs):
        nonlocal failed
        if path==store.root/'inference/litellm-config.yml' and not failed:
            failed=True
            raise OSError('Disk error')
        return atomic_write(path,content,**kwargs)
    monkeypatch.setattr('control_panel.store.atomic_write',fail_second)
    with pytest.raises(ValueError,match='restored'):
        with store.edit(revision):manager.save('fast',payload())
    assert before=={p:p.read_bytes() for p in store.paths}
    store.brand_path.write_text(store.brand_path.read_text()+'\n')
    with pytest.raises(Conflict):
        with store.edit(revision):manager.save('fast',payload())


@pytest.mark.parametrize('updates',[
    {'secret':'sk-literal-secret'}, {'secret':'LITELLM_MASTER_KEY'}, {'secret':'PATH'},
    {'api_base':'https://user:password@example.org/v1'}, {'api_base':'https://example.org/?key=secret'},
    {'api_base':'http://example.org/v1'}, {'api_base':'file:///tmp/data'},
    {'provider':'unknown'}, {'model':'bad model'}, {'secret':''},
])
def test_invalid_or_insecure_settings_rejected(updates):
    with pytest.raises(ValueError):ModelDefinition.model_validate({**payload(),**updates})


def test_local_and_custom_model_ids_and_shared_alias_deletion(store):
    manager=ModelManager(store)
    with store.edit(store.revision()):name=manager.save(None,payload('custom',api_base='http://127.0.0.1:1234/v1',model='openai/my-model'))
    entry=store.yaml('inference/litellm-config.yml')['model_list'][-1]
    assert entry['litellm_params']['model']=='openai/openai/my-model'
    # A second preference can share a deployment in advanced YAML configurations.
    registry=store.yaml('models/model_config.yml')
    registry['models']['shared']={'model_type':store.models()[name]['model_type']}
    store.save(store.root/'models/model_config.yml',registry)
    assert not next(m for m in manager.list() if m['id']==name)['editable']
    with store.edit(store.revision()):manager.delete('shared')
    assert entry in store.yaml('inference/litellm-config.yml')['model_list']


def test_model_mutation_requires_csrf(client,store):
    result=client.post('/api/models',json={'revision':store.revision(),'model':payload()},headers={'X-CSRF-Token':''})
    assert result.status_code==403
