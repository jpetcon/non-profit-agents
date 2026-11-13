import json
from pathlib import Path
import stat

import pytest
from dotenv import dotenv_values

from control_panel.store import Conflict, atomic_write


def test_roundtrip_conflict_and_backups(store):
    original = store.agents()
    revision = store.revision()
    with store.edit(revision):
        validated = store.validate_agents(original)
        store.save(store.agents_path, validated)
    assert store.agents() == validated
    assert list((store.local / 'backups').iterdir())
    with pytest.raises(Conflict):
        with store.edit(revision): pass
    assert store.validate_agents(original)['root'] == 'coordinator'


@pytest.mark.parametrize('change', ['cycle','missing','duplicate','unreachable','model','tool'])
def test_invalid_hierarchies(store, change):
    data = store.agents()
    if change == 'cycle': data['agents']['strategy_agent']['sub_agents'] = ['coordinator']
    if change == 'missing': data['agents']['coordinator']['sub_agents'].append('ghost')
    if change == 'duplicate': data['agents']['strategy_agent']['sub_agents'] = ['influencer_search_agent']
    if change == 'unreachable': data['agents']['coordinator']['sub_agents'] = ['strategy_agent']
    if change == 'model': data['agents']['strategy_agent']['models'] = ['ghost']
    if change == 'tool': data['agents']['strategy_agent']['tools'] = ['ghost']
    with pytest.raises(ValueError): store.validate_agents(data)


def test_atomic_write_failure_preserves_original(tmp_path, monkeypatch):
    path = tmp_path / 'data.yml'
    path.write_text('original')
    monkeypatch.setattr('os.replace', lambda *args: (_ for _ in ()).throw(OSError('disk unavailable')))
    with pytest.raises(OSError): atomic_write(path, 'new')
    assert path.read_text() == 'original'
    assert list(tmp_path.iterdir()) == [path]


def test_external_edit_during_form_save_is_rejected(store):
    config=store.agents()
    with store.edit(store.revision()):
        store.agents_path.write_text(store.agents_path.read_text()+'\n# external change\n')
        with pytest.raises(Conflict):store.save(store.agents_path,config)
    assert '# external change' in store.agents_path.read_text()


def test_secret_roundtrip_preserves_unrelated_lines(store):
    value = "spaces ' quotes \\ and\nnewlines $(literal) `literal`"
    store.write_secrets({'SPECIAL_KEY':value})
    assert store.secret('SPECIAL_KEY') == value
    assert '# unrelated comment' in store.env_path.read_text()
    assert store.secret('BRAVE_API_KEY') == 'private-brave-test-key'
    assert stat.S_IMODE(store.env_path.stat().st_mode) == 0o600
    assert value not in json.dumps(store.secret_metadata())
    assert store.redact('private-provider-test-key and Bearer abcdefgh') == '[REDACTED] and Bearer [REDACTED]'
    store.write_secrets({'SPECIAL_KEY':None})
    assert 'SPECIAL_KEY' not in store.values()
    for name in ['PATH','PYTHONPATH','LD_PRELOAD','DYLD_INSERT_LIBRARIES']:
        with pytest.raises(ValueError): store.write_secrets({name:'unsafe'})


def test_agents_crud_reference_protection(client):
    state = client.get('/api/state').json()
    spec = {'display_name':'Campaign helper','instruction':'Help with campaigns.','models':['fast'],'tools':['get_strategy']}
    result = client.post('/api/agents', json={'revision':state['revision'],'agent':spec,'parent':'coordinator'})
    assert result.status_code == 200, result.text
    name = result.json()['name']
    assert name == 'campaign_helper'
    data = client.get('/api/state').json()
    assert name in data['agents']['agents']['coordinator']['sub_agents']
    spec['display_name'] = 'Campaign teammate'
    result = client.put('/api/agents/'+name,json={'revision':data['revision'],'agent':spec,'parent':'strategy_agent'})
    assert result.status_code == 200
    stale = client.request('DELETE','/api/agents/'+name,json={'revision':data['revision']})
    assert stale.status_code == 409
    data=client.get('/api/state').json()
    assert client.request('DELETE','/api/agents/strategy_agent',json={'revision':data['revision']}).status_code == 400
    assert client.request('DELETE','/api/agents/coordinator',json={'revision':data['revision']}).status_code == 400
    assert client.request('DELETE','/api/agents/'+name,json={'revision':data['revision']}).status_code == 200


def test_brand_live_reads(client, store, monkeypatch):
    from tools.custom_tools.master_brand import get_strategy, get_brand_profile, get_target_audience, get_brand_voice
    monkeypatch.setenv('MASTERBRAND_PATH', str(store.brand_path))
    state=client.get('/api/state').json()
    brand=state['brand']
    assert 'not been configured' in get_brand_voice()
    strategy=brand['strategy']
    brand.update(organisation_name='Kind Futures',mission='Help children thrive.',values=['Care','Evidence'],target_audience='Parents',brand_voice='Warm and clear')
    result=client.put('/api/masterbrand',json={'revision':state['revision'],'brand':brand})
    assert result.status_code==200
    assert get_strategy()==strategy
    assert get_brand_profile()['organisation_name']=='Kind Futures'
    assert get_target_audience()=='Parents'
    assert get_brand_voice()=='Warm and clear'
