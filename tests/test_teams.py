from copy import deepcopy
import json
import sqlite3

import pytest

from agents.config import AppConfig
from control_panel.chat import Chat


def create_team(client, store, name='Fundraising', default=False):
    response=client.post('/api/teams',json={'revision':store.revision(),'team':{'display_name':name,'description':'Build lasting support.'},'coordinator':{'display_name':name+' lead','instruction':'Coordinate this team.','models':['fast']},'default':default})
    assert response.status_code==200,response.text
    team=response.json()['name']
    return team,store.agents()['teams'][team]['root']


def test_legacy_config_normalizes_without_changing_disk(store):
    config=store.agents()
    legacy={'root':config['root'],'agents':config['agents']}
    store.save(store.agents_path,legacy)
    before=store.agents_path.read_bytes()
    normalized=store.agents()
    assert normalized['teams']['charity_team']['root']==legacy['root']
    assert normalized['default_team']=='charity_team'
    assert store.agents_path.read_bytes()==before


def test_create_edit_default_and_delete_teams(client,store):
    previous=store.agents()
    team,root=create_team(client,store)
    config=store.agents()
    assert config['agents'][root]['sub_agents']==[]
    assert config['teams'][team]['root']==root
    assert config['root']==previous['root']
    assert config['agents']['strategy_agent']==previous['agents']['strategy_agent']
    assert client.get('/api/teams').json()['default_team']=='charity_team'
    assert client.request('DELETE','/api/agents/'+root,json={'revision':store.revision()}).status_code==400
    result=client.put('/api/teams/'+team,json={'revision':store.revision(),'team':{'display_name':'Supporter relationships','description':'Grow support.'},'default':True})
    assert result.status_code==200
    assert store.agents()['root']==root
    assert store.agents()['default_team']==team
    conversation=client.post('/api/conversations',json={}).json()
    assert conversation['agent']==root and conversation['team']==team
    assert conversation['team_name']=='Supporter relationships'
    assert client.request('DELETE','/api/teams/'+team,json={'revision':store.revision()}).status_code==400
    result=client.request('DELETE','/api/teams/charity_team',json={'revision':store.revision()})
    assert result.status_code==200
    assert set(store.agents()['agents'])=={root}
    assert client.request('DELETE','/api/teams/'+team,json={'revision':store.revision()}).status_code==400


@pytest.mark.parametrize('replacement',[None,'missing','charity_team',[],{}])
def test_default_team_deletion_requires_valid_replacement(client,store,replacement):
    create_team(client,store)
    before=store.agents_path.read_bytes()
    result=client.request('DELETE','/api/teams/charity_team',json={'revision':store.revision(),'replacement_default':replacement})
    assert result.status_code==400
    assert 'new default' in result.json()['error']
    assert store.agents_path.read_bytes()==before


def test_delete_default_team_updates_root_and_preserves_history(client,store):
    original=store.agents()
    conversation=client.post('/api/conversations',json={}).json()
    client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':'Explain the strategy'})
    team,root=create_team(client,store)
    other,other_root=create_team(client,store,'Campaigns')
    result=client.request('DELETE','/api/teams/charity_team',json={'revision':store.revision(),'replacement_default':team})
    assert result.status_code==200,result.text
    config=store.agents()
    assert config['default_team']==team and config['root']==root
    assert set(config['teams'])=={team,other}
    assert set(config['agents'])=={root,other_root}
    assert not set(original['agents']) & set(config['agents'])
    assert client.post('/api/conversations',json={}).json()['team']==team
    saved=client.get('/api/conversations/'+conversation['id']).json()
    assert saved['team_name']=='Charity team' and saved['outdated'] and saved['messages']


def test_team_deletion_rejects_stale_and_unprotected_requests(client,store):
    revision=store.revision()
    team,_=create_team(client,store)
    before=store.agents_path.read_bytes()
    assert client.request('DELETE','/api/teams/'+team,json={'revision':revision}).status_code==409
    assert client.request('DELETE','/api/teams/'+team,json={'revision':store.revision()},headers={'X-CSRF-Token':''}).status_code==403
    assert store.agents_path.read_bytes()==before


def test_default_team_deletion_blocks_active_chat(client,store,app):
    team,_=create_team(client,store)
    conversation=client.post('/api/conversations',json={}).json()
    app.state.chat.active_id=conversation['id']
    before=store.agents_path.read_bytes()
    try:
        result=client.request('DELETE','/api/teams/charity_team',json={'revision':store.revision(),'replacement_default':team})
        assert result.status_code==409
        assert store.agents_path.read_bytes()==before
    finally:
        app.state.chat.active_id=None


def test_agents_belong_to_selected_team_and_branches_can_move(client,store):
    team,root=create_team(client,store)
    spec={'display_name':'Grant writer','description':'Writes proposals.','instruction':'Draft proposals.','models':['fast'],'tools':[]}
    result=client.post('/api/agents',json={'revision':store.revision(),'team':team,'agent':spec})
    assert result.status_code==200,result.text
    writer=result.json()['name']
    assert writer in store.agents()['agents'][root]['sub_agents']
    result=client.post('/api/agents',json={'revision':store.revision(),'team':team,'parent':'coordinator','agent':spec})
    assert result.status_code==400
    nested=client.post('/api/agents',json={'revision':store.revision(),'team':'charity_team','parent':'strategy_agent','agent':{**spec,'display_name':'Research helper'}})
    assert nested.status_code==200
    child=nested.json()['name']
    # Move a whole existing branch, preserving stable IDs and its specialists.
    config=store.agents()
    strategy=deepcopy(config['agents']['strategy_agent'])
    strategy.pop('sub_agents')
    strategy['display_name']='Strategy'
    result=client.put('/api/agents/strategy_agent',json={'revision':store.revision(),'team':team,'parent':root,'agent':strategy})
    assert result.status_code==200,result.text
    app=AppConfig.model_validate(store.agents())
    assert app.team_for_agent('strategy_agent')==team
    assert 'strategy_agent' not in app.team_members('charity_team')
    assert 'strategy_agent' in app.agents[root].sub_agents
    assert child in app.team_members(team)
    assert app.agents['strategy_agent'].sub_agents==[child]
    root_spec=app.agents[root].model_dump()
    root_spec.pop('sub_agents')
    result=client.put('/api/agents/'+root,json={'revision':store.revision(),'team':'charity_team','agent':root_spec})
    assert result.status_code==400


@pytest.mark.parametrize('change',['shared_root','cross_team_child','unreachable','cycle','missing_root','bad_default','mismatched_root'])
def test_invalid_forests_rejected(client,store,change):
    team,root=create_team(client,store)
    config=store.agents()
    if change=='shared_root':config['teams'][team]['root']='coordinator'
    if change=='cross_team_child':config['agents'][root]['sub_agents']=['strategy_agent']
    if change=='unreachable':config['agents']['coordinator']['sub_agents']=[]
    if change=='cycle':config['agents'][root]['sub_agents']=[root]
    if change=='missing_root':config['teams'][team]['root']='missing'
    if change=='bad_default':config['default_team']='missing'
    if change=='mismatched_root':config['root']=root
    with pytest.raises(ValueError):store.validate_agents(config)


def test_conversations_are_team_scoped_and_survive_team_deletion(client,store):
    original=client.post('/api/conversations',json={}).json()
    team,root=create_team(client,store)
    # Adding an unrelated team does not invalidate an existing team's chat.
    assert not client.get('/api/conversations/'+original['id']).json()['outdated']
    assert client.post('/api/conversations',json={'team':team,'agent':'strategy_agent'}).status_code==400
    assert client.post('/api/conversations',json={'team':'missing'}).status_code==400
    conversation=client.post('/api/conversations',json={'team':team}).json()
    assert conversation['agent']==root
    assert conversation['team_name']=='Fundraising'
    assert client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':'Help with a proposal'}).status_code==200
    assert client.request('DELETE','/api/teams/'+team,json={'revision':store.revision()}).status_code==200
    archived=client.get('/api/conversations/'+conversation['id']).json()
    assert archived['team_name']=='Fundraising'
    assert archived['agent_name']=='Fundraising lead'
    assert archived['outdated'] and archived['messages']
    assert any(c['id']==conversation['id'] for c in client.get('/api/conversations').json()['conversations'])
    assert not client.get('/api/conversations/'+original['id']).json()['outdated']


def test_legacy_sqlite_conversation_migration_preserves_transcript(store):
    path=store.local/'conversations.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE conversations (id TEXT PRIMARY KEY, agent TEXT, title TEXT, revision TEXT, created TEXT)')
        db.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY, conversation TEXT, payload TEXT)')
        db.execute('INSERT INTO conversations VALUES (?,?,?,?,?)',('old','coordinator','Earlier chat',store.agent_revision(),'2026-01-01'))
        db.execute('INSERT INTO messages(conversation,payload) VALUES (?,?)',('old',json.dumps({'type':'user','text':'Earlier message'})))
    chat=Chat(store)
    old=chat.get('old')
    assert old['team']=='charity_team' and old['team_name']=='Charity team'
    assert old['messages'][0]['text']=='Earlier message'
    assert not old['outdated']


def test_team_api_conflicts_and_csrf(client,store):
    revision=store.revision()
    create_team(client,store)
    assert client.post('/api/teams',json={'revision':revision,'team':{'display_name':'Stale'}}).status_code==409
    assert client.post('/api/teams',json={'revision':store.revision(),'team':{'display_name':'Unprotected'}},headers={'X-CSRF-Token':''}).status_code==403


def test_factory_builds_only_selected_team(client,store):
    from agents.agent_factory import AgentFactory
    team,root=create_team(client,store)
    class Models:
        def resolve(self,names,**kwargs):return 'mock'
    class Tools:
        def resolve(self,names,**kwargs):return []
    factory=AgentFactory(store.agents_path,Models(),Tools(),team=team)
    built=factory.build()
    assert built.name==root and built.sub_agents==[]
    default=AgentFactory(store.agents_path,Models(),Tools()).build()
    assert default.name=='coordinator'
    assert {a.name for a in default.sub_agents}=={'strategy_agent','influencer_search_agent'}
    with pytest.raises(ValueError):AgentFactory(store.agents_path,Models(),Tools(),team='missing').build()


@pytest.mark.asyncio
async def test_real_adk_runner_isolates_team_contexts(client,store,monkeypatch):
    from unittest.mock import AsyncMock
    from google.adk.models import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types
    team,root=create_team(client,store)
    instructions=[]
    class MockModel(BaseLlm):
        async def generate_content_async(self,llm_request,stream=False):
            instructions.append(str(llm_request.config.system_instruction))
            yield LlmResponse(content=types.Content(role='model',parts=[types.Part(text='Team response')]))
    monkeypatch.setattr('models.model_registry.Models.resolve',lambda *args,**kwargs:MockModel(model='mock'))
    monkeypatch.setattr('tools.tool_registry.ToolRegistry.resolve',lambda *args,**kwargs:[])
    monkeypatch.setattr('tools.tool_registry.ToolRegistry.validate_available',AsyncMock())
    chat=Chat(store)
    fundraising=chat.create(team=team)
    charity=chat.create(team='charity_team')
    try:
        first=[e async for e in chat.adk(fundraising,'Help us')]
        second=[e async for e in chat.adk(charity,'Help us')]
        assert next(e['agent'] for e in first if e['type']=='answer')==root
        assert next(e['agent'] for e in second if e['type']=='answer')=='coordinator'
        assert 'influencer_search_agent' not in instructions[0]
        assert root not in instructions[1]
        assert fundraising['id']!=charity['id']
    finally:
        await chat.close()
