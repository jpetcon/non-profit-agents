"""Privacy and payload regressions. Every provider/tool is local and fake."""
import json

from fastapi.testclient import TestClient
from fastmcp import Client
import httpx
import pytest

from guardrails.policy import PolicyDenied, Restrictions
from guardrails.runtime import Runtime
from inference.app import InferenceHooks, create_inference_app
from tests.test_guardrails import identity_for, setup_model, save_policy


PERSON = 'Mrs. Anne Smith, 10 Acacia Lane EC1 1AA, 07891000000, aged 45'
EXAMPLES = [
    PERSON, 'anne@example.org', '+44 (0)7891 000000', '07891 000000',
    'EC1 1AA', 'SW1A1AA', '10 Acacia Lane', 'Mrs. Anne Smith',
    'DOB: 12/04/1981',
    'anne&#64;example.org', 'anne%40example.org', 'anne\u200b@example.org',
    '０７８９１００００００',
]


@pytest.mark.parametrize('text', EXAMPLES)
def test_personal_data_is_held_locally_and_not_logged(store, text):
    runtime = Runtime(store.root)
    for output in [False, True]:
        with pytest.raises(PolicyDenied, match='data.output' if output else 'data.personal'):
            runtime.inspect({'context': [{'text': text}]}, Restrictions(), output=output)
    assert text not in runtime.path.read_bytes().decode(errors='ignore')


@pytest.mark.parametrize('value', [
    {'Full Name': 'Anne Smith'}, {'phone_number': 'extension 123'},
    {'tool': '```json\n{"Bank Account":"test"}\n```'},
    {'content': [{'type':'text','text':'anne@'}, {'type':'text','text':'example.org'}]},
    {'arguments': '{"ni_\\u006eumber":"test"}'},
    {'note': 'Sort the records: Bank account: 12345678'},
    {'note': 'AB 12 34 56 C'},
    {'note': '4111 1111 1111 1111'},
    {'note': 'Here is a record: {"full_name":"Anne Smith"}'},
])
def test_structured_encoded_and_fragmented_content_cannot_bypass_checks(store, value):
    with pytest.raises(PolicyDenied):
        Runtime(store.root).inspect(value, Restrictions())


@pytest.mark.parametrize('location', ['input','output'])
def test_unknown_provider_secrets_are_blocked_in_all_workflows(store,location):
    key='sk-proj-'+'a1b2c3d4'*5
    with pytest.raises(PolicyDenied,match='data.secret'):
        Runtime(store.root).inspect(key, Restrictions(), identity={'data_class':'sensitive'},output=location=='output')


def test_sensitive_workflow_does_not_implicitly_approve_a_destination(store):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience='inference', data_class='personal')
    calls = []
    async def provider(**kwargs):
        calls.append(kwargs)
        return {}
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        response = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+token}, json={'model':'agent-fast','messages':[{'role':'user','content':PERSON}]})
    assert response.status_code == 403 and calls == []


def test_reviewed_personal_workflow_can_use_approved_data(store):
    runtime, policy = setup_model(store)
    policy.profile['activities']['beneficiary_data'] = True
    rule = policy.models['agent-fast']
    rule.approved_data_classes = ['public', 'personal']
    rule.purpose = 'reviewed purpose'
    rule.provider_terms_reference = 'reviewed terms'
    rule.transfer_reference = 'reviewed transfer'
    save_policy(store, policy)
    token, _ = identity_for(store, runtime, audience='inference', data_class='personal')
    calls = []
    async def provider(**kwargs):
        calls.append(kwargs)
        return answer('Checked')
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result = client.post('/v1/chat/completions', headers={'Authorization':'Bearer '+token}, json={'model':'agent-fast','messages':[{'role':'user','content':PERSON}]})
    assert result.status_code == 200, result.text
    assert len(calls) == 1


@pytest.mark.parametrize('location', ['prompt', 'history', 'system', 'tool_result', 'tool_argument', 'reasoning'])
def test_gateway_scans_complete_context_before_dispatch(store, location):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience='inference')
    payload = {'model':'agent-fast','messages':[{'role':'user','content':'Help me sign up'}]}
    call = {'id':'call_1','type':'function','function':{'name':'get_strategy','arguments':'{}'}}
    if location == 'prompt': payload['messages'][0]['content'] = PERSON
    elif location == 'history': payload['messages'] = [{'role':'user','content':PERSON},{'role':'assistant','content':'What next?'},*payload['messages']]
    elif location == 'system': payload['messages'].insert(0, {'role':'system','content':PERSON})
    elif location in {'tool_result','tool_argument'}:
        if location == 'tool_argument':
            payload['tools'] = [{'type':'function','function':{'name':'get_strategy','parameters':{'type':'object','properties':{'query':{'type':'string'}}}}}]
            call['function']['arguments'] = json.dumps({'query':PERSON})
        payload['messages'] += [{'role':'assistant','content':None,'tool_calls':[call]}, {'role':'tool','tool_call_id':'call_1','content':PERSON if location == 'tool_result' else 'public'}]
    else: payload['messages'] += [{'role':'assistant','content':'Thinking','reasoning_content':PERSON},{'role':'user','content':'Continue'}]
    calls = []
    async def provider(**kwargs): calls.append(kwargs); return answer('Checked')
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result = client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json=payload)
    assert result.status_code == 403 and result.json()['error']['code'] == 'data.personal', result.text
    assert not calls


def answer(content):
    return {'id':'test','choices':[{'index':0,'message':{'role':'assistant','content':content},'finish_reason':'stop'}],'usage':{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}}


@pytest.mark.parametrize('stream', [False, True])
@pytest.mark.parametrize('location', ['content', 'tool_arguments', 'reasoning', 'metadata'])
def test_rejected_output_never_reaches_client(store, stream, location):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience='inference')
    response = answer('safe')
    payload = {'model':'agent-fast','messages':[{'role':'user','content':'hello'}],'stream':stream}
    message = response['choices'][0]['message']
    if location == 'content': message['content'] = PERSON
    elif location == 'reasoning': message['reasoning_content'] = PERSON
    elif location == 'metadata': response['provider_metadata'] = {'note':PERSON}
    else:
        payload['tools'] = [{'type':'function','function':{'name':'lookup','parameters':{'type':'object','properties':{'query':{'type':'string'}},'required':['query']}}}]
        message['tool_calls'] = [{'id':'1','type':'function','function':{'name':'lookup','arguments':json.dumps({'query':PERSON})}}]
        response['choices'][0]['finish_reason'] = 'tool_calls'
    async def provider(**kwargs): return response
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result = client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json=payload)
    assert result.status_code == 403 and 'Anne' not in result.text and not result.text.startswith('data: '), result.text
    assert runtime.summary()['usage']['today']['reported_tokens'] == 15


@pytest.mark.parametrize('fragment', ['078910', 'anne@', 'private-provider-'])
def test_real_stream_fragments_are_assembled_before_validation(store, monkeypatch, fragment):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience='inference')
    tail = {'078910':'00000','anne@':'example.org','private-provider-':'test-key'}[fragment]
    frames = [{'id':'test','object':'chat.completion.chunk','created':1,'model':'test','choices':[{'index':0,'delta':delta,'finish_reason':finish}]} for delta,finish in [({'role':'assistant','content':fragment},None),({'content':tail},None),({},'stop')]]
    body = ''.join('data: '+json.dumps(f)+'\n\n' for f in frames)+'data: [DONE]\n\n'
    async def fake(request): return httpx.Response(200,content=body,headers={'content-type':'text/event-stream'})
    monkeypatch.setattr('inference.app.transport_for',lambda *args,**kwargs:httpx.MockTransport(fake))
    with TestClient(create_inference_app(store.root)) as client:
        result = client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}],'stream':True})
    assert result.status_code == 403 and fragment not in result.text


@pytest.mark.parametrize('changes', [
    {'tools':{}}, {'tools':[1]}, {'model':[]}, {'temperature':True}, {'top_p':2},
    {'stream':'false'}, {'parallel_tool_calls':1}, {'stream_options':{'raw':True}},
    {'stop':[1]}, {'seed':False}, {'max_tokens':True}, {'max_tokens':2,'max_completion_tokens':3},
    {'tool_choice':{'type':'function','function':{'name':'unknown'}}},
    {'messages':[{'role':'user','content':'hello','tool_calls':[]}]},
    {'messages':[{'role':'tool','content':'result','tool_call_id':'unknown'}]},
    {'messages':[{'role':'user','content':None}]},
    {'response_format':{'type':'json_schema','json_schema':{'name':'test'}}},
    {'response_format':{'type':'text','json_schema':{}}},
])
def test_invalid_input_never_dispatches(store, changes):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience='inference')
    calls=[]
    async def provider(**kwargs): calls.append(kwargs); return answer('safe')
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}],**changes})
    assert result.status_code == 403 and not calls, result.text


@pytest.mark.parametrize('raw,content_type', [
    ('{"model":"agent-fast","model":"agent-backup"}', 'application/json'),
    ('{"model":"agent-fast","temperature":NaN}', 'application/json'),
    ('{}', 'text/plain'),
])
def test_ambiguous_json_and_content_types_are_rejected(store, raw, content_type):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store, runtime, audience='inference')
    calls=[]
    async def provider(**kwargs): calls.append(kwargs); return answer('safe')
    with TestClient(create_inference_app(store.root, completion=provider)) as client:
        result=client.post('/v1/chat/completions',content=raw,headers={'Authorization':'Bearer '+token,'Content-Type':content_type})
    assert result.status_code == 403 and not calls


def test_structured_response_is_revalidated_after_redaction(store):
    runtime, _ = setup_model(store)
    _, identity = identity_for(store, runtime, audience='inference')
    data = {'response_format':{'type':'json_schema','json_schema':{'schema':{'type':'object','properties':{'ref':{'const':'REF1234'}},'required':['ref']}}}}
    with pytest.raises(PolicyDenied, match='inference.output_schema'):
        InferenceHooks(runtime).response(identity, answer('{"ref":"REF1234"}'), data, {}, Restrictions(redact_patterns=['REF[0-9]{4}']))


@pytest.mark.parametrize('malformed', [
    {'choices':[None]}, {'choices':[{'message':[]}]},
    {'choices':[{'message':{'role':'user','content':'Rejected'},'finish_reason':'stop'}]},
    {'choices':[{'message':{'role':'assistant','content':'Rejected'},'finish_reason':None}]},
    {'choices':[{'message':{'role':'assistant','content':'Rejected','tool_calls':{}},'finish_reason':'stop'}]},
    {'choices':[{'message':{'role':'assistant','content':'Rejected','reasoning_content':{}},'finish_reason':'stop'}]},
    {'choices':[{'message':{'role':'assistant','content':'Rejected','function_call':{'name':'lookup','arguments':'{}'}},'finish_reason':'stop'}]},
    {'choices':[{'message':{'role':'assistant','content':'Rejected','audio':{'data':'unsupported'}},'finish_reason':'stop'}]},
])
def test_malformed_provider_output_is_withheld(store, malformed):
    runtime, _ = setup_model(store)
    token, _ = identity_for(store,runtime,audience='inference')
    async def provider(**kwargs): return malformed
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}]})
    assert result.status_code==403 and 'Rejected' not in result.text


def test_unvalidated_vendor_fields_are_not_forwarded_to_the_agent(store):
    runtime, _ = setup_model(store)
    _, identity=identity_for(store,runtime,audience='inference')
    response=answer('Checked')
    response['internal_route']='private routing metadata'
    response['choices'][0]['message']['provider_specific_fields']={'custom_action':'unsupported'}
    checked,_=InferenceHooks(runtime).response(identity,response,{}, {}, Restrictions())
    assert 'internal_route' not in checked and 'provider_specific_fields' not in checked['choices'][0]['message']


@pytest.mark.parametrize('arguments', ['{"value":1,"value":2}', '{"value":NaN}', '{"value":1e999}', '[]'])
def test_ambiguous_generated_arguments_never_pass_validation(store, arguments):
    call={'id':'call_1','type':'function','function':{'name':'lookup','arguments':arguments}}
    with pytest.raises(PolicyDenied,match='inference.tool_arguments'):
        InferenceHooks(Runtime(store.root)).tool_call(call,{'lookup':{'type':'object'}})


@pytest.mark.asyncio
async def test_tool_arguments_block_before_execution_and_results_are_withheld(store, guarded_gateway, monkeypatch):
    calls=[]
    def lookup(query: str) -> str:
        calls.append(query)
        return PERSON
    monkeypatch.setattr('tools.custom_tools.master_brand.get_strategy', lookup)
    gateway = await guarded_gateway(['get_strategy'])
    async with Client(gateway) as client:
        with pytest.raises(Exception): await client.call_tool('get_strategy',{'query':PERSON})
        assert calls == []
        with pytest.raises(Exception) as error: await client.call_tool('get_strategy',{'query':'public'})
        assert calls == ['public'] and 'Anne' not in str(error.value)


@pytest.mark.asyncio
async def test_chat_buffers_untrusted_fragments_and_keeps_rejected_output_out_of_history(store):
    from control_panel.chat import Chat
    async def backend(conversation,prompt):
        yield {'type':'delta','text':'anne@'}
        yield {'type':'delta','text':'example.org'}
    chat=Chat(store,backend=backend)
    conversation=chat.create()
    queue=chat.start(conversation['id'],'hello')
    events=[]
    while True:
        event=await queue.get();events.append(event)
        if event['type']=='done': break
    await chat.close()
    assert not any(e['type'] in {'delta','answer'} for e in events)
    assert 'anne@' not in json.dumps(chat.get(conversation['id'])['messages'])
    assert next(e for e in events if e['type']=='error')['issue']['code']=='data.output'


def test_chat_holds_draft_with_a_local_fix_and_no_persistence(client, app):
    calls=[]
    async def backend(conversation,prompt):
        calls.append(True)
        yield {'type':'answer','text':'safe'}
    app.state.chat.backend=backend
    conversation=client.post('/api/conversations',json={}).json()
    result=client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':PERSON})
    assert result.status_code == 400 and result.json()['issue']['code']=='data.personal'
    assert calls == [] and app.state.chat.get(conversation['id'])['messages']==[]
    card=client.get('/api/chat/requirements',params={'conversation':conversation['id'],'problem':'data.personal'}).json()
    assert card['requirements'][0]['actions'][0]['kind']=='sanitise'
    draft=client.post('/api/chat/sanitise',json={'message':PERSON}).json()['draft']
    for detail in ['Anne','Acacia','EC1','07891']: assert detail not in draft
    assert calls == [] and app.state.chat.get(conversation['id'])['messages']==[]


def test_clean_draft_cannot_resend_restricted_old_history(client,app):
    conversation=client.post('/api/conversations',json={}).json()
    app.state.chat.append(conversation['id'],{'type':'user','text':PERSON})
    result=client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':'Try again without personal details'})
    assert result.status_code==400 and result.json()['issue']['code']=='data.history'
    assert len(app.state.chat.get(conversation['id'])['messages'])==1


@pytest.mark.asyncio
async def test_local_mcp_client_rejects_foreign_requests_and_does_not_follow_redirects():
    import httpx2
    from guardrails.client import local_mcp_client_factory
    sent=[]
    async def upstream(request):
        sent.append(str(request.url))
        return httpx2.Response(307,headers={'location':'https://external.example/mcp'})
    factory=local_mcp_client_factory('http://127.0.0.1:9000/mcp')
    async with factory(headers={'Authorization':'Bearer local-test-token'},transport=httpx2.MockTransport(upstream)) as client:
        with pytest.raises(PolicyDenied): await client.get('https://external.example/mcp')
        with pytest.raises(PolicyDenied): await client.get('http://127.0.0.1:9001/mcp')
        with pytest.raises(PolicyDenied): await client.get('http://127.0.0.1:9000/unapproved')
        assert sent==[]
        result=await client.post('http://127.0.0.1:9000/mcp',json={})
        assert result.status_code==307 and len(sent)==1
