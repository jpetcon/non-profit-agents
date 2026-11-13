"""Payment data stays local, including PAN/expiry/CVV pasted together."""
import json

from fastapi.testclient import TestClient
from fastmcp import Client
import httpx
import pytest

from guardrails.policy import PolicyDenied, Restrictions
from guardrails.runtime import Runtime
from guardrails.validation import card_spans, payment_spans, inspection_text, sanitise_draft
from inference.app import create_inference_app
from tests.test_guardrails import identity_for, setup_model
from tests.test_validation import answer


# Synthetic test data only. Never submit it to a payment service or real model.
PAN = '4000056655665556'
DETAILS = PAN + ' 12/29 123'
REQUEST = 'Can you go and pay for a loaf of facebook ads that target our supporters? Here are my card details ' + DETAILS
PAYMENT_EXAMPLES = [
    DETAILS,
    '4000 0566 5566 5556 12/29 123',
    '4000-0566-5566-5556 exp: 12 / 2029 CVC: 123',
    PAN + '\n12/29\n123',
    PAN + ', expiry: 12/29, CVV: 123',
    PAN + ' CVV: 123 Expiry: 12/29',
    '378282246310005 12/2029 1234',
    '4000000000000000006 12/29 123',
    'card number: 4000056655665557',  # Invalid checksum, explicit card context.
    '4000056655665557 12/29 123',     # Invalid checksum, payment-shaped group.
    '8000056655665557 12/29 123',     # Group detection does not depend on issuer.
    'CVV: 123', 'CVC2=1234', 'card expiry:12/29',
    '４００００５６６５５６６５５５６ １２／２９ １２３',
    PAN + '%2012%2F29%20123',
    PAN + '&#32;12/29&#32;123',
    PAN[:8] + '\u200b' + PAN[8:] + ' 12/29 123',
]


@pytest.mark.parametrize('pan', [PAN, '4222222222222', '378282246310005', '5555555555554444', '2223003122003222', '6011111111111117', '4000000000000000006'])
def test_card_is_still_found_when_expiry_follows(pan):
    text = pan + ' 12/29 123'
    assert (0, len(pan), 'payment_card') in card_spans(text)


@pytest.mark.parametrize('text', PAYMENT_EXAMPLES)
@pytest.mark.parametrize('data_class', ['public', 'personal', 'sensitive'])
def test_payment_details_are_blocked_and_whole_group_can_be_removed(store, text, data_class):
    runtime=Runtime(store.root)
    for output in [False, True]:
        with pytest.raises(PolicyDenied, match='data.output' if output else 'data.payment'):
            runtime.inspect(text, Restrictions(), identity={'data_class':data_class}, output=output)
    clean = sanitise_draft('Please use ' + text + '. Thank you.')
    assert clean.startswith('Please use ') and clean.endswith('. Thank you.')
    assert not any(char.isdigit() for char in clean)
    assert not payment_spans(inspection_text(clean))
    assert runtime.inspect(clean, Restrictions(), identity={'data_class':data_class})[0]==clean


@pytest.mark.parametrize('text', [
    'Our campaign runs until 12/29 and has 123 participants.',
    'Budget: 1234. Expiry date: 12/29.',
    'Explain how card details should be protected.',
    'Reference 40000566556655560000',   # Never check a truncated numeric prefix.
    'Reference 4000056655665557',       # No checksum or payment context.
])
def test_ordinary_dates_numbers_and_discussion_are_allowed(store,text):
    assert not payment_spans(text)
    assert Runtime(store.root).inspect(text,Restrictions())[0]==text


@pytest.mark.parametrize('value', [
    {'card_number':PAN,'expiry_date':'12/29','cvv':'123'},
    {'payment':{'cardNumber':'4000056655665557','expirationDate':'12/29','securityCode':'123'}},
    {'credit_card_number':PAN,'exp_month':12,'exp_year':2029,'cvc':123},
    {'PAN':PAN,'cardholder_name':'Example','expiry':'12/29','cid':'123'},
])
def test_structured_payment_fields_are_blocked_and_removed_together(store,value):
    runtime=Runtime(store.root)
    with pytest.raises(PolicyDenied,match='data.payment'):
        runtime.inspect(value,Restrictions(),identity={'data_class':'sensitive'})
    with pytest.raises(PolicyDenied,match='data.payment'):
        runtime.inspect('Record: '+json.dumps(value),Restrictions())
    clean=sanitise_draft(json.dumps(value))
    assert not any(char.isdigit() for char in clean)
    assert json.loads(clean) in ({}, {'payment':{}})


def test_removing_a_numeric_pan_preserves_valid_json(store):
    with pytest.raises(PolicyDenied,match='data.payment'):
        Runtime(store.root).inspect({'reference':int(PAN)},Restrictions())
    clean=sanitise_draft(json.dumps({'reference':int(PAN),'note':'Keep this public note'}))
    assert json.loads(clean)=={'reference':'[DETAIL REMOVED]','note':'Keep this public note'}


@pytest.mark.parametrize('location', ['prompt','history','tool_argument','tool_result'])
def test_payment_data_never_dispatches_to_a_provider(store,location):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    payload={'model':'agent-fast','messages':[{'role':'user','content':'Plan some public advertising'}]}
    if location=='prompt': payload['messages'][0]['content']=REQUEST
    elif location=='history': payload['messages']=[{'role':'user','content':REQUEST},{'role':'assistant','content':'Held here'},*payload['messages']]
    else:
        payload['tools']=[{'type':'function','function':{'name':'get_strategy','parameters':{'type':'object','properties':{'query':{'type':'string'}}}}}]
        arguments={'query':DETAILS} if location=='tool_argument' else {}
        payload['messages'] += [{'role':'assistant','content':None,'tool_calls':[{'id':'1','type':'function','function':{'name':'get_strategy','arguments':json.dumps(arguments)}}]}, {'role':'tool','tool_call_id':'1','content':DETAILS if location=='tool_result' else 'public'}]
    calls=[]
    async def provider(**kwargs): calls.append(True);return answer('Safe')
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json=payload)
    assert result.status_code==403 and result.json()['error']['code']=='data.payment'
    assert calls==[]
    assert PAN not in result.text and PAN not in runtime.path.read_bytes().decode(errors='ignore')


@pytest.mark.parametrize('stream',[False,True])
def test_payment_response_is_not_released(store,stream):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    async def provider(**kwargs):return answer(DETAILS)
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}],'stream':stream})
    assert result.status_code==403 and PAN not in result.text and '12/29' not in result.text


def test_real_provider_fragments_are_held_until_payment_group_is_checked(store,monkeypatch):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    frames=[{'id':'test','object':'chat.completion.chunk','created':1,'model':'test','choices':[{'index':0,'delta':delta,'finish_reason':finish}]} for delta,finish in [({'role':'assistant','content':PAN[:8]},None),({'content':PAN[8:]+' 12/'},None),({'content':'29 123'},None),({},'stop')]]
    body=''.join('data: '+json.dumps(f)+'\n\n' for f in frames)+'data: [DONE]\n\n'
    async def fake(request):return httpx.Response(200,content=body,headers={'content-type':'text/event-stream'})
    monkeypatch.setattr('inference.app.transport_for',lambda *args,**kwargs:httpx.MockTransport(fake))
    with TestClient(create_inference_app(store.root)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}],'stream':True})
    assert result.status_code==403 and PAN[:8] not in result.text and 'data: ' not in result.text


@pytest.mark.asyncio
async def test_tool_input_never_dispatches_and_payment_result_is_withheld(store,guarded_gateway,monkeypatch):
    calls=[]
    def lookup(query: str) -> str:
        calls.append(query)
        return DETAILS
    monkeypatch.setattr('tools.custom_tools.master_brand.get_strategy',lookup)
    gateway=await guarded_gateway(['get_strategy'])
    async with Client(gateway) as client:
        with pytest.raises(Exception):await client.call_tool('get_strategy',{'query':DETAILS})
        assert calls==[]
        with pytest.raises(Exception) as error:await client.call_tool('get_strategy',{'query':'public'})
        assert calls==['public'] and PAN not in str(error.value)


def test_chat_holds_payment_draft_and_removes_every_payment_component(client,app):
    conversation=client.post('/api/conversations',json={}).json()
    result=client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':REQUEST})
    assert result.status_code==400 and result.json()['issue']['code']=='data.payment'
    assert app.state.chat.get(conversation['id'])['messages']==[]
    cards=client.get('/api/chat/requirements',params={'conversation':conversation['id'],'problem':'data.payment'}).json()
    assert cards['requirements'][0]['actions'][0]['kind']=='sanitise'
    clean=client.post('/api/chat/sanitise',json={'message':REQUEST}).json()['draft']
    assert PAN not in clean and '12/29' not in clean and '123' not in clean
    assert app.state.chat.get(conversation['id'])['messages']==[]


def test_old_payment_details_cannot_be_resent_with_a_clean_draft(client,app):
    conversation=client.post('/api/conversations',json={}).json()
    app.state.chat.append(conversation['id'],{'type':'user','text':REQUEST})
    result=client.post('/api/conversations/'+conversation['id']+'/messages',json={'message':'Please plan public advertising'})
    assert result.status_code==400 and result.json()['issue']['code']=='data.history'
    assert len(app.state.chat.get(conversation['id'])['messages'])==1


@pytest.mark.asyncio
async def test_chat_never_releases_or_persists_payment_fragments(store):
    from control_panel.chat import Chat
    async def backend(conversation,prompt):
        for text in [PAN[:8],PAN[8:]+' 12/','29 123']:
            yield {'type':'delta','text':text}
    chat=Chat(store,backend=backend)
    conversation=chat.create()
    queue=chat.start(conversation['id'],'Plan public advertising')
    events=[]
    while True:
        event=await queue.get();events.append(event)
        if event['type']=='done':break
    await chat.close()
    assert not any(e['type'] in {'delta','answer'} for e in events)
    assert next(e for e in events if e['type']=='error')['issue']['code']=='data.output'
    saved=json.dumps(chat.get(conversation['id'])['messages'])
    assert PAN[:8] not in saved and '12/29' not in saved
