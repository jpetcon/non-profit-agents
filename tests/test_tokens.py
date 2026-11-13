import asyncio
from concurrent.futures import ThreadPoolExecutor
import sqlite3

from fastapi.testclient import TestClient
import httpx
import pytest

from guardrails.policy import PolicyDenied
from guardrails.runtime import Runtime
from inference.app import create_inference_app
from tests.test_guardrails import identity_for, setup_model, save_policy


@pytest.mark.parametrize('period',['per_run','daily','monthly'])
def test_token_denials_are_terminal_and_never_dispatch(store,period):
    runtime,policy=setup_model(store)
    setattr(policy.token_limits,period,1)
    save_policy(store,policy)
    token,_=identity_for(store,runtime,audience='inference')
    calls=[]
    async def provider(**kwargs):calls.append(kwargs);return {}
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'Hello'}]})
    assert result.status_code==403
    assert result.json()['error']['code']=='tokens.'+{'per_run':'run','daily':'day','monthly':'month'}[period]
    assert calls==[]


@pytest.mark.parametrize('usage',[None,{}, {'prompt_tokens':0,'completion_tokens':0}, {'prompt_tokens':10,'completion_tokens':-1}, {'prompt_tokens':10,'completion_tokens':True}, {'prompt_tokens':10,'completion_tokens':5,'total_tokens':4}])
def test_missing_or_invalid_usage_keeps_reservation(store,usage):
    runtime,_=setup_model(store)
    _,identity=identity_for(store,runtime,audience='inference')
    call=runtime.reserve(identity,'inference','agent-fast','request',0,runtime.policy().effective(identity),tokens=900)
    runtime.settle(call,usage=usage)
    current=Runtime(store.root).summary()['usage']['today']
    assert current['reserved_tokens']==900 and current['reported_tokens']==0


def test_narrow_agent_token_limit_cannot_be_loosened(store):
    runtime,policy=setup_model(store)
    from guardrails.policy import Restrictions
    policy.agents['strategy_agent']=Restrictions(max_tokens_per_run=20)
    save_policy(store,policy)
    _,identity=identity_for(store,runtime,audience='inference')
    with pytest.raises(PolicyDenied,match='tokens.run'):
        runtime.reserve(identity,'inference','agent-fast','request',0,policy.effective(identity),tokens=21)


def test_provider_exceeding_output_cap_is_accounted_but_not_released(store):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    calls=[]
    async def provider(**kwargs):
        calls.append(kwargs)
        return {'id':'test','choices':[{'message':{'role':'assistant','content':'Withheld oversized provider output'},'finish_reason':'stop'}],'usage':{'prompt_tokens':10,'completion_tokens':50,'total_tokens':60}}
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'Hello'}],'max_tokens':8})
    assert result.status_code==403 and result.json()['error']['code']=='inference.tokens'
    assert 'Withheld oversized provider output' not in result.text
    assert len(calls)==1 and calls[0]['max_tokens']==8
    assert runtime.summary()['usage']['today']['reported_tokens']==60


@pytest.mark.asyncio
async def test_cancellation_keeps_tokens_and_cleans_provider_work(store):
    runtime,_=setup_model(store)
    token,identity=identity_for(store,runtime,audience='inference')
    entered,closed=asyncio.Event(),asyncio.Event()
    async def provider(**kwargs):
        entered.set()
        try:await asyncio.Event().wait()
        finally:closed.set()
    app=create_inference_app(store.root,completion=provider)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://127.0.0.1') as client:
        task=asyncio.create_task(client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'Hello'}]}))
        await asyncio.wait_for(entered.wait(),2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        await asyncio.wait_for(closed.wait(),2)
    runtime.revoke(identity['run'])
    assert Runtime(store.root).summary()['usage']['today']['reserved_tokens']>0


def test_legacy_financial_ledger_migrates_without_inventing_token_usage(store):
    path=store.local/'guardrails.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE calls (id TEXT PRIMARY KEY, run TEXT, agent TEXT, kind TEXT, name TEXT, signature TEXT, created REAL, day TEXT, month TEXT, reserved INTEGER, reported INTEGER, state TEXT, price_revision TEXT)')
        db.execute("INSERT INTO calls VALUES ('legacy','run','agent','inference','model','signature',0,'old-day','old-month',12345,6789,'complete','old-prices')")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _:Runtime(store.root),range(2)))
    runtime=Runtime(store.root)
    with runtime.db() as db:
        row=db.execute("SELECT reserved,reported,reserved_tokens,reported_tokens FROM calls WHERE id='legacy'").fetchone()
    assert tuple(row)==(12345,6789,0,None)
