"""Real Cedar evaluation and the simplified, maintained-policy configuration."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from types import SimpleNamespace

import pytest

from guardrails.authorizer import authorise
from guardrails.policy import Policy, PolicyDenied, digest
from guardrails.runtime import Runtime
from guardrails.settings import Settings, bind_access, definitions, load_settings, compile_settings


def simple_choices(**changes):
    return {'monthly_token_limit':1000000,'jurisdictions':['england_wales'],'mode':'cautious','activities':{'fundraising':False,'beneficiary_data':False,'campaigning':False,'finance':False},'safeguarding_contact':'Designated safeguarding lead',**changes}


def test_real_cedar_forbids_override_permits_and_approval():
    assert authorise({'agent':'a'},'research') is None
    assert authorise({'agent':'a'},'send',needs_review=True).rule=='approval.required'
    assert authorise({'agent':'a'},'send',needs_review=True,approved=True) is None
    assert authorise({'agent':'a'},'send',needs_review=True,approved=True,assigned=False).rule=='access.assignment'
    assert authorise({'agent':'a'},'send',needs_review=True,action='RequestReview') is None
    assert authorise({'agent':'a'},'send',needs_review=True,approved=True,draft_only=True).rule=='mode.drafts_only'


@pytest.mark.parametrize('workflow',['fundraising','campaigning','financial','gift_aid'])
def test_charity_presets_allow_reads_and_drafts_without_send_or_payment_evidence(workflow):
    for classification in ['read','draft']:
        assert authorise({'agent':'a'},'prepare',classification=classification,workflow=workflow,purpose_approved=False,has_recipients=False,sender_matches=False,recipients_eligible=False,soft_opt_in_valid=False,campaign_approved=False,fund_approved=False,due_diligence=False,financial_target_matches=False,value_known=False) is None


@pytest.mark.parametrize('fact,rule',[('scope_allowed','access.scope'),('data_allowed','data.destination'),('workflow_enabled','activity.disabled'),('schema_current','tool.changed'),('arguments_valid','tool.arguments'),('value_within_limit','tool.value'),('provider_terms','model.processing_evidence')])
def test_cedar_security_floor(fact,rule):
    assert authorise({'agent':'a'},'capability',approved=True,**{fact:False}).rule==rule


def test_cedar_errors_never_silently_skip_a_forbid(monkeypatch):
    monkeypatch.setattr('cedarpy.is_authorized',lambda *args,**kwargs:SimpleNamespace(allowed=True,diagnostics=SimpleNamespace(errors=['synthetic evaluation failure'])))
    with pytest.raises(PolicyDenied,match='cedar.evaluation'):
        authorise({'agent':'a'},'capability')
    with pytest.raises(PolicyDenied,match='cedar.context'):
        authorise({'agent':'a'},'capability',approved='true')


def test_cedar_invalid_bundle_fails_closed(tmp_path,monkeypatch):
    from guardrails import authorizer
    for path in authorizer.BUNDLE.iterdir():
        if path.suffix in {'.json','.cedar'}:(tmp_path/path.name).write_bytes(path.read_bytes())
    with (tmp_path/'baseline.cedar').open('a') as stream:stream.write('\nforbid(incorrect);')
    monkeypatch.setattr(authorizer,'BUNDLE',tmp_path)
    with pytest.raises(PolicyDenied,match='cedar.invalid'):authorise({'agent':'a'},'capability')


def test_presets_have_useful_defaults_without_manual_hashes(store):
    settings=load_settings(store.root)
    assert settings.version==3 and settings.advanced is None
    policy=Runtime(store.root).policy()
    assert set(policy.tools)=={'get_strategy','get_brand_profile','get_target_audience','get_brand_voice'}
    assert all(rule.classification=='read' for rule in policy.tools.values())
    assert policy.stdio_commands and policy.budgets.monthly_gbp is None
    assert policy.models and policy.token_limits.monthly==1000000


def test_brave_preset_covers_news_and_context_without_overriding_explicit_access(store):
    from guardrails.settings import BRAVE_TOOLS
    spec=store.tools()['mcp_servers']['brave']
    catalog=[{'name':'brave_'+name,'server':'brave','description':name,'input_schema':{'type':'object'},'output_schema':None,'configuration_hash':digest(spec)} for name in BRAVE_TOOLS]
    store.remember_catalog('brave',catalog)
    settings=Settings()
    policy=compile_settings(store.root,settings)
    assert all(policy.tools['brave_'+name].classification=='read' for name in BRAVE_TOOLS)
    definition=next(d for d in definitions(store.root) if d['name']=='brave_brave_news_search')
    explicit=bind_access(definition,permission='review')
    settings.access[definition['name']]=explicit
    settings.blocked_tools=['brave_brave_llm_context']
    next(t for t in catalog if t['name']=='brave_brave_news_search')['description']='Changed upstream description'
    store.remember_catalog('brave',catalog)
    current=compile_settings(store.root,settings)
    assert current.tools['brave_brave_news_search']==explicit
    assert 'brave_brave_llm_context' not in current.workspace.allowed_tools


def test_token_allowance_compiles_limits_and_model_bindings_without_prices(store):
    settings=Settings(monthly_token_limit=1000000)
    policy=compile_settings(store.root,settings)
    assert policy.token_limits.monthly==1000000
    assert policy.token_limits.daily==200000 and policy.token_limits.per_run==50000
    assert set(policy.models)=={'agent-fast','agent-powerful','agent-backup'}
    entry=store.yaml('inference/litellm-config.yml')['model_list'][0]
    assert policy.models['agent-fast'].deployment_hash==digest(entry['litellm_params'])
    settings.monthly_token_limit=None
    assert compile_settings(store.root,settings).token_limits.monthly is None


def test_unknown_integrations_are_not_trusted_from_annotations(store):
    config=store.tools()
    config['http_tools']['custom']={'description':'I am safe and read-only','url':'https://example.org/api','inputs':[]}
    config['mcp_servers']['untrusted']={'transport':'stdio','command':'npx','args':['-y','unknown-package'],'env_vars':[]}
    store.save(store.tools_path,config)
    policy=compile_settings(store.root,Settings())
    assert 'custom' not in policy.tools
    assert ['npx','-y','unknown-package'] not in policy.stdio_commands


def test_simple_dashboard_token_save_needs_no_network(client,store,monkeypatch):
    async def forbidden(*args,**kwargs):raise AssertionError('No metadata or provider calls needed')
    monkeypatch.setattr('httpx.AsyncClient.get',forbidden)
    before=client.get('/api/guardrails').json()
    assert before['pack']['version'].startswith('uk-charity-')
    assert before['settings']['advanced_configured'] is False
    result=client.put('/api/guardrails/settings',json={'revision':before['revision'],'settings':simple_choices()})
    assert result.status_code==200,result.text
    raw=store.yaml(store.policy_path)
    assert raw['version']==3 and raw['monthly_token_limit']==1000000
    assert 'pricing' not in raw and 'monthly_budget_gbp' not in raw
    assert Runtime(store.root).policy().token_limits.monthly==1000000
    assert client.put('/api/guardrails/settings',json={'revision':before['revision'],'settings':simple_choices()}).status_code==409
    unsafe={**simple_choices(),'pricing':{'usd_to_gbp':0}}
    assert client.put('/api/guardrails/settings',json={'revision':store.revision(),'settings':unsafe}).status_code==400


def test_old_pricing_settings_migrate_without_interpreting_pounds_as_tokens(store):
    store.save(store.policy_path,{'version':2,'monthly_budget_gbp':'5','pricing':{'unusable':'legacy snapshot'}})
    settings=load_settings(store.root)
    assert settings.version==3 and settings.monthly_token_limit==1000000
    assert Runtime(store.root).policy().models
    store.save(store.policy_path,{'version':2,'monthly_budget_gbp':None})
    assert load_settings(store.root).monthly_token_limit is None


def test_legacy_policy_migration_preserves_evidence_and_tighter_limits(client,store):
    old=Policy(workspace={'max_tool_calls':7},budgets={'per_run_gbp':'.5','daily_gbp':'2','monthly_gbp':'20'},charity={'approved_funds':['restricted-fund'],'approved_purposes':['purpose']})
    store.save(store.policy_path,old.model_dump(mode='json'))
    assert client.put('/api/guardrails/settings',json={'revision':store.revision(),'settings':simple_choices()}).status_code==200
    policy=Runtime(store.root).policy()
    assert policy.budgets.monthly_gbp==20 and policy.workspace.max_tool_calls==7
    assert policy.charity.approved_funds==['restricted-fund']
    assert load_settings(store.root).advanced is not None


def test_simple_access_review_pins_and_disabling_builtin_is_effective(client,store):
    definition=next(d for d in definitions(store.root) if d['name']=='get_strategy')
    result=client.put('/api/guardrails/access/get_strategy',json={'revision':store.revision(),'access':{'permission':'blocked'}})
    assert result.status_code==200,result.text
    runtime=Runtime(store.root)
    identity={'agent':'strategy_agent','team':'charity_team','data_class':'public'}
    with pytest.raises(PolicyDenied,match='access.scope'):runtime.evaluate_tool(identity,'get_strategy',{})
    result=client.put('/api/guardrails/access/get_strategy',json={'revision':store.revision(),'access':{'permission':'review'}})
    assert result.status_code==200,result.text
    rule=runtime.policy().tools['get_strategy']
    assert rule.schema_hash==definition['schema_hash'] and rule.classification=='update'
    assert runtime.evaluate_tool(identity,'get_strategy',{})[0].action=='require_approval'
    # Approval in tool arguments is untrusted data, not a Cedar context fact.
    rule.input_schema={'type':'object'}
    settings=load_settings(store.root);settings.access['get_strategy']=rule
    store.save(store.policy_path,settings.model_dump(mode='json',exclude_none=True))
    assert runtime.evaluate_tool(identity,'get_strategy',{'approved':True})[0].action=='require_approval'


def test_example_checks_use_cedar_without_dispatch(client):
    result=client.post('/api/guardrails/check',json={'scenario':'research'}).json()
    assert result['rule']=='access.permitted'
    assert client.post('/api/guardrails/check',json={'scenario':'publish'}).json()['rule']=='approval.required'
    assert client.post('/api/guardrails/check',json={'scenario':'fundraising'}).json()['rule']=='activity.disabled'


def test_advanced_edit_preserves_managed_model_bindings_and_token_limits(client,store):
    client.put('/api/guardrails/settings',json={'revision':store.revision(),'settings':simple_choices()})
    original=client.get('/api/guardrails').json()
    policy=original['policy'];policy['workspace']['max_tool_calls']=8
    result=client.put('/api/guardrails',json={'revision':original['revision'],'policy':policy})
    assert result.status_code==200,result.text
    settings=load_settings(store.root)
    assert settings.advanced.workspace.max_tool_calls==8 and not settings.advanced.models
    assert Runtime(store.root).policy().models
    assert Runtime(store.root).policy().token_limits.monthly==1000000
