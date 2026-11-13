"""Fixed-width MCP/ADK schema compatibility without external calls."""
from copy import deepcopy
import json
from unittest.mock import Mock

from fastapi.testclient import TestClient
import jsonschema
import pytest

from guardrails.policy import Policy, ToolRule, check_pattern, check_schema
from inference.app import create_inference_app
from tests.test_guardrails import identity_for, setup_model
from tests.test_validation import answer


FRESHNESS = r'^\d{4}-\d{2}-\d{2}to\d{4}-\d{2}-\d{2}$'
# The date-range constraint shipped by the pinned Brave MCP connection.
BRAVE_SCHEMA = {
    '$schema':'http://json-schema.org/draft-07/schema#',
    'type':'object',
    'properties':{
        'query':{'type':'string'},
        'freshness':{'anyOf':[{'type':'string','enum':['pd','pw','pm','py']},{'type':'string','pattern':FRESHNESS}]},
    },
    'required':['query'],
}


@pytest.mark.parametrize('pattern', [FRESHNESS, r'^\d{4}-\d{2}-\d{2}$', r'\w{8}', r'\s{2}', r'\D{3}', r'\S{2}', r'\W{1}', r'[\d]{4}'])
def test_fixed_width_character_shorthands_are_safe(pattern):
    check_pattern(pattern)
    check_schema({'type':'string','pattern':pattern})


@pytest.mark.parametrize('pattern', [r'(\d+)+$', r'\d*', r'\w+', r'\d{1,8}', r'(\d)\1', r'\1', r'\d(?=x)', r'(a|b)', r'\\d', r'\d{100000}', r'\d\x61'])
def test_unsafe_or_unsupported_regex_constructs_still_fail_closed(pattern):
    with pytest.raises(ValueError):check_pattern(pattern)


def test_tool_policy_roundtrip_preserves_brave_date_constraints():
    original=deepcopy(BRAVE_SCHEMA)
    policy=Policy(tools={'search':ToolRule(classification='read',schema_hash='test',input_schema=original)})
    restored=Policy.model_validate(policy.model_dump(mode='json'))
    assert restored.tools['search'].input_schema==BRAVE_SCHEMA
    jsonschema.validate({'query':'public charity news','freshness':'2026-10-01to2026-11-01'},restored.tools['search'].input_schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate({'query':'public charity news','freshness':'yesterday'},restored.tools['search'].input_schema)


def adk_tool():
    from google.adk.tools.mcp_tool.mcp_tool import McpTool
    from google.adk.models.lite_llm import _function_declaration_to_tool_param
    from mcp.types import Tool
    tool=McpTool(mcp_tool=Tool(name='brave_brave_news_search',description='Search public charity news',inputSchema=deepcopy(BRAVE_SCHEMA)),mcp_session_manager=Mock())
    # Use the shipped MCP-to-ADK-to-LiteLLM conversion. No permissive mock of
    # the function schema hides compatibility failures at the gateway boundary.
    return _function_declaration_to_tool_param(tool._get_declaration())


def test_real_adk_mcp_tool_definition_passes_the_inference_gateway(store):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    calls=[]
    async def provider(**kwargs):calls.append(kwargs);return answer('Checked public request')
    definition=adk_tool()
    assert definition['function']['parameters']['properties']['freshness']['anyOf'][1]['pattern']==FRESHNESS
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'Find public charity news'}],'tools':[definition]})
    assert result.status_code==200, result.text
    assert len(calls)==1 and calls[0]['tools']==[definition]


def test_invalid_generated_date_range_is_still_withheld(store):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    response=answer(None)
    response['choices'][0]['finish_reason']='tool_calls'
    response['choices'][0]['message']['tool_calls']=[{'id':'1','type':'function','function':{'name':'brave_brave_news_search','arguments':json.dumps({'query':'public news','freshness':'yesterday'})}}]
    async def provider(**kwargs):return response
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'Find public news'}],'tools':[adk_tool()]})
    assert result.status_code==403 and result.json()['error']['code']=='inference.tool_arguments'


def test_unsupported_tool_schema_has_a_safe_specific_error_and_no_dispatch(store):
    runtime,_=setup_model(store)
    token,_=identity_for(store,runtime,audience='inference')
    calls=[]
    async def provider(**kwargs):calls.append(True);return answer('Unused')
    definition=adk_tool()
    definition['function']['parameters']['properties']['query']['pattern']='(a+)+$'
    with TestClient(create_inference_app(store.root,completion=provider)) as client:
        result=client.post('/v1/chat/completions',headers={'Authorization':'Bearer '+token},json={'model':'agent-fast','messages':[{'role':'user','content':'hello'}],'tools':[definition]})
    assert result.status_code==403 and result.json()['error']['code']=='inference.tool_schema'
    assert calls==[] and '(a+)+$' not in result.text


def test_tool_schema_error_can_be_explained_inside_chat(client):
    result=client.get('/api/chat/requirements',params={'problem':'inference.tool_schema'}).json()
    problem=result['requirements'][0]
    assert problem['code']=='inference.tool_schema'
    assert problem['title']=='A connected tool needs attention'
    assert problem['actions'][0]['kind']=='discover'
