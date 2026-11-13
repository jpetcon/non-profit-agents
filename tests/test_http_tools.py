import json
import httpx
import pytest

from tools.definitions import HTTPToolSpec, MCPSpec
from tools.http_tools import HTTPTool


@pytest.mark.asyncio
async def test_mapping_secret_header_and_redacted_result():
    async def upstream(request):
        assert request.url.path == '/people/A B'
        assert request.url.params['active'] == 'true'
        assert request.url.params['fixed'] == 'yes'
        assert json.loads(request.content) == {'limit':3}
        assert request.headers['Authorization'] == 'Bearer a-private-token'
        return httpx.Response(200,json={'token':'a-private-token','count':3})
    spec=HTTPToolSpec(display_name='Lookup',description='Look up a person',method='POST',url='https://example.org/people/{id}?fixed=yes',inputs=[{'name':'id','location':'path'},{'name':'active','location':'query','type':'boolean'},{'name':'limit','location':'body','type':'integer'}],headers=[{'name':'Authorization','secret':'API_KEY','prefix':'Bearer '}])
    tool=HTTPTool('lookup',spec,secret_resolver=lambda name:'a-private-token',transport=httpx.MockTransport(upstream))
    assert await tool.execute({'id':'A B','active':True,'limit':3}) == {'token':'[REDACTED]','count':3}
    with pytest.raises(ValueError): await tool.execute({'id':'..','active':True,'limit':3})
    with pytest.raises(ValueError): await tool.execute({'id':'a','active':True,'limit':'wrong'})


@pytest.mark.asyncio
@pytest.mark.parametrize('failure',['timeout','large','status','connection','redirect'])
async def test_bounded_errors(failure):
    async def upstream(request):
        if failure=='timeout': raise httpx.ReadTimeout('token in error')
        if failure=='connection': raise httpx.ConnectError('token in error')
        if failure=='large': return httpx.Response(200,content=b'x'*(HTTPTool.MAX_BYTES+1))
        return httpx.Response(302 if failure=='redirect' else 403,text='upstream private token')
    tool=HTTPTool('test',HTTPToolSpec(description='test',url='https://example.org'),transport=httpx.MockTransport(upstream))
    with pytest.raises(ValueError) as error: await tool.execute({})
    assert 'private token' not in str(error.value)


def test_definition_constraints_and_literal_arguments():
    for spec in [dict(url='ftp://example.org'),dict(url='https://user:password@example.org'),dict(url='https://{host}/'),dict(url='https://example.org/{id}'),dict(url='http://example.org',headers=[{'name':'Authorization','secret':'API_KEY'}])]:
        with pytest.raises(ValueError): HTTPToolSpec(description='test',**spec)
    spec=MCPSpec(transport='stdio',command='npx',args=['$(touch /tmp/never)','argument with spaces','`id`'])
    from tools.gateway import mcp_transport
    transport=mcp_transport(spec.model_dump())
    assert transport.args == spec.args


@pytest.mark.asyncio
@pytest.mark.parametrize('content,content_type', [
    (b'private upstream bytes', 'application/octet-stream'),
    (b'{"value":1,"value":2}', 'application/json'),
    (b'{"value":NaN}', 'application/json'),
    (b'\xff', 'text/plain'),
])
async def test_invalid_results_fail_without_reflecting_content(content, content_type):
    async def upstream(request):
        return httpx.Response(200,content=content,headers={'content-type':content_type})
    tool=HTTPTool('test',HTTPToolSpec(description='Test',url='https://example.org'),transport=httpx.MockTransport(upstream))
    with pytest.raises(ValueError) as error:
        await tool.execute({})
    assert 'private upstream' not in str(error.value) and 'NaN' not in str(error.value)


@pytest.mark.asyncio
async def test_fake_mcp_gateway_namespacing_and_http_schema(store, monkeypatch, guarded_gateway):
    from fastmcp import Client, FastMCP
    from tools.gateway import build_gateway
    remote=FastMCP('fake remote')
    @remote.tool
    def search(query: str) -> str: return 'Found '+query
    monkeypatch.setattr('tools.gateway.mcp_transport',lambda spec,**kwargs:remote)
    config=store.tools()
    config['http_tools']['lookup']={'description':'Example API','url':'https://example.org','inputs':[{'name':'term','location':'query'}]}
    store.save(store.tools_path,config)
    gateway=await guarded_gateway(['get_strategy','get_brand_profile','get_target_audience','get_brand_voice','brave_search','lookup'])
    async with Client(gateway) as client:
        found={tool.name:tool for tool in await client.list_tools()}
        assert {'get_strategy','get_brand_profile','get_target_audience','get_brand_voice','brave_search','lookup'} <= set(found)
        assert found['lookup'].input_schema['properties']['term']['type']=='string'
        result=await client.call_tool('brave_search',{'query':'charity'})
        assert 'Found charity' in str(result)
