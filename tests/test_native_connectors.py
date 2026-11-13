"""Offline contracts, actual FastMCP dispatch and preset resource boundaries."""
import asyncio
import base64
import json
import time
from urllib.parse import parse_qs

import httpx
import httpx2
import pytest
from fastmcp import Client

from connectors.registry import catalogue, preset, REVISION, hosted_read_allowed
from connectors.native import NativeClient, operations, text_content
from connectors.auth import endpoints, access_token
from control_panel.mcp_auth import AuthenticationManager
from control_panel.connections import discover_connection
from guardrails.policy import PolicyDenied, digest
from guardrails.runtime import Runtime
from tools.definitions import MCPSpec
from tools.mcp_auth import AuthenticationRequired, CredentialVault
from tools.gateway import mcp_transport

OPTIONS={'mailchimp':{'datacenter':'us21'},'beacon':{'account_id':'123'},'vwo':{'account_id':'456'},'wordpress':{'site_url':'https://charity.org','username':'reader'},'sharepoint':{'tenant':'charity.onmicrosoft.com'},'engaging_networks':{'region':'ca'}}
KEY='private-native-api-key'


def connection(provider, resources=None):
    p=preset(provider)
    refs={'api_key':'NATIVE_KEY'} if p['authentication'] in {'key','token','session','basic'} else {'subscription_key':'NATIVE_KEY'} if p['authentication']=='blackbaud' else {}
    return MCPSpec.model_validate({'display_name':p['name'],'transport':'native','managed':{'preset':provider,'revision':REVISION},'native':{'provider':provider,'options':OPTIONS.get(provider,{}),'secret_refs':refs,'resources':resources or ['selected'],'capabilities':[c['id'] for c in p['capabilities']]}}).model_dump(exclude_none=True)


def native(store,provider,resources=None):
    spec=connection(provider,resources)
    config=store.tools();config['mcp_servers']['native']=spec;store.save(store.tools_path,config)
    store.write_secrets({'NATIVE_KEY':KEY})
    runtime=Runtime(store.root)
    vault=CredentialVault(store.root)
    handle=vault.reset('native',spec,store.secret)
    handle.change(lambda d:d.update(connected=True,api_tokens={'access_token':'private-native-access','refresh_token':'private-native-refresh','expires':time.time()+3600,'environment_id':'selected','environment_name':'Charity'}),status='connected')
    return NativeClient('native',spec,store.root,runtime.policy(),store.secret),runtime


def test_complete_catalogue_and_typed_validation():
    ids={p['id'] for p in catalogue()}
    assert {'masterbrand','google','brave','web','google_ads','meta_ads','search_console','salesforce','raisers_edge','blackbaud_crm','beacon','mailchimp','brevo','engaging_networks','wordpress_com','wordpress','contentful','meta_social','linkedin','buffer','google_drive','sharepoint','vwo','optimizely','eventbrite','remote'}==ids
    for p in catalogue():
        if p['route']=='native':
            spec=connection(p['id'])
            assert all(op['input_schema']['additionalProperties'] is False for op in operations(spec))
            assert all(not any(w in op['name'] for w in ['send','publish','mutate','delete','launch','pay']) for op in operations(spec))
    for provider,values in [('mailchimp',{'datacenter':'evil.org'}),('wordpress',{'site_url':'http://localhost','username':'reader'}),('sharepoint',{'tenant':'../common'}),('beacon',{}),('engaging_networks',{'region':'evil'})]:
        spec=connection(provider);spec['native']['options']=values
        with pytest.raises(ValueError):MCPSpec.model_validate(spec)


@pytest.mark.asyncio
@pytest.mark.parametrize('provider', [p['id'] for p in catalogue() if p['route']=='native'])
async def test_native_unknown_writes_and_unselected_resources_never_dispatch(store,provider,monkeypatch):
    client,_=native(store,provider)
    calls=[]
    async def request(*a,**k):calls.append(a);return {}
    monkeypatch.setattr(client,'request',request)
    for op,args in [('delete',{}),('execute',{'method':'POST'}),(operations(client.spec)[0]['name'],{'resource':'unselected','record_id':'42','query':'example','url':'https://charity.org'})]:
        with pytest.raises(Exception):await client.execute(op,args)
    assert calls==[]


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,operation,resource,args,path',[
 ('google_ads','read_reports','123',{},'/v26/customers/123/googleAds:search'),
 ('meta_ads','read_reports','act_123',{},'/v27.0/act_123/insights'),
 ('search_console','read_search','https://charity.org/',{},'/webmasters/v3/sites/https://charity.org//searchAnalytics/query'),
 ('raisers_edge','read_records','selected',{'record_id':'42'},'/constituent/v1/constituents/42'),
 ('blackbaud_crm','read_records','selected',{'record_id':'42'},'/crm-conmg/constituents/42/view'),
 ('beacon','read_records','person',{'record_id':'42'},'/v1/account/123/entity/person/42'),
 ('mailchimp','read_reports','123',{},'/3.0/reports'),
 ('engaging_networks','read_content','page:42',{},'/ens/service/page/42'),
 ('wordpress','read_content','https://charity.org',{},'/wp-json/wp/v2/posts'),
 ('meta_social','read_social','instagram:123',{},'/v27.0/123/media'),
 ('linkedin','read_social','urn:li:organization:123',{},'/rest/posts'),
 ('vwo','read_experiments','123',{},'/api/v2/accounts/456/campaigns/123'),
 ('eventbrite','read_events','123',{},'/v3/organizations/123/events/'),
])
async def test_provider_read_contracts(store,provider,operation,resource,args,path,monkeypatch):
    client,_=native(store,provider,[resource])
    calls=[]
    def respond(request):
        calls.append(request)
        if request.url.path.endswith('/authenticate'):
            assert json.loads(request.content)==KEY
            return httpx.Response(200,json={'ens-auth-token':'private-ens-session','expires':3600000})
        return httpx.Response(200,json={'id':'42','name':'Test charity','account_id':'123','events':[],'value':[]})
    monkeypatch.setattr('connectors.native.transport_for',lambda *a,**k:httpx.MockTransport(respond))
    await client.execute(operation,{'resource':resource,**args})
    assert any(r.url.path==path for r in calls),[str(r.url) for r in calls]
    assert all(r.method in {'GET','POST'} for r in calls)
    for r in calls:
        if r.method=='POST' and provider=='google_ads':
            query=json.loads(r.content)['query'];assert query.startswith('SELECT campaign.id') and 'LIMIT 50' in query and 'mutat' not in query.lower()
        if provider=='beacon':assert r.url.params['populate']=='false'
        assert 'Bearer sk-' not in r.headers.get('authorization','')


@pytest.mark.asyncio
async def test_drive_boundary_precedes_download_and_quotes_search(store,monkeypatch):
    client,_=native(store,'google_drive',['folder_1'])
    requests=[]
    def respond(r):
        requests.append(r)
        return httpx.Response(200,json={'id':'doc_1','parents':['outside'],'files':[]})
    monkeypatch.setattr('connectors.native.transport_for',lambda *a,**k:httpx.MockTransport(respond))
    with pytest.raises(PolicyDenied,match='outside'):await client.execute('read_document',{'resource':'folder_1','document_id':'doc_1'})
    assert len(requests)==1 and 'alt' not in requests[0].url.params
    await client.execute('search_documents',{'resource':'folder_1','query':"x' or trashed = true"})
    assert "'folder_1' in parents" in requests[-1].url.params['q']
    assert "x\\' or" in requests[-1].url.params['q']


@pytest.mark.asyncio
@pytest.mark.parametrize('download',['https://evil.org/content','https://tenant.sharepoint.com.evil.org/x','http://tenant.sharepoint.com/x','https://user:pass@tenant.sharepoint.com/x'])
async def test_sharepoint_rejects_foreign_download_before_dispatch(store,monkeypatch,download):
    client,_=native(store,'sharepoint',['site|drive|tenant.sharepoint.com'])
    requests=[]
    async def request(*args,**kwargs):requests.append(args);return {'parentReference':{'driveId':'drive'},'@microsoft.graph.downloadUrl':download}
    monkeypatch.setattr(client,'request',request)
    with pytest.raises(PolicyDenied):await client.execute('read_document',{'resource':'site|drive|tenant.sharepoint.com','document_id':'doc'})
    assert len(requests)==1


def test_public_text_extraction_and_unsupported_content():
    assert text_content(b'<p>Charity</p><script>bad()</script>','text/html').strip()=='Charity'
    with pytest.raises(ValueError):text_content(b'','application/octet-stream')


@pytest.mark.asyncio
async def test_public_fetch_never_carries_service_credentials_and_rejects_redirect(store,monkeypatch):
    client,_=native(store,'web',['public_https'])
    def respond(r):
        assert 'authorization' not in r.headers and KEY not in str(r.url)
        return httpx.Response(302,headers={'location':'http://169.254.169.254/latest/meta-data'})
    monkeypatch.setattr('connectors.native.transport_for',lambda *a,**k:httpx.MockTransport(respond))
    with pytest.raises(ValueError):await client.execute('fetch_page',{'url':'https://charity.org'})
    with pytest.raises(PolicyDenied):await client.execute('fetch_page',{'url':'http://127.0.0.1'})


@pytest.mark.asyncio
async def test_actual_fastmcp_native_discovery_and_gateway_checks(store,guarded_gateway,monkeypatch):
    client,runtime=native(store,'web',['public_https'])
    manager=AuthenticationManager(store,runtime);store.authentication=manager
    found=await discover_connection(store,runtime,'native')
    assert [t['name'] for t in found]==['native_fetch_page']
    calls=[]
    def respond(r):calls.append(r);return httpx.Response(200,text='Public charity information',headers={'content-type':'text/plain'})
    monkeypatch.setattr('connectors.native.transport_for',lambda *a,**k:httpx.MockTransport(respond))
    gateway=await guarded_gateway(['native_fetch_page'])
    async with Client(gateway) as mcp:
        assert [t.name for t in await mcp.list_tools()]==['native_fetch_page']
        assert calls==[]
        result=await mcp.call_tool('native_fetch_page',{'url':'https://charity.org'})
        assert 'Public charity information' in str(result)
    assert len(calls)==1
    CredentialVault(store.root).disconnect('native')


@pytest.mark.asyncio
async def test_native_refresh_rotation_shared_lease_and_restart(store,monkeypatch):
    client,runtime=native(store,'google_drive',['folder'])
    h=client.handle
    h.change(lambda d:d['api_tokens'].update(expires=0))
    client.vault.save_provider('google',{'client_json':{'installed':{'client_id':'test.apps.googleusercontent.com','client_secret':'private-client-secret'}},'project':'charity'},'')
    count=0
    async def respond(request):
        nonlocal count
        count+=1;await asyncio.sleep(.02)
        fields=parse_qs(request.content.decode());assert fields['refresh_token']==['private-native-refresh']
        return httpx2.Response(200,json={'access_token':'private-rotated-access','refresh_token':'private-rotated-refresh','token_type':'Bearer','expires_in':3600,'scope':'https://www.googleapis.com/auth/drive.readonly'})
    monkeypatch.setattr('connectors.auth.transport_for',lambda *a,**k:httpx2.MockTransport(respond))
    values=await asyncio.gather(*[access_token(CredentialVault(store.root).handle('native',client.spec,store.secret),runtime.policy()) for _ in range(5)])
    assert values==['private-rotated-access']*5 and count==1
    assert {'private-native-refresh','private-rotated-refresh','private-rotated-access'} <= set(CredentialVault(store.root).secret_values())
    client.vault.disconnect('native')
    with pytest.raises(AuthenticationRequired):await access_token(h,runtime.policy())


@pytest.mark.parametrize('provider',[p['id'] for p in catalogue() if p['route']=='hosted'])
def test_hosted_contracts_deny_writes_multiplexers_and_endpoint_changes(provider):
    p=preset(provider)
    spec={'managed':{'preset':provider,'revision':REVISION}}
    for tool,args in [('execute',{'operation':'delete'}),('send',{}),(p['read_tools'][0],{'nested':{'method':'POST'}})]:assert not hosted_read_allowed(spec,tool,args)
    assert hosted_read_allowed(spec,p['read_tools'][0],{})
    with pytest.raises(ValueError):MCPSpec.model_validate({**spec,'display_name':p['name'],'transport':'http','url':'https://evil.org/mcp','auth':{'type':'none'}})

@pytest.mark.asyncio
async def test_native_oauth_callback_pkce_replay_and_cancel(store,monkeypatch):
    from urllib.parse import urlsplit,urlencode
    client,runtime=native(store,'google_drive',['folder'])
    vault=client.vault
    vault.save_provider('google',{'client_json':{'installed':{'client_id':'test.apps.googleusercontent.com','client_secret':'private-google-registration'}},'project':'charity'},'')
    manager=AuthenticationManager(store,runtime)
    verifier=[]
    def token(request):
        fields=parse_qs(request.content.decode());verifier.append(fields['code_verifier'][0])
        return httpx2.Response(200,json={'access_token':'private-oauth-access','refresh_token':'private-oauth-refresh','expires_in':3600,'scope':'https://www.googleapis.com/auth/drive.readonly'})
    monkeypatch.setattr('connectors.auth.transport_for',lambda *a,**k:httpx2.MockTransport(token))
    await manager.start('native')
    transaction=manager.transactions['native']
    async with asyncio.timeout(5):
        while transaction.phase!='review':await asyncio.sleep(.01)
        transaction.approve(transaction.id)
        while transaction.phase!='sign_in':await asyncio.sleep(.01)
    query=parse_qs(urlsplit(transaction.authorization_url).query)
    assert query['scope']==['https://www.googleapis.com/auth/drive.readonly']
    assert query['code_challenge_method']==['S256'] and query['access_type']==['offline']
    url=query['redirect_uri'][0]+'?'+urlencode({'state':query['state'][0],'code':'fake-code'})
    async with httpx2.AsyncClient(trust_env=False) as browser:
        assert (await browser.get(url.replace(query['state'][0],'wrong'))).status_code==400
        assert (await browser.get(url)).status_code==200
    await transaction.task
    import hashlib
    assert base64.urlsafe_b64encode(hashlib.sha256(verifier[0].encode()).digest()).decode().rstrip('=')==query['code_challenge'][0]
    assert manager.status('native')['status']=='connected'
    monkeypatch.setattr('guardrails.network.transport_for',lambda *a,**k:httpx2.MockTransport(lambda request:httpx2.Response(200,json={})))
    await manager.disconnect('native')
    assert manager.provider_status()['configured']
    assert manager.status('native')['status']!='connected'
    await manager.start('native')
    transaction=manager.transactions['native']
    async with asyncio.timeout(5):
        while transaction.phase!='review':await asyncio.sleep(.01)
    await manager.cancel('native')
    assert transaction.server.is_serving() is False
    assert manager.status('native')['status']!='connected'


@pytest.mark.asyncio
@pytest.mark.parametrize('provider,response,path',[
 ('google_ads',{'resourceNames':['customers/123']},'/v26/customers:listAccessibleCustomers'),
 ('meta_ads',{'data':[{'id':'act_123','name':'Charity'}]},'/v27.0/me/adaccounts'),
 ('search_console',{'siteEntry':[{'siteUrl':'https://charity.org/'}]},'/webmasters/v3/sites'),
 ('raisers_edge',{},None),('blackbaud_crm',{},None),
 ('beacon',{'entity_types':[{'id':'person','name':'person','display_name':'Supporters'}]},'/v1/account/123/entity_types'),
 ('mailchimp',{'account_id':'123','account_name':'Charity'},'/3.0/'),
 ('engaging_networks',[{'id':42,'name':'Charity page'}],'/ens/service/page'),
 ('wordpress',{'post':{}},'/wp-json/wp/v2/types'),
 ('meta_social',{'data':[{'id':'123','name':'Charity','instagram_business_account':{'id':'456'}}]},'/v27.0/me/accounts'),
 ('linkedin',{'elements':[{'organization':'urn:li:organization:123','organizationName':'Charity'}]},'/rest/organizationAcls'),
 ('google_drive',{'files':[{'id':'folder','name':'Charity documents'}]},'/drive/v3/files'),
 ('sharepoint',{'value':[{'id':'site','displayName':'Charity','name':'Documents','webUrl':'https://tenant.sharepoint.com/sites/charity'}]},'/v1.0/sites'),
 ('vwo',{'campaigns':[{'id':123,'name':'Existing experiment'}]},'/api/v2/accounts/456/campaigns'),
 ('eventbrite',{'organizations':[{'id':'123','name':'Charity events'}]},'/v3/users/me/organizations/'),
])
async def test_every_metadata_driver_uses_minimal_read_contract(store,provider,response,path,monkeypatch):
    client,_=native(store,provider)
    calls=[]
    def respond(request):
        calls.append(request)
        assert request.method=='GET' or request.url.path.endswith('/authenticate') or provider=='google_ads'
        if provider=='google_ads' and request.method=='POST':
            assert json.loads(request.content)['query']=='SELECT customer.id, customer.descriptive_name FROM customer LIMIT 1'
        if request.url.path.endswith('/authenticate'):return httpx.Response(200,json={'ens-auth-token':'private-ens-token','expires':3600000})
        if provider=='sharepoint' and request.url.path.endswith('/drives'):return httpx.Response(200,json={'value':[{'id':'drive','name':'Documents'}]})
        return httpx.Response(200,json=response)
    monkeypatch.setattr('connectors.native.transport_for',lambda *a,**k:httpx.MockTransport(respond))
    choices=await client.resources()
    assert choices and all(c['id'] and c['label'] for c in choices)
    if path:assert any(r.url.path==path for r in calls)
    else:assert not calls
    assert not any('insights' in r.url.path or '/reports' in r.url.path or '/supporter/42' in r.url.path for r in calls)


@pytest.mark.asyncio
async def test_pdf_worker_extracts_and_rejects_bad_files():
    import io
    from pypdf import PdfWriter
    from connectors.native import extract
    writer=PdfWriter();writer.add_blank_page(width=100,height=100)
    buffer=io.BytesIO();writer.write(buffer)
    assert await extract(buffer.getvalue(),'application/pdf')==''
    with pytest.raises(ValueError):await extract(b'not a pdf','application/pdf')


@pytest.mark.asyncio
async def test_hosted_gateway_hard_denies_writes_and_unbound_reads(store,guarded_gateway,monkeypatch):
    from fastmcp import FastMCP
    from fastmcp.exceptions import ToolError
    from mcp.shared.exceptions import MCPError
    from guardrails.settings import load_settings
    p=preset('contentful')
    spec=MCPSpec.model_validate({'display_name':'Contentful','transport':'http','url':p['url'],'auth':{'type':'oauth'},'managed':{'preset':'contentful','revision':REVISION}}).model_dump(exclude_none=True)
    config=store.tools();config['mcp_servers']={'content':spec};store.save(store.tools_path,config)
    vault=CredentialVault(store.root);vault.reset('content',spec,store.secret).change(lambda d:d.update(connected=True),status='connected')
    upstream=FastMCP('Fake hosted Contentful')
    calls=[]
    @upstream.tool
    def get_spaces()->dict:
        calls.append('spaces');return {'spaces':[]}
    @upstream.tool
    def get_entries(space_id:str)->dict:
        calls.append('entries');return {'items':[]}
    @upstream.tool
    def publish_entry()->dict:
        calls.append('publish');return {'published':True}
    monkeypatch.setattr('tools.gateway.mcp_transport',lambda *a,**k:upstream)
    gateway=await guarded_gateway(['content_get_spaces','content_get_entries','content_publish_entry'])
    async with Client(gateway) as mcp:
        names=[t.name for t in await mcp.list_tools()]
        assert names==['content_get_spaces'] and calls==[]
        for tool,args in [('content_publish_entry',{}),('content_get_entries',{'space_id':'outside'})]:
            with pytest.raises((ToolError,MCPError)):await mcp.call_tool(tool,args)
        assert calls==[]
        await mcp.call_tool('content_get_spaces',{})
    assert calls==['spaces']


@pytest.mark.asyncio
async def test_pdf_worker_cancellation_kills_request_process_and_receives_no_secrets(monkeypatch):
    from connectors.native import extract
    class Process:
        returncode=None
        killed=False
        async def communicate(self,data):await asyncio.Event().wait()
        def kill(self):self.killed=True;self.returncode=-9
        async def wait(self):return self.returncode
    process=Process()
    async def start(*a,**kw):
        assert set(kw['env'])=={'PATH','LANG'}
        assert '-I' in a
        return process
    monkeypatch.setattr('connectors.native.asyncio.create_subprocess_exec',start)
    task=asyncio.create_task(extract(b'fake','application/pdf'))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    assert process.killed


@pytest.mark.asyncio
async def test_token_bearing_pagination_is_discarded_and_never_followed(store,monkeypatch):
    client,_=native(store,'meta_ads',['act_123'])
    calls=[]
    def respond(request):
        calls.append(request)
        return httpx.Response(200,json={'data':[{'campaign_id':'42','impressions':'25'}],'paging':{'next':'https://evil.org/steal?access_token='+KEY}})
    monkeypatch.setattr('connectors.native.transport_for',lambda *a,**k:httpx.MockTransport(respond))
    result=await client.execute('read_reports',{'resource':'act_123'})
    assert result['data']['data']==[{'campaign_id':'42','impressions':'25'}]
    assert result['data']['page_limited'] is True
    assert KEY not in json.dumps(result) and 'evil.org' not in json.dumps(result)
    assert len(calls)==1


@pytest.mark.asyncio
async def test_document_transfer_rejects_compressed_bodies_before_extraction(store,monkeypatch):
    from connectors.native import NativeClient
    client,_=native(store,'web',['public_https'])
    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail('Compressed body must not be consumed')
            yield b''
    def respond(request):
        assert request.headers['accept-encoding']=='identity'
        return httpx.Response(200,headers={'content-encoding':'gzip','content-type':'text/html'},stream=Body())
    monkeypatch.setattr('connectors.native.transport_for',lambda *a,**k:httpx.MockTransport(respond))
    with pytest.raises(ValueError,match='Compressed'):await client.execute('fetch_page',{'url':'https://charity.org'})


def test_native_endpoint_and_scope_contract_changes_invalidate_existing_credentials(store,monkeypatch):
    client,_=native(store,'google_drive',['folder'])
    before=client.vault.handle('native',client.spec,store.secret)
    assert before.read()['connected']
    original=endpoints(client.spec)
    monkeypatch.setattr('connectors.auth.endpoints',lambda spec:{**original,'scopes':['https://www.googleapis.com/auth/adwords']})
    changed=client.vault.handle('native',client.spec,store.secret)
    with pytest.raises(AuthenticationRequired):changed.read()
    monkeypatch.setattr('connectors.auth.endpoints',lambda spec:{**original,'token':'https://different-provider.org/token'})
    with pytest.raises(AuthenticationRequired):client.vault.handle('native',client.spec,store.secret).read()
