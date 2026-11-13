"""Optional isolation: mode transitions, boundaries and real-runtime contracts."""
import asyncio
import io
import json
import os
from pathlib import Path
import shutil
import sys
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from guardrails.policy import Policy, PolicyDenied, digest
from guardrails.settings import load_policy, load_settings, settings_from_policy
from sandboxing.activity import Busy, gate, lease, leases, require_idle
from sandboxing.manager import SandboxManager, publish, supported_node
from sandboxing.models import ConnectionProfile, PROFILE_REVISION, SRT_VERSION
from sandboxing.runtime import RESOURCES, SandboxRunner, build_config, connection_profile, installation, minimal_environment, validate_profile


def enable(store):
    settings = load_settings(store.root)
    settings.sandbox.enabled = True
    store.save(store.policy_path, settings.model_dump(mode='json', exclude_none=True))
    return load_policy(store.root)


def fake_install(store, node=None, *, verified=True):
    directory = store.local / 'sandbox/installations/test'
    package = directory / 'node_modules/@anthropic-ai/sandbox-runtime'
    package.mkdir(parents=True)
    (package / 'package.json').write_text(json.dumps({'version': SRT_VERSION}))
    receipt = {'version':SRT_VERSION,'directory':str(directory),'node':node or sys.executable,'profile_revision':PROFILE_REVISION,'verified':verified,'verified_platform':sys.platform}
    if os.name == 'nt':
        receipt.update(windows={'sandboxUser':'kindred-test','proxyPortRange':[61000,61009]},windows_helper=str(directory/'srt-win.exe'))
    publish(store.local / 'sandbox/current.json', receipt)
    return receipt


def test_defaults_migrate_and_fingerprint(store):
    old = load_policy(store.root)
    assert not old.sandbox.enabled
    assert not settings_from_policy(Policy()).sandbox.enabled
    assert enable(store).revision != old.revision
    assert load_settings(store.root).sandbox.enabled


def test_private_atomic_publication_without_unix_fchmod(tmp_path,monkeypatch):
    monkeypatch.delattr(os,'fchmod',raising=False)
    target=tmp_path/'receipt.json'
    publish(target,{'version':SRT_VERSION})
    assert json.loads(target.read_text())=={'version':SRT_VERSION}
    assert list(tmp_path.iterdir())==[target]


def test_api_toggle_preserves_unrelated_settings_and_revisions(client, app):
    before = client.get('/api/guardrails').json()['settings']
    status = client.get('/api/sandbox').json()
    assert status['state'] == 'off' and not status['enabled']
    response = client.put('/api/sandbox', json={'revision': status['revision'], 'enabled': True})
    assert response.status_code == 200
    assert client.get('/api/sandbox').json()['enabled']
    assert client.put('/api/sandbox', json={'revision': status['revision'], 'enabled': False}).status_code == 409
    assert client.put('/api/sandbox', json={'revision': response.json()['revision'], 'enabled': 'false'}).status_code == 400
    preferences = {k:v for k,v in before.items() if k in {'monthly_token_limit','per_run_token_limit','daily_token_limit','jurisdictions','mode','activities','safeguarding_contact'}}
    preferences['safeguarding_contact'] = 'Local reviewer'
    result = client.put('/api/guardrails/settings', json={'revision':app.state.store.revision(),'settings':preferences})
    assert result.status_code == 200
    assert load_settings(app.state.store.root).sandbox.enabled
    result = client.put('/api/sandbox', json={'revision':app.state.store.revision(),'enabled':False})
    assert result.status_code == 200
    assert client.get('/api/sandbox').json()['state'] in {'off','applying'}


def test_saved_choice_is_separate_from_gateway_application(client,app):
    sync=app.state.synchronisation
    sync.state={'state':'updating','message':''}
    result=client.get('/api/sandbox').json()
    assert result['state']=='applying' and not result['enabled']
    sync.state={'state':'attention','message':'External gateway needs reconnection.'}
    result=client.get('/api/sandbox').json()
    assert result['state']=='needs_attention' and not result['enabled']
    assert 'Gateways' in result['checks'][-1]['message']


def test_toggle_and_setup_reject_active_workers(client, app):
    root = app.state.store.root
    with lease(root, 'local'):
        revision = app.state.store.revision()
        assert client.put('/api/sandbox', json={'revision':revision,'enabled':True}).status_code == 409
        assert client.post('/api/sandbox/setup', json={'revision':revision}).status_code == 409
    assert not leases(root)


@pytest.mark.asyncio
async def test_connection_test_lease_blocks_sandbox_changes(client,app,monkeypatch):
    from control_panel import connections
    store=app.state.store
    async def discover(*args,**kwargs):
        revision=store.revision()
        assert client.put('/api/sandbox',json={'revision':revision,'enabled':True}).status_code==409
        assert client.post('/api/sandbox/check',json={'revision':revision}).status_code==409
        return []
    monkeypatch.setattr(connections,'_discover_connection',discover)
    assert await connections.discover_connection(store,None,'fixture')==[]
    assert not leases(store.root)


def test_setup_routes_require_pairing_csrf_and_do_not_enable(client, app, monkeypatch):
    manager = app.state.sandbox
    monkeypatch.setattr(manager, 'setup', AsyncMock())
    result = client.post('/api/sandbox/setup', json={'revision':app.state.store.revision(),'confirm_windows':True})
    assert result.status_code == 202
    assert client.get('/api/sandbox/jobs/'+result.json()['id']).status_code == 200
    assert not load_settings(app.state.store.root).sandbox.enabled
    assert client.get('/api/sandbox/jobs/missing').status_code == 404
    assert client.put('/api/sandbox',json={'revision':app.state.store.revision(),'enabled':True},headers={'X-CSRF-Token':'wrong'}).status_code == 403


def test_custom_profile_review_and_protected_paths(client, app, tmp_path):
    store = app.state.store
    config = store.tools()
    spec = {'transport':'stdio','command':sys.executable,'args':['-m','example']}
    config['mcp_servers']['custom'] = spec
    store.save(store.tools_path, config)
    safe = tmp_path / 'documents';safe.mkdir()
    profile = {'configuration_hash':digest(spec),'read_paths':[str(safe)],'write_paths':[],'destinations':['api.example.org:443']}
    assert client.put('/api/sandbox/connections/custom',json={'revision':store.revision(),'profile':profile}).status_code == 200
    policy = load_policy(store.root)
    assert connection_profile(store.root,policy,'custom',spec)[0] == 'custom'
    with pytest.raises(PolicyDenied,match='Review'):
        connection_profile(store.root,policy,'custom',{**spec,'args':['changed']})
    for path in [store.root, store.local, store.env_path, Path.home()]:
        bad = {**profile,'read_paths':[str(path)]}
        assert client.put('/api/sandbox/connections/custom',json={'revision':store.revision(),'profile':bad}).status_code == 400
    assert client.put('/api/sandbox/connections/custom',json={'revision':store.revision(),'profile':{**profile,'destinations':['127.0.0.1:1234']}}).status_code == 400


@pytest.mark.parametrize('destination',['*','*.example.org','localhost','http://api.example.org','api.example.org:0','api.example.org:99999','api.internal','[::1]:80'])
def test_profile_rejects_broad_or_local_destinations(destination):
    with pytest.raises(ValidationError):
        ConnectionProfile(configuration_hash='a'*64,destinations=[destination])


@pytest.mark.parametrize('version,expected',[('v20.19.1',False),('v22.12.0',False),('v22.21.0',True),('v24.4.0',False),('v24.5.0',True),('v25.0.0',False)])
def test_proxy_capable_node_lts(version,expected):
    assert supported_node(version) == expected


@pytest.mark.asyncio
async def test_off_mode_does_not_resolve_srt_and_preserves_arguments(store,monkeypatch):
    import sandboxing.runtime as runtime
    monkeypatch.setattr(runtime,'installation',lambda *a,**kw:pytest.fail('Off mode must not inspect SRT'))
    argv = [sys.executable,'literal argument','$(touch forbidden)','a; b',"quote'\"",'']
    async with SandboxRunner(store.root).prepare(argv,env={'EXAMPLE':'value'}) as prepared:
        assert prepared.argv == argv and prepared.env == {'EXAMPLE':'value'}
        assert not prepared.sandboxed
        with gate(store.root),pytest.raises(Busy):require_idle(store.root)
    assert not leases(store.root)


@pytest.mark.asyncio
async def test_on_mode_fails_closed_without_runtime(store,monkeypatch):
    enable(store)
    start = AsyncMock()
    monkeypatch.setattr('asyncio.create_subprocess_exec',start)
    with pytest.raises(PolicyDenied) as failure:
        await SandboxRunner(store.root).run([sys.executable,'-c','print(1)'])
    assert failure.value.rule == 'sandbox.setup'
    start.assert_not_awaited()
    assert not leases(store.root)


@pytest.mark.asyncio
async def test_sandbox_prepares_private_config_and_only_connection_environment(store,monkeypatch):
    fake_install(store)
    if os.name == 'nt':
        async def cleanup(self):
            (store.local/'sandbox/windows-dirty.json').unlink(missing_ok=True)
        monkeypatch.setattr(SandboxRunner,'windows_cleanup',cleanup)
    policy = enable(store)
    spec = store.tools()['mcp_servers']['brave']
    async with SandboxRunner(store.root).prepare([spec['command'],*spec['args']],spec=spec,connection='brave',policy=policy,env={'BRAVE_API_KEY':'fake-key'}) as prepared:
        assert prepared.sandboxed
        assert prepared.argv[0] == sys.executable
        record = next((store.local/'sandbox/workers').glob('*.json'))
        config_file = Path(json.loads(record.read_text())['work'])/'settings.json'
        config = json.loads(config_file.read_text())
        assert config['network']['allowedDomains'] == ['api.search.brave.com:443']
        assert config['network']['strictAllowlist']
        assert config['network']['allowLocalBinding'] is False
        assert 'OPENROUTER_API_KEY' not in prepared.env
        assert prepared.env['BRAVE_API_KEY'] == 'fake-key'
        assert 'npx' not in prepared.argv
    assert not config_file.exists()


def test_minimal_environment_blocks_host_loader_injection(tmp_path):
    for key in ['NODE_OPTIONS','PYTHONPATH','SRT_DEBUG','HTTP_PROXY','PATH','LD_PRELOAD']:
        with pytest.raises(PolicyDenied):minimal_environment(tmp_path,sys.executable,{key:'malicious'})


def test_receipt_never_accepts_ambient_or_unverified_runtime(store):
    fake_install(store,verified=False)
    with pytest.raises(PolicyDenied):installation(store.root)
    assert installation(store.root,checked=False)


@pytest.mark.asyncio
async def test_pdf_off_and_on_do_not_require_provider_access(store):
    from pypdf import PdfWriter
    from connectors.native import extract
    writer = PdfWriter();writer.add_blank_page(width=100,height=100)
    stream = io.BytesIO();writer.write(stream)
    assert await extract(stream.getvalue(),'application/pdf',root=store.root) == ''
    enable(store)
    with pytest.raises(PolicyDenied) as failure:
        await extract(stream.getvalue(),'application/pdf',root=store.root)
    assert failure.value.rule == 'sandbox.setup'


@pytest.mark.asyncio
async def test_setup_failure_releases_activity_and_keeps_choice(store,monkeypatch):
    from sandboxing.manager import SetupError
    manager = SandboxManager(store.root)
    monkeypatch.setattr(manager,'setup',AsyncMock(side_effect=SetupError('Install Node.js LTS first.')))
    job = manager.start('setup')
    await asyncio.gather(*manager.tasks)
    assert job['state'] == 'failed' and 'Node.js' in job['message']
    assert not leases(store.root)
    assert not load_settings(store.root).sandbox.enabled


@pytest.fixture
def real_srt(store):
    """Supply installed locked npm packages and Node via explicit test settings.

    The normal regression suite never downloads software or attempts elevation.
    """
    source = os.environ.get('KINDRED_TEST_SRT_PACKAGES')
    node = os.environ.get('KINDRED_TEST_SRT_NODE')
    if not source or not node:
        pytest.skip('Set KINDRED_TEST_SRT_PACKAGES and KINDRED_TEST_SRT_NODE for actual SRT integration')
    receipt = fake_install(store,node,verified=False)
    target = Path(receipt['directory']) / 'node_modules'
    shutil.rmtree(target)
    shutil.copytree(Path(source) / 'node_modules',target,copy_function=shutil.copyfile)
    if (Path(source) / 'analytics').exists():
        shutil.copytree(Path(source) / 'analytics',Path(receipt['directory']) / 'analytics',symlinks=True)
    if os.name == 'nt':
        supplied = os.environ.get('KINDRED_TEST_SRT_RECEIPT')
        if not supplied:
            pytest.skip('Windows real checks require an explicitly provisioned test receipt/account')
        original = json.loads(Path(supplied).read_text())
        receipt.update(windows=original['windows'],windows_helper=original['windows_helper'])
    receipt['dependencies'] = {name:shutil.which(name) for name in ['rg','bwrap','socat'] if shutil.which(name)}
    publish(store.local / 'sandbox/current.json',receipt)
    return receipt


@pytest.mark.asyncio
async def test_real_srt_readiness_and_literal_arguments(store,real_srt):
    manager = SandboxManager(store.root)
    await manager.check()
    assert installation(store.root)['verified']
    enable(store)
    args = ['space value',"a'b",'$(touch forbidden)','a;b','', 'percent%value', 'quote"value', 'emoji-🐾']
    code, output = await SandboxRunner(store.root).run([sys.executable,'-I','-c','import sys,json;print(json.dumps(sys.argv[1:]))',*args],timeout=20)
    assert code == 0 and json.loads(output) == args
    vault=store.local/'mcp-auth';vault.mkdir(exist_ok=True)
    secret=vault/'fake-credential';secret.write_text('fake-only')
    runtime_file=Path(real_srt['directory'])/'read-only-fixture';runtime_file.write_text('unchanged')
    probe='''import json,sys
from pathlib import Path
checks=[]
for filename in sys.argv[1:3]:
    try:Path(filename).read_bytes();checks.append(False)
    except OSError:checks.append(True)
try:Path(sys.argv[3]).write_text('changed');checks.append(False)
except OSError:checks.append(True)
Path('scratch.txt').write_text('allowed')
checks.append(Path('scratch.txt').read_text()=='allowed')
print(json.dumps(checks))
'''
    code,output=await SandboxRunner(store.root).run([sys.executable,'-I','-c',probe,str(store.env_path),str(secret),str(runtime_file)],timeout=20)
    assert code==0 and json.loads(output)==[True,True,True,True]
    assert runtime_file.read_text()=='unchanged'
    assert not leases(store.root)


@pytest.mark.asyncio
async def test_real_srt_pdf_and_maintained_mcp_discovery(store,real_srt):
    from fastmcp import Client
    from connectors.native import extract
    from pypdf import PdfWriter
    from tools.gateway import mcp_transport
    from tools.mcp_auth import CredentialVault
    from sandboxing.runtime import GOOGLE
    await SandboxManager(store.root).check()
    policy = enable(store)
    writer=PdfWriter();writer.add_blank_page(width=100,height=100)
    stream=io.BytesIO();writer.write(stream)
    assert await extract(stream.getvalue(),'application/pdf',root=store.root,policy=policy) == ''
    spec=store.tools()['mcp_servers']['brave']
    async with Client(mcp_transport(spec,store.secret,policy=policy,root=store.root,connection='brave'),timeout=25) as client:
        assert 'brave_web_search' in {t.name for t in await client.list_tools()}
    analytics=Path(real_srt['directory']) / 'analytics'
    if not analytics.exists():
        pytest.skip('Copy a locked Analytics environment into the supplied test package directory for Analytics verification')
    spec={'transport':'stdio','command':GOOGLE[0],'args':GOOGLE[1:],'auth':{'type':'google_adc','project':'fake-test-project'}}
    config=store.tools();config['mcp_servers']['analytics']=spec;store.save(store.tools_path,config)
    settings=load_settings(store.root);settings.approved_connections['analytics']=digest(spec);store.save(store.policy_path,settings.model_dump(mode='json'))
    vault=CredentialVault(store.root)
    handle=vault.reset('analytics',spec)
    handle.change(lambda d:d.update(connected=True,google={'type':'authorized_user','client_id':'test.apps.googleusercontent.com','client_secret':'fake-client-secret','refresh_token':'fake-refresh-token'}),status='connected')
    policy=load_policy(store.root)
    async with Client(mcp_transport(spec,store.secret,policy=policy,root=store.root,connection='analytics'),timeout=30) as client:
        assert len(await client.list_tools()) > 0
    assert not list(vault.directory.glob('adc-*.json'))
    assert not leases(store.root)


@pytest.mark.asyncio
async def test_real_srt_custom_mcp_concurrency_and_cancellation(store,real_srt):
    from fastmcp import Client
    from tools.gateway import mcp_transport
    await SandboxManager(store.root).check()
    script=store.root/'fake_sandbox_mcp.py'
    script.write_text('''import asyncio,os,sys
from fastmcp import FastMCP
m=FastMCP('Sandbox fixture')
@m.tool
async def echo(value: str,delay: float=0)->dict:
    await asyncio.sleep(delay)
    return {'value':value,'unrelated_secret':bool(os.environ.get('OPENROUTER_API_KEY'))}
m.run(transport='stdio',show_banner=False)
''')
    spec={'transport':'stdio','command':sys.executable,'args':['-I',str(script)]}
    config=store.tools();config['mcp_servers']['fixture']=spec;store.save(store.tools_path,config)
    settings=load_settings(store.root);settings.sandbox.enabled=True;settings.approved_connections['fixture']=digest(spec)
    settings.sandbox.connections['fixture']=ConnectionProfile(configuration_hash=digest(spec),read_paths=[str(script)])
    store.save(store.policy_path,settings.model_dump(mode='json'))
    policy=load_policy(store.root)
    if os.name == 'nt':
        # Windows intentionally serializes sessions because ACLs are shared.
        async with Client(mcp_transport(spec,policy=policy,root=store.root,connection='fixture'),timeout=30) as client:
            result=await client.call_tool('echo',{'value':'literal $(value); quote\"'})
            assert result.structured_content['unrelated_secret'] is False
    else:
        async with Client(mcp_transport(spec,policy=policy,root=store.root,connection='fixture'),timeout=30) as first, Client(mcp_transport(spec,policy=policy,root=store.root,connection='fixture'),timeout=30) as second:
            slow=asyncio.create_task(first.call_tool('echo',{'value':'slow','delay':60}))
            await asyncio.sleep(.15)
            slow.cancel()
            with pytest.raises(asyncio.CancelledError):await slow
            result=await second.call_tool('echo',{'value':'literal $(value); quote\"'})
            assert result.structured_content['value'] == 'literal $(value); quote\"'
            assert result.structured_content['unrelated_secret'] is False
    assert not leases(store.root)
    assert not list((store.local/'sandbox/workers').glob('*.json'))


@pytest.mark.asyncio
async def test_setup_cancelled_before_start_releases_lease(store):
    manager=SandboxManager(store.root)
    job=manager.start('setup')
    await manager.close()
    await asyncio.sleep(0)
    assert job['state']=='cancelled'
    assert not leases(store.root)


@pytest.mark.asyncio
async def test_real_srt_emergency_stop_terminates_owned_worker(store,real_srt):
    from guardrails.runtime import Runtime
    await SandboxManager(store.root).check()
    enable(store)
    runtime=Runtime(store.root)
    worker=asyncio.create_task(SandboxRunner(store.root).run([sys.executable,'-I','-c','import time;time.sleep(60)'],timeout=30))
    # Wait for SRT's owned host to start, then stop while its child is active.
    async with asyncio.timeout(15):
        while not any(Path(json.loads(r.read_text())['work']).joinpath('owner.json').exists() for r in (store.local/'sandbox/workers').glob('*.json')):
            await asyncio.sleep(.05)
    runtime.stop()
    with pytest.raises(PolicyDenied) as error:
        await asyncio.wait_for(worker,5)
    assert error.value.rule=='runtime.stopped'
    assert not leases(store.root)
    assert not list((store.local/'sandbox/workers').glob('*.json'))


@pytest.mark.asyncio
async def test_abandoned_workspace_recovery_preserves_live_and_unrelated_paths(store,tmp_path):
    import tempfile
    import psutil
    from sandboxing.activity import directory
    runner=SandboxRunner(store.root)
    records=directory(store.root)/'workers';records.mkdir()
    temporary_root='/private/tmp' if sys.platform=='darwin' else '/tmp' if sys.platform=='linux' else tempfile.gettempdir()
    work=Path(tempfile.mkdtemp(prefix='ks-',dir=temporary_root))
    (work/'fake-credential.json').write_text('fake-only')
    record=records/(work.name+'.json')
    record.write_text(json.dumps({'work':str(work),'pid':os.getpid(),'created':psutil.Process().create_time()}))
    await runner.recover()
    assert work.exists() and record.exists()
    record.write_text(json.dumps({'work':str(work),'pid':os.getpid(),'created':0}))
    await runner.recover()
    assert not work.exists() and not record.exists()
    record.write_text(json.dumps({'work':str(tmp_path),'pid':os.getpid(),'created':0}))
    with pytest.raises(PolicyDenied):await runner.recover()
    assert tmp_path.exists()


@pytest.mark.asyncio
async def test_failed_runtime_replacement_restores_receipt(store,tmp_path,monkeypatch):
    import sandboxing.manager as module
    previous=fake_install(store)
    binary=tmp_path/'bin';binary.mkdir()
    node=binary/'node';node.write_text('fake-node')
    npm=binary/'npm-cli.js';npm.write_text('fake-npm')
    from tools.node_runtime import NodeRuntime
    monkeypatch.setattr(module,'bundled_node',lambda:NodeRuntime(node,npm,'24.19.0'))
    monkeypatch.setattr(module.shutil,'which',lambda name:str(npm if name=='npm' else node))
    async def command(argv,**kwargs):
        if '--version' in argv:return 0,b'v24.19.0'
        # Fail during package provisioning: no replacement is published.
        return 1,b''
    monkeypatch.setattr(module,'bounded_command',command)
    manager=SandboxManager(store.root)
    job=manager.start('setup');await asyncio.gather(*manager.tasks)
    assert job['state']=='failed'
    assert json.loads((store.local/'sandbox/current.json').read_text())==previous
    assert not leases(store.root)
