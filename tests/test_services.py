import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import psutil
import pytest

from control_panel.services import Services


@pytest.mark.asyncio
async def test_missing_secret_startup_is_usable(store,monkeypatch):
    store.write_secrets({name:None for name in store.values()})
    for name in ['OPENROUTER_API_KEY','LITELLM_MASTER_KEY','LITELLM_PROXY_API_KEY','BRAVE_API_KEY']:monkeypatch.delenv(name,raising=False)
    services=Services(store)
    monkeypatch.setattr(services,'occupied',lambda port:False)
    spawn=AsyncMock(return_value=MagicMock(pid=1234,returncode=None))
    monkeypatch.setattr('asyncio.create_subprocess_exec',spawn)
    identity=MagicMock()
    identity.create_time.return_value=123
    monkeypatch.setattr('psutil.Process',lambda pid:identity)
    monkeypatch.setattr(services,'owned',lambda name:identity if name in services.records else None)
    services.health=AsyncMock(return_value=True)
    services._read_log=AsyncMock()
    services._stop=AsyncMock()
    await services.start_ready()
    assert services.states['inference']['status']=='needs_setup'
    assert services.states['tools']['status']=='running'
    spawn.assert_awaited_once()
    assert spawn.call_args.args[2]=='tools.gateway'
    await services.close()


@pytest.mark.asyncio
async def test_external_service_protection_and_port_conflict(store,monkeypatch):
    services=Services(store)
    monkeypatch.setattr(services,'occupied',lambda port:True)
    services.health=AsyncMock(return_value=True)
    spawn=AsyncMock()
    monkeypatch.setattr('asyncio.create_subprocess_exec',spawn)
    await services.action('inference','start')
    assert services.states['inference']['status']=='external'
    spawn.assert_not_awaited()
    with pytest.raises(ValueError):await services.action('inference','stop')
    services.health=AsyncMock(return_value=False)
    assert (await services.observe('inference'))['status']=='failed'


def test_process_identity_and_environment(store,monkeypatch):
    services=Services(store)
    fake=MagicMock()
    fake.create_time.return_value=123
    fake.cwd.return_value=str(store.root)
    fake.cmdline.return_value=['python','-m','tools.gateway']
    fake.status.return_value=psutil.STATUS_RUNNING
    monkeypatch.setattr('psutil.Process',lambda pid:fake)
    services.records['tools']={'pid':42,'created':123,'command':['python','-m','tools.gateway']}
    assert services.owned('tools') is fake
    fake.create_time.return_value=124
    assert services.owned('tools') is None
    fake.create_time.return_value=123
    fake.cmdline.return_value=['unrelated-process']
    assert services.owned('tools') is None
    env=store.process_environment()
    assert env['DEBUG']=='false'
    assert env['OPENROUTER_API_KEY']=='private-provider-test-key'


@pytest.mark.asyncio
async def test_duplicate_start_and_bounded_failed_health(store,monkeypatch):
    services=Services(store)
    monkeypatch.setattr(services,'occupied',lambda port:False)
    services.health=AsyncMock(return_value=True)
    services._read_log=AsyncMock()
    process=MagicMock(pid=1234,returncode=None)
    spawn=AsyncMock(return_value=process)
    monkeypatch.setattr('asyncio.create_subprocess_exec',spawn)
    fake=MagicMock()
    fake.create_time.return_value=123
    monkeypatch.setattr('psutil.Process',lambda pid:fake)
    # Track a stable verified identity after launch.
    monkeypatch.setattr(services,'owned',lambda name:fake if name in services.records else None)
    await services.action('inference','start')
    await services.action('inference','start')
    assert spawn.await_count==1
    command=spawn.call_args.args
    assert '--host' in command and '127.0.0.1' in command and '--config' in command
    assert spawn.call_args.kwargs['env']['DEBUG']=='false'
    services.states['tools']['status']='stopped'
    services.health=AsyncMock(return_value=False)
    services._stop=AsyncMock()
    process.returncode=1
    await services._start('tools')
    assert services.states['tools']['status']=='failed'
    services._stop.assert_awaited_once_with('tools',preserve_error=True)


@pytest.mark.asyncio
async def test_shutdown_only_owned_processes(store,monkeypatch):
    services=Services(store)
    monkeypatch.setattr(services,'owned',lambda name:object() if name=='tools' else None)
    services._stop=AsyncMock()
    await services.close()
    services._stop.assert_awaited_once_with('tools')


@pytest.mark.asyncio
async def test_log_redaction(store):
    services=Services(store)
    reader=asyncio.StreamReader()
    reader.feed_data(b'error private-provider-test-key Bearer abcdefghi\n')
    reader.feed_eof()
    process=MagicMock(stdout=reader)
    await services._read_log('inference',process)
    text=(store.local/'logs/inference.log').read_text()
    assert 'private-provider-test-key' not in text and 'abcdefghi' not in text
    assert '[REDACTED]' in text


@pytest.mark.asyncio
async def test_missing_executable_reports_failure_instead_of_starting_forever(store,monkeypatch):
    services=Services(store)
    monkeypatch.setattr(services,'occupied',lambda port:False)
    monkeypatch.setattr('asyncio.create_subprocess_exec',AsyncMock(side_effect=FileNotFoundError('Executable not installed')))
    await services.action('inference','start')
    assert services.states['inference']['status']=='failed'
    assert 'Executable not installed' in services.states['inference']['detail']


@pytest.mark.asyncio
async def test_stalled_health_check_releases_startup_lock(store,monkeypatch):
    services=Services(store)
    services.STARTUP_TIMEOUT=.03
    monkeypatch.setattr('control_panel.connections.discover_connection',AsyncMock())
    monkeypatch.setattr(services,'occupied',lambda port:False)
    monkeypatch.setattr(services,'owned',lambda name:None)
    identity=MagicMock()
    identity.create_time.return_value=1
    monkeypatch.setattr('psutil.Process',lambda pid:identity)
    monkeypatch.setattr('asyncio.create_subprocess_exec',AsyncMock(return_value=MagicMock(pid=999,returncode=None)))
    services._read_log=AsyncMock()
    services._stop=AsyncMock()
    cancelled=[]
    async def stalled(name):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(name)
    services.health=stalled
    await asyncio.wait_for(services.start_ready(),1)
    assert not services.lock.locked()
    assert set(cancelled)=={'inference','tools'}
    assert all(state['status']=='failed' for state in services.states.values())
    assert services._stop.await_count==2


@pytest.mark.asyncio
async def test_external_health_check_has_total_deadline(store,monkeypatch):
    services=Services(store)
    services.HEALTH_TIMEOUT=.03
    monkeypatch.setattr(services,'occupied',lambda port:True)
    async def stalled(name):
        await asyncio.Event().wait()
    services._health=stalled
    state=await asyncio.wait_for(services.observe('inference'),1)
    assert state['status']=='failed'
    assert 'Stop the existing server in its original terminal' in state['detail']


def test_agent_edits_do_not_restart_gateways(store):
    services=Services(store)
    before={name:services.fingerprint(name) for name in services.states}
    agents=store.agents()
    agents['agents']['strategy_agent']['instruction']='Retrieve the approved charity context.'
    store.save(store.agents_path,agents)
    assert {name:services.fingerprint(name) for name in services.states}==before


@pytest.mark.asyncio
async def test_automatic_updates_preserve_manual_stops(store,monkeypatch):
    services=Services(store)
    services.observe=AsyncMock(side_effect=lambda name:services.states[name])
    services._stop=AsyncMock()
    services._start=AsyncMock()
    await services.action('tools','stop')
    services._start.reset_mock()
    await services.apply()
    assert all(call.args[0]!='tools' for call in services._start.await_args_list)
