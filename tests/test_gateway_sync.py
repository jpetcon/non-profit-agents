import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from control_panel.synchronisation import GatewaySynchronisation


async def wait_for_state(sync, state):
    async def wait():
        while sync.state['state'] != state:
            await asyncio.sleep(.01)
    await asyncio.wait_for(wait(), 3)


@pytest.mark.asyncio
async def test_saved_changes_coalesce_and_wait_for_active_work(store):
    active=asyncio.get_running_loop().create_future()
    services=SimpleNamespace(lock=asyncio.Lock(),apply=AsyncMock(return_value=[]))
    sync=GatewaySynchronisation(store,services,SimpleNamespace(active=active))
    task=asyncio.create_task(sync.run())
    try:
        sync.request();sync.request()
        await asyncio.sleep(.2)
        services.apply.assert_not_awaited()
        assert sync.pending
        active.set_result(None)
        await wait_for_state(sync,'ready')
        services.apply.assert_awaited_once()
        assert not sync.pending
    finally:
        task.cancel();await asyncio.gather(task,return_exceptions=True)


@pytest.mark.asyncio
async def test_updates_arriving_during_restart_are_not_lost(store):
    entered,release=asyncio.Event(),asyncio.Event()
    calls=[]
    async def apply():
        calls.append(True)
        if len(calls)==1:
            entered.set();await release.wait()
        return []
    sync=GatewaySynchronisation(store,SimpleNamespace(lock=asyncio.Lock(),apply=apply),SimpleNamespace(active=None))
    task=asyncio.create_task(sync.run())
    try:
        sync.request();await asyncio.wait_for(entered.wait(),2)
        sync.request();release.set()
        await wait_for_state(sync,'ready')
        assert len(calls)==2
    finally:
        task.cancel();await asyncio.gather(task,return_exceptions=True)


@pytest.mark.asyncio
async def test_failed_reconnect_is_redacted_and_waits_for_retry(store):
    services=SimpleNamespace(lock=asyncio.Lock(),apply=AsyncMock(side_effect=RuntimeError('private-provider-test-key failed')))
    sync=GatewaySynchronisation(store,services,SimpleNamespace(active=None))
    task=asyncio.create_task(sync.run())
    try:
        sync.request();await wait_for_state(sync,'attention')
        assert 'private-provider-test-key' not in sync.state['message']
        assert not sync.pending
        await asyncio.sleep(.2)
        services.apply.assert_awaited_once()
        services.apply.side_effect=None;services.apply.return_value=[]
        sync.request();await wait_for_state(sync,'ready')
        assert services.apply.await_count==2
    finally:
        task.cancel();await asyncio.gather(task,return_exceptions=True)
