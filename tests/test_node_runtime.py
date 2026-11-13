"""The two-command install supplies native Node and npm without global setup."""
import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools.node_runtime import bundled_node, NodeRuntimeError


def test_installed_native_node_and_npm_work_without_system_node(tmp_path):
    runtime=bundled_node()
    # A hostile/obsolete PATH must not select a global Node or npm. Invoking
    # the native binary directly also avoids a Python wrapper inside SRT.
    env={**os.environ,'PATH':str(tmp_path)}
    version=subprocess.check_output([str(runtime.node),'--version'],env=env,text=True).strip()
    assert version=='v'+runtime.version
    assert runtime.node.is_relative_to(Path(sys.prefix))
    with runtime.node.open('rb') as stream:
        assert stream.read(2) != b'#!'
    assert subprocess.check_output([str(runtime.node),str(runtime.npm_cli),'--version'],env=env,text=True).strip()


@pytest.mark.parametrize('windows',[False,True])
def test_packaged_layout_including_windows(tmp_path,monkeypatch,windows):
    import nodejs_wheel.executable as wheel
    import tools.node_runtime as module
    monkeypatch.setattr(wheel,'ROOT_DIR',str(tmp_path))
    monkeypatch.setattr(module,'os',SimpleNamespace(name='nt' if windows else 'posix'))
    node=tmp_path/('node.exe' if windows else 'bin/node')
    npm=tmp_path/'lib/node_modules/npm/bin/npm-cli.js'
    node.parent.mkdir(parents=True,exist_ok=True);node.write_bytes(b'native fixture')
    npm.parent.mkdir(parents=True);npm.write_text('// fixture')
    runtime=bundled_node()
    assert runtime.node==node and runtime.npm_cli==npm
    npm.unlink()
    with pytest.raises(NodeRuntimeError,match='uv sync'):bundled_node()


@pytest.mark.asyncio
async def test_setup_uses_private_node_when_path_has_no_node(store,tmp_path,monkeypatch):
    import sandboxing.manager as module
    runtime=bundled_node()
    seen=[]
    def which(name):
        assert name not in {'node','npm'}, 'Setup must not discover system Node'
        return str(tmp_path/name)
    monkeypatch.setattr(module.shutil,'which',which)
    async def command(argv,**kwargs):
        seen.append(argv)
        if '--version' in argv:return 0,('v'+runtime.version).encode()
        return 1,b''  # No downloads: inspect the exact package installation call.
    monkeypatch.setattr(module,'bounded_command',command)
    manager=module.SandboxManager(store.root)
    job=manager.start('setup')
    await asyncio.gather(*manager.tasks)
    assert job['state']=='failed' and 'locked npm packages' in job['message']
    assert seen==[[str(runtime.node),'--version'],[str(runtime.node),str(runtime.npm_cli),'ci','--ignore-scripts','--no-audit','--no-fund']]


@pytest.mark.asyncio
async def test_missing_private_runtime_gives_two_command_repair(store,monkeypatch):
    import sandboxing.manager as module
    def missing():
        raise NodeRuntimeError('Run uv sync and restart Kindred.')
    monkeypatch.setattr(module,'bundled_node',missing)
    manager=module.SandboxManager(store.root)
    job=manager.start('setup');await asyncio.gather(*manager.tasks)
    assert job['state']=='failed' and 'uv sync' in job['message']
    assert 'Install Node' not in job['message']


def test_uv_run_exposes_private_node_npm_npx_with_old_system_path(tmp_path):
    uv=shutil.which('uv')
    assert uv, 'The documented installation requires uv'
    source=Path(__file__).resolve().parents[1]
    # No sync/download: dependencies were supplied by the test's uv sync.
    # Private caches keep this check independent of a user's uv configuration.
    env={**os.environ,'PATH':str(tmp_path),'UV_CACHE_DIR':str(tmp_path/'uv-cache'),'UV_OFFLINE':'true'}
    script='''import json,shutil,subprocess,sys
result={name:shutil.which(name) for name in ['node','npm','npx']}
result['version']=subprocess.check_output(['node','--version'],text=True).strip()
print(json.dumps(result))
'''
    result=subprocess.run([uv,'run','--no-sync','--offline','python','-c',script],cwd=source,env=env,check=True,capture_output=True,text=True,timeout=20)
    actual=json.loads(result.stdout)
    assert actual['version']=='v'+bundled_node().version
    for name in ['node','npm','npx']:
        assert actual[name] and Path(actual[name]).is_relative_to(Path(sys.prefix))
