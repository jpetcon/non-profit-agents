"""Explicit, private runtime provisioning and offline readiness checks."""
import asyncio
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import sys
import time
import uuid

from guardrails.policy import PolicyDenied, digest
from tools.node_runtime import bundled_node, NodeRuntimeError
from .activity import directory, gate, lease, leases, require_idle
from .models import ConnectionProfile, PROFILE_REVISION, SRT_VERSION
from .runtime import RESOURCES, SandboxRunner, bounded_command, connection_profile, installation, platform_support, setup_environment


def publish(path, value):
    from control_panel.store import atomic_write
    atomic_write(path, json.dumps(value), private=True)


def supported_node(version):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version.strip())
    if not match:
        return False
    major, minor, _ = map(int, match.groups())
    return (major == 22 and minor >= 21) or (major == 24 and minor >= 5) or major in {26, 28}


class SandboxManager:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.jobs = {}
        self.tasks = set()

    def status(self, policy):
        base = directory(self.root)
        checks = []
        ready = False
        try:
            receipt = installation(self.root)
            ready = True
            checks.append({"ok": True, "message": "The installed runtime passed local isolation checks.", "checked_at": receipt.get("checked_at")})
        except PolicyDenied as error:
            checks.append({"ok": False, "message": str(error).removeprefix(error.rule + ': '), "code": error.rule})
        connections = []
        import yaml
        config = yaml.safe_load((self.root / "tools/config.yml").read_text())
        for name, spec in config.get("mcp_servers", {}).items():
            if spec.get("transport") != "stdio" or not spec.get("enabled", True):
                continue
            try:
                kind, profile = connection_profile(self.root, policy, name, spec)
                item = {"name": name, "label": spec.get("display_name") or name, "ready": ready, "profile": kind, "configuration_hash": digest(spec), "access": profile.model_dump()}
            except PolicyDenied as error:
                item = {"name": name, "label": spec.get("display_name") or name, "ready": False, "profile": "custom", "code": error.rule, "message": str(error).removeprefix(error.rule + ': '), "configuration_hash": digest(spec)}
            connections.append(item)
        active = leases(self.root)
        applying = any(j["state"] == "running" for j in self.jobs.values())
        failed = any(j['state'] == 'failed' for j in list(self.jobs.values())[-1:])
        state = "applying" if applying else "off" if not policy.sandbox.enabled else "needs_attention" if failed or platform_support() == 'unsupported' else "setup_needed" if not ready else "needs_attention" if any(not c["ready"] for c in connections) else "ready"
        return {"enabled": policy.sandbox.enabled, "state": state, "ready": ready, "support": platform_support(), "platform": sys.platform, "version": SRT_VERSION, "profile_revision": PROFILE_REVISION, "checks": checks, "connections": connections, "busy": bool(active), "jobs": list(self.jobs.values())[-5:], "experimental_message": "Windows sandbox support is experimental. SRT documents residual network and permission limitations; local checks do not establish equivalent guarantees across platforms." if sys.platform == "win32" else ""}

    def start(self, operation):
        # Register synchronously before returning: no launch can race setup's task.
        guard = lease(self.root, "setup")
        guard.__enter__()
        job = {"id": secrets.token_hex(12), "operation": operation, "state": "running", "message": "Checking local sandbox requirements…"}
        self.jobs[job["id"]] = job
        released = False
        def release(task=None):
            nonlocal released
            if not released:
                guard.__exit__(None, None, None)
                released = True
            if task is not None:
                self.tasks.discard(task)
                if task.cancelled() and job['state'] == 'running':
                    job.update(state='cancelled', message='Sandbox setup was cancelled. Check again before enabling it.')
        async def run():
            try:
                if operation == "setup":
                    await self.setup(job)
                else:
                    await self.check()
                job.update(state="complete", message="Sandbox checks passed. Use the switch to choose whether it runs.")
            except asyncio.CancelledError:
                job.update(state="cancelled", message="Sandbox setup was cancelled. Check again before enabling it.")
                raise
            except Exception as error:
                # Do not publish arbitrary package/SDK stderr or exceptions.
                message = str(error) if isinstance(error, (SetupError, PolicyDenied)) else "Sandbox setup or verification failed. Check the prerequisites and try again."
                if isinstance(error, PolicyDenied):
                    message = message.removeprefix(error.rule + ': ')
                job.update(state="failed", message=message)
            finally:
                release()
        task = asyncio.create_task(run())
        self.tasks.add(task)
        task.add_done_callback(release)
        return job

    async def setup(self, job):
        if platform_support() == "unsupported":
            raise SetupError("Sandboxing supports macOS, Linux and Windows only.")
        try:
            runtime = bundled_node()
        except NodeRuntimeError as error:
            raise SetupError(str(error)) from None
        node, npm_cli, uv = str(runtime.node), runtime.npm_cli, shutil.which('uv')
        code, version = await bounded_command([node, "--version"], env=setup_environment())
        if code or version.decode().strip() != 'v' + runtime.version or not supported_node(version.decode().strip()):
            raise SetupError("Kindred’s bundled tools need repair. Run uv sync, restart Kindred and retry sandbox setup.")
        required = ["rg"] + (["bwrap", "socat"] if sys.platform == "linux" else []) if os.name != "nt" else []
        missing = [name for name in required if not shutil.which(name)]
        if missing:
            raise SetupError("Administrator setup needed: install " + ", ".join(missing) + ". Linux also requires working unprivileged namespaces; do not disable system security settings.")
        if not uv:
            raise SetupError("Install uv to prepare the maintained Analytics connector, then retry.")
        base = directory(self.root)
        installations = base / "installations"
        installations.mkdir(exist_ok=True, mode=0o700)
        target = installations / secrets.token_hex(16)
        target.mkdir(mode=0o700)
        previous = (base / "current.json").read_bytes() if (base / "current.json").exists() else None
        activated = False
        try:
            for name in ["package.json", "package-lock.json"]:
                shutil.copyfile(RESOURCES / name, target / name)
            # The wheel's npm lives beside its private Node distribution, not
            # beside the Python console wrappers found on PATH. Invoke its JS
            # entrypoint directly on every platform, without a host shell.
            environment = setup_environment()
            environment.update(PATH=os.pathsep.join([str(Path(node).parent), environment.get("PATH", os.defpath)]), NPM_CONFIG_USERCONFIG=str(target / "empty.npmrc"), NPM_CONFIG_GLOBALCONFIG=str(target / "empty-global.npmrc"), NPM_CONFIG_CACHE=str(base / "npm-cache"))
            (target / "empty.npmrc").write_text("")
            (target / "empty-global.npmrc").write_text("")
            job["message"] = "Installing locked sandbox and Brave packages…"
            code, _ = await bounded_command([node, str(npm_cli), "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=target, env=environment, timeout=240, maximum=262144)
            if code:
                raise SetupError("Could not install locked npm packages. Check internet access and retry; the previous installation is retained.")
            job["message"] = "Preparing the locked Analytics environment…"
            code, _ = await bounded_command([uv, "venv", "--python", sys.executable, str(target / "analytics")], env=environment, timeout=60)
            if code:
                raise SetupError("Could not create the Analytics environment.")
            python = target / "analytics" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            code, _ = await bounded_command([uv, "pip", "sync", "--python", str(python), "--require-hashes", str(RESOURCES / "analytics.lock")], env=environment, timeout=240, maximum=262144)
            if code:
                raise SetupError("Could not install locked Analytics packages. Check internet access and retry.")
            receipt = {"directory": str(target), "node": node, "node_version": version.decode().strip(), "version": SRT_VERSION, "profile_revision": PROFILE_REVISION, "verified": False, "dependencies": {name: str(Path(shutil.which(name)).resolve()) for name in required}}
            if os.name == "nt":
                identity = uuid.uuid5(uuid.NAMESPACE_URL, str(self.root))
                receipt["windows"] = {"sandboxUser": "kindred-" + identity.hex[:10], "sublayerGuid": str(identity), "proxyPortRange": [61000, 61009]}
            publish(base / "current.json", receipt)
            activated = True
            if os.name == "nt":
                job["message"] = "Waiting for Windows administrator approval for the sandbox account and firewall rules…"
                code, output = await bounded_command([node, str(RESOURCES / "maintenance.mjs"), "windows-install", str(base / "current.json")], env=environment, timeout=180)
                if code or not (result := json.loads(output)).get("ok"):
                    raise SetupError("Windows setup was cancelled or could not provision this app’s sandbox. Existing SRT installations are not replaced automatically.")
                receipt["windows_helper"] = result["helper"]
                publish(base / "current.json", receipt)
            job["message"] = "Verifying file and network restrictions with local fixtures…"
            await self.check()
        except BaseException:
            if activated:
                if previous is not None:
                    from control_panel.store import atomic_write
                    atomic_write(base / "current.json", previous.decode(), private=True)
                elif not (base / "windows-dirty.json").exists():
                    (base / "current.json").unlink(missing_ok=True)
            # Preserve failed Windows installs for explicit repair of ACL state.
            if not (base / "windows-dirty.json").exists():
                shutil.rmtree(target, ignore_errors=True)
            raise

    async def check(self):
        receipt = installation(self.root, checked=False)
        receipt["verified"] = False
        publish(directory(self.root) / "current.json", receipt)
        code, version = await bounded_command([receipt["node"], "--version"], env=setup_environment())
        if code or not supported_node(version.decode().strip()):
            raise SetupError("The installed Node.js version is no longer compatible. Set up sandbox again.")
        runner = SandboxRunner(self.root)
        await runner.recover()
        if os.name == "nt":
            await runner.windows_cleanup()
        # A live local listener proves direct networking was refused rather than
        # simply failing because no service was listening. A second port proves
        # the proxy can reach an explicitly permitted fixture.
        async def respond(reader, writer):
            try:
                await asyncio.wait_for(reader.read(8192), 3)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nkindred-probe")
                await writer.drain()
            except (OSError, TimeoutError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(respond, "127.0.0.1", 0)
        forbidden = await asyncio.start_server(respond, "127.0.0.1", 0)
        probes = directory(self.root) / "probes"
        probes.mkdir(exist_ok=True, mode=0o700)
        sentinel = probes / "private.txt"
        sentinel.write_text("local-fixture")
        write_target = probes / "must-not-write.txt"
        write_target.unlink(missing_ok=True)
        port = server.sockets[0].getsockname()[1]
        denied_port = forbidden.sockets[0].getsockname()[1]
        # Only the internal readiness fixture can grant a loopback destination.
        # User profiles reject IP literals and cannot set this override.
        profile = ConnectionProfile.model_construct(configuration_hash="0" * 64, read_paths=[], write_paths=[], destinations=[f"127.0.0.1:{port}"])
        try:
            code, output = await runner.run([sys.executable, "-I", str(RESOURCES / "probe.py"), str(sentinel), str(write_target), str(denied_port), f"http://127.0.0.1:{port}/"], timeout=40, maximum=4096, force=True, internal=True, profile_override=profile, extra_reads=[RESOURCES / "probe.py"])
            checks = json.loads(output) if not code else {}
            if set(checks) != {"read_denied", "write_denied", "direct_network_denied", "proxy_allowed", "proxy_denied"} or not all(v is True for v in checks.values()) or write_target.exists():
                raise SetupError("Local isolation checks failed. Check the OS sandbox prerequisites; local tools remain blocked while sandboxing is on.")
            receipt.update(verified=True, verified_platform=sys.platform, checked_at=time.time(), architecture=platform.machine())
            publish(directory(self.root) / "current.json", receipt)
        finally:
            server.close()
            forbidden.close()
            await server.wait_closed()
            await forbidden.wait_closed()
            sentinel.unlink(missing_ok=True)
            write_target.unlink(missing_ok=True)

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


class SetupError(ValueError):
    pass
