"""Own and supervise gateway subprocesses without touching unrelated services."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import signal
import socket
import sys
import time

import httpx
import psutil

from .store import Store, atomic_write


class Services:
    STARTUP_TIMEOUT = 60
    HEALTH_TIMEOUT = 12
    def __init__(self, store: Store):
        self.store = store
        from guardrails.runtime import Runtime
        self.guardrails = Runtime(store.root)
        self.lock = asyncio.Lock()
        self.processes: dict[str, asyncio.subprocess.Process] = {}
        self.readers: set[asyncio.Task] = set()
        self.records_path = store.local / "services.json"
        self.external_fingerprints = {}
        self.manual_stops = set()
        try:
            self.records = json.loads(self.records_path.read_text())
        except (OSError, ValueError):
            self.records = {}
        self.states = {name: {"name": name, "label": label, "status": "stopped", "detail": "Ready to start", "managed": False, "pending": False} for name, label in [("inference", "Inference gateway"), ("tools", "Tool gateway")]}

    def settings(self, name):
        if name == "inference":
            from urllib.parse import urlsplit
            url = urlsplit(self.store.yaml("models/model_config.yml")["gateway"]["url"])
            if url.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("Automatic service management requires a local inference gateway address.")
            return url.port or 4000, f"http://127.0.0.1:{url.port or 4000}"
        config = self.store.tools()["gateway"]
        if config["host"] not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Bind the tool gateway to loopback before managing it here.")
        return int(config["port"]), f"http://127.0.0.1:{config['port']}"

    def required_secrets(self, name):
        if name == "inference":
            config = self.store.yaml("inference/litellm-config.yml")
            keys = set()
            for entry in config["model_list"]:
                value = entry["litellm_params"].get("api_key", "")
                if value.startswith("os.environ/"):
                    keys.add(value.split("/", 1)[1])
            return keys
        keys = set()
        tools = self.store.tools()
        for spec in tools["mcp_servers"].values():
            if not spec.get("enabled", True):
                continue
            keys.update(spec.get("env_vars", []))
            keys.update(spec.get("env_secrets", {}).values())
            keys.update(spec.get("header_secrets", {}).values())
            keys.update((spec.get('native') or {}).get('secret_refs', {}).values())
            if spec.get("token_env"):
                keys.add(spec["token_env"])
            # OAuth is connected separately. Its missing client registration must
            # not prevent unrelated MCP connections from starting.
        for spec in tools["http_tools"].values():
            if spec.get("enabled", True):
                keys.update(h["secret"] for h in spec.get("headers", []) if h.get("secret"))
        return keys

    def fingerprint(self, name):
        content = self.store.yaml("inference/litellm-config.yml") if name == "inference" else self.store.tools()
        keys = self.required_secrets(name)
        if name == "tools":
            keys |= {(spec.get("auth") or {}).get("client_secret_env") for spec in content["mcp_servers"].values()} - {None, ""}
        values = {key: self.store.secret(key) for key in keys}
        return hashlib.sha256(json.dumps([content, values, self.guardrails.policy().revision, self.settings(name)], sort_keys=True).encode()).hexdigest()

    def owned(self, name):
        record = self.records.get(name)
        if not record:
            return None
        try:
            process = psutil.Process(record["pid"])
            if abs(process.create_time() - record["created"]) > 0.01 or Path(process.cwd()).resolve() != self.store.root:
                return None
            if process.cmdline() != record["command"] or process.status() == psutil.STATUS_ZOMBIE:
                return None
            return process
        except (psutil.Error, OSError, KeyError):
            return None

    def occupied(self, port):
        with socket.socket() as sock:
            sock.settimeout(0.2)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    async def health(self, name):
        try:
            async with asyncio.timeout(self.HEALTH_TIMEOUT):
                return await self._health(name)
        except TimeoutError:
            return False

    async def _health(self, name):
        _, base = self.settings(name)
        try:
            token = self.guardrails.admin_token(name)
            headers = {"Authorization": "Bearer " + token}
            async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
                check = await client.get(base + ("/health/liveliness" if name == "inference" else "/guardrails/health"), headers=headers)
                if check.status_code != 200 or check.json() != {"guardrails": 1, "revision": self.guardrails.policy().revision}:
                    return False
            if name == "inference":
                async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
                    response = await client.get(base + "/health/liveliness", headers=headers)
                    if response.status_code != 200:
                        return False
                    models = await client.get(base + "/v1/models", headers=headers)
                    expected = {e["model_name"] for e in self.store.yaml("inference/litellm-config.yml")["model_list"]}
                    return models.status_code == 200 and expected <= {m["id"] for m in models.json().get("data", [])}
            from fastmcp import Client
            from guardrails.client import tool_transport
            async def check():
                async with Client(tool_transport(base, token)) as client:
                    tools = await client.list_tools()
                    config = self.store.tools()
                    required = set(config["custom_tools"])
                    required.update(name for name, spec in config["http_tools"].items() if spec.get("enabled", True))
                    required.update(name for agent in self.store.agents()["agents"].values() for name in agent["tools"])
                    return required <= {tool.name for tool in tools}
            return await asyncio.wait_for(check(), 8)
        except (Exception, asyncio.TimeoutError):
            return False

    async def observe(self, name):
        state = self.states[name]
        if state["status"] == "starting":
            return state.copy()
        try:
            port, _ = self.settings(name)
            state["port"] = port
            owned = self.owned(name)
            state["managed"] = bool(owned)
            if owned:
                state["pending"] = self.records[name].get("fingerprint") != self.fingerprint(name)
                if state["status"] not in {"failed", "running"}:
                    state["status"] = "running" if await self.health(name) else "failed"
                    state["detail"] = "Running in the background" if state["status"] == "running" else "The process is running but its health check failed."
                elif state["status"] == "running" and not self.occupied(port):
                    state.update(status="failed", detail="The gateway stopped responding. Restart it to reconnect.")
            elif self.occupied(port):
                healthy = await self.health(name)
                state.update(status="external" if healthy else "failed", managed=False, detail="Already running outside this app. Stop its original terminal process to manage it here." if healthy else f"Port {port} is occupied by a service that did not pass the guarded gateway check. Stop the existing server in its original terminal, then choose Start gateway.")
                previous = self.external_fingerprints.setdefault(name, self.fingerprint(name))
                state["pending"] = previous != self.fingerprint(name)
            elif state["status"] in {"running", "external"}:
                state.update(status="stopped", managed=False, detail="The gateway has stopped.")
        except Exception as error:
            state.update(status="failed", detail=str(self.store.redact(str(error))))
        return state.copy()

    async def snapshot(self):
        return [await self.observe(name) for name in self.states]

    async def _read_log(self, name, process):
        path = self.store.local / "logs" / f"{name}.log"
        path.parent.mkdir(mode=0o700, exist_ok=True)
        handler = RotatingFileHandler(path, maxBytes=512 * 1024, backupCount=2, encoding="utf-8")
        os.chmod(path, 0o600)
        try:
            while line := await process.stdout.readline():
                text = self.store.redact(line.decode("utf-8", errors="replace").rstrip())
                handler.emit(logging.LogRecord(name, logging.INFO, "", 0, text, (), None))
        except (ValueError, asyncio.CancelledError):
            pass
        finally:
            handler.close()

    async def _start(self, name):
        try:
            return await self._start_checked(name)
        except asyncio.CancelledError:
            if self.owned(name):
                await self._stop(name)
            raise
        except Exception as error:
            self.states[name].update(status="failed", detail=self.store.redact(str(error)) or "Could not start the gateway. Check diagnostics and try again.")
            if self.owned(name):
                await self._stop(name, preserve_error=True)
            return self.states[name].copy()

    async def _start_checked(self, name):
        state = self.states[name]
        current = await self.observe(name)
        if current.get("pending") and self.owned(name):
            await self._stop(name)
            current = self.states[name].copy()
        if current["status"] in {"running", "external", "starting"}:
            return current
        if self.owned(name):
            state.update(status="failed", detail="The owned gateway needs attention. Restart it to reconnect.")
            return state.copy()
        missing = sorted(key for key in self.required_secrets(name) if not self.store.secret(key)) if name == "inference" else []
        if missing:
            state.update(status="needs_setup", detail="Add these secrets to connect: " + ", ".join(missing))
            return state.copy()
        port, _ = self.settings(name)
        if self.occupied(port):
            return await self.observe(name)
        if name == "inference":
            command = [sys.executable, "-m", "inference", "--config", str(self.store.root / "inference/litellm-config.yml"), "--host", "127.0.0.1", "--port", str(port)]
        else:
            command = [sys.executable, "-m", "tools.gateway"]
        state.update(status="starting", detail="Starting and checking the connection…", pending=False)
        env = self.store.process_environment()
        env["MASTERBRAND_PATH"] = str(self.store.brand_path)
        env["TOOL_CONFIG_PATH"] = str(self.store.tools_path)
        options = {"start_new_session": True} if os.name != "nt" else {"creationflags": 0x00000200}
        process = await asyncio.create_subprocess_exec(*command, cwd=self.store.root, env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, limit=1024 * 1024, **options)
        self.processes[name] = process
        identity = psutil.Process(process.pid)
        self.records[name] = {"pid": process.pid, "created": identity.create_time(), "command": command, "fingerprint": self.fingerprint(name)}
        atomic_write(self.records_path, json.dumps(self.records), private=True)
        task = asyncio.create_task(self._read_log(name, process))
        self.readers.add(task)
        task.add_done_callback(self.readers.discard)
        state["managed"] = True
        deadline = time.monotonic() + self.STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if process.returncode is not None:
                break
            try:
                async with asyncio.timeout(max(0, deadline - time.monotonic())):
                    healthy = await self.health(name)
            except TimeoutError:
                break
            if healthy:
                state.update(status="running", detail="Running in the background")
                return state.copy()
            await asyncio.sleep(min(0.4, max(0, deadline - time.monotonic())))
        state.update(status="failed", detail="Startup did not complete. Open diagnostics to see the connection error.")
        await self._stop(name, preserve_error=True)
        return state.copy()

    async def _stop(self, name, preserve_error=False):
        process = self.owned(name)
        if not process:
            if self.occupied(self.settings(name)[0]):
                raise ValueError("This service was started outside the app. Stop it in its original terminal first.")
        else:
            try:
                children = process.children(recursive=True)
                process.terminate()
                for child in children:
                    try:
                        child.terminate()
                    except psutil.Error:
                        pass
                _, alive = await asyncio.to_thread(psutil.wait_procs, [process, *children], timeout=5)
                for child in alive:
                    try:
                        child.kill()
                    except psutil.Error:
                        pass
            except psutil.Error:
                pass
            tracked = self.processes.pop(name, None)
            if tracked:
                await tracked.wait()
        self.records.pop(name, None)
        atomic_write(self.records_path, json.dumps(self.records), private=True)
        if not preserve_error:
            self.states[name].update(status="stopped", detail="Stopped", pending=False, managed=False)

    async def action(self, name, action):
        if name not in self.states or action not in {"start", "stop", "restart"}:
            raise ValueError("Choose a valid service and action.")
        async with self.lock:
            if action == "stop":
                self.manual_stops.add(name)
            else:
                self.manual_stops.discard(name)
            if action in {"stop", "restart"}:
                await self._stop(name)
            if action in {"start", "restart"}:
                await self._start(name)
        return await self.snapshot()

    async def start_ready(self):
        # Separate processes start in parallel; the dashboard stays responsive.
        async def start(name):
            try:
                await self._start(name)
            except Exception as error:
                self.states[name].update(status="failed", detail=self.store.redact(str(error)))
        async with self.lock:
            # A maintained preset can bootstrap its reviewed, pinned connection
            # metadata. Unknown commands still require an explicit access review.
            from guardrails.settings import curated_connection, BRAVE_TOOLS
            from guardrails.policy import digest
            from .connections import discover_connection
            for name, spec in self.store.tools()["mcp_servers"].items():
                known = [t for t in self.store.catalog() if t.get("server") == name]
                required = {tool for agent in self.store.agents()["agents"].values() for tool in agent["tools"] if tool.startswith(name + "_") and tool.removeprefix(name + "_") in BRAVE_TOOLS}
                if spec.get("enabled", True) and curated_connection(spec) and (not required <= {t["name"] for t in known} or not known or any("input_schema" not in t or t.get("configuration_hash") != digest(spec) for t in known)):
                    try:
                        await discover_connection(self.store, self.guardrails, name)
                    except Exception as error:
                        self.states["tools"].update(status="failed", detail=self.store.redact(str(error)))
            await asyncio.gather(*(start(name) for name in self.states))

    async def apply(self):
        async with self.lock:
            for name in self.states:
                if name in self.manual_stops:
                    continue
                await self.observe(name)
                if self.states[name].get("pending"):
                    if not self.owned(name) and self.occupied(self.settings(name)[0]):
                        self.states[name]["detail"] = "Settings changed. Restart this externally managed gateway in its original terminal to reconnect."
                        continue
                    await self._stop(name)
                    await self._start(name)
                elif self.states[name]["status"] in {"needs_setup", "stopped", "failed"}:
                    if self.owned(name):
                        await self._stop(name)
                    await self._start(name)
        return await self.snapshot()

    def logs(self, name):
        if name not in self.states:
            raise ValueError("Unknown service.")
        path = self.store.local / "logs" / f"{name}.log"
        return self.store.redact(path.read_text(errors="replace")[-20000:] if path.exists() else "No logs yet. Externally started services keep logs in their original terminal.")

    async def close(self):
        for name in self.states:
            if self.owned(name):
                await self._stop(name)
        if self.readers:
            await asyncio.gather(*self.readers, return_exceptions=True)
