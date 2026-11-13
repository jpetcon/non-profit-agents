"""Paired-browser controls for optional isolation, separate from tool approval."""
from fastapi import Request
from pydantic import BaseModel, ConfigDict, StrictBool

from control_panel.store import Conflict
from guardrails.settings import load_settings
from guardrails.policy import digest
from .activity import Busy, gate, require_idle
from .models import ConnectionProfile
from .runtime import validate_profile


class Toggle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: str
    enabled: StrictBool


def install_routes(app, store, chat, services, manager, response, idle):
    def save(settings, revision):
        idle()
        try:
            with gate(store.root):
                require_idle(store.root)
                with store.edit(revision):
                    store.save(store.policy_path, settings.model_dump(mode="json", exclude_none=True))
                chat.guardrails.invalidate_pending()
        except Busy as error:
            raise Conflict(str(error)) from None

    @app.get("/api/sandbox")
    async def status():
        result = manager.status(chat.guardrails.policy())
        result["revision"] = store.revision()
        synchronisation = app.state.synchronisation
        if synchronisation.pending:
            result["state"] = "applying"
        elif synchronisation.state['state'] == 'attention':
            result['state'] = 'needs_attention'
            result['checks'].append({'ok': False, 'message': 'Gateways could not apply the saved settings. Review their connection status on Overview.'})
        return response(result)

    @app.put("/api/sandbox")
    async def toggle(request: Request):
        data = Toggle.model_validate(await request.json())
        settings = load_settings(store.root)
        settings.sandbox.enabled = data.enabled
        save(settings, data.revision)
        return response({"revision": store.revision(), "enabled": settings.sandbox.enabled})

    @app.put("/api/sandbox/connections/{name}")
    async def review(name: str, request: Request):
        data = await request.json()
        spec = store.tools()["mcp_servers"].get(name)
        if not spec or spec.get("transport") != "stdio":
            raise ValueError("Choose a saved local MCP connection.")
        profile = ConnectionProfile.model_validate(data.get("profile"))
        if profile.configuration_hash != digest(spec):
            raise Conflict("The connection changed. Reload before reviewing sandbox access.")
        validate_profile(store.root, profile)
        settings = load_settings(store.root)
        settings.sandbox.connections[name] = profile
        save(settings, data.get("revision"))
        return response({"revision": store.revision()})

    async def start(request, operation):
        idle()
        data = await request.json()
        # Explicit user action, current revision, and a separate acknowledgement
        # for Windows account/firewall changes. Neither action enables the switch.
        with store.edit(data.get("revision")):
            if operation == "setup":
                import sys
                if sys.platform == "win32" and data.get("confirm_windows") is not True:
                    raise ValueError("Review and confirm the Windows sandbox account and firewall setup first.")
            try:
                job = manager.start(operation)
            except Busy as error:
                raise Conflict(str(error)) from None
        return response(job, 202)

    @app.post("/api/sandbox/setup")
    async def setup(request: Request):
        return await start(request, "setup")

    @app.post("/api/sandbox/check")
    async def check(request: Request):
        return await start(request, "check")

    @app.get("/api/sandbox/jobs/{job_id}")
    async def job_status(job_id: str):
        job = manager.jobs.get(job_id)
        if job is None:
            return response({"error": "This setup job is no longer available. Check sandbox status again."}, 404)
        return response(job)
