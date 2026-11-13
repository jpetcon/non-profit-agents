"""Loopback-only management API and buildless browser application."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
from pathlib import Path
import secrets

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from agents.config import AppConfig, AgentConfig, TeamConfig

from tools.definitions import HTTPToolSpec, MCPSpec
from .chat import Chat
from .model_management import ModelManager, PROVIDERS, location_of
from .security import LocalSecurity, redacted_logging
from .services import Services
from .store import Brand, Conflict, Store, slug

STATIC = Path(__file__).parent / "static"


def create_app(root=None, *, auto_start=True, pairing_token=None, service_factory=Services, chat_backend=None):
    store = Store(root or Path(__file__).resolve().parent.parent)
    security = LocalSecurity(pairing_token)
    services = service_factory(store)
    chat = Chat(store, chat_backend)
    from .mcp_auth import AuthenticationManager
    authentication = AuthenticationManager(store, chat.guardrails, busy=lambda: bool(chat.active and not chat.active.done()))
    store.authentication = authentication
    chat.guardrails.invalidate_pending()
    models = ModelManager(store)
    from .synchronisation import GatewaySynchronisation
    synchronisation = GatewaySynchronisation(store, services, chat)
    from sandboxing.manager import SandboxManager
    sandbox = SandboxManager(store.root)
    store.on_change = synchronisation.request
    jobs = set()
    operation_error = ""

    def launch(coro):
        nonlocal operation_error
        operation_error = ""
        async def run():
            nonlocal operation_error
            try:
                await coro
            except asyncio.CancelledError:
                raise
            except Exception as error:
                operation_error = store.redact(str(error))[:1000]
        task = asyncio.create_task(run())
        jobs.add(task)
        task.add_done_callback(jobs.discard)

    @asynccontextmanager
    async def lifespan(app):
        with redacted_logging(store):
            launch(synchronisation.run())
            if auto_start:
                launch(services.start_ready())
            try:
                yield
            finally:
                store.on_change = None
                await sandbox.close()
                for task in list(jobs):
                    task.cancel()
                await asyncio.gather(*jobs, return_exceptions=True)
                await authentication.close()
                await chat.close()
                await services.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.security = store, security
    app.state.services, app.state.chat = services, chat
    app.state.synchronisation = synchronisation
    app.state.sandbox = sandbox
    app.state.authentication = authentication

    def response(value, status=200):
        return JSONResponse(store.redact(value), status_code=status)

    async def service_snapshot():
        statuses = await services.snapshot()
        # Also pick up edits made directly in the workspace. A failed update
        # needs an explicit retry rather than an endless restart loop.
        if any(s.get("pending") for s in statuses) and synchronisation.state["state"] == "ready":
            synchronisation.request()
        elif synchronisation.state["state"] == "attention" and all(s["status"] in {"running", "external"} and not s.get("pending") for s in statuses):
            synchronisation.state = {"state": "ready", "message": ""}
        return statuses

    @app.middleware("http")
    async def protect(request, call_next):
        host = request.headers.get("host", "")
        origin = request.headers.get("origin")
        if not security.local_host(host) or (origin and origin != "http://" + host) or request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"error": "This app accepts requests from its local browser only."}, 403)
        if request.url.path.startswith("/api/"):
            if request.url.path != "/api/pair":
                csrf = security.csrf(request.cookies.get("local_session", ""))
                if not csrf:
                    return JSONResponse({"error": "Open the pairing link from the app launcher to connect this browser."}, 401)
                if request.method not in {"GET", "HEAD"} and not secrets.compare_digest(csrf, request.headers.get("x-csrf-token", "")):
                    return JSONResponse({"error": "Browser security check failed. Reload this page."}, 403)
            if request.method not in {"GET", "HEAD"}:
                if request.headers.get("content-type", "").split(";")[0] != "application/json":
                    return JSONResponse({"error": "Send a JSON request."}, 415)
                # Enforce a bound even for chunked bodies.
                data = bytearray()
                async for chunk in request.stream():
                    data.extend(chunk)
                    if len(data) > 1024 * 1024:
                        return JSONResponse({"error": "This request is too large."}, 413)
                request._body = bytes(data)
                # Changes to live routing, secrets or policy cannot invalidate
                # a response midway through its guarded execution.
                config_change = request.url.path.startswith(("/api/models", "/api/secrets")) or (request.url.path.startswith("/api/connections") and "/auth" not in request.url.path and not request.url.path.endswith("/test")) or (request.url.path.startswith("/api/http-tools") and not request.url.path.endswith("/test"))
                if config_change and chat.active and not chat.active.done():
                    return JSONResponse({"error": "Finish or stop the current response before changing connections or models. Saved changes connect automatically."}, 409)
        result = await call_next(request)
        result.headers.update({
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        })
        return result

    @app.exception_handler(ValueError)
    async def invalid(request, error):
        from tools.mcp_auth import AuthenticationRequired
        if isinstance(error, AuthenticationRequired):
            from .issues import issue
            problem = issue("connection.auth_required", actions=[{"kind": "auth", "target": error.connection, "label": "Sign in to connection"}])
            return response({"error": problem["message"], "issue": problem}, 409)
        if request.url.path.startswith("/api/conversations/") and request.url.path.endswith("/messages"):
            from .issues import error_issue
            problem = error_issue(error)
            return response({"error": problem["message"], "issue": problem}, 409 if isinstance(error, Conflict) else 400)
        if isinstance(error, ValidationError):
            detail = "; ".join(str(e["msg"]) for e in error.errors(include_input=False, include_url=False))
        elif isinstance(error, json.JSONDecodeError):
            detail = "The request contains invalid JSON."
        else:
            detail = str(error)
        return response({"error": detail}, 409 if isinstance(error, Conflict) else 400)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, error):
        return response({"error": "Check the request fields and try again."}, 422)

    @app.exception_handler(Exception)
    async def unexpected(request, error):
        return response({"error": "This action could not be completed. Check your configuration files and try again."}, 500)

    @app.get("/")
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.post("/api/pair")
    async def pair(request: Request):
        data = await request.json()
        session, csrf = security.pair(str(data.get("token", "")))
        result = response({"csrf": csrf})
        result.set_cookie("local_session", session, httponly=True, samesite="strict", max_age=12 * 3600, path="/")
        return result

    @app.get("/api/session")
    async def session(request: Request):
        return response({"csrf": security.csrf(request.cookies.get("local_session", ""))})

    def catalog():
        tools = store.tools()
        local = [{"name": name, "label": spec.get("display_name") or name.replace("_", " ").title(), "description": spec.get("description", ""), "kind": kind, "enabled": spec.get("enabled", True)} for section, kind in [("custom_tools", "Python"), ("http_tools", "API")] for name, spec in tools[section].items()]
        known = {t["name"] for t in local}
        remote = store.catalog()
        # Keep existing assignments visible before a connection has been discovered.
        for agent in store.agents()["agents"].values():
            for name in agent["tools"]:
                if name not in known and not any(t["name"] == name for t in remote):
                    remote.append({"name": name, "label": name.replace("_", " ").title(), "description": "Connect and discover this tool to verify availability.", "kind": "MCP"})
        return local + remote

    @app.get("/api/state")
    async def state():
        inference = store.yaml("inference/litellm-config.yml")
        routing = [{"alias": item["model_name"], "model": item["litellm_params"]["model"], "location": location_of(item["litellm_params"])} for item in inference["model_list"]]
        from .mcp_setup import connection_summaries
        connection_setup = connection_summaries(store, chat.guardrails, authentication.vault)
        from connectors.dashboard import normalised_connections, available_connections
        connections = normalised_connections(store, authentication, connection_setup)
        return response({"revision": store.revision(), "agents": store.agents(), "tools": store.tools(), "connections": connections, "available_connections": available_connections(store), "connection_setup": connection_setup, "connection_auth": {name: authentication.status(name) for name, spec in store.tools()["mcp_servers"].items() if spec.get("enabled", True)}, "catalog": catalog(), "models": store.models(), "model_catalog": models.list(), "providers": PROVIDERS, "brand": store.brand(), "secrets": store.secret_metadata(), "routing": routing, "services": await service_snapshot(), "services_busy": services.lock.locked() or synchronisation.pending, "synchronisation": synchronisation.state, "chat_active": bool(chat.active and not chat.active.done()), "sandbox": sandbox.status(chat.guardrails.policy())})

    @app.get("/api/models")
    async def model_list():
        return response({"models": models.list(), "providers": PROVIDERS, "revision": store.revision()})

    @app.post("/api/models")
    @app.api_route("/api/models/{name}", methods=["PUT", "DELETE"])
    async def edit_model(request: Request, name: str | None = None):
        data = await request.json()
        with store.edit(data.get("revision")):
            if request.method == "DELETE":
                models.delete(name)
            else:
                name = models.save(name, data.get("model", {}))
        return response({"name": name, "revision": store.revision()})

    def identifier(label, existing):
        base = slug(label)
        name, suffix = base, 2
        while name in existing:
            name = f"{base[:58]}_{suffix}"
            suffix += 1
        return name

    @app.get("/api/teams")
    async def team_list():
        config = store.agents()
        return response({"teams": config["teams"], "default_team": config["default_team"], "revision": store.revision()})

    @app.post("/api/teams")
    @app.api_route("/api/teams/{name}", methods=["PUT", "DELETE"])
    async def edit_team(request: Request, name: str | None = None):
        data = await request.json()
        with store.edit(data.get("revision")):
            config = store.agents()
            current = AppConfig.model_validate(config)
            if name and name not in config["teams"]:
                raise ValueError("This team no longer exists.")
            if request.method == "DELETE":
                if len(config["teams"]) == 1:
                    raise ValueError("Keep at least one team. Create another team before deleting this one.")
                if chat.active_id and chat.get(chat.active_id).get("team") == name:
                    raise Conflict("Stop this team's current chat response before deleting it.")
                if name == config["default_team"]:
                    replacement = data.get("replacement_default")
                    if not isinstance(replacement, str) or replacement == name or replacement not in config["teams"]:
                        raise ValueError("Choose another team as the new default before deleting this one.")
                    config["default_team"] = replacement
                    config["root"] = config["teams"][replacement]["root"]
                for member in current.team_members(name):
                    del config["agents"][member]
                del config["teams"][name]
            else:
                raw = data.get("team", {})
                display = str(raw.get("display_name", "")).strip()
                if not display:
                    raise ValueError("Give the team a name.")
                if name is None:
                    name = identifier(display, config["teams"])
                    root = identifier(display + " coordinator", config["agents"])
                    spec = {"display_name": display + " coordinator", "description": raw.get("description", ""), "instruction": "Coordinate this team's work. Delegate tasks to the appropriate specialists and combine their findings. Ask for clarification when needed. Never invent tool results.", "models": [next(iter(store.models()))], **data.get("coordinator", {}), "sub_agents": []}
                    config["agents"][root] = AgentConfig.model_validate(spec).model_dump()
                else:
                    root = config["teams"][name]["root"]
                config["teams"][name] = TeamConfig.model_validate({**raw, "display_name": display, "root": root}).model_dump()
                if data.get("default") is True:
                    config["default_team"], config["root"] = name, root
            store.save(store.agents_path, store.validate_agents(config))
        return response({"name": name, "revision": store.revision()})

    @app.api_route("/api/agents", methods=["POST"])
    @app.api_route("/api/agents/{name}", methods=["PUT", "DELETE"])
    async def edit_agent(request: Request, name: str | None = None):
        data = await request.json()
        with store.edit(data.get("revision")):
            config = store.agents()
            agents = config["agents"]
            current = AppConfig.model_validate(config)
            roots = {team["root"] for team in config["teams"].values()}
            if name and name not in agents:
                raise ValueError("This agent no longer exists.")
            if request.method == "DELETE":
                if name in roots or agents[name]["sub_agents"]:
                    raise ValueError("Keep each team's coordinator and move this agent's specialists to another supervisor before deleting it.")
                del agents[name]
                for spec in agents.values():
                    spec["sub_agents"] = [child for child in spec["sub_agents"] if child != name]
            else:
                spec = data.get("agent", {})
                display = str(spec.get("display_name", "")).strip()
                if not display:
                    raise ValueError("Give the agent a name.")
                name = name or identifier(display, agents)
                children = agents.get(name, {}).get("sub_agents", [])
                agent = {**spec, "sub_agents": children}
                team = data.get("team") or (current.team_for_agent(name) if name in current.agents else config["default_team"])
                if team not in config["teams"]:
                    raise ValueError("Choose an existing team.")
                if name in roots and current.team_for_agent(name) != team:
                    raise ValueError("A coordinator stays with its team. Move specialists or create another team instead.")
                parent = data.get("parent") or config["teams"][team]["root"]
                if name not in roots and parent not in current.team_members(team):
                    raise ValueError("Choose a supervising agent from the selected team.")
                agents[name] = agent
                for key, other in agents.items():
                    if key != name:
                        other["sub_agents"] = [child for child in other["sub_agents"] if child != name]
                if name not in roots:
                    agents[parent]["sub_agents"].append(name)
            store.save(store.agents_path, store.validate_agents(config))
        return response({"name": name, "revision": store.revision()})

    def tool_references(name, namespace=False):
        config = store.agents()
        return [store.agent_label(key, config) for key, spec in config["agents"].items() if any(tool == name or (namespace and tool.startswith(name + "_")) for tool in spec["tools"])]

    @app.api_route("/api/http-tools", methods=["POST"])
    @app.api_route("/api/http-tools/{name}", methods=["PUT", "DELETE"])
    @app.api_route("/api/connections", methods=["POST"])
    @app.api_route("/api/connections/{name}", methods=["PUT", "DELETE"])
    async def edit_tool(request: Request, name: str | None = None):
        data = await request.json()
        connection = request.url.path.startswith("/api/connections")
        section = "mcp_servers" if connection else "http_tools"
        with store.edit(data.get("revision")):
            config = store.tools()
            if name and name not in config[section]:
                raise ValueError("This item no longer exists.")
            if request.method == "DELETE":
                refs = tool_references(name, namespace=connection)
                if refs:
                    raise ValueError("Remove this capability from these agents first: " + ", ".join(refs))
                del config[section][name]
            else:
                spec = (MCPSpec if connection else HTTPToolSpec).model_validate(data.get("spec", {})).model_dump(exclude_none=True)
                if not spec["display_name"].strip():
                    raise ValueError("Give this capability a name.")
                name = name or identifier(spec["display_name"], set(config["http_tools"]) | set(config["custom_tools"]) | set(config["mcp_servers"]))
                config[section][name] = spec
            store.save(store.tools_path, config)
            if connection and request.method == "DELETE":
                store.remember_catalog(name, [])
        if connection and request.method == "DELETE":
            await authentication.cancel(name)
            authentication.vault.disconnect(name)
        return response({"name": name, "revision": store.revision()})

    @app.get("/api/connections/{name}/auth")
    async def auth_status(name: str):
        return response(authentication.status(name))

    async def auth_payload(request, allowed):
        from guardrails.validation import strict_json
        data = strict_json(await request.body())
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError("Send the supported sign-in settings as a JSON object.")
        if len(json.dumps(data).encode()) > 65536:
            raise ValueError("Credential JSON must be smaller than 64 KB.")
        return data

    @app.post("/api/connections/{name}/auth/start")
    async def auth_start(name: str, request: Request):
        data = await auth_payload(request, {"client_json"})
        return response(await authentication.start(name, data.get("client_json")), 202)

    @app.post("/api/connections/{name}/auth/approve")
    async def auth_approve(name: str, request: Request):
        data = await auth_payload(request, {"transaction"})
        transaction = authentication.transactions.get(name)
        if not transaction:
            raise ValueError("This sign-in expired. Start again.")
        transaction.approve(data.get("transaction"))
        return response(authentication.status(name))

    @app.post("/api/connections/{name}/auth/cancel")
    async def auth_cancel(name: str):
        await authentication.cancel(name)
        return response(authentication.status(name))

    @app.post("/api/connections/{name}/auth/disconnect")
    async def auth_disconnect(name: str):
        return response(await authentication.disconnect(name))

    @app.post("/api/connections/{name}/auth/import")
    async def auth_import(name: str, request: Request):
        data = await auth_payload(request, {"credentials"})
        return response(await authentication.import_google(name, data.get("credentials")))

    @app.post("/api/connections/{name}/test")
    async def test_connection(name: str):
        from .connections import discover_connection
        def before_save():
            if chat.active and not chat.active.done():
                raise Conflict("A response started during this test. Finish it before updating this connection.")
        tools = await discover_connection(store, chat.guardrails, name, before_save=before_save)
        return response({"tools": tools, "message": f"Connected. Found {len(tools)} tools. Saved changes connect automatically."})

    @app.post("/api/http-tools/{name}/test")
    async def test_http(name: str, request: Request):
        from fastmcp import Client
        raw = store.tools()["http_tools"].get(name)
        if not raw:
            raise ValueError("Save this tool before testing it.")
        data = await request.json()
        config = AppConfig.model_validate(store.agents())
        agent = data.get("agent") or next((key for key, spec in config.agents.items() if name in spec.tools), "")
        if agent not in config.agents or name not in config.agents[agent].tools:
            raise ValueError("Assign this tool to an agent before testing it through the guarded gateway.")
        run = chat.guardrails.start_run("tool-test", config.team_for_agent(agent), data.get("data_class", "public"))
        token = chat.guardrails.issue(run, agent, "tools")
        gateway = store.tools()["gateway"]
        try:
            from guardrails.client import tool_transport, verify_gateway
            url = f"http://{gateway['host']}:{gateway['port']}"
            await verify_gateway(url, "tools", token, chat.guardrails.policy().revision)
            async with Client(tool_transport(url, token), timeout=510) as client:
                result = await client.call_tool(name, data.get("arguments", {}))
                return response({"result": result.data})
        finally:
            chat.guardrails.revoke(run)

    @app.put("/api/masterbrand")
    async def edit_brand(request: Request):
        data = await request.json()
        with store.edit(data.get("revision")):
            brand = Brand.model_validate(data.get("brand", {})).model_dump()
            store.save(store.brand_path, brand, json_file=True)
        return response({"revision": store.revision()})

    @app.api_route("/api/secrets/{name}", methods=["PUT", "DELETE"])
    async def edit_secret(name: str, request: Request):
        data = await request.json()
        with store.edit(data.get("revision")):
            if name == "LITELLM_PROXY_API_KEY":
                name = "LITELLM_MASTER_KEY"
            if request.method == "DELETE" and store.secret_references().get(name):
                raise ValueError("This secret is in use. Remove its connection references before deleting it.")
            value = None if request.method == "DELETE" else data.get("value")
            if request.method != "DELETE" and not isinstance(value, str):
                raise ValueError("Enter a secret value.")
            updates = {name: value}
            if name == "LITELLM_MASTER_KEY":
                if value and not value.startswith("sk-"):
                    raise ValueError("Use a local gateway password starting with sk-.")
                updates["LITELLM_PROXY_API_KEY"] = value
            store.write_secrets(updates)
        return response({"revision": store.revision(), "secrets": store.secret_metadata()})

    @app.get("/api/services")
    async def service_state():
        return response({"services": await service_snapshot(), "services_busy": services.lock.locked() or synchronisation.pending, "synchronisation": synchronisation.state, "chat_active": bool(chat.active and not chat.active.done()), "operation_error": operation_error})

    @app.get("/api/services/{name}/logs")
    async def service_logs(name: str):
        return response({"text": services.logs(name)})

    def idle():
        if chat.active and not chat.active.done():
            raise Conflict("Stop the current chat response before changing services.")
        if services.lock.locked():
            raise Conflict("A service change is already underway. Wait for it to finish.")

    from guardrails.dashboard import install_routes
    install_routes(app, store, chat, services, response, idle)
    from sandboxing.dashboard import install_routes as install_sandbox_routes
    install_sandbox_routes(app, store, chat, services, sandbox, response, idle)
    from .mcp_setup import install_routes as install_setup_routes
    install_setup_routes(app, store, authentication, chat.guardrails, response, idle)

    @app.post("/api/services/apply")
    async def apply_services():
        idle()
        synchronisation.request()
        return response({"message": "Reconnecting gateways. Status will update automatically."}, 202)

    @app.post("/api/services/{name}/{action}")
    async def service_action(name: str, action: str):
        idle()
        if name not in services.states or action not in {"start", "stop", "restart"}:
            raise ValueError("Choose a valid service action.")
        current = await services.observe(name)
        if action in {"stop", "restart"} and not current.get("managed") and current["status"] != "stopped":
            raise ValueError("Stop this externally managed gateway in its original terminal first.")
        launch(services.action(name, action))
        return response({"message": "Service change started."}, 202)

    @app.get("/api/conversations")
    async def conversations():
        return response({"conversations": chat.list()})

    @app.get("/api/chat/requirements")
    async def requirements(conversation: str | None = None, team: str | None = None, agent: str | None = None, problem: str | None = None):
        from .requirements import chat_requirements
        from .issues import issue, MESSAGES
        statuses = await service_snapshot()
        problems = chat_requirements(store, chat, statuses, conversation=conversation, team=team, agent=agent, busy=services.lock.locked() or synchronisation.pending, problem=issue(problem) if problem in MESSAGES else None)
        return response({"requirements": problems, "ready": not problems, "synchronisation": synchronisation.state})

    @app.post("/api/conversations")
    async def create_conversation(request: Request):
        data = await request.json()
        return response(chat.create(data.get("agent"), data.get("team"), data.get("data_class", "public")), 201)

    @app.post('/api/chat/sanitise')
    async def sanitise(request: Request):
        from guardrails.validation import sanitise_draft
        data = await request.json()
        text = data.get('message') if isinstance(data, dict) else None
        if not isinstance(text, str) or len(text) > 32000:
            raise ValueError('Supply a draft of up to 32,000 characters.')
        draft = sanitise_draft(text)
        message = 'Detected details removed locally. Check the whole draft before sending; patterns cannot find every personal detail.' if draft != text else 'These details need manual editing. Your message has not been sent. Check the whole draft before sending.'
        return response({'draft': draft, 'message': message})

    @app.get("/api/conversations/{conversation}")
    async def get_conversation(conversation: str):
        return response(chat.get(conversation))

    @app.post('/api/conversations/{conversation}/context/reset')
    async def reset_context(conversation: str):
        return response(chat.reset_context(conversation))

    @app.delete("/api/conversations/{conversation}")
    async def delete_conversation(conversation: str):
        await chat.delete(conversation)
        return response({"deleted": True})

    @app.post("/api/chat/cancel")
    async def cancel():
        await chat.cancel()
        return response({"stopped": True})

    @app.post("/api/conversations/{conversation}/messages")
    async def send(conversation: str, request: Request):
        data = await request.json()
        from .requirements import chat_requirements
        statuses = await service_snapshot()
        problems = chat_requirements(store, chat, statuses, conversation=conversation, busy=services.lock.locked() or synchronisation.pending)
        if problems:
            return response({"error": problems[0]["message"], "requirements": problems}, 409)
        if services.lock.locked() or synchronisation.pending:
            raise Conflict("The gateways are connecting saved changes automatically. Your message has not been sent; try again when they are ready.")
        statuses = await service_snapshot()
        # A service operation can begin while snapshot() awaits its health check.
        if services.lock.locked() or synchronisation.pending:
            raise Conflict("The gateways are connecting saved changes automatically. Your message has not been sent; try again when they are ready.")
        if any(s["status"] not in {"running", "external"} or s.get("pending") for s in statuses):
            details = " ".join(s["label"] + ": " + s["detail"] for s in statuses if s["status"] not in {"running", "external"})
            raise Conflict(details or "Saved settings are reconnecting automatically. Check gateway status in Overview.")
        queue = chat.start(conversation, data.get("message"))
        async def events():
            try:
                while True:
                    item = await queue.get()
                    yield "data: " + json.dumps(item) + "\n\n"
                    if item["type"] == "done":
                        break
            finally:
                if chat.active_id == conversation:
                    await chat.cancel()
        return StreamingResponse(events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
