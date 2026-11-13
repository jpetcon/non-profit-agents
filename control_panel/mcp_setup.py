"""Small, dashboard-owned MCP setup adapters; no tool execution or model calls."""
from __future__ import annotations

import asyncio
import secrets
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Request
import httpx
from pydantic import Field

from guardrails.dashboard import AccessChoice
from guardrails.network import permitted_url, transport_for
from guardrails.policy import Strict, PolicyDenied, canonical, digest
from guardrails.settings import BRAVE_COMMAND, bind_access, curated_connection, definitions, load_settings
from tools.definitions import MCPSpec, check_url, example_endpoint
from .store import Conflict, slug


from connectors.registry import catalogue, preset as connector_preset, CATEGORIES, REVISION
PRESETS = catalogue()


class Check(Strict):
    url: str = Field(min_length=1, max_length=2048)


class Setup(Strict):
    revision: str
    preset: str = Field(max_length=80)
    display_name: str = Field(default="", max_length=120)
    url: str = Field(default="", max_length=2048)
    authentication: Literal["none", "oauth", "key"] = "none"
    api_key: str = Field(default="", max_length=16384)
    confirm_local: bool = False
    options: dict[str, str] = Field(default_factory=dict, max_length=12)
    credentials: dict[str, str] = Field(default_factory=dict, max_length=8)


class Review(AccessChoice):
    schema_hash: str


class Complete(Strict):
    revision: str
    configuration_hash: str
    reviews: dict[str, Review] = Field(max_length=500)
    assignments: dict[str, list[str]] = Field(max_length=500)


class ProviderSetup(Strict):
    revision: str
    client_json: dict
    project: str = Field(min_length=1, max_length=128)


class ProviderDelete(Strict):
    revision: str


class ReplaceKey(Strict):
    revision: str
    api_key: str = Field(min_length=1, max_length=16384)


async def payload(request, model):
    from guardrails.validation import strict_json
    raw = await request.body()
    if len(raw) > 131072:
        raise ValueError("These setup settings are too large.")
    return model.model_validate(strict_json(raw))


def remote_url(value, policy):
    value = value.strip()
    check_url(value)
    parsed = urlsplit(value)
    if parsed.query or parsed.fragment:
        raise ValueError("Use a server link without a query or fragment. Special endpoint settings are available under Advanced.")
    local = permitted_url(value, [value], policy.local_endpoints)
    if example_endpoint(value) and not local:
        raise ValueError("This is an example address. Enter the link to your actual MCP server.")
    return value


async def check_connection(url, policy):
    url = remote_url(url, policy)
    # Inspect headers only: an MCP GET can otherwise be an endless SSE stream.
    # No cookies, credentials, tool discovery, metadata fetches or redirects.
    try:
        async with asyncio.timeout(10):
            async with httpx.AsyncClient(transport=transport_for(url, [url], policy.local_endpoints, max_bytes=16384, max_requests=1), trust_env=False, follow_redirects=False, timeout=8) as client:
                async with client.stream("GET", url, headers={"Accept": "application/json, text/event-stream"}) as result:
                    challenge = result.headers.get("www-authenticate", "")[:8192].lower()
                    if result.status_code == 401 and "bearer" in challenge and "resource_metadata=" in challenge:
                        return {"authentication": "oauth", "code": "connection.sign_in", "message": "This server advertises browser sign-in. You will review the provider and permissions before continuing."}
                    if result.status_code in {401, 403}:
                        return {"authentication": "unknown", "code": "connection.auth_unknown", "message": "This server requires access. Choose the sign-in method in its setup instructions; an API key is sent as a bearer token."}
                    return {"authentication": "unknown", "code": "connection.auth_unknown", "message": "The server did not advertise a sign-in method. Choose the method in its instructions. Connecting will verify it without executing tools."}
    except PolicyDenied:
        raise
    except (httpx.RequestError, TimeoutError):
        raise ValueError("The server could not be reached. Check the link and network, then try again.") from None


def connection_view(store, runtime, name):
    spec = store.tools()["mcp_servers"].get(name)
    if not spec:
        raise ValueError("This connection no longer exists.")
    policy, settings = runtime.policy(), load_settings(store.root)
    maintained = connector_preset(spec["managed"]["preset"]) if spec.get("managed") else None
    items = []
    for item in definitions(store.root):
        if item.get("server") != name or item.get("configuration_hash") != digest(spec):
            continue
        rule = policy.tools.get(item["name"])
        current = bool(rule and rule.schema_hash == item["schema_hash"] and rule.configuration_hash == item["configuration_hash"])
        permission = "blocked" if not current or item["name"] in settings.blocked_tools else "read" if rule.classification == "read" else "review"
        floor = item.get("data_class", "public")
        if maintained and maintained["route"] == "hosted":
            from connectors.registry import source_class
            floor = source_class(maintained,item["name"][len(name)+1:])
        source = max([floor, rule.source_data_class if current else floor], key=["public", "personal", "sensitive"].index)
        items.append({**item, "permission": permission, "data_class": source, "workflow": rule.charity_workflow if current else "none"})
    return {"revision": store.revision(), "configuration_hash": digest(spec), "tools": items, "command_review_required": spec.get("transport") == "stdio" and [spec["command"], *spec.get("args", [])] not in policy.stdio_commands}


def connection_summaries(store, runtime, vault):
    from guardrails.runtime import tool_hash
    policy, settings, checks = runtime.policy(), load_settings(store.root), vault.connection_checks()
    catalog = [t for t in store.catalog() if store.tools()["mcp_servers"].get(t.get("server"), {}).get("transport") != "native"]
    catalog += [t for t in definitions(store.root) if store.tools()["mcp_servers"].get(t.get("server"), {}).get("transport") == "native"]
    summaries = {}
    for name, spec in store.tools()["mcp_servers"].items():
        stamp = digest(spec)
        check = checks.get(name, {})
        tools = [t for t in catalog if t.get("server") == name and t.get("configuration_hash") == stamp]
        reviewed_tools = []
        for tool in tools:
            rule = policy.tools.get(tool["name"])
            schema_hash = tool_hash(tool["name"], tool.get("description", ""), tool.get("input_schema", {}), tool.get("output_schema"))
            if rule and rule.schema_hash == schema_hash and rule.configuration_hash == stamp and tool["name"] not in settings.blocked_tools:
                reviewed_tools.append(tool['name'])
        summaries[name] = {"connection": check.get("status", "not_connected") if check.get("binding") == stamp else "not_connected", "checked_at": check.get("checked") if check.get("binding") == stamp else None, "reviewed": len(reviewed_tools), "reviewed_tools": reviewed_tools, "total": len(tools)}
    return summaries


def install_routes(app, store, authentication, runtime, response, idle):
    @app.get("/api/connection-presets")
    async def presets():
        return response({"presets": catalogue(), "categories": CATEGORIES, "revision": REVISION})

    @app.post("/api/connections/check")
    async def check(request: Request):
        idle()
        data = await payload(request, Check)
        return response(await check_connection(data.url, runtime.policy()))

    @app.post("/api/connections/setup")
    async def setup(request: Request):
        idle()
        data = await payload(request, Setup)
        maintained = connector_preset(data.preset)
        if maintained["route"] in {"native", "hosted"}:
            from connectors.dashboard import create
            return response(create(store, runtime, data, maintained), 201)
        if maintained["route"] == "installed":
            raise ValueError("Masterbrand is already available in your existing tools. Choose its agents under Advanced.")
        with store.edit(data.revision):
            config, settings = store.tools(), load_settings(store.root)
            preset = next(p for p in PRESETS if p["id"] == data.preset)
            if data.preset != "remote" and not data.confirm_local:
                raise ValueError("Confirm the publisher and local command before connecting.")
            name = slug(data.display_name.strip() or (urlsplit(data.url).hostname if data.preset == "remote" else preset["name"]) or "connection")[:40]
            used = set().union(*(set(config[s]) for s in ["mcp_servers", "custom_tools", "http_tools"]))
            base, suffix = name, 2
            def overlaps_namespace(candidate):
                return any(candidate.startswith(other + "_") or other.startswith(candidate + "_") for other in config["mcp_servers"])
            if overlaps_namespace(name):
                base = name.replace("_", "")
                name = base
            while name in used or overlaps_namespace(name):
                name, suffix = f"{base}{suffix}", suffix + 1
            spec = {"display_name": data.display_name.strip() or (urlsplit(data.url).hostname if data.preset == "remote" else preset["name"]), "enabled": True}
            updates = {}
            if data.preset == "remote":
                spec.update(transport="http", url=remote_url(data.url, runtime.policy()), auth={"type": "bearer" if data.authentication == "key" else data.authentication})
            else:
                command = preset["command"]
                spec.update(transport="stdio", command=command[0], args=command[1:], auth={"type": "google_adc" if data.preset == "google" else "none"})
            needs_key = data.preset == "brave" or (data.preset == "remote" and data.authentication == "key")
            if needs_key:
                if not data.api_key or any(ord(c) < 32 or ord(c) == 127 for c in data.api_key):
                    raise ValueError("Enter an API key without line breaks or control characters.")
                reference = "MCP_" + name.upper() + "_" + secrets.token_hex(6).upper()
                updates[reference] = data.api_key
                if data.preset == "brave":
                    spec["env_secrets"] = {"BRAVE_API_KEY": reference}
                else:
                    spec["token_env"] = reference
            elif data.api_key:
                raise ValueError("Only API-key connections accept a key.")
            if data.preset == "google":
                _, provider = authentication.vault.provider("google")
                if not provider:
                    raise ValueError("Complete the one-time Google provider setup under Advanced first.")
                spec["auth"]["project"] = provider["project"]
            spec = MCPSpec.model_validate(spec).model_dump(exclude_none=True)
            config["mcp_servers"][name] = spec
            if spec["transport"] == "stdio":
                settings.approved_connections[name] = digest(spec)
            store.save_with_new_secrets({store.tools_path: config, store.policy_path: settings.model_dump(mode="json", exclude_none=True)}, updates)
        runtime.invalidate_pending()
        return response({"name": name, "revision": store.revision(), "message": "Connection saved. Connect and review its tools next."}, 201)

    @app.get("/api/providers/google/setup")
    async def provider_status():
        return response(authentication.provider_status())

    @app.put("/api/providers/google/setup")
    async def provider_update(request: Request):
        idle()
        data = await payload(request, ProviderSetup)
        if len(canonical(data.client_json).encode()) > 65536:
            raise ValueError("Choose a Google client file smaller than 64 KB.")
        return response(await authentication.update_provider(data.revision, {"client_json": data.client_json, "project": data.project}))

    @app.delete("/api/providers/google/setup")
    async def provider_delete(request: Request):
        idle()
        data = await payload(request, ProviderDelete)
        return response(await authentication.update_provider(data.revision, None))

    @app.get("/api/connections/{name}/setup")
    async def status(name: str):
        view = connection_view(store, runtime, name)
        spec = store.tools()["mcp_servers"][name]
        if spec.get("managed"):
            from connectors.dashboard import view as managed_view
            view.update(managed_view(store, runtime, authentication, name, spec))
        return response(view)

    @app.put("/api/connections/{name}/setup/key")
    async def replace_key(name: str, request: Request):
        idle()
        data = await payload(request, ReplaceKey)
        if any(ord(c) < 32 or ord(c) == 127 for c in data.api_key):
            raise ValueError("Enter an API key without line breaks or control characters.")
        with store.edit(data.revision):
            config, settings = store.tools(), load_settings(store.root)
            old = config["mcp_servers"].get(name)
            if not old:
                raise ValueError("This connection no longer exists.")
            spec = MCPSpec.model_validate(old)
            reference = "MCP_" + slug(name).upper()[:40] + "_" + secrets.token_hex(6).upper()
            if spec.transport == "native" and connector_preset(spec.native.provider)["authentication"] in {"key", "token", "session", "basic"}:
                spec.native.secret_refs["api_key"] = reference
            elif spec.transport == "http" and spec.authentication().type == "bearer":
                spec.token_env = reference
            elif curated_connection(old):
                spec.env_vars = [key for key in spec.env_vars if key != "BRAVE_API_KEY"]
                spec.env_secrets["BRAVE_API_KEY"] = reference
            else:
                raise ValueError("Use Advanced settings for this connection's custom credentials.")
            updated = MCPSpec.model_validate(spec.model_dump()).model_dump(exclude_none=True)
            if spec.transport == "stdio" and [spec.command, *spec.args] in runtime.policy().stdio_commands:
                settings.approved_connections[name] = digest(updated)
            config["mcp_servers"][name] = updated
            store.save_with_new_secrets({store.tools_path: config, store.policy_path: settings.model_dump(mode="json", exclude_none=True)}, {reference: data.api_key})
        runtime.invalidate_pending()
        return response({"revision": store.revision(), "message": "API key saved for this connection. Retry discovery and review its tools."})

    @app.post("/api/connections/{name}/setup/complete")
    async def complete(name: str, request: Request):
        idle()
        data = await payload(request, Complete)
        with store.edit(data.revision):
            view = connection_view(store, runtime, name)
            if data.configuration_hash != view["configuration_hash"]:
                raise Conflict("The connection changed. Connect and review its tools again.")
            if view["command_review_required"]:
                raise ValueError("Approve the exact local command before reviewing tools.")
            available = {item["name"]: item for item in view["tools"]}
            if not available or set(data.reviews) != set(available):
                raise Conflict("The discovered tools changed. Review the current tool list again.")
            settings, policy = load_settings(store.root), runtime.policy()
            for key, review in data.reviews.items():
                definition = available[key]
                spec = store.tools()["mcp_servers"][name]
                if spec.get("managed") and review.permission != "blocked":
                    from connectors.registry import hosted_read_allowed
                    if review.permission != "read" or not hosted_read_allowed(spec, key[len(name)+1:]):
                        raise ValueError("Maintained presets expose reviewed read operations only.")
                    floor = definition.get("data_class", "public")
                    if ["public", "personal", "sensitive"].index(review.data_class) < ["public", "personal", "sensitive"].index(floor):
                        raise ValueError("Keep the maintained information sensitivity.")
                if review.schema_hash != definition["schema_hash"]:
                    raise Conflict("A tool definition changed. Review its current description again.")
                if review.permission == "blocked":
                    settings.blocked_tools = sorted(set(settings.blocked_tools) | {key})
                    continue
                previous = policy.tools.get(key)
                # Keep existing consequential classifications and charity controls.
                if previous:
                    if previous.classification not in {"read", "draft"} and review.permission == "read":
                        raise ValueError("An action tool cannot become a read-only tool through guided setup. Use Advanced review.")
                    if previous.charity_workflow != "none" and review.workflow != previous.charity_workflow:
                        raise ValueError("Keep the tool's existing charity workflow. Changes need Advanced review.")
                    if ["public", "personal", "sensitive"].index(review.data_class) < ["public", "personal", "sensitive"].index(previous.source_data_class):
                        raise ValueError("Keep the tool's existing information sensitivity. Changes need Advanced review.")
                rule = bind_access(definition, permission=review.permission, workflow=review.workflow, data_class=review.data_class, previous=previous)
                if previous and review.permission == "review" and previous.classification not in {"read", "draft"}:
                    rule.classification = previous.classification
                settings.access[key] = rule
                settings.blocked_tools = [t for t in settings.blocked_tools if t != key]
            agents = store.agents()
            if set(data.assignments) - set(agents["agents"]):
                raise ValueError("Choose existing agents for these tools.")
            for agent, selected in data.assignments.items():
                if len(selected) != len(set(selected)) or set(selected) - set(available) or any(data.reviews[t].permission == "blocked" for t in selected):
                    raise ValueError("Assign only tools you have reviewed and enabled for this connection.")
                original = agents["agents"][agent]["tools"]
                agents["agents"][agent]["tools"] = [t for t in original if t not in available or data.reviews[t].permission == "blocked"] + selected
            settings = type(settings).model_validate(settings.model_dump(mode="json"))
            if any(s in canonical(settings.model_dump(mode="json")) for s in runtime.secret_values()):
                raise ValueError("The connection disclosed a secret. Its tool review was withheld.")
            store.save_many({store.policy_path: settings.model_dump(mode="json", exclude_none=True), store.agents_path: store.validate_agents(agents)})
        runtime.invalidate_pending()
        return response({"revision": store.revision(), "message": "Tool access and agents saved. Changes connect automatically."})

    from connectors.dashboard import install_routes as install_connector_routes
    install_connector_routes(app, store, authentication, runtime, response, idle)
