"""Discover reviewed connections without executing their tools."""
import asyncio

from fastmcp import Client

from guardrails.policy import digest, canonical, PolicyDenied
from .store import Conflict


async def discover_connection(store, runtime, name, *, before_save=None):
    from sandboxing.activity import Busy, lease
    try:
        # Cover the entire test, including HTTP/native discovery and catalog
        # publication. Windows workers serialize separately within this lease.
        with lease(store.root, 'connection-test'):
            return await _discover_connection(store, runtime, name, before_save=before_save)
    except Busy as error:
        raise Conflict(str(error)) from None


async def _discover_connection(store, runtime, name, *, before_save=None):
    from tools.gateway import mcp_transport
    from tools.mcp_auth import CredentialVault
    spec = store.tools()["mcp_servers"].get(name)
    if spec is None:
        raise ValueError("Save the connection before testing it.")
    revision = runtime.policy().revision

    async def discover():
        if spec.get("transport") == "native":
            from connectors.dashboard import discover_resources
            await discover_resources(store, runtime, store.authentication, name, spec)
        async with Client(mcp_transport(spec, store.secret, policy=runtime.policy(), root=store.root, connection=name), timeout=15) as client:
            return await client.list_tools()

    try:
        found = await asyncio.wait_for(discover(), 30)
    except Exception as error:
        if store.tools()["mcp_servers"].get(name) == spec:
            CredentialVault(store.root).record_check(name, spec, "failed")
        from tools.mcp_auth import AuthenticationRequired, is_auth_failure
        # SDK task groups may wrap the deterministic denial.
        if is_auth_failure(error):
            raise AuthenticationRequired(name) from None
        pending, seen = [error], set()
        while pending and len(seen) < 32:
            item = pending.pop()
            if id(item) in seen:
                continue
            seen.add(id(item))
            if isinstance(item, PolicyDenied):
                raise PolicyDenied(item.rule, str(item)) from None
            pending.extend(getattr(item, "exceptions", ()))
            pending.extend(e for e in (getattr(item, "__cause__", None), getattr(item, "__context__", None)) if e is not None)
        raise ValueError("Connection failed. Check the server link, sign-in or API key, and local command approval, then retry. Advanced connection settings are available in this dashboard.") from None
    CredentialVault(store.root).record_check(name, spec, "failed")
    tools = [{"name": f"{name}_{tool.name}", "label": tool.title or tool.name.replace("_", " ").title(), "description": tool.description or "", "server": name, "kind": "MCP", "input_schema": tool.input_schema, "output_schema": tool.output_schema, "configuration_hash": digest(spec), "targets": [spec["url"]] if spec.get("transport") == "http" else []} for tool in found]
    if any(secret in canonical(tools) for secret in runtime.secret_values()):
        raise PolicyDenied("data.secret", "The connection disclosed a secret in its tool definitions. Discovery was withheld.")
    with store.lock:
        if store.tools()["mcp_servers"].get(name) != spec:
            raise Conflict("This connection changed during its test. Test the saved connection again.")
        if runtime.policy().revision != revision:
            raise Conflict("Sandbox or gateway settings changed during discovery. Test the saved connection again.")
        if before_save:
            before_save()
        store.remember_catalog(name, tools)
        CredentialVault(store.root).record_check(name, spec, "connected")
    return tools
