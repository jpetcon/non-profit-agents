"""Build and run the shared gateway without eager configuration side effects."""
import os
from importlib import import_module
from pathlib import Path
import yaml
from fastmcp import FastMCP
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport
from fastmcp.server.providers.proxy import ProxyClient
from .definitions import HTTPToolSpec, MCPSpec
from .http_tools import HTTPTool


def mcp_transport(spec: dict, secret_resolver=None, *, policy=None, root=None, connection=None, oauth=None, interactive=None):
    definition = MCPSpec.model_validate(spec)
    authentication = definition.authentication()
    if root and secret_resolver is None:
        from .mcp_auth import secret_resolver as resolve_for
        secret_resolver = resolve_for(root)
    get_secret = secret_resolver or (lambda key: os.environ.get(key, ""))
    if definition.transport == "native":
        if not root or policy is None or not connection:
            raise ValueError("Native connectors require the guarded gateway context.")
        from connectors.native import server
        return server(connection, spec, root, policy, get_secret)
    def require(key):
        value = get_secret(key)
        if not value:
            raise ValueError(f"Set the secret {key} to connect this MCP server.")
        return value
    if definition.transport == "stdio":
        from sandboxing.transport import LocalStdioTransport
        if policy is not None and policy.sandbox.enabled and not root:
            from guardrails.policy import PolicyDenied
            raise PolicyDenied("sandbox.setup", "Sandboxed local connections require the workspace context.")
        if policy is not None and [definition.command, *definition.args] not in policy.stdio_commands:
            raise ValueError("Review and allow this exact local MCP command in Guardrails.")
        env = {key: require(key) for key in definition.env_vars}
        env.update({key: require(reference) for key, reference in definition.env_secrets.items()})
        if authentication.type == "google_adc":
            from .mcp_auth import CredentialVault, AuthenticationRequired
            from .google_transport import GoogleStdioTransport
            if not root or not connection or policy is None:
                raise AuthenticationRequired(connection)
            handle = CredentialVault(root).handle(connection, spec, get_secret)
            return GoogleStdioTransport(handle, command=definition.command, args=definition.args, env=env, project=authentication.project, root=root, connection=connection, spec=spec, policy=policy)
        return LocalStdioTransport(command=definition.command, args=definition.args, env=env, keep_alive=False, log_file=Path(os.devnull), root=root, connection=connection, spec=spec, policy=policy)
    headers = {name: require(key) for name, key in definition.header_secrets.items()}
    if definition.token_env:
        headers["Authorization"] = "Bearer " + require(definition.token_env)
    if policy is not None:
        from guardrails.network import transport_for, permitted_url
        import httpx2
        auth = None
        if authentication.type == "oauth":
            from .mcp_auth import CredentialVault, GatewayOAuth, AuthenticationRequired
            if not root or not connection:
                raise AuthenticationRequired(connection)
            auth = oauth or GatewayOAuth(CredentialVault(root).handle(connection, spec, get_secret), policy)

        class ConnectionTransport(httpx2.AsyncBaseTransport):
            def __init__(self):
                self.mcp = transport_for(definition.url, [definition.url], policy.local_endpoints, httpx_module="httpx2")
                if interactive:
                    from .mcp_auth import AuthNetwork
                    self.authentication = AuthNetwork(interactive.handle, policy, interactive=interactive)

            async def handle_async_request(self, request):
                from guardrails.policy import PolicyDenied
                try:
                    permitted_url(str(request.url), [definition.url], policy.local_endpoints)
                    from urllib.parse import urlsplit
                    upstream = urlsplit(str(request.url)).path.rstrip("/") == urlsplit(definition.url).path.rstrip("/")
                except PolicyDenied:
                    upstream = False
                if upstream:
                    if interactive:
                        interactive.handle.read()
                    elif auth is not None:
                        if not auth.handle.read().get("connected"):
                            from .mcp_auth import AuthenticationRequired
                            raise AuthenticationRequired(connection)
                    for key, value in headers.items():
                        request.headers[key] = value
                    return await self.mcp.handle_async_request(request)
                if interactive:
                    return await self.authentication.handle_async_request(request)
                raise PolicyDenied("network.target", "The request left its approved MCP endpoint.")

            async def aclose(self):
                await self.mcp.aclose()
                if interactive:
                    await self.authentication.aclose()

        def factory(**kwargs):
            kwargs.update(follow_redirects=False, trust_env=False, transport=ConnectionTransport())
            return httpx2.AsyncClient(**kwargs)
        # SDK discovery runs through the same HTTP client as MCP. Secret headers
        # are injected only at the MCP dispatch boundary, never as client defaults.
        return StreamableHttpTransport(definition.url, headers={}, auth=auth, httpx_client_factory=factory)
    if authentication.type == "oauth":
        from .mcp_auth import AuthenticationRequired
        raise AuthenticationRequired(connection)
    return StreamableHttpTransport(definition.url, headers=headers)


def build_gateway(config_path: str | Path | None = None, *, runtime=None, identity_provider=None) -> FastMCP:
    config_path = Path(config_path or Path(__file__).with_name("config.yml"))
    config = yaml.safe_load(config_path.read_text())
    from guardrails.runtime import Runtime
    from guardrails.tool_middleware import ToolGuardrails
    from starlette.responses import JSONResponse
    runtime = runtime or Runtime(config_path.resolve().parent.parent)
    guard = ToolGuardrails(runtime, identity_provider=identity_provider)
    mcp = FastMCP(config["gateway"]["name"], on_duplicate="error")
    mcp.add_middleware(guard)

    @mcp.custom_route("/guardrails/health", methods=["GET"])
    async def health(request):
        try:
            identity = runtime.authenticate(request.headers.get("authorization", "").removeprefix("Bearer "), "tools")
            return JSONResponse({"guardrails": 1, "revision": guard.active_revision})
        except Exception:
            return JSONResponse({"error": "Gateway authentication failed."}, 403)

    @mcp.custom_route("/guardrails/approvals", methods=["GET"])
    async def previews(request):
        try:
            identity = runtime.authenticate(request.headers.get("authorization", "").removeprefix("Bearer "), "tools")
            if identity["role"] != "admin":
                return JSONResponse({"error": "Administrative scope required."}, 403)
            return JSONResponse({"arguments": runtime.pending_payloads})
        except Exception:
            return JSONResponse({"error": "Gateway authentication failed."}, 403)
    for name, spec in config.get("custom_tools", {}).items():
        module_path, _, function_name = spec["handler"].rpartition(".")
        if not module_path.startswith("tools.custom_tools."):
            raise ValueError(f"Unapproved handler: {spec['handler']}")
        handler = getattr(import_module(module_path), function_name)
        mcp.tool(name=name, description=spec["description"])(handler)
    for name, spec in config.get("http_tools", {}).items():
        definition = HTTPToolSpec.model_validate(spec)
        if definition.enabled:
            mcp.add_tool(HTTPTool(name, definition, runtime=runtime))
    for name, spec in config.get("mcp_servers", {}).items():
        try:
            definition = MCPSpec.model_validate(spec)
        except ValueError:
            # A stale maintained preset is held for review independently.
            continue
        if definition.enabled:
            # Client.new() shares its transport. A non-persistent stdio transport
            # would therefore disconnect concurrent requests when either exits.
            # Each request must own both its client and its subprocess transport.
            def client_factory(spec=spec, connection=name):
                return ProxyClient(mcp_transport(spec, policy=runtime.policy(), root=runtime.root, connection=connection), forward_incoming_headers=False)
            from .mcp_auth import CredentialVault, AuthenticationRequired
            from fastmcp.server.providers.proxy import ProxyProvider, _CacheEntry
            import time

            class ConnectionProxy(ProxyProvider):
                def __init__(self, factory, connection, settings):
                    super().__init__(factory, cache_ttl=0)
                    self.connection, self.settings = connection, settings

                async def _list_tools(self):
                    try:
                        identity = guard.identity()
                        if identity.get("role") != "admin":
                            agents = yaml.safe_load((runtime.root / "agents/config.yml").read_text())["agents"]
                            assigned = agents.get(identity.get("agent"), {}).get("tools", [])
                            if not any(tool.startswith(self.connection + "_") for tool in assigned):
                                self._tools_cache = _CacheEntry([], time.monotonic())
                                return []
                        if MCPSpec.model_validate(self.settings).authentication().type in {"oauth", "google_adc"}:
                            handle = CredentialVault(runtime.root).handle(self.connection, self.settings)
                            if not handle.read().get("connected"):
                                raise AuthenticationRequired(self.connection)
                        return await super()._list_tools()
                    except Exception:
                        # Discovery fails closed for this connection. Its dashboard
                        # test provides diagnostics; unrelated capabilities stay usable.
                        self._tools_cache = _CacheEntry([], time.monotonic())
                        return []

            mcp.add_provider(ConnectionProxy(client_factory, name, spec), namespace=name)
    return mcp


def __getattr__(name):
    if name == "mcp":
        instance = build_gateway()
        globals()[name] = instance
        return instance
    raise AttributeError(name)


if __name__ == "__main__":
    import logging
    from starlette.middleware import Middleware
    from guardrails.http_boundary import GatewayHTTPBoundary
    from guardrails.runtime import Runtime
    config_path = Path(os.getenv("TOOL_CONFIG_PATH", str(Path(__file__).with_name("config.yml"))))
    settings = yaml.safe_load(config_path.read_text())["gateway"]
    if settings["host"] not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("The guarded tool gateway must bind to loopback.")
    runtime = Runtime(config_path.resolve().parent.parent)
    runtime.invalidate_pending()
    # SDK error logs can contain submitted content. Decisions are recorded without
    # payloads in the audit database instead.
    logging.disable(logging.CRITICAL)
    build_gateway(config_path, runtime=runtime).run(transport="http", host=settings["host"], port=settings["port"], middleware=[Middleware(GatewayHTTPBoundary, runtime=runtime)], uvicorn_config={"access_log": False})
