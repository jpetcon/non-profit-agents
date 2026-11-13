
import asyncio
import os

from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import (
    StreamableHTTPConnectionParams,
)
from guardrails.policy import PolicyDenied


def require_tools(names, available):
    missing = sorted(set(names) - set(available))
    if missing:
        raise ValueError(
            "Assigned tools are unavailable from the tool gateway: "
            + ", ".join(missing)
            + ". Check access in Guardrails or test the connection in Tools & Connections. Saved changes connect automatically."
        )


class RequiredMcpToolset(McpToolset):
    """Never silently turn missing assigned capabilities into an empty tool list."""

    def __init__(self, names: list[str], gateway_url: str, token: str = "", revision_provider=None):
        from guardrails.client import local_gateway, local_mcp_client_factory
        local_gateway(gateway_url)
        # ADK otherwise probes cloud credentials/metadata even for localhost.
        # This app uses scoped local credentials, with no client certificates.
        os.environ['GOOGLE_API_USE_CLIENT_CERTIFICATE'] = 'false'
        super().__init__(
            connection_params=StreamableHTTPConnectionParams(url=gateway_url, headers={"Authorization": "Bearer " + token} if token else None, timeout=10, sse_read_timeout=510, httpx_client_factory=local_mcp_client_factory(gateway_url)),
            tool_filter=list(names),
        )
        self.required_names = tuple(names)
        self.guardrail_token = token
        self.guardrail_url = gateway_url
        self.guardrail_revision = revision_provider

    async def get_tools(self, readonly_context=None):
        if self.guardrail_revision:
            from guardrails.client import verify_gateway
            await verify_gateway(self.guardrail_url, "tools", self.guardrail_token, self.guardrail_revision())
        try:
            tools = await super().get_tools(readonly_context)
        except Exception:
            raise ValueError(
                "Could not load assigned tools from the tool gateway. "
                "Check its status in Overview and test the connection in Tools & Connections."
            ) from None
        require_tools(self.required_names, [tool.name for tool in tools])
        return tools


class ToolRegistry:
    def __init__(self, gateway_url: str, *, credential_provider=None, revision_provider=None):
        self.gateway_url = gateway_url
        self.credential_provider = credential_provider
        self.revision_provider = revision_provider
        if credential_provider:
            from guardrails.client import local_gateway
            local_gateway(gateway_url)

    async def validate_available(self, names: list[str], *, agent: str = "") -> None:
        """Preflight the selected agent tree before spending inference tokens."""
        if not names:
            return
        from fastmcp import Client
        async def discover():
            token = self.credential_provider(agent, "tools") if self.credential_provider else ""
            if self.revision_provider:
                from guardrails.client import verify_gateway
                await verify_gateway(self.gateway_url, "tools", token, self.revision_provider())
            from guardrails.client import tool_transport
            transport = tool_transport(self.gateway_url, token) if self.credential_provider else self.gateway_url
            async with Client(transport, timeout=10) as client:
                return [tool.name for tool in await client.list_tools()]
        try:
            available = await asyncio.wait_for(discover(), timeout=15)
        except PolicyDenied:
            raise
        except Exception:
            raise ValueError(
                "Could not validate assigned tools. Check gateway diagnostics in Overview "
                "and test the connection in Tools & Connections."
            ) from None
        require_tools(names, available)

    def resolve(self, names: list[str], *, agent: str = "") -> list[McpToolset]:
        if not names:
            return []

        token = self.credential_provider(agent, "tools") if self.credential_provider else ""
        return [RequiredMcpToolset(names, self.gateway_url, token, self.revision_provider)]
