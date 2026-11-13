"""Verify that agent entry points connect to the expected guarded local service."""
from urllib.parse import urlsplit

import httpx

from .policy import PolicyDenied


def local_gateway(url):
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise PolicyDenied("gateway.local", "Scoped agent credentials may only connect to a local guarded gateway.")
    return f"{parsed.scheme}://{parsed.netloc}"


def tool_transport(url, token):
    """Keep scoped credentials on the local MCP connection, outside Client args."""
    from fastmcp.client.transports import StreamableHttpTransport
    base = local_gateway(url)
    return StreamableHttpTransport(base + "/mcp", headers={"Authorization": "Bearer " + token}, httpx_client_factory=local_mcp_client_factory(url))


def local_mcp_client_factory(url):
    """Constrain ADK and FastMCP to one local destination without ambient auth."""
    import httpx2
    base = local_gateway(url)
    async def check(request):
        if local_gateway(str(request.url)) != base or request.url.path.rstrip('/') != '/mcp':
            raise PolicyDenied('gateway.local', 'Gateway credentials cannot be sent to another destination.')
    def factory(headers=None, timeout=None, auth=None, **kwargs):
        if auth is not None:
            raise PolicyDenied('gateway.auth', 'Use only scoped gateway authentication.')
        kwargs.update(trust_env=False, follow_redirects=False, event_hooks={'request':[check]})
        return httpx2.AsyncClient(headers=headers, timeout=timeout if timeout is not None else httpx2.Timeout(10, read=510), **kwargs)
    return factory


async def verify_gateway(url, audience, token, revision):
    base = local_gateway(url)
    path = "/health/liveliness" if audience == "inference" else "/guardrails/health"
    try:
        async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
            response = await client.get(base + path, headers={"Authorization": "Bearer " + token})
            if response.status_code != 200 or response.json() != {"guardrails": 1, "revision": revision}:
                raise ValueError()
    except Exception:
        raise PolicyDenied("gateway.unverified", "Connect a compatible local gateway with the current policy revision.") from None
