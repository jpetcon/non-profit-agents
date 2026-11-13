"""Destination checking and DNS-pinned connections (original TLS SNI retained)."""
from __future__ import annotations

import asyncio
import importlib
import ipaddress
import socket
from urllib.parse import urlsplit

from .policy import PolicyDenied


def origin(value):
    url = urlsplit(str(value))
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
        raise PolicyDenied("network.url", "Use an HTTP(S) endpoint without embedded credentials.")
    return url.scheme, url.hostname.lower(), url.port or (443 if url.scheme == "https" else 80)


def permitted_url(value, targets, local_endpoints=()):
    parsed = urlsplit(str(value))
    current = origin(value)
    if not any(origin(t) == current and (parsed.path == urlsplit(t).path.rstrip("/") or parsed.path.startswith(urlsplit(t).path.rstrip("/") + "/")) for t in targets):
        raise PolicyDenied("network.target", "The endpoint or path is outside the approved destinations.")
    local = any(origin(t) == current and (parsed.path == urlsplit(t).path.rstrip("/") or parsed.path.startswith(urlsplit(t).path.rstrip("/") + "/")) for t in local_endpoints)
    if parsed.scheme != "https" and not local:
        raise PolicyDenied("network.https", "Remote destinations require HTTPS; approve local exceptions explicitly.")
    return local


async def resolve_public(host, port, allow_local=False):
    try:
        addresses = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise PolicyDenied("network.dns", "The approved destination could not be resolved.") from None
    ips = list(dict.fromkeys(a[4][0] for a in addresses))
    if not ips:
        raise PolicyDenied("network.dns", "The destination has no usable address.")
    for value in ips:
        address = ipaddress.ip_address(value)
        mapped = getattr(address, "ipv4_mapped", None)
        effective = mapped or address
        if not effective.is_global or effective.is_multicast or effective.is_reserved:
            # Exceptions are only for local/private services, never cloud metadata,
            # multicast, unspecified or link-local addresses.
            if not allow_local or effective.is_link_local or effective.is_multicast or effective.is_unspecified or str(effective) in {"169.254.169.254", "100.100.100.200"}:
                raise PolicyDenied("network.private", "Private, reserved and metadata destinations are blocked.")
    return ips


def transport_for(endpoint, targets, local_endpoints=(), *, httpx_module="httpx", max_bytes=4 * 1024 * 1024, max_requests=None):
    client_module = importlib.import_module(httpx_module)
    core_name = "httpcore2" if httpx_module == "httpx2" else "httpcore"
    backend_type = importlib.import_module(core_name + "._backends.auto").AutoBackend
    allow_local = permitted_url(endpoint, targets, local_endpoints)
    endpoint_origin = origin(endpoint)

    class PinnedBackend(backend_type):
        async def connect_tcp(self, host, port, **kwargs):
            if isinstance(host, bytes):
                host = host.decode()
            if (host.lower(), port) != endpoint_origin[1:]:
                raise PolicyDenied("network.origin", "A connection attempted to leave the approved origin.")
            ips = await resolve_public(host, port, allow_local)
            # No second DNS lookup of the original hostname can rebind this request.
            return await super().connect_tcp(ips[0], port, **kwargs)

    class BoundedStream(client_module.AsyncByteStream):
        def __init__(self, stream):
            self.stream = stream
        async def __aiter__(self):
            total = 0
            async for chunk in self.stream:
                total += len(chunk)
                if total > max_bytes:
                    raise PolicyDenied("network.response_size", "The upstream response exceeds its transport limit.")
                yield chunk
        async def aclose(self):
            await self.stream.aclose()

    class GuardedTransport(client_module.AsyncHTTPTransport):
        dispatch_count = 0
        async def handle_async_request(self, request):
            permitted_url(str(request.url), targets, local_endpoints)
            if max_requests is not None and self.dispatch_count >= max_requests:
                raise PolicyDenied("provider.retry", "An SDK attempted an additional unreserved provider request.")
            self.dispatch_count += 1
            response = await super().handle_async_request(request)
            if 300 <= response.status_code < 400:
                await response.aclose()
                raise PolicyDenied("network.redirect", "Redirects require an explicitly configured destination.")
            response.stream = BoundedStream(response.stream)
            return response

    transport = GuardedTransport(trust_env=False, retries=0)
    transport._pool._network_backend = PinnedBackend()
    return transport
