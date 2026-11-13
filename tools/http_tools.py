"""Schema-backed HTTP tools: no generated source code or shell execution."""
from __future__ import annotations
import json
import os
from typing import Any, Callable, ClassVar
from urllib.parse import quote
import httpx
import jsonschema
from guardrails.validation import strict_json
from fastmcp.tools import Tool
from fastmcp.tools.base import ToolResult
from pydantic import PrivateAttr
from .definitions import HTTPToolSpec


class HTTPTool(Tool):
    _spec: HTTPToolSpec = PrivateAttr()
    _secrets: Callable[[str], str] = PrivateAttr()
    _transport: Any = PrivateAttr(default=None)
    _runtime: Any = PrivateAttr(default=None)
    MAX_BYTES: ClassVar[int] = 1024 * 1024

    def __init__(self, name: str, spec: HTTPToolSpec, *, secret_resolver=None, transport=None, runtime=None):
        super().__init__(name=name, description=spec.description, parameters=spec.input_schema(), timeout=35)
        self._spec = spec
        self._secrets = secret_resolver or (lambda key: os.environ.get(key, ""))
        self._transport = transport
        self._runtime = runtime

    async def execute(self, arguments: dict) -> Any:
        try:
            jsonschema.validate(arguments, self.parameters)
        except jsonschema.ValidationError as error:
            raise ValueError(f"Check tool input: {error.message}") from None
        url, query, body, headers = self._spec.url, {}, {}, {}
        secret_values = []
        for item in self._spec.inputs:
            if item.name not in arguments:
                continue
            value = arguments[item.name]
            if item.location == "path":
                if str(value) in {".", ".."}:
                    raise ValueError("Path inputs cannot be dot segments.")
                url = url.replace("{" + item.name + "}", quote(str(value), safe=""))
            elif item.location == "query":
                query[item.name] = json.dumps(value) if isinstance(value, (dict, list, bool)) else value
            else:
                body[item.name] = value
        for header in self._spec.headers:
            value = self._secrets(header.secret) if header.secret else header.value
            if header.secret:
                if not value:
                    raise ValueError(f"Set the secret {header.secret} before using this tool.")
                if "\r" in value or "\n" in value:
                    raise ValueError(f"The secret {header.secret} must fit on one line for use in a header.")
                secret_values.append(value)
            headers[header.name] = header.prefix + value
        try:
            request_url = httpx.URL(url).copy_merge_params(query)
            transport = self._transport
            if self._runtime is not None:
                from guardrails.network import transport_for
                policy = self._runtime.policy()
                rule = policy.tools.get(self.name)
                if not rule:
                    raise ValueError("Review this API tool in Guardrails first.")
                transport = transport or transport_for(str(request_url), rule.targets, policy.local_endpoints)
            async with httpx.AsyncClient(timeout=30, follow_redirects=False, transport=transport, trust_env=False) as client:
                async with client.stream(self._spec.method, request_url, json=body or None, headers=headers) as response:
                    if not 200 <= response.status_code < 300:
                        raise ValueError(f"The API returned HTTP {response.status_code}. Check the address, inputs and permissions.")
                    content_type = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
                    is_json = content_type == 'application/json' or content_type.startswith('application/') and content_type.endswith('+json')
                    if not is_json and content_type not in {'text/plain', 'text/html', 'text/markdown', 'text/csv'}:
                        raise ValueError('The API returned an unsupported content type. Use a text or JSON endpoint.')
                    data = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        data.extend(chunk)
                        if len(data) > self.MAX_BYTES:
                            raise ValueError("The API response is too large. Narrow the request to less than 1 MB.")
                    try:
                        text = bytes(data).decode('utf-8')
                    except UnicodeError:
                        raise ValueError('The API response must be valid UTF-8 text.') from None
                    for secret in secret_values:
                        text = text.replace(secret, "[REDACTED]")
                    try:
                        return strict_json(text)
                    except ValueError:
                        if is_json:
                            raise ValueError('The API returned invalid or ambiguous JSON.') from None
                        return text
        except httpx.TimeoutException:
            raise ValueError("The API did not respond within 30 seconds.") from None
        except httpx.HTTPError:
            raise ValueError("Could not connect to the API. Check its address and try again.") from None

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        return self.convert_result(await self.execute(arguments))
