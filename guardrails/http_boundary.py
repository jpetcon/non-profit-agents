"""Authenticate and bound MCP HTTP bodies before JSON-RPC parsing."""
from starlette.responses import JSONResponse


class GatewayHTTPBoundary:
    def __init__(self, app, runtime):
        self.app, self.runtime = app, runtime

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        try:
            headers = dict(scope.get("headers", []))
            token = headers.get(b"authorization", b"").decode().removeprefix("Bearer ")
            self.runtime.authenticate(token, "tools")
            limit = self.runtime.policy().workspace.max_input_bytes
            chunks, length = [], 0
            if scope.get("method") == "POST":
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    length += len(message.get("body", b""))
                    if length > limit:
                        return await JSONResponse({"error": "The tool request exceeds its payload limit."}, 413)(scope, receive, send)
                    chunks.append(message)
                    if not message.get("more_body"):
                        break
                if headers.get(b'content-type', b'').split(b';', 1)[0].strip().lower() != b'application/json' or headers.get(b'content-encoding', b'identity') != b'identity':
                    return await JSONResponse({'error': 'Send an uncompressed JSON tool request.'}, 415)(scope, receive, send)
                from .validation import strict_json
                strict_json(b''.join(m.get('body', b'') for m in chunks))
            async def bounded_receive():
                return chunks.pop(0) if chunks else await receive()
        except Exception:
            return await JSONResponse({"error": "A valid scoped tool credential and policy state are required."}, 403)(scope, receive, send)
        return await self.app(scope, bounded_receive, send)
