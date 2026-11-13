"""Dashboard-owned, bounded OAuth transactions and Google Analytics setup."""
from __future__ import annotations

import asyncio
from contextlib import suppress
import json
import secrets
import time
from urllib.parse import parse_qs, urlsplit, urlencode

import httpx2
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthMetadata, OAuthToken
from mcp.client.auth.utils import validate_authorization_response_iss

from guardrails.network import origin, permitted_url, resolve_public
from tools.definitions import MCPSpec, example_endpoint
from tools.mcp_auth import (
    AuthNetwork, AuthenticationRequired, CredentialVault, SavedOAuth,
    GOOGLE_SCOPE, GOOGLE_TOKEN, GOOGLE_AUTHORIZE, GOOGLE_REVOKE,
    validate_google_credentials, validate_google_client, GOOGLE_IMPORT_SCOPES,
)

SIGN_IN_SECONDS = 300

FAILURES = {
    "connection.placeholder": "This is an example server address, not a live MCP service. Edit the connection to enter the address of your deployed MCP server.",
    "auth.expired": "Sign-in expired after five minutes. Choose Connect to start again.",
    "auth.declined": "Sign-in was declined. Choose Connect when you are ready to grant access.",
    "auth.callback_port": "The local sign-in callback port could not be opened. Choose another callback port in the connection settings, or close the other app using it.",
    "auth.dns": "The MCP server or sign-in provider could not be found. Check the saved server address and your network connection.",
    "auth.network": "The sign-in destination was blocked by network policy. Check the server address and any approved local-service exceptions.",
    "auth.unreachable": "The MCP server or sign-in provider could not be reached. Check the server address, that the server is running, and your network connection.",
    "auth.registration": "The sign-in provider could not register this app. If it requires a registered OAuth client, add its client ID and saved client-secret reference in the connection settings.",
    "auth.metadata": "This endpoint did not advertise usable MCP OAuth sign-in settings. Check the MCP server address and its supported authentication method.",
    "auth.credentials": "The sign-in provider did not return usable credentials. Check the OAuth client setup and callback address, then connect again.",
    "auth.permissions": "The provider granted different permissions from those approved. Check the requested permissions, then connect again.",
    "auth.offline": "Google did not return permission to stay connected. Reconnect and grant offline access with the read-only Analytics permission.",
    "auth.changed": "The connection settings changed during sign-in. Choose Connect to sign in with the saved settings.",
    "auth.failed": "Sign-in could not complete. Check the connection settings and try again.",
}


class SignInFailure(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(FAILURES[code])


def sign_in_failure(error, stage):
    """Classify known failures without rendering provider bodies or tracebacks."""
    from mcp.client.auth import OAuthRegistrationError, OAuthTokenError
    from guardrails.policy import PolicyDenied
    pending, seen = [error], set()
    while pending and len(seen) < 32:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, SignInFailure):
            return item.code
        if isinstance(item, AuthenticationRequired):
            return "auth.changed"
        if isinstance(item, PolicyDenied):
            return "auth.dns" if item.rule == "network.dns" else "auth.network" if item.rule.startswith("network.") else "auth.failed"
        if isinstance(item, TimeoutError):
            return "auth.expired"
        if isinstance(item, (httpx2.RequestError, OSError)):
            return "auth.callback_port" if stage == "callback" else "auth.unreachable"
        if isinstance(item, OAuthRegistrationError):
            return "auth.registration"
        if isinstance(item, OAuthTokenError):
            return "auth.credentials"
        pending.extend(getattr(item, "exceptions", []))
        pending.extend(child for child in (getattr(item, "__cause__", None), getattr(item, "__context__", None)) if child is not None)
    return "auth.failed"


class DashboardOAuth(SavedOAuth):
    def __init__(self, transaction):
        self.transaction = transaction
        super().__init__(transaction.handle, callback_port=transaction.port)

    async def redirect_handler(self, authorization_url):
        await self.transaction.review_provider()
        self.transaction.handle.read()
        self.transaction.authorization_url = authorization_url
        self.transaction.expected_state = parse_qs(urlsplit(authorization_url).query)["state"][0]
        self.transaction.phase = "sign_in"
        self.transaction.stage = "authorization"

    async def callback_handler(self):
        return await self.transaction.callback

class SignIn:
    def __init__(self, manager, name, handle):
        self.manager, self.name, self.handle = manager, name, handle
        self.id = secrets.token_urlsafe(24)
        self.expires = time.time() + SIGN_IN_SECONDS
        self.phase, self.message = "connecting", "Preparing secure sign-in…"
        self.stage, self.error_code = "callback", ""
        self.authorization_url, self.expected_state = "", ""
        self.approval = asyncio.Event()
        self.callback = asyncio.get_running_loop().create_future()
        self.provider = None
        self.server, self.port, self.task = None, 0, None
        self.review = None
        self.reviewed = None
        self.client_json = None

    async def listen(self, port):
        self.server = await asyncio.start_server(self.receive_callback, "127.0.0.1", port, limit=16384)
        self.port = self.server.sockets[0].getsockname()[1]

    async def receive_callback(self, reader, writer):
        status, message = "400 Bad Request", "This sign-in response is invalid or expired. Return to the app."
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            first, *headers = raw.decode("ascii").split("\r\n")
            method, target, version = first.split(" ")
            header_values = [line.split(":", 1) for line in headers if ":" in line]
            host = [v.strip() for k, v in header_values if k.lower() == "host"]
            parsed = urlsplit(target)
            query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=12)
            valid = (method == "GET" and parsed.path == "/callback" and not parsed.netloc and host == [f"127.0.0.1:{self.port}"]
                     and time.time() < self.expires and not self.callback.done() and bool(self.expected_state)
                     and all(len(values) == 1 for values in query.values())
                     and secrets.compare_digest(query.get("state", [""])[0], self.expected_state))
            if valid:
                self.handle.read()
                issuer = query.get("iss", [None])[0]
                validate_authorization_response_iss(issuer, self.provider.context.oauth_metadata)
                if query.get("error"):
                    self.callback.set_exception(SignInFailure("auth.declined"))
                elif query.get("code", [""])[0]:
                    self.callback.set_result(AuthorizationCodeResult(code=query["code"][0], state=self.expected_state, iss=issuer))
                else:
                    raise ValueError("Missing authorization code.")
                status, message = "200 OK", "Sign-in response received. You can close this tab and return to Kindred."
        except (Exception, asyncio.CancelledError):
            pass
        finally:
            body = ("<!doctype html><html><head><title>Kindred sign-in</title></head><body><p>" + message + "</p></body></html>").encode()
            writer.write((f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n").encode() + body)
            with suppress(Exception):
                await writer.drain()
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    async def review_provider(self):
        metadata = self.provider.context.oauth_metadata
        if metadata is None:
            raise SignInFailure("auth.metadata")
        scopes = sorted(set((self.provider.context.client_metadata.scope or "").split()))
        targets = [str(value) for value in (metadata.authorization_endpoint, metadata.token_endpoint, metadata.registration_endpoint, metadata.revocation_endpoint) if value]
        if self.reviewed == (metadata.model_dump(mode="json"), scopes):
            return
        policy = self.manager.runtime.policy()
        # Reject malicious metadata even if a user would approve it in the browser.
        for endpoint in [str(metadata.issuer), *targets]:
            local = permitted_url(endpoint, [endpoint], policy.local_endpoints)
            parts = origin(endpoint)
            await resolve_public(parts[1], parts[2], local)
        self.review = {"provider": str(metadata.issuer), "scopes": scopes, "destinations": targets}
        self.approval.clear()
        self.stage = "provider_review"
        self.phase = "review"
        await self.approval.wait()
        self.handle.read()
        self.handle.change(lambda data: data.update(metadata=metadata.model_dump(mode="json"), auth_targets=targets, approved_scopes=scopes))
        self.reviewed = (metadata.model_dump(mode="json"), scopes)
        self.phase = "connecting"

    def approve(self, transaction):
        if transaction != self.id or self.phase != "review" or time.time() >= self.expires:
            raise ValueError("This sign-in request expired or changed. Start again.")
        self.handle.read()
        self.approval.set()

    async def run(self):
        try:
            async with asyncio.timeout(SIGN_IN_SECONDS):
                definition = MCPSpec.model_validate(self.handle.spec)
                await self.listen(definition.authentication().callback_port)
                self.provider = DashboardOAuth(self)
                self.stage = "discovery"
                if definition.authentication().type == "google_adc":
                    await self.google_sign_in()
                else:
                    from tools.gateway import mcp_transport
                    from fastmcp import Client
                    async with Client(mcp_transport(self.handle.spec, self.manager.store.secret, policy=self.manager.runtime.policy(), root=self.manager.store.root, connection=self.name, oauth=self.provider, interactive=self), timeout=315) as client:
                        await client.list_tools()
                self.handle.read()
                tokens = await self.provider.token_storage_adapter.get_tokens()
                if not tokens:
                    raise SignInFailure("auth.credentials")
                scopes = set((tokens.scope or "").split())
                if not scopes <= set(self.handle.read().get("approved_scopes", [])):
                    raise SignInFailure("auth.permissions")
                self.handle.change(lambda data: data.update(connected=True), status="connected")
                self.phase = "discovering"
                try:
                    from .connections import discover_connection
                    def before_save():
                        self.handle.read()
                        if self.manager.busy():
                            raise ValueError("Finish the current response before saving discovered tools.")
                    await discover_connection(self.manager.store, self.manager.runtime, self.name, before_save=before_save)
                    self.message = "Signed in. Tools discovered; review their access before assigning them."
                except Exception:
                    self.message = "Signed in. Discovery needs attention; test the connection when the current response has finished."
                self.phase = "connected"
        except asyncio.CancelledError:
            self.phase, self.message = "not_connected", "Sign-in cancelled."
            raise
        except Exception as error:
            # Provider error bodies can contain tokens, codes or personal account data.
            self.error_code = sign_in_failure(error, self.stage)
            self.phase, self.message = "failed", FAILURES[self.error_code]
            with suppress(AuthenticationRequired):
                self.handle.change(lambda data: data.update(connected=False, error_code=self.error_code, failure_stage=self.stage), status="failed")
        finally:
            if self.server:
                self.server.close()
                await self.server.wait_closed()
            self.authorization_url, self.expected_state, self.client_json = "", "", None
            if not self.callback.done():
                self.callback.cancel()
            elif not self.callback.cancelled():
                self.callback.exception()  # Retrieve denied-consent errors on cancellation.

    async def google_sign_in(self):
        info = self.client_json
        self.client_json = None
        if not isinstance(info, dict) or set(info) != {"installed"} or not isinstance(info["installed"], dict):
            raise ValueError("Use a Google OAuth desktop client JSON.")
        info = info["installed"]
        if info.get("auth_uri") != "https://accounts.google.com/o/oauth2/auth" or info.get("token_uri") != GOOGLE_TOKEN:
            raise ValueError("Use Google's standard OAuth desktop client endpoints.")
        credentials = validate_google_credentials({"type": "authorized_user", "client_id": info.get("client_id"), "client_secret": info.get("client_secret"), "refresh_token": "pending"})
        provider = self.provider
        provider.context.client_metadata.scope = GOOGLE_SCOPE
        provider.context.client_info = OAuthClientInformationFull(client_id=credentials["client_id"], client_secret=credentials["client_secret"], token_endpoint_auth_method="client_secret_post", redirect_uris=provider.context.client_metadata.redirect_uris)
        provider.context.oauth_metadata = OAuthMetadata(issuer="https://accounts.google.com", authorization_endpoint=GOOGLE_AUTHORIZE, token_endpoint=GOOGLE_TOKEN, revocation_endpoint=GOOGLE_REVOKE, code_challenge_methods_supported=["S256"])
        await provider.token_storage_adapter.set_client_info(provider.context.client_info)
        # The SDK supplies PKCE, state validation and code exchange. Google also
        # requires offline access and explicit consent to issue a refresh token.
        original = provider.context.redirect_handler
        async def redirect(url):
            await original(url + "&" + urlencode({"access_type": "offline", "prompt": "consent"}))
        provider.context.redirect_handler = redirect
        request = await provider._perform_authorization()
        self.stage = "token_exchange"
        async with httpx2.AsyncClient(transport=AuthNetwork(self.handle, self.manager.runtime.policy()), trust_env=False, follow_redirects=False, timeout=15) as client:
            response = await client.send(request)
        await provider._handle_token_response(response)
        tokens = provider.context.current_tokens
        if not tokens.refresh_token:
            raise SignInFailure("auth.offline")
        credentials["refresh_token"] = tokens.refresh_token
        self.handle.change(lambda data: data.update(google=credentials))


class AuthenticationManager:
    def __init__(self, store, runtime, *, busy=lambda: False):
        self.store, self.runtime, self.busy = store, runtime, busy
        self.vault = CredentialVault(store.root)
        self.transactions = {}
        self.tasks = set()
        # Credential files are request-owned. Remove only abandoned owners.
        from tools.google_transport import clean_abandoned_credentials
        clean_abandoned_credentials(self.vault.directory)

    def spec(self, name):
        spec = self.store.tools()["mcp_servers"].get(name)
        if not spec:
            raise ValueError("Save the connection before signing in.")
        definition = MCPSpec.model_validate(spec)
        if not definition.enabled:
            raise ValueError("Enable this connection before signing in.")
        return spec, definition

    def provider_status(self):
        revision, value = self.vault.provider("google")
        return {"configured": value is not None, "revision": revision, "project": value.get("project", "") if value else ""}

    async def update_provider(self, expected, value):
        if self.busy():
            raise ValueError("Finish or stop the current response before changing provider setup.")
        if value is not None:
            validate_google_client(value["client_json"])
            from tools.definitions import MCPAuthentication
            MCPAuthentication(type="google_adc", project=value["project"])
        linked = []
        for name, transaction in list(self.transactions.items()):
            with suppress(AuthenticationRequired):
                record = transaction.handle.read()
                if record.get("provider_registration") and record.get("provider_registration_name", "google") == "google":
                    linked.append(name)
        self.vault.save_provider("google", value, expected)
        for name in linked:
            await self.cancel(name)
        return self.provider_status()

    def status(self, name):
        try:
            spec, definition = self.spec(name)
        except ValueError:
            return {"method": "none", "status": "failed", "message": "Connection settings need administrator review. Other services remain available."}
        if definition.transport == "native":
            from connectors.auth import status
            return status(self, name, spec)
        auth = definition.authentication()
        transaction = self.transactions.get(name)
        result = {"method": auth.type, "status": "not_connected", "message": "Sign in to connect this service."}
        if auth.type == "google_adc":
            result["provider_setup"] = self.provider_status()
        if auth.type == "oauth" and example_endpoint(definition.url):
            return {"method": auth.type, "status": "failed", "error_code": "connection.placeholder", "message": FAILURES["connection.placeholder"]}
        if auth.type not in {"oauth", "google_adc"}:
            missing = any(not self.store.secret(key) for key in [*definition.env_vars, *definition.env_secrets.values(), *definition.header_secrets.values(), *([definition.token_env] if definition.token_env else [])])
            return {"method": auth.type, "status": "not_connected" if missing else "connected", "message": "Add the required secrets." if missing else "Authentication configured."}
        handle = self.vault.handle(name, spec, self.store.secret)
        try:
            record = handle.read()
            if record.get("connected"):
                result.update(status="connected", message="Signed in. Tool access is reviewed separately.")
            else:
                with self.vault.db() as db:
                    row = handle.row(db)
                result["status"] = row["status"] if row["status"] != "connecting" else "reconnect_required"
                if result["status"] == "failed":
                    code = record.get("error_code", "auth.failed")
                    result.update(error_code=code if code in FAILURES else "auth.failed", message=FAILURES.get(code, FAILURES["auth.failed"]))
        except AuthenticationRequired:
            if handle.generation is None:
                with self.vault.db() as db:
                    previous = db.execute("SELECT 1 FROM credentials WHERE name=?", (name,)).fetchone()
                if previous:
                    result.update(status="reconnect_required", message="Connection settings changed. Sign in again.")
        if transaction and not transaction.task.done():
            try:
                transaction.handle.read()
            except AuthenticationRequired:
                return result
            result.update(status="connecting", phase=transaction.phase, transaction=transaction.id, expires=transaction.expires, message="Review the sign-in provider and permissions." if transaction.phase == "review" else "Complete sign-in in your browser.")
            if transaction.review:
                result.update(transaction.review)
            if transaction.phase == "sign_in":
                result["authorization_url"] = transaction.authorization_url
        elif transaction and transaction.phase in {"failed", "connected"}:
            result["message"] = transaction.message
            if transaction.error_code:
                result["error_code"] = transaction.error_code
        return result

    async def start(self, name, client_json=None):
        if self.busy():
            raise ValueError("Finish or stop the current response before signing in.")
        spec, definition = self.spec(name)
        if definition.transport == "native":
            from connectors.auth import start
            return await start(self, name, spec)
        auth = definition.authentication()
        if auth.type not in {"oauth", "google_adc"}:
            raise ValueError("Choose browser sign-in or Google credentials in the connection settings.")
        if auth.type == "oauth" and example_endpoint(definition.url):
            raise SignInFailure("connection.placeholder")
        if auth.client_secret_env and not self.store.secret(auth.client_secret_env):
            raise ValueError("Add the saved OAuth client secret before connecting.")
        if auth.type == "google_adc" and client_json:
            validate_google_client(client_json)
        await self.cancel(name)
        registration = ""
        if auth.type == "google_adc" and not client_json:
            registration, provider = self.vault.provider("google")
            if not provider:
                raise ValueError("Complete the one-time Google provider setup, or choose a Google OAuth desktop-client JSON file.")
            client_json = provider["client_json"]
        handle = self.vault.reset(name, spec, self.store.secret)
        if registration:
            handle.change(lambda data: data.update(provider_registration=registration))
        transaction = SignIn(self, name, handle)
        transaction.client_json = client_json
        self.transactions[name] = transaction
        transaction.task = asyncio.create_task(transaction.run())
        self.tasks.add(transaction.task)
        transaction.task.add_done_callback(self.tasks.discard)
        return self.status(name)

    async def cancel(self, name):
        transaction = self.transactions.pop(name, None)
        if transaction and not transaction.task.done():
            # Invalidate before cancellation, even if a response is being committed.
            self.vault.disconnect(name)
            transaction.task.cancel()
            await asyncio.gather(transaction.task, return_exceptions=True)

    async def disconnect(self, name):
        spec, _ = self.spec(name)
        handle = self.vault.handle(name, spec, self.store.secret)
        try:
            saved = handle.read()
        except AuthenticationRequired:
            saved = {}
        await self.cancel(name)
        self.vault.disconnect(name)
        if spec.get("native") and spec["native"].get("secret_refs"):
            from connectors.auth import protect
            from guardrails.policy import canonical
            # Remove only this connection's private key values. A custom/shared
            # reference is retained for its other users and remains disconnected.
            with self.store.lock:
                config = self.store.tools()
                others = {**config, "mcp_servers": {k:v for k,v in config["mcp_servers"].items() if k != name}}
                references = canonical([others, self.store.yaml("inference/litellm-config.yml")])
                remove = {}
                for reference in spec["native"]["secret_refs"].values():
                    protect(self.vault, self.store.secret(reference))
                    if reference.startswith("MCP_") and reference not in references:
                        remove[reference] = None
                if remove:
                    with self.store.edit(self.store.revision()):
                        self.store.write_secrets(remove)
        # Revoke after local invalidation, using a detached snapshot that cannot write.
        metadata = saved.get("metadata", {})
        endpoint = metadata.get("revocation_endpoint")
        if spec.get("native"):
            from connectors.auth import endpoints, provider_name
            if provider_name(spec):
                endpoint = endpoints(spec).get("revoke")
                metadata = {"revocation_endpoint": endpoint}
                saved["auth_targets"] = [endpoint] if endpoint else []
        if endpoint and endpoint in saved.get("auth_targets", []):
            tokens = [v for k, v in saved.get("kv", {}).items() if k.startswith("mcp-oauth-token:")]
            token = (tokens[0].get("refresh_token") or tokens[0].get("access_token")) if tokens else (saved.get("google") or {}).get("refresh_token")
            if spec.get("native"):
                token = saved.get("api_tokens", {}).get("refresh_token") or saved.get("api_tokens", {}).get("access_token")
            if token:
                from guardrails.network import transport_for
                with suppress(Exception):
                    async with asyncio.timeout(5):
                        async with httpx2.AsyncClient(transport=transport_for(endpoint, [endpoint], self.runtime.policy().local_endpoints, httpx_module="httpx2", max_bytes=16384, max_requests=1), trust_env=False, follow_redirects=False, timeout=5) as client:
                            await client.post(endpoint, data={"token": token})
        return self.status(name)

    async def import_google(self, name, credentials):
        if self.busy():
            raise ValueError("Finish the current response before importing credentials.")
        spec, definition = self.spec(name)
        if definition.authentication().type != "google_adc":
            raise ValueError("Choose Google credentials for this local connection first.")
        credentials = validate_google_credentials(credentials)
        await self.cancel(name)
        handle = self.vault.reset(name, spec, self.store.secret)
        # Validate the refresh grant before marking an imported credential connected.
        handle.change(lambda data: data.update(google=credentials, metadata={"issuer": "https://accounts.google.com", "authorization_endpoint": GOOGLE_AUTHORIZE, "token_endpoint": GOOGLE_TOKEN, "revocation_endpoint": GOOGLE_REVOKE}, auth_targets=[GOOGLE_TOKEN, GOOGLE_REVOKE], approved_scopes=[GOOGLE_SCOPE]))
        try:
            async with asyncio.timeout(25):
                async with httpx2.AsyncClient(transport=AuthNetwork(handle, self.runtime.policy()), trust_env=False, follow_redirects=False, timeout=15) as client:
                    response = await client.post(GOOGLE_TOKEN, data={"grant_type": "refresh_token", "refresh_token": credentials["refresh_token"], "client_id": credentials["client_id"], "client_secret": credentials["client_secret"], "scope": GOOGLE_SCOPE})
            if response.status_code != 200:
                raise ValueError("Google did not accept these credentials. Sign in again.")
            tokens = OAuthToken.model_validate(response.json())
            if not tokens.scope or GOOGLE_SCOPE not in tokens.scope.split() or set(tokens.scope.split()) - GOOGLE_IMPORT_SCOPES:
                raise ValueError("These credentials do not include Google Analytics read access.")
            handle.change(lambda data: data.update(connected=True), status="connected")
        except Exception:
            self.vault.disconnect(name)
            raise ValueError("Could not validate the Google read-only credentials. Check their permissions or sign in again.") from None
        try:
            from .connections import discover_connection
            def before_save():
                handle.read()
                if self.busy():
                    raise ValueError("Finish the current response before saving discovered tools.")
            await discover_connection(self.store, self.runtime, name, before_save=before_save)
        except Exception:
            return {**self.status(name), "message": "Signed in. Test the connection to discover tools after reviewing the local command."}
        return self.status(name)

    async def close(self):
        for name in list(self.transactions):
            await self.cancel(name)
        remaining = list(self.tasks)
        for task in remaining:
            task.cancel()
        await asyncio.gather(*remaining, return_exceptions=True)
