"""Provider-specific, dashboard-owned OAuth. Gateways only reuse/refresh tokens."""
import asyncio
import base64
from contextlib import suppress
import hashlib
import secrets
import time
from types import SimpleNamespace
from urllib.parse import urlencode

import httpx2
from mcp.shared.auth import OAuthMetadata

from guardrails.network import transport_for, origin
from guardrails.policy import PolicyDenied
from tools.mcp_auth import CredentialVault, AuthenticationRequired
from .registry import preset

GOOGLE_SCOPES = {
    "google_ads": ["https://www.googleapis.com/auth/adwords"],
    "search_console": ["https://www.googleapis.com/auth/webmasters.readonly"],
    "google_drive": ["https://www.googleapis.com/auth/drive.readonly"],
}


def provider_name(spec):
    kind = preset(spec["native"]["provider"])["authentication"]
    return {"google_api": "google", "microsoft": "microsoft", "blackbaud": "blackbaud", "linkedin": "linkedin"}.get(kind)


def endpoints(spec):
    provider = spec["native"]["provider"]
    kind = preset(provider)["authentication"]
    if kind == "google_api":
        return {"issuer": "https://accounts.google.com", "authorize": "https://accounts.google.com/o/oauth2/v2/auth", "token": "https://oauth2.googleapis.com/token", "revoke": "https://oauth2.googleapis.com/revoke", "scopes": GOOGLE_SCOPES[provider]}
    if kind == "microsoft":
        tenant = spec["native"]["options"]["tenant"]
        base = f"https://login.microsoftonline.com/{tenant}"
        return {"issuer": base+"/v2.0", "authorize": base+"/oauth2/v2.0/authorize", "token": base+"/oauth2/v2.0/token", "scopes": ["https://graph.microsoft.com/Sites.Read.All", "https://graph.microsoft.com/Files.Read.All", "offline_access"]}
    if kind == "blackbaud":
        return {"issuer": "https://oauth2.sky.blackbaud.com", "authorize": "https://oauth2.sky.blackbaud.com/authorization", "token": "https://oauth2.sky.blackbaud.com/token", "scopes": []}
    if kind == "linkedin":
        return {"issuer": "https://www.linkedin.com", "authorize": "https://www.linkedin.com/oauth/v2/authorization", "token": "https://www.linkedin.com/oauth/v2/accessToken", "scopes": ["r_organization_social", "r_organization_admin"]}
    raise ValueError("This connection uses a provider-issued key rather than browser sign-in.")


def profile(vault, spec):
    key = provider_name(spec)
    revision, value = vault.provider(key) if key else ("", None)
    if value and key == "google":
        info = value["client_json"]["installed"]
        value = {"client_id": info["client_id"], "client_secret": info["client_secret"], "callback_port": 0}
    return key, revision, value


def provider_status(vault, name):
    if name not in {"google", "microsoft", "blackbaud", "linkedin"}:
        raise ValueError("Choose a supported provider registration.")
    revision, value = vault.provider(name)
    return {"configured": bool(value), "revision": revision, "provider": name}


def status(manager, name, spec):
    p = preset(spec["native"]["provider"])
    kind = p["authentication"]
    result = {"method": "api_oauth" if provider_name(spec) else kind, "status": "not_connected", "message": "Connect this service before choosing information."}
    if provider_name(spec):
        result["provider"] = provider_name(spec)
        result["provider_setup"] = provider_status(manager.vault, result["provider"])
        handle = manager.vault.handle(name, spec, manager.store.secret)
        try:
            if handle.read().get("connected"):
                result.update(status="connected", message="Signed in. Choose the accounts or documents agents may read.")
            else:
                result["status"] = "reconnect_required"
        except AuthenticationRequired:
            pass
        transaction = manager.transactions.get(name)
        if transaction and not transaction.task.done():
            try:
                transaction.handle.read()
                result.update(status="connecting", phase=transaction.phase, transaction=transaction.id, expires=transaction.expires)
                result.update(transaction.review or {})
                if transaction.phase == "sign_in":
                    result["authorization_url"] = transaction.authorization_url
            except AuthenticationRequired:
                pass
        elif transaction and transaction.phase == "failed":
            result.update(status="failed", message=transaction.message)
    else:
        missing = any(not manager.store.secret(v) for v in spec["native"].get("secret_refs", {}).values())
        result.update(status="not_connected" if missing else "connected", message="Add the required credentials." if missing else "Credentials configured. Test the connection before choosing information.")
        if kind != "none":
            try:
                row = manager.vault.handle(name, spec, manager.store.secret)
                with manager.vault.db() as db:
                    if row.generation and row.row(db)["status"] == "not_connected":
                        result.update(status="not_connected", message="Disconnected. Replace the connection credentials to connect again.")
            except AuthenticationRequired:
                pass
    return result


async def token_request(handle, policy, data, settings):
    e = endpoints(handle.spec)
    # Only this maintained token endpoint receives the installation credentials.
    data = {**data, "client_id": settings["client_id"]}
    headers = {}
    if settings.get("client_secret"):
        if provider_name(handle.spec) == "blackbaud":
            value = base64.b64encode((settings["client_id"]+":"+settings["client_secret"]).encode()).decode()
            headers["Authorization"] = "Basic " + value
            protect(handle.vault, headers["Authorization"])
        else:
            data["client_secret"] = settings["client_secret"]
    handle.read()
    async with asyncio.timeout(20):
        async with httpx2.AsyncClient(transport=transport_for(e["token"], [e["token"]], (), httpx_module="httpx2", max_bytes=65536, max_requests=1), trust_env=False, follow_redirects=False, timeout=15) as client:
            response = await client.post(e["token"], data=data, headers=headers)
    if response.status_code != 200:
        raise AuthenticationRequired(handle.name)
    from guardrails.validation import strict_json
    value = strict_json(response.content)
    with handle.vault.db() as db:
        handle.vault.remember(db, value)
    if not isinstance(value, dict) or not isinstance(value.get("access_token"), str) or not 1 <= len(value["access_token"]) <= 16384 or any(ord(c) < 33 for c in value["access_token"]):
        raise AuthenticationRequired(handle.name)
    if str(value.get("token_type", "Bearer")).lower() != "bearer":
        raise AuthenticationRequired(handle.name)
    scopes = value.get("scope", " ".join(e["scopes"]))
    if isinstance(scopes, str) and provider_name(handle.spec) == "microsoft":
        # Entra returns Microsoft Graph permissions without the resource prefix.
        scopes = " ".join(s if s == "offline_access" or s.startswith("https://") else "https://graph.microsoft.com/"+s for s in scopes.split())
    if not isinstance(scopes, str) or set(scopes.split()) - set(e["scopes"]) or (set(e["scopes"]) - {"offline_access"}) - set(scopes.split()):
        raise AuthenticationRequired(handle.name)
    expires = value.get("expires_in", 3600)
    if not isinstance(expires, (float, int)) or not 1 <= expires <= 366*86400:
        raise AuthenticationRequired(handle.name)
    saved = {k: value[k] for k in ("access_token", "refresh_token") if isinstance(value.get(k), str)}
    saved["expires"] = time.time()+expires
    # Blackbaud identifies the authorised environment in its token response.
    saved["environment_id"] = str(value.get("environment_id", ""))[:512]
    saved["environment_name"] = str(value.get("environment_name", "Blackbaud environment"))[:200]
    return saved


def protect(vault, value):
    if not value:
        return
    with vault.db() as db:
        row = db.execute("SELECT expires FROM redactions WHERE hash=?", (hashlib.sha256(value.encode()).hexdigest(),)).fetchone()
        if not row or row[0] < time.time()+86400:
            vault.remember(db, {"access_token": value})


async def access_token(handle, policy):
    current = handle.read()
    tokens = current.get("api_tokens", {})
    if current.get("connected") and tokens.get("expires", 0) > time.time()+60:
        return tokens["access_token"]
    async with handle.lease():
        current = handle.read()
        tokens = current.get("api_tokens", {})
        if current.get("connected") and tokens.get("expires", 0) > time.time()+60:
            return tokens["access_token"]
        _, _, settings = profile(handle.vault, handle.spec)
        if not current.get("connected") or not tokens.get("refresh_token") or not settings:
            raise AuthenticationRequired(handle.name)
        try:
            updated = await token_request(handle, policy, {"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]}, settings)
            updated.setdefault("refresh_token", tokens["refresh_token"])
            updated["environment_id"] = updated.get("environment_id") or tokens.get("environment_id", "")
            handle.change(lambda data: data.update(api_tokens=updated))
            return updated["access_token"]
        except BaseException:
            with suppress(AuthenticationRequired):
                handle.change(lambda data: data.update(connected=False), status="reconnect_required")
            raise


async def start(manager, name, spec):
    from control_panel.mcp_auth import SignIn
    key, revision, settings = profile(manager.vault, spec)
    if not settings:
        raise ValueError("Administrator setup is needed for this provider before signing in.")
    await manager.cancel(name)
    handle = manager.vault.reset(name, spec, manager.store.secret)
    handle.change(lambda data: data.update(provider_registration=revision, provider_registration_name=key))

    class ApiSignIn(SignIn):
        async def run(self):
            try:
                async with asyncio.timeout(300):
                    e = endpoints(spec)
                    await self.listen(settings.get("callback_port", 0))
                    self.provider = SimpleNamespace(context=SimpleNamespace(oauth_metadata=OAuthMetadata(issuer=e["issuer"], authorization_endpoint=e["authorize"], token_endpoint=e["token"])))
                    self.review = {"provider": e["issuer"], "scopes": e["scopes"], "destinations": [e["authorize"], e["token"]]}
                    self.phase = "review"
                    await self.approval.wait()
                    self.handle.read()
                    verifier = secrets.token_urlsafe(48)
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
                    self.expected_state = secrets.token_urlsafe(32)
                    redirect = f"http://127.0.0.1:{self.port}/callback"
                    args = {"client_id": settings["client_id"], "redirect_uri": redirect, "response_type": "code", "state": self.expected_state, "code_challenge": challenge, "code_challenge_method": "S256"}
                    if e["scopes"]:
                        args["scope"] = " ".join(e["scopes"])
                    if key == "google":
                        args.update(access_type="offline", prompt="consent")
                    self.authorization_url = e["authorize"]+"?"+urlencode(args)
                    self.phase = "sign_in"
                    result = await self.callback
                    tokens = await token_request(self.handle, manager.runtime.policy(), {"grant_type": "authorization_code", "code": result.code, "redirect_uri": redirect, "code_verifier": verifier}, settings)
                    self.handle.change(lambda data: data.update(api_tokens=tokens, connected=True), status="connected")
                    self.phase, self.message = "connected", "Signed in. Choose which information and agents to connect."
            except asyncio.CancelledError:
                self.phase = "not_connected"
                raise
            except Exception:
                self.phase, self.message = "failed", "Sign-in could not complete. Check administrator setup, callback address and provider permissions, then reconnect."
                with suppress(AuthenticationRequired):
                    self.handle.change(lambda data: data.update(connected=False), status="failed")
            finally:
                if self.server:
                    self.server.close()
                    await self.server.wait_closed()
                self.authorization_url, self.expected_state = "", ""
                if not self.callback.done():
                    self.callback.cancel()
                elif not self.callback.cancelled():
                    self.callback.exception()

    transaction = ApiSignIn(manager, name, handle)
    manager.transactions[name] = transaction
    transaction.task = asyncio.create_task(transaction.run())
    manager.tasks.add(transaction.task)
    transaction.task.add_done_callback(manager.tasks.discard)
    return status(manager, name, spec)
