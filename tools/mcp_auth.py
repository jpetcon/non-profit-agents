"""Private upstream credentials and non-interactive gateway authentication.

Nothing in this module grants tool permissions. Local gateway credentials must
never enter these clients. The dashboard owns all interactive consent.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
import hashlib
import json
import logging
import os
import re
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
from urllib.parse import urlsplit

import httpx2
from cryptography.fernet import Fernet
from dotenv import dotenv_values
from fastmcp.client.auth import OAuth
from mcp.shared.auth import OAuthMetadata

from guardrails.network import origin, transport_for
from guardrails.policy import PolicyDenied, canonical, digest
from .definitions import MCPSpec

GOOGLE_SCOPE = "https://www.googleapis.com/auth/analytics.readonly"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_REVOKE = "https://oauth2.googleapis.com/revoke"
GOOGLE_IMPORT_SCOPES = {GOOGLE_SCOPE, "https://www.googleapis.com/auth/cloud-platform", "openid", "email", "https://www.googleapis.com/auth/userinfo.email"}

# These SDK error logs may embed provider bodies or authorization URLs. Safe
# connection status is returned by our adapters instead; payloads are never logs.
for _logger in ("mcp.client.auth.oauth2", "mcp.client.auth.utils", "fastmcp.client.auth.oauth"):
    logging.getLogger(_logger).disabled = True


class AuthenticationRequired(PolicyDenied):
    def __init__(self, name=""):
        super().__init__("connection.auth_required", "Sign in to the assigned MCP connection in Chat setup or Tools & Connections.")
        self.connection = name


def is_auth_failure(error):
    pending, seen = [error], set()
    while pending and len(seen) < 32:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, AuthenticationRequired):
            return True
        pending.extend(getattr(item, "exceptions", []))
        pending.extend(child for child in (getattr(item, "__cause__", None), getattr(item, "__context__", None)) if child is not None)
    return False


def secret_resolver(root):
    def resolve(key):
        return dotenv_values(Path(root) / ".env", interpolate=False).get(key) or os.environ.get(key, "")
    return resolve


def binding(spec, resolve):
    definition = MCPSpec.model_validate(spec)
    if definition.transport == "native":
        n = definition.native
        from connectors.auth import endpoints, provider_name
        from connectors.registry import preset
        driver = endpoints(spec) if provider_name(spec) else preset(n.provider)["authentication"]
        return digest([definition.managed.model_dump(exclude={'default_capabilities'}), preset(n.provider)["api_version"], driver, n.provider, n.options, {k: hashlib.sha256(resolve(v).encode()).hexdigest() for k, v in n.secret_refs.items()}])
    auth = definition.authentication()
    # New optional connector fields must not invalidate existing MCP credentials.
    public = definition.model_dump(exclude={"display_name", "native", "managed"})
    if definition.managed:
        public["managed"] = definition.managed.model_dump(exclude={'default_capabilities'})
    return digest([public, hashlib.sha256(resolve(auth.client_secret_env).encode()).hexdigest() if auth.client_secret_env else ""])


class CredentialVault:
    """Encrypted records with generation checks and cross-process refresh leases.

    The key is separate from the database, both private and outside config backups.
    As elsewhere in this trusted local app, code running as this OS user can read
    these files. Encryption does not sandbox trusted MCP subprocesses.
    """
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.directory = self.root / ".local" / "mcp-auth"
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.directory.chmod(0o700)
        key_path = self.directory / "key"
        # Publish a complete key atomically; never read a concurrently empty file.
        if not key_path.exists():
            fd, temporary = tempfile.mkstemp(dir=self.directory, prefix="key-")
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(Fernet.generate_key()); stream.flush(); os.fsync(stream.fileno())
                try:
                    os.link(temporary, key_path)
                except FileExistsError:
                    pass
            finally:
                os.unlink(temporary)
        key_path.chmod(0o600)
        self.fernet = Fernet(key_path.read_bytes())
        self.path = self.directory / "credentials.sqlite"
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS credentials (
                  name TEXT PRIMARY KEY, binding TEXT NOT NULL, generation TEXT NOT NULL,
                  payload BLOB NOT NULL, status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS leases (
                  name TEXT PRIMARY KEY, owner TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS redactions (
                  hash TEXT PRIMARY KEY, value BLOB NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS providers (
                  name TEXT PRIMARY KEY, revision TEXT NOT NULL, payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS connection_checks (
                  name TEXT PRIMARY KEY, binding TEXT NOT NULL, status TEXT NOT NULL, checked REAL NOT NULL);
            """)
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def encode(self, value):
        return self.fernet.encrypt(canonical(value).encode())

    def decode(self, value):
        return json.loads(self.fernet.decrypt(value))

    def handle(self, name, spec, resolve=None):
        return CredentialHandle(self, name, spec, resolve or secret_resolver(self.root))

    def reset(self, name, spec, resolve=None):
        handle = self.handle(name, spec, resolve)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT payload FROM credentials WHERE name=?", (name,)).fetchone()
            if previous:
                self.remember(db, self.decode(previous[0]))
            db.execute("INSERT OR REPLACE INTO credentials VALUES (?,?,?,?,?)", (name, handle.binding, secrets.token_hex(24), self.encode({}), "connecting"))
            db.execute("DELETE FROM leases WHERE name=?", (name,))
        return self.handle(name, spec, resolve)

    def disconnect(self, name):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT payload FROM credentials WHERE name=?", (name,)).fetchone()
            if previous:
                self.remember(db, self.decode(previous[0]))
            # Keep an empty generation tombstone so in-flight writers cannot revive it.
            db.execute("UPDATE credentials SET generation=?,payload=?,status='not_connected' WHERE name=?", (secrets.token_hex(24), self.encode({}), name))
            db.execute("DELETE FROM leases WHERE name=?", (name,))

    def provider(self, name):
        with self.db() as db:
            row = db.execute("SELECT revision,payload FROM providers WHERE name=?", (name,)).fetchone()
            return (row["revision"], self.decode(row["payload"])) if row else ("", None)

    def record_check(self, name, spec, status):
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO connection_checks VALUES (?,?,?,?)", (name, digest(spec), status, time.time()))

    def connection_checks(self):
        with self.db() as db:
            return {row["name"]: dict(row) for row in db.execute("SELECT * FROM connection_checks")}

    def save_provider(self, name, value, expected):
        from control_panel.store import Conflict
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT revision,payload FROM providers WHERE name=?", (name,)).fetchone()
            if (row[0] if row else "") != expected:
                raise Conflict("Provider setup changed in another window. Reload before saving.")
            if row:
                self.remember(db, self.decode(row["payload"]))
            # Invalidate linked Google account generations in the same transaction.
            # Pending exchanges and refresh writers cannot revive old credentials.
            for account in db.execute("SELECT name,payload FROM credentials").fetchall():
                data = self.decode(account["payload"])
                if data.get("provider_registration") and data.get("provider_registration_name", "google") == name:
                    self.remember(db, data)
                    db.execute("UPDATE credentials SET generation=?,payload=?,status='reconnect_required' WHERE name=?", (secrets.token_hex(24), self.encode({}), account["name"]))
                    db.execute("DELETE FROM leases WHERE name=?", (account["name"],))
            if value is not None:
                self.remember(db, value)
            # Retain a revision tombstone so delete/recreate cannot make a stale
            # "not configured" window appear current again.
            db.execute("INSERT OR REPLACE INTO providers VALUES (?,?,?)", (name, secrets.token_hex(24), self.encode(value)))

    def remember(self, db, value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"access_token", "refresh_token", "client_secret", "id_token"} and isinstance(item, str) and item:
                    db.execute("INSERT OR REPLACE INTO redactions VALUES (?,?,?)", (hashlib.sha256(item.encode()).hexdigest(), self.encode(item), time.time() + 90 * 86400))
                self.remember(db, item)
        elif isinstance(value, list):
            for item in value:
                self.remember(db, item)

    def secret_values(self):
        def active_values(value):
            found = set()
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in {"access_token", "refresh_token", "client_secret", "id_token"} and isinstance(item, str) and item:
                        found.add(item)
                    found.update(active_values(item))
            elif isinstance(value, list):
                for item in value:
                    found.update(active_values(item))
            return found
        with self.db() as db:
            # Active registrations and credentials remain protected for their
            # full lifetime; 90 days is the retention for retired values only.
            current = set()
            for table in ("credentials", "providers"):
                for row in db.execute(f"SELECT payload FROM {table}"):
                    current.update(active_values(self.decode(row[0])))
            db.execute("DELETE FROM redactions WHERE expires<?", (time.time(),))
            current.update(self.decode(row[0]) for row in db.execute("SELECT value FROM redactions"))
            return list(current)


class CredentialHandle:
    def __init__(self, vault, name, spec, resolve):
        self.vault, self.name, self.spec, self.resolve = vault, name, spec, resolve
        self.binding = binding(spec, resolve)
        with vault.db() as db:
            row = db.execute("SELECT generation,binding FROM credentials WHERE name=?", (name,)).fetchone()
        self.generation = row["generation"] if row and row["binding"] == self.binding else None

    def row(self, db):
        row = db.execute("SELECT * FROM credentials WHERE name=?", (self.name,)).fetchone()
        if not row or row["generation"] != self.generation or row["binding"] != self.binding:
            raise AuthenticationRequired(self.name)
        # Protect against a saved endpoint/client/scope change while OAuth is pending.
        import yaml
        current = (yaml.safe_load((self.vault.root / "tools/config.yml").read_text()) or {}).get("mcp_servers", {}).get(self.name)
        if current is None or binding(current, self.resolve) != self.binding or not current.get("enabled", True):
            raise AuthenticationRequired(self.name)
        registration = self.vault.decode(row["payload"]).get("provider_registration")
        if registration:
            provider_name = self.vault.decode(row["payload"]).get("provider_registration_name", "google")
            provider = db.execute("SELECT revision FROM providers WHERE name=?", (provider_name,)).fetchone()
            if not provider or provider[0] != registration:
                raise AuthenticationRequired(self.name)
        return row

    def read(self):
        with self.vault.db() as db:
            return self.vault.decode(self.row(db)["payload"])

    def change(self, edit, *, status=None):
        with self.vault.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.row(db)
            value = self.vault.decode(row["payload"])
            self.vault.remember(db, value)
            edit(value)
            self.vault.remember(db, value)
            db.execute("UPDATE credentials SET payload=?,status=? WHERE name=?", (self.vault.encode(value), status or row["status"], self.name))

    @asynccontextmanager
    async def lease(self):
        owner = secrets.token_hex(24)
        deadline = time.monotonic() + 35
        while True:
            with self.vault.db() as db:
                db.execute("BEGIN IMMEDIATE")
                self.row(db)
                db.execute("DELETE FROM leases WHERE expires<?", (time.time(),))
                acquired = db.execute("INSERT OR IGNORE INTO leases VALUES (?,?,?)", (self.name, owner, time.time() + 40)).rowcount
            if acquired:
                break
            if time.monotonic() >= deadline:
                raise AuthenticationRequired(self.name)
            await asyncio.sleep(.05)
        try:
            yield
        finally:
            with self.vault.db() as db:
                db.execute("DELETE FROM leases WHERE name=? AND owner=?", (self.name, owner))


class VaultKV:
    """AsyncKeyValue adapter used by FastMCP's own token/expiry adapter."""
    def __init__(self, handle):
        self.handle = handle

    def key(self, key, collection):
        return (collection or "") + ":" + key

    async def get(self, key, *, collection=None):
        saved = self.handle.read()
        expiry = saved.get("kv_expiry", {}).get(self.key(key, collection))
        if expiry is not None and expiry <= time.time():
            return None
        return saved.get("kv", {}).get(self.key(key, collection))

    async def put(self, key, value, *, collection=None, ttl=None):
        def edit(record):
            record.setdefault("kv", {})[self.key(key, collection)] = value
            record.setdefault("kv_expiry", {})[self.key(key, collection)] = time.time() + float(ttl) if ttl is not None else None
        self.handle.change(edit)

    async def delete(self, key, *, collection=None):
        deleted = []
        def edit(record):
            deleted.append(self.key(key, collection) in record.setdefault("kv", {}))
            record["kv"].pop(self.key(key, collection), None)
            record.setdefault("kv_expiry", {}).pop(self.key(key, collection), None)
        self.handle.change(edit)
        return deleted[0]

    async def ttl(self, key, *, collection=None):
        value = await self.get(key, collection=collection)
        expiry = self.handle.read().get("kv_expiry", {}).get(self.key(key, collection))
        return value, max(0, expiry - time.time()) if expiry is not None else None

    async def get_many(self, keys, *, collection=None):
        return [await self.get(key, collection=collection) for key in keys]

    async def ttl_many(self, keys, *, collection=None):
        return [await self.ttl(key, collection=collection) for key in keys]

    async def put_many(self, keys, values, *, collection=None, ttl=None):
        for key, value in zip(keys, values, strict=True):
            await self.put(key, value, collection=collection, ttl=ttl)

    async def delete_many(self, keys, *, collection=None):
        return sum([await self.delete(key, collection=collection) for key in keys])


class SavedOAuth(OAuth):
    """FastMCP OAuth with durable metadata and no implicit browser interaction."""
    def __init__(self, handle, *, callback_port=0):
        self.handle = handle
        definition = MCPSpec.model_validate(handle.spec)
        auth = definition.authentication()
        super().__init__(definition.url or "https://analytics.google.com/mcp", scopes=auth.scopes or ([GOOGLE_SCOPE] if auth.type == "google_adc" else None), client_name="Kindred", token_storage=VaultKV(handle), callback_port=callback_port or auth.callback_port or 9, callback_host="127.0.0.1", client_id=auth.client_id or None, client_secret=handle.resolve(auth.client_secret_env) if auth.client_secret_env else None, client_metadata_url=auth.client_metadata_url or None)

    async def _initialize(self):
        await super()._initialize()
        saved = self.handle.read()
        if saved.get("metadata"):
            self.context.oauth_metadata = OAuthMetadata.model_validate(saved["metadata"])
            self.context.auth_server_url = str(self.context.oauth_metadata.issuer)

    async def redirect_handler(self, authorization_url):
        raise AuthenticationRequired(self.handle.name)

    async def callback_handler(self):
        raise AuthenticationRequired(self.handle.name)


class AuthNetwork(httpx2.AsyncBaseTransport):
    """Guard every OAuth fetch, preserving DNS pinning and endpoint isolation."""
    def __init__(self, handle, policy, *, interactive=None):
        self.handle, self.policy, self.interactive = handle, policy, interactive
        self.transports = {}
        self.requests = 0

    async def handle_async_request(self, request):
        self.handle.read()  # generation, saved settings and disconnect check
        self.requests += 1
        if self.requests > 24:
            raise ValueError("The sign-in service exceeded its request limit.")
        endpoint = str(request.url)
        parsed = urlsplit(endpoint)
        if parsed.fragment or parsed.username or parsed.password:
            raise ValueError("Invalid authentication destination.")
        saved = self.handle.read()
        targets = saved.get("auth_targets", [])
        if self.interactive:
            # Only anonymous metadata reads may precede the user's provider review.
            if request.method == "GET" and not request.headers.get("authorization") and not request.content:
                pass
            else:
                await self.interactive.review_provider()
                targets = self.handle.read().get("auth_targets", [])
                if endpoint not in targets:
                    raise PolicyDenied("network.target", "The authentication endpoint was not approved.")
        elif endpoint not in targets:
            raise PolicyDenied("network.target", "The authentication endpoint was not approved.")
        transport = self.transports.get(endpoint)
        if transport is None:
            transport = transport_for(endpoint, [endpoint], self.policy.local_endpoints, httpx_module="httpx2", max_bytes=256 * 1024, max_requests=8)
            self.transports[endpoint] = transport
        # Authentication never carries local scoped tokens or arbitrary cookies.
        if request.headers.get("cookie") or request.headers.get("authorization", "").startswith("Bearer gr_"):
            raise PolicyDenied("auth.credentials", "Local credentials cannot be sent to an authentication service.")
        response = await transport.handle_async_request(request)
        # Snapshot issued/rotated secrets before any SDK validation error can
        # reach a local diagnostic. No response body is included in public state.
        await response.aread()
        try:
            value = response.json()
            with self.handle.vault.db() as db:
                self.handle.vault.remember(db, value)
        except (ValueError, UnicodeError):
            pass
        return response

    async def aclose(self):
        for transport in self.transports.values():
            await transport.aclose()


async def current_access_token(handle, policy):
    """Refresh once under a shared lease, then dispatch without holding the lease."""
    async with handle.lease():
        saved = handle.read()
        if not saved.get("connected"):
            raise AuthenticationRequired(handle.name)
        provider = SavedOAuth(handle)
        await provider._initialize()
        if provider.context.token_expiry_time is not None:
            provider.context.token_expiry_time -= 30
        if not provider.context.is_token_valid():
            if not provider.context.can_refresh_token():
                handle.change(lambda data: data.update(connected=False), status="reconnect_required")
                raise AuthenticationRequired(handle.name)
            try:
                # A read timeout alone permits an indefinitely slow response and
                # could outlive the shared refresh lease.
                async with asyncio.timeout(25):
                    async with httpx2.AsyncClient(transport=AuthNetwork(handle, policy), trust_env=False, follow_redirects=False, timeout=15) as client:
                        response = await client.send(await provider._refresh_token())
                if not await provider._handle_refresh_response(response):
                    handle.change(lambda data: data.update(connected=False), status="reconnect_required")
                    raise AuthenticationRequired(handle.name)
            except asyncio.CancelledError:
                # An interrupted exchange may have rotated a refresh token upstream.
                handle.change(lambda data: data.update(connected=False), status="reconnect_required")
                raise
            except Exception:
                handle.change(lambda data: data.update(connected=False), status="reconnect_required")
                raise AuthenticationRequired(handle.name) from None
        tokens = provider.context.current_tokens
        scopes = set((tokens.scope or "").split())
        if scopes != set(saved.get("approved_scopes", [])):
            handle.change(lambda data: data.update(connected=False), status="reconnect_required")
            raise AuthenticationRequired(handle.name)
        handle.read()
        return tokens.access_token


class GatewayOAuth(httpx2.Auth):
    def __init__(self, handle, policy):
        self.handle, self.policy = handle, policy

    async def async_auth_flow(self, request):
        target = MCPSpec.model_validate(self.handle.spec).url
        if origin(request.url) != origin(target):
            raise PolicyDenied("network.target", "Upstream credentials cannot leave their MCP connection.")
        request.headers["Authorization"] = "Bearer " + await current_access_token(self.handle, self.policy)
        response = yield request
        if response.status_code in {401, 403}:
            self.handle.change(lambda data: data.update(connected=False), status="reconnect_required")
            raise AuthenticationRequired(self.handle.name)


def validate_google_credentials(value):
    if not isinstance(value, dict) or value.get("type") != "authorized_user":
        raise ValueError("Import Google user ADC credentials, not a service account or external credential provider.")
    allowed = {"type", "client_id", "client_secret", "refresh_token", "quota_project_id", "universe_domain", "account", "token_uri", "scopes"}
    if set(value) - allowed or value.get("token_uri", GOOGLE_TOKEN) != GOOGLE_TOKEN or value.get("universe_domain", "googleapis.com") != "googleapis.com":
        raise ValueError("Only standard Google user credentials and Google authentication endpoints are supported.")
    if any(not isinstance(value.get(key), str) or not 1 <= len(value[key]) <= 8192 for key in ("client_id", "client_secret", "refresh_token")):
        raise ValueError("The Google credentials need a client ID, client secret and refresh token.")
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.apps\.googleusercontent\.com", value["client_id"]):
        raise ValueError("Use a Google OAuth client ID.")
    scopes = value.get("scopes", [])
    if isinstance(scopes, str):
        scopes = scopes.split()
    if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes) or set(scopes) - GOOGLE_IMPORT_SCOPES:
        raise ValueError("Use Google Analytics read-only credentials without edit permissions.")
    return {key: value[key] for key in ("type", "client_id", "client_secret", "refresh_token")}


def validate_google_client(value):
    if not isinstance(value, dict) or set(value) != {"installed"} or not isinstance(value["installed"], dict):
        raise ValueError("Choose the downloaded JSON for a Google OAuth desktop client.")
    info = value["installed"]
    if info.get("auth_uri") != "https://accounts.google.com/o/oauth2/auth" or info.get("token_uri") != GOOGLE_TOKEN:
        raise ValueError("Use Google's standard OAuth desktop client endpoints.")
    validate_google_credentials({"type": "authorized_user", "client_id": info.get("client_id"), "client_secret": info.get("client_secret"), "refresh_token": "pending"})
    return value


def credential_secrets(root):
    if not (Path(root) / ".local/mcp-auth/credentials.sqlite").exists():
        return []
    return CredentialVault(root).secret_values()
