"""Shared definitions for form-built API tools and MCP connections."""
from __future__ import annotations
import re
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, model_validator


def check_url(value: str) -> str:
    url = urlsplit(value)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or "{" in url.netloc:
        raise ValueError("Use an HTTP(S) address without embedded credentials or hostname placeholders.")
    return value


def example_endpoint(value: str) -> bool:
    """Documentation addresses cannot be used as a live sign-in service."""
    host = (urlsplit(value).hostname or "").lower().rstrip(".")
    examples = {"yourdomain.com", "your-domain.com", "example.com", "example.org", "example.net", "example", "invalid", "test"}
    return any(host == name or host.endswith("." + name) for name in examples)


class InputSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    description: str = ""
    type: Literal["string", "number", "integer", "boolean", "object", "array"] = "string"
    location: Literal["path", "query", "body"] = "query"
    required: bool = True


class HeaderSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
    value: str = ""
    secret: str = ""
    prefix: str = ""

    @model_validator(mode="after")
    def valid(self):
        if any("\r" in x or "\n" in x for x in [self.value, self.prefix]):
            raise ValueError("Headers cannot contain line breaks.")
        if self.secret and (self.value or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", self.secret)):
            raise ValueError("Choose a secret reference or a literal value for each header.")
        return self


class HTTPToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = ""
    description: str = Field(min_length=1, max_length=8000)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] = "GET"
    url: str
    inputs: list[InputSpec] = Field(default_factory=list)
    headers: list[HeaderSpec] = Field(default_factory=list)
    enabled: bool = True

    @model_validator(mode="after")
    def valid(self):
        check_url(self.url)
        names = [item.name for item in self.inputs]
        if len(names) != len(set(names)):
            raise ValueError("Each input needs a unique name.")
        placeholders = set(re.findall(r"\{([A-Za-z][A-Za-z0-9_]*)\}", self.url))
        if placeholders != {item.name for item in self.inputs if item.location == "path"}:
            raise ValueError("URL placeholders and path inputs must match, for example /people/{person_id}.")
        if any(not item.required for item in self.inputs if item.location == "path"):
            raise ValueError("Path inputs must be required.")
        if self.method in {"GET", "HEAD"} and any(item.location == "body" for item in self.inputs):
            raise ValueError("GET and HEAD tools use query or path inputs, not a JSON body.")
        if len({h.name.lower() for h in self.headers}) != len(self.headers):
            raise ValueError("Header names must be unique.")
        if any(h.secret for h in self.headers) and urlsplit(self.url).scheme != "https" and urlsplit(self.url).hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Use HTTPS when sending a secret to a remote API.")
        return self

    def input_schema(self) -> dict:
        properties = {}
        for item in self.inputs:
            schema = {"type": item.type, "description": item.description}
            if item.type == "array":
                schema["items"] = {}
            properties[item.name] = schema
        return {"type": "object", "properties": properties, "required": [item.name for item in self.inputs if item.required], "additionalProperties": False}


class MCPAuthentication(BaseModel):
    """Public connection settings; credential material lives in the local vault."""
    model_config = ConfigDict(extra="forbid")
    type: Literal["none", "bearer", "headers", "oauth", "google_adc"] = "none"
    client_id: str = Field(default="", max_length=1024)
    client_secret_env: str = ""
    client_metadata_url: str = ""
    scopes: list[str] = Field(default_factory=list, max_length=50)
    callback_port: int = Field(default=0, ge=0, le=65535)
    project: str = Field(default="", max_length=128, pattern=r"^[a-zA-Z0-9:._-]*$")

    @model_validator(mode="after")
    def valid(self):
        if self.client_secret_env and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", self.client_secret_env):
            raise ValueError("Use a saved secret reference for the OAuth client secret.")
        if any(not s or len(s) > 512 or any(c.isspace() or ord(c) < 33 for c in s) for s in self.scopes):
            raise ValueError("Enter OAuth permissions separately, without whitespace.")
        if self.client_secret_env and not self.client_id:
            raise ValueError("An OAuth client secret also needs a client ID.")
        if self.client_metadata_url:
            check_url(self.client_metadata_url)
            parsed = urlsplit(self.client_metadata_url)
            if parsed.scheme != "https" or parsed.path in {"", "/"}:
                raise ValueError("Client metadata needs a public HTTPS document address.")
        return self


class ManagedConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preset: str
    revision: str
    # Snapshot first-setup suggestions, never permissions. Later catalogue
    # additions are absent from this snapshot and require an explicit choice.
    default_capabilities: list[str] | None = None


class NativeConnector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    options: dict[str, str] = Field(default_factory=dict, max_length=12)
    secret_refs: dict[str, str] = Field(default_factory=dict, max_length=8)
    resources: list[str] = Field(default_factory=list, max_length=50)
    capabilities: list[str] = Field(default_factory=list, max_length=12)

    @model_validator(mode="after")
    def valid(self):
        from connectors.registry import preset
        p = preset(self.provider)
        if p["route"] != "native" or set(self.capabilities) - {c["id"] for c in p["capabilities"]}:
            raise ValueError("Choose supported read-only information for this connector.")
        allowed = {f["key"] for f in p["fields"] if not f["secret"]}
        if any(not self.options.get(f["key"], "").strip() for f in p["fields"] if f["required"] and not f["secret"]):
            raise ValueError("Complete this provider’s required connection settings.")
        if set(self.options) - allowed or any(len(v) > 2048 or any(ord(c) < 32 for c in v) for v in self.options.values()):
            raise ValueError("Use this provider’s supported connection settings.")
        if set(self.secret_refs) - {"api_key", "subscription_key"}:
            raise ValueError("Use supported credential references.")
        required_secrets = {f["key"] for f in p["fields"] if f["secret"] and f["required"]}
        if p["authentication"] in {"key", "token", "session", "basic"}:
            required_secrets.add("api_key")
        if set(self.secret_refs) != required_secrets:
            raise ValueError("Use the credential references required by this preset.")
        if any(not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", v) for v in self.secret_refs.values()):
            raise ValueError("Use saved secret references, not credential values.")
        if len(self.resources) != len(set(self.resources)) or any(not r or len(r) > 512 or any(ord(c) < 32 for c in r) for r in self.resources):
            raise ValueError("Choose distinct, valid account or resource identifiers.")
        if self.provider == "engaging_networks" and self.options.get("region") not in {"ca", "us", "us2"}:
            raise ValueError("Choose the ca, us or us2 Engaging Networks data centre.")
        if self.provider == "mailchimp" and not re.fullmatch(r"us[0-9]{1,3}", self.options.get("datacenter", "")):
            raise ValueError("Enter the Mailchimp server prefix, such as us21.")
        if self.provider == "wordpress":
            check_url(self.options.get("site_url", ""))
            url = urlsplit(self.options["site_url"])
            if url.scheme != "https" or url.query or url.fragment:
                raise ValueError("Use your WordPress HTTPS website address without query parameters.")
        if self.provider == "sharepoint" and not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", self.options.get("tenant", "")):
            raise ValueError("Enter your Microsoft tenant ID or verified domain.")
        for key in ("account_id",):
            if key in self.options and not re.fullmatch(r"[0-9]{1,30}", self.options[key]):
                raise ValueError("Enter the provider’s numeric account ID.")
        return self


class MCPSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str = ""
    enabled: bool = True
    transport: Literal["http", "stdio", "native"] = "http"
    url: str = ""
    token_env: str = ""
    header_secrets: dict[str, str] = Field(default_factory=dict)
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env_vars: list[str] = Field(default_factory=list)
    env_secrets: dict[str, str] = Field(default_factory=dict)
    auth: MCPAuthentication | None = None
    native: NativeConnector | None = None
    managed: ManagedConnection | None = None

    def authentication(self):
        # Legacy fields keep their existing representation and configuration hash.
        return self.auth or MCPAuthentication(type="bearer" if self.token_env else "headers" if self.header_secrets else "none")

    @model_validator(mode="after")
    def valid(self):
        if self.transport == "native":
            if not self.native or not self.managed or self.native.provider != self.managed.preset or self.url or self.command or self.args or self.env_vars or self.env_secrets or self.token_env or self.header_secrets or self.auth:
                raise ValueError("Native connectors use maintained settings and their own credential driver.")
            from connectors.registry import managed_check
            managed_check(self.model_dump(exclude_none=True))
            return self
        if self.native:
            raise ValueError("Native settings require a native connector.")
        if self.managed:
            from connectors.registry import managed_check
            maintained = managed_check(self.model_dump(exclude_none=True))
            if maintained["route"] != "hosted" or self.transport != "http":
                raise ValueError("Use the maintained connection route.")
            from connectors.registry import hosted_url
            hosted_url(maintained, self.url)
            expected = "bearer" if maintained["authentication"] == "key" else "oauth"
            if self.authentication().type != expected:
                raise ValueError("Use this maintained preset’s authentication driver.")
        auth = self.authentication()
        if auth.type == "google_adc" and self.transport != "stdio":
            raise ValueError("Google application credentials are for local servers; use browser sign-in for remote MCP OAuth.")
        if auth.type in {"oauth", "bearer", "headers"} and self.transport != "http":
            raise ValueError("Local servers receive explicitly selected environment credentials.")
        if auth.type == "oauth" and (self.token_env or any(h.lower() == "authorization" for h in self.header_secrets)):
            raise ValueError("OAuth manages Authorization; remove any bearer token or Authorization header.")
        if self.auth and auth.type == "none" and (self.token_env or self.header_secrets):
            raise ValueError("Select bearer token or secret headers for this connection.")
        if auth.type == "bearer" and not self.token_env:
            raise ValueError("Choose the saved bearer token.")
        if auth.type == "google_adc" and (any(arg.startswith("--allow-write") for arg in self.args) or any(k.startswith("GOOGLE_") or k == "ANALYTICS_MCP_ALLOW_WRITE" for k in [*self.env_vars, *self.env_secrets]) or (auth.scopes and auth.scopes != ["https://www.googleapis.com/auth/analytics.readonly"])):
            raise ValueError("The Google Analytics preset manages its read-only credentials and project explicitly.")
        if self.transport == "http":
            check_url(self.url)
            if self.command or self.args or self.env_vars or self.env_secrets:
                raise ValueError("HTTP connections use an address and headers; local commands use stdio.")
            if (self.token_env or self.header_secrets or auth.type == "oauth") and urlsplit(self.url).scheme != "https" and urlsplit(self.url).hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("Use HTTPS when connecting with credentials.")
        elif not self.command.strip() or any(c in self.command for c in "\r\n\x00"):
            raise ValueError("Enter a local MCP command with arguments in separate entries.")
        for name in self.env_vars + list(self.env_secrets.values()) + list(self.header_secrets.values()) + ([self.token_env] if self.token_env else []):
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", name):
                raise ValueError("Use secret references such as BRAVE_API_KEY.")
        for name in [*self.env_vars, *self.env_secrets]:
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", name) or name in {"PATH", "HOME", "USER", "SHELL", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "DEBUG"} or name.startswith("DYLD_"):
                raise ValueError("Local servers may receive named service secrets, not system environment overrides.")
        if set(self.env_vars) & set(self.env_secrets):
            raise ValueError("Choose one secret source per local environment variable.")
        for name in self.header_secrets:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
                raise ValueError("Enter a valid header name.")
        return self
