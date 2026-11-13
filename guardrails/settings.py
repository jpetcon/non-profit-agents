"""Small user preferences compiled to the gateway's internal enforcement types."""
from functools import lru_cache
from importlib import import_module
import json
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
import yaml

from .policy import Policy, Strict, ToolRule, ModelRule, digest, MAX_OUTPUT_TOKENS
from .runtime import tool_hash
from sandboxing.models import SandboxSettings

BRAVE_COMMAND = ["npx", "-y", "@brave/brave-search-mcp-server@2.1.4", "--transport", "stdio"]
MASTERBRAND = {"get_strategy", "get_brand_profile", "get_target_audience", "get_brand_voice"}
BRAVE_TOOLS = {"brave_web_search", "brave_local_search", "brave_image_search", "brave_video_search", "brave_news_search", "brave_summarizer", "brave_summarizer_streaming", "brave_llm_context", "brave_place_search", "web_search"}
ANALYTICS_COMMAND = ['uvx', '--from', 'analytics-mcp==1.0.0', 'analytics-mcp']
ANALYTICS_TOOLS = {'get_account_summaries', 'list_google_ads_links', 'get_property_details', 'list_property_annotations', 'get_custom_dimensions_and_metrics', 'run_report', 'run_realtime_report', 'run_funnel_report', 'run_conversions_report'}


class Activities(Strict):
    fundraising: bool = False
    beneficiary_data: bool = False
    campaigning: bool = False
    finance: bool = False


class Settings(Strict):
    version: Literal[3] = 3
    monthly_token_limit: int | None = Field(default=1000000, ge=1, le=1000000000)
    per_run_token_limit: int = Field(default=50000, ge=1, le=1000000000)
    max_output_tokens: int | None = Field(default=None, ge=1, le=MAX_OUTPUT_TOKENS, strict=True)
    daily_token_limit: int | None = Field(default=None, ge=1, le=1000000000)
    jurisdictions: list[Literal["england_wales", "scotland", "northern_ireland"]] = Field(default_factory=lambda: ["england_wales", "scotland", "northern_ireland"])
    mode: Literal["cautious", "draft_only"] = "cautious"
    activities: Activities = Field(default_factory=Activities)
    safeguarding_contact: str = ""
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)
    # Bindings and catalogue data are maintained by adapters, not user form fields.
    access: dict[str, ToolRule] = Field(default_factory=dict)
    approved_connections: dict[str, str] = Field(default_factory=dict)
    blocked_tools: list[str] = Field(default_factory=list)
    advanced: Policy | None = None

    def model_dump(self, *args, **kwargs):
        value = super().model_dump(*args, **kwargs)
        # None is an explicit off switch, distinct from an omitted default.
        if self.monthly_token_limit is None and 'monthly_token_limit' not in (kwargs.get('exclude') or set()):
            value['monthly_token_limit'] = None
        # Explicit automatic mode must survive exclude_none saves, including
        # when an older advanced policy still contains a workspace cap.
        if self.max_output_tokens is None and 'max_output_tokens' not in (kwargs.get('exclude') or set()):
            value['max_output_tokens'] = None
        return value

    @model_validator(mode="before")
    @classmethod
    def migrate_pricing_preferences(cls, value):
        if isinstance(value, dict) and 'max_output_tokens' not in value:
            # Preserve a previously configured workspace cap when introducing
            # its ordinary preference field. Narrower scope caps still inherit.
            advanced = value.get('advanced')
            workspace = advanced.workspace if isinstance(advanced, Policy) else advanced.get('workspace', {}) if isinstance(advanced, dict) else {}
            explicit = workspace.model_fields_set if isinstance(workspace, Strict) else workspace if isinstance(workspace, dict) else {}
            if 'max_output_tokens' in explicit:
                value = {**value, 'max_output_tokens': workspace.max_output_tokens if isinstance(workspace, Strict) else workspace['max_output_tokens']}
        if isinstance(value, dict) and value.get("version") == 2:
            value = dict(value)
            # Pounds cannot be converted to tokens; preserve an explicit off switch.
            if "monthly_budget_gbp" in value and value["monthly_budget_gbp"] is None:
                value.setdefault("monthly_token_limit", None)
            value.pop("monthly_budget_gbp", None)
            value.pop("pricing", None)
            value["version"] = 3
        return value


def settings_from_policy(policy):
    enabled = {r.charity_workflow for r in policy.tools.values()}
    return Settings(monthly_token_limit=policy.token_limits.monthly, per_run_token_limit=policy.token_limits.per_run or 50000, max_output_tokens=policy.workspace.max_output_tokens, daily_token_limit=policy.token_limits.daily, jurisdictions=policy.charity.jurisdictions, activities=Activities(fundraising="fundraising" in enabled, beneficiary_data=any(r.source_data_class != "public" for r in policy.tools.values()), campaigning="campaigning" in enabled, finance=bool(enabled & {"financial", "gift_aid"})), safeguarding_contact=policy.charity.safeguarding_instructions, sandbox=policy.sandbox, advanced=policy)


def load_settings(root):
    path = Path(root) / "guardrails/config.yml"
    raw = yaml.safe_load(path.read_text()) if path.exists() else {"version": 3}
    return Settings.model_validate(raw) if raw.get("version") in {2, 3} else settings_from_policy(Policy.model_validate(raw))


def curated_connection(spec):
    return spec.get("transport") == "stdio" and [spec.get("command"), *spec.get("args", [])] == BRAVE_COMMAND and (set(spec.get("env_vars", [])) | set(spec.get("env_secrets", {}))) <= {"BRAVE_API_KEY"}


def local_definitions(config):
    """Introspect installed functions; do not start an MCP process or call a tool."""
    from fastmcp.tools import Tool
    from tools.definitions import HTTPToolSpec
    result = []
    for name, spec in config.get("custom_tools", {}).items():
        module_name, _, function_name = spec["handler"].rpartition(".")
        if not spec.get("enabled", True) or not module_name.startswith("tools.custom_tools."):
            continue
        handler = getattr(import_module(module_name), function_name)
        tool = Tool.from_function(handler, name=name, description=spec.get("description", ""))
        result.append({"name": name, "description": tool.description or "", "input_schema": tool.parameters, "output_schema": tool.output_schema, "configuration_hash": digest(spec), "targets": [], "curated": module_name == "tools.custom_tools.master_brand" and function_name in MASTERBRAND and name == function_name})
    for name, raw in config.get("http_tools", {}).items():
        spec = HTTPToolSpec.model_validate(raw)
        if spec.enabled:
            result.append({"name": name, "description": spec.description, "input_schema": spec.input_schema(), "output_schema": None, "configuration_hash": digest(raw), "targets": [spec.url.split("{")[0].rstrip("/")], "curated": False})
    return result


def definitions(root):
    root = Path(root)
    config = yaml.safe_load((root / "tools/config.yml").read_text())
    result = local_definitions(config)
    from connectors.native import operations
    for server, spec in config.get("mcp_servers", {}).items():
        if spec.get("transport") == "native" and spec.get("enabled", True):
            for operation in operations(spec):
                result.append({**operation, "name": server+"_"+operation["name"], "server": server, "kind": "Native", "configuration_hash": digest(spec), "targets": [], "curated": False})
    catalog = root / ".local/catalog.json"
    for raw in json.loads(catalog.read_text()) if catalog.exists() else []:
        if "input_schema" not in raw:
            continue
        item = dict(raw)
        spec = config.get("mcp_servers", {}).get(item.get("server"), {})
        if not spec or not spec.get("enabled", True) or spec.get("transport") == "native":
            continue
        suffix = item["name"].removeprefix(item.get("server", "") + "_")
        analytics = spec.get('transport')=='stdio' and [spec.get('command'), *spec.get('args', [])]==ANALYTICS_COMMAND and (spec.get('auth') or {}).get('type')=='google_adc'
        item["curated"] = (curated_connection(spec) and suffix in BRAVE_TOOLS) or (analytics and suffix in ANALYTICS_TOOLS)
        result.append(item)
    for item in result:
        item["schema_hash"] = tool_hash(item["name"], item["description"], item["input_schema"], item.get("output_schema"))
    return result


def bind_access(definition, *, permission="read", workflow="none", data_class="public", previous=None):
    base = previous.model_dump(mode="json") if previous else {}
    # Access review pins definitions automatically. Unknown integrations never
    # gain autonomy just because their server claims to be read-only.
    base.update(classification="read" if permission == "read" else "update", schema_hash=definition["schema_hash"], configuration_hash=definition["configuration_hash"], input_schema=definition["input_schema"], output_schema=definition.get("output_schema"), description=definition["description"], targets=definition.get("targets", []), source_data_class=data_class, approved_data_classes=["public", "personal", "sensitive"] if data_class == "sensitive" else ["public", "personal"] if data_class == "personal" else ["public"], charity_workflow=workflow, autonomous=False)
    return ToolRule.model_validate(base)


def compile_settings(root, settings):
    policy = settings.advanced.model_copy(deep=True) if settings.advanced else Policy()
    policy.sandbox = settings.sandbox.model_copy(deep=True)
    policy.workspace.max_output_tokens = settings.max_output_tokens
    # Preference choices can tighten existing advanced restrictions, never erase
    # their evidence or make an existing narrower limit larger.
    monthly = settings.monthly_token_limit
    if monthly:
        for key, value in {"monthly": monthly, "daily": min(monthly, settings.daily_token_limit or max(1, monthly // 5)), "per_run": min(monthly, settings.per_run_token_limit)}.items():
            setattr(policy.token_limits, key, value)
    else:
        policy.token_limits.per_run = policy.token_limits.daily = policy.token_limits.monthly = None
    policy.profile = {"mode": settings.mode, "activities": settings.activities.model_dump(), "managed": True}
    policy.charity.jurisdictions = settings.jurisdictions
    if settings.safeguarding_contact:
        policy.charity.safeguarding_instructions = settings.safeguarding_contact
    config = yaml.safe_load((Path(root) / "tools/config.yml").read_text())
    for name, spec in config.get("mcp_servers", {}).items():
        if spec.get("enabled", True) and (curated_connection(spec) or settings.approved_connections.get(name) == digest(spec)) and spec.get("transport") == "stdio":
            command = [spec["command"], *spec.get("args", [])]
            if command not in policy.stdio_commands:
                policy.stdio_commands.append(command)
    for definition in definitions(root):
        name = definition["name"]
        if name in settings.access:
            policy.tools[name] = settings.access[name]
        elif definition.get("curated") and name not in policy.tools:
            policy.tools[name] = bind_access(definition)
    if settings.blocked_tools:
        allowed = set(policy.tools) - set(settings.blocked_tools)
        policy.workspace.allowed_tools = sorted(allowed if policy.workspace.allowed_tools is None else allowed & set(policy.workspace.allowed_tools))
    entries = yaml.safe_load((Path(root) / "inference/litellm-config.yml").read_text())["model_list"]
    for entry in entries:
        alias, params = entry["model_name"], entry["litellm_params"]
        if alias in policy.models:
            continue
        name = params["model"]
        local = name.startswith("ollama_chat/") and params.get("api_base", "").startswith(("http://127.0.0.1:", "http://localhost:"))
        if local:
            endpoint = params["api_base"]
            if endpoint not in policy.local_endpoints:
                policy.local_endpoints.append(endpoint)
        policy.models[alias] = ModelRule(deployment_hash=digest(params), free_local=local)
    return policy


@lru_cache(maxsize=16)
def _compiled(root, settings_text, dependency_texts):
    return compile_settings(root, Settings.model_validate(yaml.safe_load(settings_text)))


def load_policy(root):
    path = Path(root) / "guardrails/config.yml"
    text = path.read_text() if path.exists() else "version: 3\n"
    raw = yaml.safe_load(text)
    if raw.get("version") in {2, 3}:
        settings = Settings.model_validate(raw)
        dependencies = [Path(root) / p for p in ["tools/config.yml", "inference/litellm-config.yml", ".local/catalog.json"]]
        dependency_texts = tuple(p.read_text() if p.exists() else "" for p in dependencies)
        return _compiled(str(Path(root).resolve()), text, dependency_texts).model_copy(deep=True)
    return Policy.model_validate(raw)
