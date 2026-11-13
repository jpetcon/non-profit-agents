"""Provider-aware model editing; credentials remain environment references."""
from __future__ import annotations

from copy import deepcopy
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .store import slug


PROVIDERS = {
    "openrouter": {"label": "OpenRouter", "prefix": "openrouter", "secret": "OPENROUTER_API_KEY", "api_base": "https://openrouter.ai/api/v1"},
    "openai": {"label": "OpenAI", "prefix": "openai", "secret": "OPENAI_API_KEY", "api_base": ""},
    "anthropic": {"label": "Anthropic", "prefix": "anthropic", "secret": "ANTHROPIC_API_KEY", "api_base": ""},
    "gemini": {"label": "Google AI Studio", "prefix": "gemini", "secret": "GEMINI_API_KEY", "api_base": ""},
    "mistral": {"label": "Mistral AI", "prefix": "mistral", "secret": "MISTRAL_API_KEY", "api_base": ""},
    "groq": {"label": "Groq", "prefix": "groq", "secret": "GROQ_API_KEY", "api_base": ""},
    "deepseek": {"label": "DeepSeek", "prefix": "deepseek", "secret": "DEEPSEEK_API_KEY", "api_base": ""},
    "together_ai": {"label": "Together AI", "prefix": "together_ai", "secret": "TOGETHERAI_API_KEY", "api_base": ""},
    "ollama_chat": {"label": "Ollama (local)", "prefix": "ollama_chat", "secret": "", "api_base": "http://127.0.0.1:11434"},
    "custom": {"label": "Other OpenAI-compatible provider", "prefix": "openai", "secret": "CUSTOM_MODEL_API_KEY", "api_base": ""},
}
DEFAULT_LABELS = {"fast": "Fast & efficient", "reasoning": "Deeper reasoning", "backup": "Backup model"}
LOCAL_KEYS = {"LITELLM_MASTER_KEY", "LITELLM_PROXY_API_KEY", "PATH", "HOME", "USER", "SHELL", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "DEBUG"}


class ModelDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    display_name: str = Field(min_length=1, max_length=120)
    provider: str
    model: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9_./:@+\-]*$")
    secret: str = ""
    api_base: str = Field(default="", max_length=2048)

    @model_validator(mode="after")
    def valid(self):
        if self.provider not in PROVIDERS:
            raise ValueError("Choose a supported provider.")
        if self.secret and (not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", self.secret) or self.secret in LOCAL_KEYS or self.secret.startswith("DYLD_")):
            raise ValueError("Choose a provider secret name, such as ANTHROPIC_API_KEY. Local gateway passwords cannot authenticate providers.")
        if not self.secret and self.provider != "ollama_chat":
            raise ValueError("Select a secret for this provider. You can add its value in Secrets.")
        if self.provider == "custom" and not self.api_base:
            raise ValueError("Enter the API base address for your compatible provider.")
        if self.api_base:
            url = urlsplit(self.api_base)
            if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.query or url.fragment or any(c.isspace() for c in self.api_base):
                raise ValueError("Use an HTTP(S) API base without credentials, query parameters or fragments.")
            if url.scheme != "https" and url.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("Use HTTPS for remote inference providers.")
        return self


def provider_of(params):
    prefix = params.get("model", "").split("/", 1)[0]
    if prefix == "openai" and params.get("api_base") and urlsplit(params["api_base"]).hostname != "api.openai.com":
        return "custom"
    return prefix if prefix in PROVIDERS else None


def location_of(params):
    provider = provider_of(params)
    hostname = urlsplit(params.get("api_base", "")).hostname
    if provider == "openrouter":
        return "Europe endpoint" if hostname == "eu.openrouter.ai" else "Global · development" if hostname == "openrouter.ai" else "Custom endpoint"
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return "Local endpoint"
    return "Provider default" if not params.get("api_base") else "Custom endpoint"


class ModelManager:
    def __init__(self, store):
        self.store = store

    def references(self, name):
        config = self.store.agents()
        return [self.store.agent_label(key, config) for key, agent in config["agents"].items() if name in agent["models"]]

    def list(self):
        inference = self.store.yaml("inference/litellm-config.yml")
        result = []
        for name, spec in self.store.models().items():
            entries = [entry for entry in inference["model_list"] if entry["model_name"] == spec["model_type"]]
            entry = entries[0] if len(entries) == 1 else None
            params = entry.get("litellm_params", {}) if entry else {}
            key = params.get("api_key", "")
            secret = key.split("/", 1)[1] if isinstance(key, str) and key.startswith("os.environ/") else ""
            provider = provider_of(params)
            editable = entry is not None and provider is not None and (not key or bool(secret)) and sum(item["model_type"] == spec["model_type"] for item in self.store.models().values()) == 1
            result.append({"id": name, "display_name": spec.get("display_name") or DEFAULT_LABELS.get(name, name.replace("_", " ").title()), "alias": spec["model_type"], "provider": provider, "model": params.get("model", "").split("/", 1)[-1], "secret": secret, "configured": bool(self.store.secret(secret)) if secret else not key and provider == "ollama_chat", "api_base": params.get("api_base", ""), "location": location_of(params), "used_by": self.references(name), "editable": editable})
        return result

    def save(self, name, raw):
        definition = ModelDefinition.model_validate(raw)
        registry_path = self.store.root / "models/model_config.yml"
        inference_path = self.store.root / "inference/litellm-config.yml"
        registry, inference = self.store.yaml(registry_path), self.store.yaml(inference_path)
        if name is None:
            base = slug(definition.display_name)
            name, suffix = base, 2
            existing_aliases = {entry["model_name"] for entry in inference["model_list"]}
            while name in registry["models"] or "agent-" + name in existing_aliases:
                name, suffix = f"{base[:58]}_{suffix}", suffix + 1
            alias = "agent-" + name
            registry["models"][name] = {"model_type": alias}
            entry = {"model_name": alias, "litellm_params": {}}
            inference["model_list"].append(entry)
        else:
            current = next((m for m in self.list() if m["id"] == name), None)
            if current is None:
                raise ValueError("This model no longer exists.")
            if not current["editable"]:
                raise ValueError("This deployment uses advanced or shared routing. Edit its YAML configuration directly, or add a separate model here.")
            alias = registry["models"][name]["model_type"]
            entry = next(item for item in inference["model_list"] if item["model_name"] == alias)
        previous = entry["litellm_params"]
        # Provider-specific routing (e.g. OpenRouter's extra_body) must not leak
        # into a different provider. Preserve all existing options when unchanged.
        params = deepcopy(previous) if provider_of(previous) == definition.provider else {}
        provider = PROVIDERS[definition.provider]
        params["model"] = provider["prefix"] + "/" + definition.model
        if definition.secret:
            params["api_key"] = "os.environ/" + definition.secret
        else:
            params.pop("api_key", None)
        api_base = definition.api_base or provider["api_base"]
        if api_base:
            params["api_base"] = api_base
        else:
            params.pop("api_base", None)
        if definition.provider == "openrouter" and provider_of(previous) != "openrouter":
            params["extra_body"] = {"provider": {"sort": "price", "require_parameters": True}}
        entry["litellm_params"] = params
        registry["models"][name]["display_name"] = definition.display_name
        self.store.save_many({registry_path: registry, inference_path: inference})
        return name

    def delete(self, name):
        refs = self.references(name)
        if refs:
            raise ValueError("Choose another primary or fallback model for these agents first: " + ", ".join(refs))
        registry_path, inference_path = self.store.root / "models/model_config.yml", self.store.root / "inference/litellm-config.yml"
        registry, inference = self.store.yaml(registry_path), self.store.yaml(inference_path)
        if name not in registry["models"]:
            raise ValueError("This model no longer exists.")
        if len(registry["models"]) == 1:
            raise ValueError("Keep at least one model in the workspace.")
        alias = registry["models"].pop(name)["model_type"]
        if not any(spec["model_type"] == alias for spec in registry["models"].values()):
            inference["model_list"] = [entry for entry in inference["model_list"] if entry["model_name"] != alias]
        self.store.save_many({registry_path: registry, inference_path: inference})
