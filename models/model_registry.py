import os
import yaml

from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, PrivateAttr
from google.adk.models import BaseLlm, FallbackModel
from google.adk.models.lite_llm import LiteLlm


class GuardedLiteLlm(LiteLlm):
    _runtime = PrivateAttr()
    _gateway_url = PrivateAttr()
    _scoped_token = PrivateAttr()

    def __init__(self, *, runtime, gateway_url, scoped_token, **kwargs):
        super().__init__(api_base=gateway_url, api_key=scoped_token, **kwargs)
        self._runtime, self._gateway_url, self._scoped_token = runtime, gateway_url, scoped_token

    async def generate_content_async(self, llm_request, stream=False):
        from guardrails.client import verify_gateway
        await verify_gateway(self._gateway_url, "inference", self._scoped_token, self._runtime.policy().revision)
        async for response in super().generate_content_async(llm_request, stream=stream):
            yield response

class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str

class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_type: str = Field(min_length=1)
    display_name: str = ""

class RegistryConfig(BaseModel):
    gateway : GatewayConfig
    models : dict[str, ModelConfig] = Field(min_length=1)

class Models:
    '''Inference models for agents. Set in Registry'''
    def __init__(self, config_path : str | Path, api_key: str | None = None, *, credential_provider=None):
        self.credential_provider = credential_provider
        self.api_key = api_key or os.getenv("LITELLM_PROXY_API_KEY")
        try:
            with Path(config_path).open() as f:
                models_config = yaml.safe_load(f)
        except (OSError, yaml.YAMLError):
            raise FileNotFoundError("Unable to load model config")

        self.config = RegistryConfig.model_validate(models_config)
        self.runtime = None
        if credential_provider:
            from guardrails.runtime import Runtime
            from guardrails.client import local_gateway
            local_gateway(self.config.gateway.url)
            self.runtime = Runtime(Path(config_path).resolve().parent.parent)

    
    def resolve(self, models: str | list[str], *, agent: str = "") -> BaseLlm:
        """Resolve model names into a single model or fallback chain."""
        names = [models] if isinstance(models, str) else models

        if not names:
            raise ValueError("At least one model is required")

        unknown = set(names) - self.config.models.keys()
        if unknown:
            raise ValueError(f"Unknown models: {sorted(unknown)}")

        instances = []
        for name in names:
            options = {"model": f"litellm_proxy/{self.config.models[name].model_type}", "num_retries": 0}
            if self.credential_provider:
                instance = GuardedLiteLlm(runtime=self.runtime, gateway_url=self.config.gateway.url, scoped_token=self.credential_provider(agent, "inference"), **options)
            else:
                instance = LiteLlm(api_base=self.config.gateway.url, api_key=self.api_key, **options)
            instances.append(instance)

        return (
            instances[0]
            if len(instances) == 1
            else FallbackModel(models=instances, retriable_status_codes={502, 503, 504})
        )
