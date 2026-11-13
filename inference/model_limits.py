"""Resolve output capabilities without sending prompts or making inference calls."""
import asyncio
import time

import httpx

from guardrails.network import transport_for
from guardrails.policy import PolicyDenied


def positive_limit(value):
    return value if type(value) is int and 0 < value <= 1000000000 else None


class ModelLimits:
    def __init__(self):
        self.cache = {}
        self.lock = asyncio.Lock()

    async def resolve(self, params, endpoint, local_endpoints=()):
        model = params['model']
        provider, _, slug = model.partition('/')
        if provider == 'openrouter':
            # New models frequently precede the SDK's bundled catalogue. Keep
            # metadata scoped to the reviewed endpoint, with no prompt or key.
            key = endpoint.rstrip('/')
            async with self.lock:
                cached = self.cache.get(key)
                if cached is None or cached[0] <= time.monotonic():
                    catalogue = {}
                    try:
                        async with httpx.AsyncClient(transport=transport_for(key, [key], local_endpoints, max_bytes=8 * 1024 * 1024, max_requests=1), trust_env=False, follow_redirects=False, timeout=8) as client:
                            response = await client.get(key + '/models')
                            response.raise_for_status()
                            entries = response.json()['data']
                            for entry in entries:
                                limit = positive_limit((entry.get('top_provider') or {}).get('max_completion_tokens'))
                                if isinstance(entry.get('id'), str) and limit:
                                    catalogue[entry['id']] = limit
                    except (httpx.HTTPError, PolicyDenied, ValueError, TypeError, KeyError, AttributeError):
                        pass
                    # Short negative cache bounds repeated failed lookups.
                    self.cache[key] = (time.monotonic() + (3600 if catalogue else 30), catalogue)
                return self.cache[key][1].get(slug)

        # Read the installed SDK's static metadata only. get_model_info() can
        # perform its own unguarded HTTP calls and must not be used here.
        # A custom OpenAI-compatible endpoint need not implement OpenAI models.
        defaults = {'openai': 'https://api.openai.com/v1', 'anthropic': 'https://api.anthropic.com', 'gemini': 'https://generativelanguage.googleapis.com', 'mistral': 'https://api.mistral.ai/v1', 'groq': 'https://api.groq.com/openai/v1', 'deepseek': 'https://api.deepseek.com', 'together_ai': 'https://api.together.xyz/v1'}
        if endpoint.rstrip('/') != defaults.get(provider):
            return None
        from litellm import model_cost
        for name in (model, slug):
            info = model_cost.get(name, {})
            if info.get('litellm_provider') == provider:
                limit = positive_limit(info.get('max_output_tokens'))
                if limit:
                    return limit
        return None
