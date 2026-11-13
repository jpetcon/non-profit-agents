"""Small guarded LiteLLM gateway. No management or unguarded passthrough routes."""
from __future__ import annotations

import asyncio
import json
import math
import re
from pathlib import Path
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
import httpx
import jsonschema
import yaml

from guardrails.network import origin, transport_for
from guardrails.policy import Decision, PolicyDenied, canonical, digest, check_schema
from guardrails.runtime import Runtime
from guardrails.validation import strict_json
from .model_limits import ModelLimits


ALLOWED_FIELDS = {"model", "messages", "tools", "tool_choice", "parallel_tool_calls", "temperature", "top_p", "max_tokens", "max_completion_tokens", "stream", "stream_options", "response_format", "stop", "seed", "presence_penalty", "frequency_penalty", "user"}


class InferenceHooks:
    """Request/deployment/response checks surround each individual LiteLLM attempt."""
    def __init__(self, runtime):
        self.runtime = runtime

    def request(self, identity, data, *, _redacted=False):
        runtime, policy = self.runtime, self.runtime.policy()
        if not isinstance(data, dict) or set(data) - ALLOWED_FIELDS:
            raise PolicyDenied("inference.override", "Unsupported inference fields or routing overrides were supplied.")
        data = {k: v for k, v in data.items() if v is not None}
        name = data.get("model", "")
        if not isinstance(name, str) or not name or len(name) > 128:
            raise PolicyDenied("inference.model", "Choose a configured model alias.")
        runtime.assigned(identity, model=name)
        limits = policy.effective(identity, model=name)
        from guardrails.authorizer import authorise
        denied = authorise(identity, name, kind="model", action="Discover", scope_allowed=limits.allowed_models is None or name in limits.allowed_models)
        if denied:
            raise denied
        messages = data.get("messages")
        if not isinstance(messages, list) or not messages:
            raise PolicyDenied("inference.messages", "Supply a nonempty message list.")
        for key in ("stream", "parallel_tool_calls"):
            if key in data and not isinstance(data[key], bool):
                raise PolicyDenied("inference.parameters", "Boolean inference settings must be true or false.")
        for key, low, high in [("temperature", 0, 2), ("top_p", 0, 1), ("presence_penalty", -2, 2), ("frequency_penalty", -2, 2)]:
            if key in data and (type(data[key]) not in (int, float) or not math.isfinite(data[key]) or not low <= data[key] <= high):
                raise PolicyDenied("inference.parameters", "An inference sampling setting is outside its supported range.")
        if "seed" in data and (type(data["seed"]) is not int or not -(2**63) <= data["seed"] < 2**63):
            raise PolicyDenied("inference.parameters", "The seed must be a supported integer.")
        if "stream_options" in data and (not isinstance(data["stream_options"], dict) or set(data["stream_options"]) - {"include_usage"} or any(type(v) is not bool for v in data["stream_options"].values())):
            raise PolicyDenied("inference.parameters", "Unsupported streaming options.")
        if "stop" in data:
            stops = [data["stop"]] if isinstance(data["stop"], str) else data["stop"]
            if not isinstance(stops, list) or not 1 <= len(stops) <= 4 or any(not isinstance(s, str) or not 1 <= len(s) <= 256 for s in stops):
                raise PolicyDenied("inference.parameters", "Supply up to four short stop strings.")
        if not isinstance(data.get("tools", []), list) or len(data.get("tools", [])) > 128:
            raise PolicyDenied("inference.tools", "Supply a bounded list of function definitions.")
        tools = {}
        for item in data.get("tools", []):
            if not isinstance(item, dict) or set(item) != {"type", "function"} or item.get("type") != "function" or not isinstance(item.get("function"), dict):
                raise PolicyDenied("inference.tools", "Only schema-defined function tools are supported.")
            function = item["function"]
            if not isinstance(function.get("name"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", function["name"]) or function["name"] in tools or set(function) - {"name", "description", "parameters", "strict"}:
                raise PolicyDenied("inference.tools", "Tool names must be unique strings.")
            if ("description" in function and not isinstance(function["description"], str)) or ("strict" in function and type(function["strict"]) is not bool):
                raise PolicyDenied("inference.tools", "Invalid function definition.")
            schema = function.get("parameters", {"type": "object"})
            if not isinstance(schema, dict) or schema.get("type") != "object":
                raise PolicyDenied("inference.tools", "Function parameters must describe a JSON object.")
            try:
                check_schema(schema)
            except (ValueError, TypeError, jsonschema.SchemaError):
                raise PolicyDenied('inference.tool_schema', 'A connected tool has an invalid or unsupported input schema.') from None
            tools[function["name"]] = schema
        choice = data.get("tool_choice", "auto")
        if isinstance(choice, str):
            valid_choice = choice in {"auto", "none", "required"} and (choice != "required" or bool(tools))
        else:
            valid_choice = isinstance(choice, dict) and set(choice) == {"type", "function"} and choice.get("type") == "function" and isinstance(choice.get("function"), dict) and set(choice["function"]) == {"name"} and isinstance(choice["function"]["name"], str) and choice["function"]["name"] in tools
        if not valid_choice:
            raise PolicyDenied("inference.tools", "The tool choice must select a defined function.")
        pending, seen_calls = set(), set()
        for message in messages:
            if not isinstance(message, dict) or message.get("role") not in {"system", "developer", "user", "assistant", "tool"} or set(message) - {"role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content", "thinking_blocks"}:
                raise PolicyDenied("inference.message", "A message has unsupported fields or role.")
            role = message['role']
            if "name" in message and (not isinstance(message["name"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", message["name"])):
                raise PolicyDenied("inference.message", "Message names must be valid identifiers.")
            if role != 'assistant' and any(message.get(k) is not None for k in ['tool_calls', 'reasoning_content', 'thinking_blocks']):
                raise PolicyDenied("inference.message", "Only assistant messages can contain model reasoning or function calls.")
            if pending and role != 'tool':
                raise PolicyDenied("inference.tool_history", "All function calls must have matching results before continuing.")
            if role == 'tool':
                call_id = message.get('tool_call_id')
                if not isinstance(call_id, str) or call_id not in pending:
                    raise PolicyDenied("inference.tool_history", "A tool result has no matching pending call.")
                pending.remove(call_id)
            elif message.get('tool_call_id') is not None:
                raise PolicyDenied("inference.tool_history", "Only tool results can refer to a function call.")
            if message.get("reasoning_content") is not None and not isinstance(message["reasoning_content"], str):
                raise PolicyDenied("inference.reasoning", "Reasoning context must be text.")
            if message.get("thinking_blocks") is not None and (not isinstance(message["thinking_blocks"], list) or any(not isinstance(b, dict) or b.get("type") != "thinking" or set(b) - {"type", "thinking", "signature"} or not isinstance(b.get("thinking"), str) or ('signature' in b and not isinstance(b['signature'], str)) for b in message["thinking_blocks"])):
                raise PolicyDenied("inference.reasoning", "Only text thinking blocks are supported.")
            content = message.get("content")
            if content is None and (role != 'assistant' or not message.get('tool_calls')):
                raise PolicyDenied("inference.content", "A message must contain text or assistant function calls.")
            if content is not None and not isinstance(content, str):
                if not isinstance(content, list) or any(not isinstance(p, dict) or set(p) - {"type", "text"} or p.get("type") != "text" or not isinstance(p.get("text"), str) for p in content):
                    raise PolicyDenied("inference.content", "This gateway currently accepts text content only.")
            calls = message.get('tool_calls')
            if calls is not None and (not isinstance(calls, list) or not 1 <= len(calls) <= 128):
                raise PolicyDenied("inference.tool_call", "Function calls must be a bounded list.")
            for call in calls or []:
                if not isinstance(call, dict) or not isinstance(call.get('function'), dict):
                    raise PolicyDenied("inference.tool_call", "Invalid function call.")
                name = call.get("function", {}).get("name")
                historical_tools = dict(tools)
                if name not in historical_tools:
                    prior = policy.tools.get(name)
                    if prior:
                        historical_tools[name] = prior.input_schema
                    elif name == "transfer_to_agent":
                        from agents.config import AppConfig
                        config = AppConfig.model_validate(yaml.safe_load((runtime.root / "agents/config.yml").read_text()))
                        historical_tools[name] = {"type": "object", "properties": {"agent_name": {"type": "string", "enum": config.team_members(identity["team"])}}, "required": ["agent_name"], "additionalProperties": False}
                try:
                    self.tool_call(call, historical_tools)
                except PolicyDenied:
                    raise PolicyDenied('inference.history', 'Earlier tool calls do not match the current tool definitions. Continue without earlier context.') from None
                if call['id'] in seen_calls:
                    raise PolicyDenied("inference.tool_history", "Function call identifiers must be unique.")
                seen_calls.add(call['id'])
                pending.add(call['id'])
        if pending:
            raise PolicyDenied("inference.tool_history", "Function call results are missing.")
        if "response_format" in data:
            fmt = data["response_format"]
            if not isinstance(fmt, dict) or fmt.get("type") not in {"text", "json_object", "json_schema"} or set(fmt) - {"type", "json_schema"}:
                raise PolicyDenied("inference.format", "Unsupported response format.")
            if fmt.get("type") == "json_schema":
                definition = fmt.get('json_schema')
                if not isinstance(definition, dict) or set(definition) - {'name', 'description', 'strict', 'schema'} or not isinstance(definition.get('name'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', definition['name']) or not isinstance(definition.get('schema'), dict) or ('strict' in definition and type(definition['strict']) is not bool) or ('description' in definition and not isinstance(definition['description'], str)):
                    raise PolicyDenied('inference.format', 'Supply a named, valid response schema.')
                try:
                    check_schema(definition['schema'])
                except (ValueError, TypeError, jsonschema.SchemaError):
                    raise PolicyDenied('inference.format', 'The requested response schema is invalid or unsupported.') from None
            elif set(fmt) != {'type'}:
                raise PolicyDenied('inference.format', 'This response format does not accept schema settings.')
        clean, changed = runtime.inspect(data, limits, identity=identity)
        if 'max_tokens' in clean and 'max_completion_tokens' in clean and clean['max_tokens'] != clean['max_completion_tokens']:
            raise PolicyDenied('inference.tokens', 'Conflicting output token limits are not supported.')
        for key in ['max_tokens', 'max_completion_tokens']:
            if key in clean and (type(clean[key]) is not int or clean[key] < 1 or (limits.max_output_tokens is not None and clean[key] > limits.max_output_tokens)):
                raise PolicyDenied('inference.tokens', 'Requested output tokens exceed the effective limit.')
        cap = clean.get("max_completion_tokens", clean.get("max_tokens", limits.max_output_tokens))
        clean.pop("max_completion_tokens", None)
        if cap is not None:
            clean["max_tokens"] = cap
        # No local identities or arbitrary metadata are passed to a provider.
        clean.pop("user", None)
        # Redaction must not invalidate a tool schema, call argument or JSON format.
        if changed:
            if _redacted:
                raise PolicyDenied('data.pattern', 'The redaction policy does not produce stable content.')
            validated, limits, tools, _ = self.request(identity, clean, _redacted=True)
            return validated, limits, tools, True
        return clean, limits, tools, changed

    def tool_call(self, call, tools):
        if not isinstance(call, dict) or set(call) - {'id', 'type', 'function', 'index'} or not isinstance(call.get('id'), str) or not 1 <= len(call['id']) <= 128 or not isinstance(call.get('function'), dict) or set(call['function']) != {'name', 'arguments'}:
            raise PolicyDenied('inference.tool_call', 'The model returned a malformed function call.')
        function = call.get("function", {})
        name = function.get("name")
        if call.get("type", "function") != "function" or not isinstance(name, str) or name not in tools:
            raise PolicyDenied("inference.tool_call", "The response refers to an unknown function.")
        try:
            if not isinstance(function.get('arguments'), str):
                raise ValueError()
            arguments = strict_json(function['arguments'])
            if not isinstance(arguments, dict):
                raise ValueError()
            jsonschema.validate(arguments, tools[name])
        except (ValueError, TypeError, jsonschema.ValidationError):
            raise PolicyDenied("inference.tool_arguments", "Generated tool arguments do not match their schema.") from None

    def deployment(self, identity, data, limits):
        runtime, policy = self.runtime, self.runtime.policy()
        entries = yaml.safe_load((runtime.root / "inference/litellm-config.yml").read_text())["model_list"]
        selected = [e["litellm_params"] for e in entries if e["model_name"] == data["model"]]
        if len(selected) != 1:
            raise PolicyDenied("model.deployment", "Each guarded alias must select exactly one configured deployment.")
        params = selected[0]
        if set(params) - {"model", "api_base", "api_key", "extra_body", "temperature", "top_p", "stop", "seed", "presence_penalty", "frequency_penalty"}:
            raise PolicyDenied("model.parameters", "This deployment contains settings that the guarded gateway does not support.")
        if not isinstance(params.get("extra_body", {}), dict) or set(params.get("extra_body", {})) - {"provider"}:
            raise PolicyDenied("model.parameters", "Extra provider settings may only configure reviewed routing; token or request overrides are blocked.")
        rule = policy.models.get(data["model"])
        if not rule or rule.deployment_hash != digest(params):
            raise PolicyDenied("model.unreviewed", "This saved model deployment needs an access review.")
        runtime.authorise_model(identity, data["model"], rule)
        provider = params["model"].split("/", 1)[0]
        defaults = {"openai": "https://api.openai.com/v1", "anthropic": "https://api.anthropic.com", "openrouter": "https://openrouter.ai/api/v1", "mistral": "https://api.mistral.ai/v1", "groq": "https://api.groq.com/openai/v1", "deepseek": "https://api.deepseek.com", "together_ai": "https://api.together.xyz/v1", "ollama_chat": "http://localhost:11434", "gemini": "https://generativelanguage.googleapis.com"}
        if provider not in defaults:
            raise PolicyDenied("model.provider", "This provider does not have a verified guarded HTTP adapter.")
        if params.get("api_key") and not str(params["api_key"]).startswith("os.environ/"):
            raise PolicyDenied("model.credentials", "Provider credentials must use a saved secret reference.")
        endpoint = params.get("api_base") or defaults.get(provider)
        if not endpoint:
            raise PolicyDenied("model.endpoint", "Configure an explicit API base for this provider.")
        return params, endpoint, rule

    def reservation(self, identity, data, limits, model_limit):
        runtime = self.runtime
        data['max_tokens'] = min(value for value in (data.get('max_tokens'), limits.max_output_tokens, model_limit) if value is not None)
        # Bound the whole context (including schemas and tool results) without
        # fetching tokenizers or price catalogues. UTF-8 bytes plus protocol
        # overhead form a deliberately conservative reservation for text models.
        context_tokens = len(canonical(data).encode()) + 256 + 32 * len(data["messages"])
        available = runtime.remaining_tokens(identity, limits)
        for label, remaining in available.items():
            if remaining <= context_tokens:
                raise PolicyDenied('tokens.' + label, 'The context leaves no room for output in the ' + {'run':'total agent-turn', 'day':'daily', 'month':'monthly'}[label] + ' token budget.')
        data['max_tokens'] = min(data['max_tokens'], *(remaining - context_tokens for remaining in available.values()))
        # Changing the cap can shorten its JSON encoding. Recompute the final
        # reservation; reserve() still enforces all budgets atomically.
        tokens = len(canonical(data).encode()) + 256 + 32 * len(data["messages"]) + data["max_tokens"]
        return tokens

    def response(self, identity, response, data, tools, limits):
        if not isinstance(response, dict) or not isinstance(response.get("choices"), list) or len(response["choices"]) != 1 or not isinstance(response['choices'][0], dict):
            raise PolicyDenied("inference.response", "Expected one complete model response.")
        choice = response['choices'][0]
        message = choice.get("message", {})
        if not isinstance(message, dict) or message.get("role") != "assistant" or (message.get("content") is not None and not isinstance(message["content"], str)):
            raise PolicyDenied("inference.response", "The provider returned an invalid assistant message.")
        message_fields = {'role', 'content', 'tool_calls', 'reasoning_content', 'thinking_blocks', 'refusal'}
        if any(k not in message_fields | {'annotations', 'provider_specific_fields'} and v is not None for k, v in message.items()):
            raise PolicyDenied('inference.response', 'The provider returned an unsupported assistant field.')
        calls = message.get('tool_calls')
        if calls is not None and (not isinstance(calls, list) or not 1 <= len(calls) <= 128):
            raise PolicyDenied('inference.response', 'The provider returned invalid function calls.')
        if message.get('reasoning_content') is not None and not isinstance(message['reasoning_content'], str):
            raise PolicyDenied('inference.response', 'The provider returned invalid reasoning content.')
        blocks = message.get('thinking_blocks')
        if blocks is not None and (not isinstance(blocks, list) or any(not isinstance(b, dict) or b.get('type') != 'thinking' or set(b) - {'type', 'thinking', 'signature'} or not isinstance(b.get('thinking'), str) or ('signature' in b and not isinstance(b['signature'], str)) for b in blocks)):
            raise PolicyDenied('inference.response', 'The provider returned invalid reasoning blocks.')
        if message.get('refusal') is not None and not isinstance(message['refusal'], str):
            raise PolicyDenied('inference.response', 'The provider returned an invalid refusal.')
        if choice.get('finish_reason') not in {'stop', 'length', 'tool_calls', 'content_filter'} or bool(calls) != (choice.get('finish_reason') == 'tool_calls'):
            raise PolicyDenied('inference.response', 'The provider returned an incomplete or inconsistent response.')
        if not calls and message.get('content') is None and not message.get('refusal'):
            raise PolicyDenied('inference.response', 'The provider returned no usable response.')
        if calls and (data.get('tool_choice') == 'none' or (data.get('parallel_tool_calls') is False and len(calls) > 1)):
            raise PolicyDenied('inference.tool_call', 'The provider did not respect the tool selection.')
        if not calls and (data.get('tool_choice') == 'required' or isinstance(data.get('tool_choice'), dict)):
            raise PolicyDenied('inference.tool_call', 'The required function call is missing.')
        ids = set()
        for call in calls or []:
            self.tool_call(call, tools)
            if call['id'] in ids or (isinstance(data.get('tool_choice'), dict) and call['function']['name'] != data['tool_choice']['function']['name']):
                raise PolicyDenied('inference.tool_call', 'The response contains conflicting function calls.')
            ids.add(call['id'])
        def structured(value):
            fmt = data.get('response_format', {})
            if fmt.get('type') in {'json_object', 'json_schema'} and not calls:
                try:
                    result = strict_json(value['choices'][0]['message'].get('content', ''))
                    jsonschema.validate(result, fmt.get('json_schema', {}).get('schema', {'type': 'object'}))
                except (ValueError, TypeError, jsonschema.ValidationError):
                    raise PolicyDenied('inference.output_schema', 'The response does not satisfy the requested JSON schema.') from None
        structured(response)
        clean, changed = self.runtime.inspect(response, limits, output=True, identity=identity)
        structured(clean)
        for call in clean["choices"][0]["message"].get("tool_calls") or []:
            self.tool_call(call, tools)
        # Scan all provider metadata, but expose only the response fields whose
        # structure this gateway validates. Legacy function_call/audio and vendor
        # extensions cannot open another path to the agent runtime.
        checked_choice = clean['choices'][0]
        clean = {k:v for k,v in clean.items() if k in {'id', 'object', 'created', 'model', 'usage'}}
        clean['choices'] = [{'index':0, 'finish_reason':checked_choice['finish_reason'], 'message':{k:v for k,v in checked_choice['message'].items() if k in message_fields}}]
        return clean, changed


def create_inference_app(root=None, *, completion=None):
    runtime = Runtime(root or Path(__file__).resolve().parent.parent)
    hooks = InferenceHooks(runtime)
    model_limits = ModelLimits()
    active_revision = runtime.policy().revision
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runtime = runtime

    @app.middleware("http")
    async def boundary(request, call_next):
        try:
            if request.url.path not in {"/health/liveliness", "/v1/models", "/models", "/v1/chat/completions", "/chat/completions"}:
                return JSONResponse({"error": {"message": "Unsupported guarded gateway route."}}, 404)
            token = request.headers.get("authorization", "").removeprefix("Bearer ")
            request.state.identity = runtime.authenticate(token, "inference")
            if request.method == "POST":
                if request.headers.get('content-type', '').split(';', 1)[0].strip().lower() != 'application/json' or request.headers.get('content-encoding', 'identity') != 'identity':
                    raise PolicyDenied('inference.content_type', 'Send an uncompressed JSON request.')
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > runtime.policy().workspace.max_input_bytes:
                        raise PolicyDenied("payload.size", "The inference request is too large.")
                request._body = bytes(body)
            if runtime.policy().revision != active_revision:
                raise PolicyDenied("policy.pending", "The gateways must reconnect with the saved policy before they can be used.")
            return await call_next(request)
        except PolicyDenied as error:
            return JSONResponse({"error": {"message": str(error), "type": "policy_denied", "code": error.rule}}, 403)
        except Exception:
            return JSONResponse({"error": {"message": "Guardrail state is unavailable.", "type": "policy_denied"}}, 403)

    @app.get("/health/liveliness")
    async def health():
        return {"guardrails": 1, "revision": active_revision}

    @app.get("/v1/models")
    @app.get("/models")
    async def models(request: Request):
        entries = yaml.safe_load((runtime.root / "inference/litellm-config.yml").read_text())["model_list"]
        names = [e["model_name"] for e in entries]
        if request.state.identity["role"] != "admin":
            names = [n for n in names if _assigned(runtime, request.state.identity, n)]
        return {"object": "list", "data": [{"id": n, "object": "model"} for n in names]}

    @app.post("/v1/chat/completions")
    @app.post("/chat/completions")
    async def complete(request: Request):
        identity = request.state.identity
        name, started = "", time.monotonic()
        try:
            runtime.active(identity)
            data, limits, tools, redacted = hooks.request(identity, strict_json(await request.body()))
            name = data["model"]
            params, endpoint, rule = hooks.deployment(identity, data, limits)
            # Check exhausted budgets before any capability lookup. The final
            # reservation is still checked atomically immediately before work.
            hooks.reservation(identity, dict(data), limits, 1)
            kwargs = dict(params)
            for key in ["api_base", "api_key"]:
                if isinstance(kwargs.get(key), str) and kwargs[key].startswith("os.environ/"):
                    from dotenv import dotenv_values
                    secret_name = kwargs[key].split("/", 1)[1]
                    kwargs[key] = dotenv_values(runtime.root / ".env", interpolate=False).get(secret_name) or __import__("os").environ.get(secret_name)
                    if not kwargs[key]:
                        raise PolicyDenied("model.secret", "The configured provider secret is missing.")
            model_limit = await runtime.guarded(identity, model_limits.resolve(params, endpoint, runtime.policy().local_endpoints), limits.timeout_seconds)
            if model_limit is None and data.get('max_tokens', limits.max_output_tokens) is None:
                raise PolicyDenied('model.limits', 'This model does not publish a supported output limit. Set an explicit maximum in Advanced technical limits or choose a model with published limits.')
            tokens = hooks.reservation(identity, data, limits, model_limit)
            requested_stream = bool(data.get("stream"))
            kwargs.update({k: v for k, v in data.items() if k not in {"model", "stream", "stream_options"}})
            kwargs.update(api_base=endpoint, stream=True, stream_options={"include_usage": True}, num_retries=0, max_retries=0, timeout=limits.timeout_seconds)
            # All provider bytes go through the bounded, DNS-pinned HTTP handler.
            if completion is None:
                from litellm import acompletion, stream_chunk_builder
                from litellm.llms.custom_httpx.http_handler import AsyncHTTPHandler
                import litellm
                litellm.suppress_debug_info = True
                litellm.set_verbose = False
                handler = AsyncHTTPHandler(transport=transport_for(endpoint, [endpoint], runtime.policy().local_endpoints, max_bytes=limits.max_output_bytes * 8, max_requests=1), follow_redirects=False, timeout=limits.timeout_seconds)
                client = handler.client
                if params["model"].split("/", 1)[0] == "openai":
                    from openai import AsyncOpenAI
                    kwargs["client"] = AsyncOpenAI(api_key=kwargs.get("api_key") or "local", base_url=endpoint, http_client=client, max_retries=0)
                else:
                    kwargs["client"] = handler
                backend = acompletion
            else:
                client, backend = None, completion
            call = runtime.reserve(identity, "inference", name, digest(data), 0, limits, tokens=tokens)
            chunks, total, reported_usage = [], 0, None
            try:
                async with asyncio.timeout(limits.timeout_seconds):
                    upstream = await runtime.guarded(identity, backend(**kwargs), limits.timeout_seconds)
                    if hasattr(upstream, "__aiter__"):
                        iterator = upstream.__aiter__()
                        while True:
                            try:
                                chunk = await runtime.guarded(identity, anext(iterator), limits.timeout_seconds)
                            except StopAsyncIteration:
                                break
                            runtime.active(identity)
                            item = chunk.model_dump(mode="json") if hasattr(chunk, "model_dump") else chunk
                            if item.get("usage"):
                                reported_usage = item["usage"]
                            total += len(canonical(item).encode())
                            if total > limits.max_output_bytes * 8:
                                raise PolicyDenied("inference.output_size", "The buffered response exceeds its limit.")
                            chunks.append(chunk)
                        from litellm import stream_chunk_builder
                        response = stream_chunk_builder(chunks, messages=data["messages"])
                        response = response.model_dump(mode="json") if hasattr(response, "model_dump") else response
                    else:
                        response = upstream.model_dump(mode="json") if hasattr(upstream, "model_dump") else upstream
                        reported_usage = response.get("usage")
            finally:
                if client:
                    await client.aclose()
            runtime.active(identity)
            if runtime.policy().revision != active_revision:
                raise PolicyDenied("policy.changed", "Policy changed during inference.")
            # Account even when content is rejected: provider work may be billable.
            usage = reported_usage or {}
            response["usage"] = usage
            runtime.settle(call, usage=usage)
            if isinstance(usage.get("completion_tokens"), int) and usage["completion_tokens"] > data["max_tokens"]:
                raise PolicyDenied("inference.tokens", "The provider exceeded the requested output token limit.")
            response, changed = hooks.response(identity, response, data, tools, limits)
            runtime.record(identity, Decision(action="redact" if changed or redacted else "allow", rule="inference.checked", explanation="Validated model response.", revision=active_revision), name, int((time.monotonic() - started) * 1000))
            if not requested_stream:
                return JSONResponse(response)
            # Reconstruct a single validated SSE delta. Original fragments are never released.
            choice = response["choices"][0]
            message = choice["message"]
            delta = {k: v for k, v in message.items() if k in {"role", "content", "tool_calls"} and v is not None}
            if "tool_calls" in delta:
                delta["tool_calls"] = [{**v, "index": i} for i, v in enumerate(delta["tool_calls"])]
            envelope = {"id": response.get("id", "guarded"), "object": "chat.completion.chunk", "created": response.get("created", int(time.time())), "model": name}
            async def frames():
                yield "data: " + canonical({**envelope, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}) + "\n\n"
                yield "data: " + canonical({**envelope, "choices": [{"index": 0, "delta": {}, "finish_reason": choice.get("finish_reason", "stop")}], "usage": usage}) + "\n\n"
                yield "data: [DONE]\n\n"
            return StreamingResponse(frames(), media_type="text/event-stream")
        except (PolicyDenied, jsonschema.ValidationError, jsonschema.SchemaError, ValueError, TypeError, KeyError) as error:
            runtime.denial(identity, error, name)
            return JSONResponse({"error": {"message": str(error) if isinstance(error, PolicyDenied) else "The inference payload failed validation.", "type": "policy_denied", "code": getattr(error, "rule", "validation.invalid")}}, 403)
        except Exception as error:
            # Provider exceptions can contain submitted prompts and headers.
            pending, seen, denied = [error], set(), None
            while pending:
                nested = pending.pop()
                if id(nested) in seen:
                    continue
                seen.add(id(nested))
                if isinstance(nested, PolicyDenied):
                    denied = nested
                    break
                pending.extend(e for e in [getattr(nested, "__cause__", None), getattr(nested, "__context__", None), getattr(nested, "original_exception", None)] if isinstance(e, BaseException))
            runtime.denial(identity, denied or PolicyDenied("provider.failed", "Provider request failed."), name)
            if denied:
                return JSONResponse({"error": {"message": "A provider operation was blocked by gateway policy.", "type": "policy_denied", "code": denied.rule}}, 403)
            # Only explicit upstream service outages qualify for model fallback.
            status = getattr(error, "status_code", None)
            return JSONResponse({"error": {"message": "The provider request failed; its token reservation is retained until usage is known.", "type": "provider_error"}}, status if status in {502, 503, 504} else 403)

    return app


def _assigned(runtime, identity, name):
    try:
        runtime.assigned(identity, model=name)
        limits = runtime.policy().effective(identity, model=name)
        return limits.allowed_models is None or name in limits.allowed_models
    except PolicyDenied:
        return False
