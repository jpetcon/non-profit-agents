"""FastMCP boundary checks shared by every tool implementation."""
import asyncio
import json
import time
import yaml

import jsonschema
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware
from fastmcp.tools.base import ToolResult

from .policy import Decision, PolicyDenied, digest
from .runtime import tool_hash


class ToolGuardrails(Middleware):
    def __init__(self, runtime, *, identity_provider=None):
        self.runtime = runtime
        self.active_revision = runtime.policy().revision
        self.identity_provider = identity_provider

    def identity(self):
        if self.identity_provider:
            return self.identity_provider()
        headers = get_http_headers(include={"authorization"})
        return self.runtime.authenticate(headers.get("authorization", "").removeprefix("Bearer "), "tools")

    def configuration(self, name):
        config = yaml.safe_load((self.runtime.root / "tools/config.yml").read_text())
        configuration = config.get("custom_tools", {}).get(name) or config.get("http_tools", {}).get(name)
        if configuration is None:
            matches = [spec for prefix, spec in config.get("mcp_servers", {}).items() if name.startswith(prefix + "_")]
            if len(matches) != 1:
                raise PolicyDenied("tool.connection", "The source connection is ambiguous or missing.")
            configuration = matches[0]
        return configuration

    def maintained_read(self, name, arguments=None):
        from connectors.registry import hosted_read_allowed
        config = yaml.safe_load((self.runtime.root / "tools/config.yml").read_text())
        for prefix, spec in config.get("mcp_servers", {}).items():
            if name.startswith(prefix + "_") and spec.get("managed"):
                rule = self.runtime.policy().tools.get(name)
                if spec.get("native") and rule:
                    from connectors.native import operations
                    definition = next((o for o in operations(spec) if prefix+"_"+o["name"] == name), None)
                    levels = ["public", "personal", "sensitive"]
                    if not definition or levels.index(rule.source_data_class) < levels.index(definition["data_class"]):
                        raise PolicyDenied("connector.sensitivity", "The connector’s reviewed source sensitivity cannot be lowered.")
                if not hosted_read_allowed(spec, name[len(prefix)+1:], arguments) or (rule and rule.classification != "read"):
                    raise PolicyDenied("connector.read_only", "This maintained connection exposes approved read operations only.")
                if spec.get("transport") == "http" and rule:
                    from connectors.registry import managed_check, source_class, resources_bound
                    levels = ["public", "personal", "sensitive"]
                    floor = levels.index(source_class(managed_check(spec), name[len(prefix)+1:]))
                    if levels.index(rule.source_data_class) < floor:
                        raise PolicyDenied("connector.sensitivity", "Keep the maintained source sensitivity.")
                    if not resources_bound(rule):
                        raise PolicyDenied("connector.resource", "An administrator must bind this hosted tool to its selected resources before use.")
                return

    async def on_message(self, context, call_next):
        self.identity()
        if self.runtime.policy().revision != self.active_revision:
            raise PolicyDenied("policy.pending", "The tool gateway is reconnecting saved policy changes. Wait for it to become ready.")
        # No proxied resources, prompts, sampling or subscriptions with weaker rules.
        if context.method and not (context.method in {"initialize", "ping", "server/discover", "tools/list", "tools/call"} or context.method.startswith("notifications/")):
            raise PolicyDenied("tool.protocol", "This MCP operation is not enabled by the tool policy.")
        return await call_next(context)

    async def on_list_tools(self, context, call_next):
        identity = self.identity()
        tools = await call_next(context)
        if identity["role"] == "admin":
            return tools
        result = []
        policy = self.runtime.policy()
        for tool in tools:
            try:
                self.maintained_read(tool.name)
                self.runtime.assigned(identity, tool=tool.name)
                rule = policy.tools.get(tool.name)
                limits = policy.effective(identity, tool=tool.name)
                if rule:
                    from .authorizer import authorise
                    from .facts import access_facts
                    denied = authorise(identity, tool.name, action="Discover", classification=rule.classification, workflow=rule.charity_workflow, schema_current=rule.configuration_hash == digest(self.configuration(tool.name)) and rule.schema_hash == tool_hash(tool.name, tool.description, tool.parameters, tool.output_schema), **access_facts(policy, identity, tool.name, rule, limits))
                    if denied:
                        continue
                    self.runtime.inspect({"description": tool.description, "schema": tool.parameters, "output_schema": tool.output_schema}, limits, output=True, identity=identity)
                    result.append(tool)
            except PolicyDenied:
                continue
        return result

    async def on_call_tool(self, context, call_next):
        runtime, identity = self.runtime, self.identity()
        name, started = context.message.name, time.monotonic()
        try:
            runtime.active(identity)
            runtime.assigned(identity, tool=name)
            self.maintained_read(name, context.message.arguments or {})
            # Read the live upstream definition; its pinned hash covers both schemas.
            tool = await context.fastmcp_context.fastmcp.get_tool(name)
            fingerprint = tool_hash(name, tool.description, tool.parameters, tool.output_schema)
            decision, arguments, limits, rule = runtime.evaluate_tool(identity, name, context.message.arguments or {}, fingerprint)
            if rule.configuration_hash != digest(self.configuration(name)):
                raise PolicyDenied("tool.configuration_changed", "Review this tool after its configuration changes.")
            runtime.record(identity, decision, name)
            if decision.action == "require_approval":
                preview = {"tool": name, "classification": rule.classification, "targets": rule.targets, "rule": decision.rule, "arguments_hash": digest(arguments)}
                await runtime.approval(identity, name, arguments, rule, decision.revision, preview)
                # Approval does not bypass the hard checks.
                refreshed = await context.fastmcp_context.fastmcp.get_tool(name)
                fingerprint = tool_hash(name, refreshed.description, refreshed.parameters, refreshed.output_schema)
                if rule.configuration_hash != digest(self.configuration(name)):
                    raise PolicyDenied("tool.configuration_changed", "Tool configuration changed during approval.")
                again, arguments, limits, rule = runtime.evaluate_tool(identity, name, arguments, fingerprint, approved=True)
                if again.revision != decision.revision:
                    raise PolicyDenied("approval.policy_changed", "The approved policy changed.")
            if runtime.policy().revision != self.active_revision:
                raise PolicyDenied("policy.changed", "The gateway must reconnect with the saved settings before it can be used.")
            runtime.active(identity)
            signature_arguments = {k: v for k, v in arguments.items() if k != rule.idempotency_field}
            call = runtime.reserve(identity, "tool", name, digest([name, signature_arguments]), rule.declared_cost_gbp, limits)
            message = context.message.model_copy(update={"arguments": arguments})
            result = await runtime.guarded(identity, call_next(context.copy(message=message)), limits.timeout_seconds)
            runtime.active(identity)
            runtime.settle(call, rule.declared_cost_gbp)
            raw = result.model_dump(mode="json")
            if any(block.get("type") != "text" for block in raw.get("content", [])):
                raise PolicyDenied("tool.content_type", "Only text and structured JSON tool results are enabled.")
            if rule.output_schema is not None:
                jsonschema.validate(raw.get("structured_content"), rule.output_schema)
            clean, redacted = runtime.inspect(raw, limits, output=True, identity=identity)
            if clean.get('is_error'):
                raise PolicyDenied('tool.upstream_error', 'The upstream tool did not complete successfully.')
            if rule.output_schema is not None:
                jsonschema.validate(clean.get("structured_content"), rule.output_schema)
            if runtime.policy().revision != self.active_revision:
                raise PolicyDenied("policy.changed", "Policy changed during tool execution.")
            runtime.record(identity, Decision(action="redact" if redacted else "allow", rule="tool.result_checked", explanation="Validated tool result.", revision=self.active_revision), name, int((time.monotonic() - started) * 1000))
            return ToolResult(**clean)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            runtime.denial(identity, error, name)
            # Never reflect upstream exceptions, arguments or rejected content.
            raise PolicyDenied(getattr(error, "rule", "tool.failed"), "The tool operation was rejected or failed. See Guardrails for the rule.") from None
