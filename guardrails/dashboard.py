"""Dashboard management endpoints; all inherit pairing/origin/CSRF protection."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from fastapi import Request
from pydantic import Field
import httpx

from .policy import Decision, Policy, PolicyDenied, canonical, digest
from .runtime import tool_hash
from .settings import Settings, load_settings, definitions as capability_definitions, bind_access
from .authorizer import BUNDLE, bundle_revision, _load
from typing import Literal
from .policy import Strict, MAX_OUTPUT_TOKENS
from sandboxing.models import SandboxSettings


class Preferences(Strict):
    monthly_token_limit: int | None = 1000000
    per_run_token_limit: int = 50000
    max_output_tokens: int | None = Field(default=None, ge=1, le=MAX_OUTPUT_TOKENS, strict=True)
    daily_token_limit: int | None = None
    jurisdictions: list[Literal["england_wales", "scotland", "northern_ireland"]] = Field(default_factory=lambda: ['england_wales'])
    mode: Literal["cautious", "draft_only"] = 'cautious'
    activities: dict[str, bool] = Field(default_factory=dict)
    safeguarding_contact: str = ""
    sandbox: SandboxSettings | None = None


class AccessChoice(Strict):
    permission: Literal["read", "review", "blocked"]
    workflow: Literal["none", "fundraising", "safeguarding", "campaigning", "financial", "gift_aid"] = "none"
    data_class: Literal["public", "personal", "sensitive"] = "public"


def install_routes(app, store, chat, services, response, idle):
    runtime = chat.guardrails

    async def definitions():
        return capability_definitions(store.root)

    @app.get("/api/guardrails")
    async def get_policy():
        policy = runtime.policy()
        # Surface all supported jurisdictions with the same enforceable common
        # controls; nation-specific duties are linked for human review.
        deployments = [{"name": item["model_name"], "model": item["litellm_params"]["model"], "deployment_hash": digest(item["litellm_params"])} for item in store.yaml("inference/litellm-config.yml")["model_list"]]
        settings = load_settings(store.root)
        manifest = json.loads((BUNDLE / "manifest.json").read_text())
        # Validate the maintained pack before presenting it as active.
        _load(bundle_revision())
        for deployment in deployments:
            rule = policy.models.get(deployment["name"])
            deployment["ready"] = bool(rule and rule.deployment_hash == deployment["deployment_hash"] and all([policy.token_limits.per_run, policy.token_limits.daily, policy.token_limits.monthly]))
        public_settings = settings.model_dump(mode="json", exclude={"access", "approved_connections", "advanced", "blocked_tools"})
        public_settings["advanced_configured"] = settings.advanced is not None
        return response({"settings": public_settings, "pack": manifest, "policy": policy.model_dump(mode="json"), "revision": store.revision(), "runtime": runtime.summary(), "deployments": deployments, "tool_definitions": await definitions(), "blocked_tools": settings.blocked_tools})

    def save_settings(settings, revision):
        # Validation here also prevents a browser from introducing unknown activity flags.
        settings = Settings.model_validate(settings.model_dump(mode="json"))
        if any(secret in canonical(settings.model_dump(mode="json")) for secret in runtime.secret_values()):
            raise ValueError("Use references rather than secret values in organisation settings.")
        idle()
        with store.edit(revision):
            store.save(store.policy_path, settings.model_dump(mode="json", exclude_none=True))
        runtime.invalidate_pending()
        return settings

    @app.put("/api/guardrails/settings")
    async def update_settings(request: Request):
        idle()
        data = await request.json()
        values = Preferences.model_validate(data.get("settings"))
        settings = load_settings(store.root)
        if values.sandbox is not None and values.sandbox != settings.sandbox:
            raise ValueError("Use the Local tool sandbox controls to change sandbox access.")
        candidate = Settings.model_validate({**settings.model_dump(mode="json"), **values.model_dump(mode="json", exclude={"sandbox"}, exclude_unset=True)})
        save_settings(candidate, data.get("revision"))
        return response({"revision": store.revision()})

    @app.post("/api/guardrails/pricing/refresh")
    async def update_pricing(request: Request):
        return response({"error": "Pricing is no longer required. Use token limits instead."}, 410)

    @app.put("/api/guardrails/access/{name}")
    async def update_access(name: str, request: Request):
        idle()
        data = await request.json()
        choice = AccessChoice.model_validate(data.get("access"))
        definition = next((d for d in await definitions() if d["name"] == name), None)
        if not definition:
            raise ValueError("Discover this capability before reviewing access.")
        settings = load_settings(store.root)
        if choice.permission == "blocked":
            settings.blocked_tools = sorted(set(settings.blocked_tools) | {name})
        else:
            settings.blocked_tools = [n for n in settings.blocked_tools if n != name]
            previous = runtime.policy().tools.get(name)
            settings.access[name] = bind_access(definition, permission=choice.permission, workflow=choice.workflow, data_class=choice.data_class, previous=previous)
        save_settings(settings, data.get("revision"))
        return response({"revision": store.revision()})

    @app.post("/api/guardrails/check")
    async def check_example(request: Request):
        from .authorizer import authorise
        data = await request.json()
        scenario = data.get("scenario")
        if scenario not in {"research", "publish", "fundraising", "payment"}:
            raise ValueError("Choose one of the example scenarios.")
        policy = runtime.policy()
        facts = {"needs_review": scenario != "research", "draft_only": policy.profile.get("mode") == "draft_only"}
        classification, workflow = "read", "none"
        if scenario == "publish":
            classification = "publish"
        if scenario == "fundraising":
            classification, workflow = "send", "fundraising"
            facts.update(workflow_enabled=policy.profile.get("activities", {}).get("fundraising", True), recipients_eligible=False, has_recipients=False)
        if scenario == "payment":
            classification, workflow = "financial", "financial"
            facts.update(workflow_enabled=policy.profile.get("activities", {}).get("finance", True), due_diligence=False, fund_approved=False)
        denied = authorise({"agent": "example"}, scenario, classification=classification, workflow=workflow, **facts)
        return response({"rule": denied.rule if denied else "access.permitted", "explanation": str(denied) if denied else "Allowed: public research and drafting are included. This example did not execute a tool or contact a model."})

    @app.put("/api/guardrails")
    async def save_policy(request: Request):
        idle()
        data = await request.json()
        policy = Policy.model_validate(data.get("policy"))
        if policy.sandbox != runtime.policy().sandbox:
            raise ValueError("Use the Local tool sandbox controls to change sandbox settings or connection access.")
        # Evidence/settings are administrator input. Do not save provider secrets
        # or active scoped credentials into shareable YAML.
        encoded = canonical(policy.model_dump(mode="json"))
        if any(v in encoded for v in runtime.secret_values()):
            raise ValueError("Use references rather than secret values in guardrail settings.")
        with store.edit(data.get("revision")):
            raw = store.yaml(store.policy_path)
            if raw.get("version") in {2, 3}:
                settings = load_settings(store.root)
                # Persist only explicit expert changes, not generated tool pins,
                # current prices or derived budgets from the effective-policy view.
                current = runtime.policy()
                advanced = settings.advanced.model_copy(deep=True) if settings.advanced else Policy()
                for key in Policy.model_fields:
                    if key in {"version", "profile"}:
                        continue
                    changed, before = getattr(policy, key), getattr(current, key)
                    if changed == before:
                        continue
                    if key == "token_limits":
                        settings.monthly_token_limit = changed.monthly
                        settings.per_run_token_limit = changed.per_run or 50000
                        settings.daily_token_limit = changed.daily
                        continue
                    if key == 'workspace':
                        # Ordinary and Advanced editors share one workspace
                        # reply cap; neither save may silently undo the other.
                        settings.max_output_tokens = changed.max_output_tokens
                    if isinstance(changed, dict):
                        target = getattr(advanced, key)
                        for name in set(changed) | set(before):
                            if changed.get(name) != before.get(name):
                                if name in changed:
                                    target[name] = changed[name]
                                else:
                                    target.pop(name, None)
                    else:
                        setattr(advanced, key, changed)
                settings.advanced = advanced
                store.save(store.policy_path, settings.model_dump(mode="json", exclude_none=True))
            else:
                store.save(store.policy_path, policy.model_dump(mode="json"))
        runtime.invalidate_pending()
        return response({"revision": store.revision(), "policy_revision": runtime.policy().revision})

    @app.post("/api/guardrails/test")
    async def test_policy(request: Request):
        data = await request.json()
        identity = {"team": str(data.get("team", "")), "agent": str(data.get("agent", "")), "data_class": data.get("data_class", "public")}
        policy = runtime.policy()
        try:
            if data.get("kind") == "tool":
                decision, _, limits, _ = runtime.evaluate_tool(identity, str(data.get("name", "")), data.get("arguments", {}))
            else:
                limits = policy.effective(identity, model=str(data.get("name", "")))
                _, changed = runtime.inspect(data.get("content", ""), limits, output=data.get("kind") == "output")
                decision = Decision(action="redact" if changed else "allow", rule="data.redacted" if changed else "data.checked", explanation="Synthetic content satisfies these data checks. No gateway operation was executed.", revision=policy.revision)
        except Exception as error:
            limits = policy.effective(identity)
            decision = Decision(action="block", rule=getattr(error, "rule", "validation.invalid"), explanation=str(error) if isinstance(error, PolicyDenied) else "Synthetic input failed validation.", revision=policy.revision)
        return response({"decision": decision.model_dump(), "effective": limits.model_dump(mode="json")})

    @app.get("/api/guardrails/activity")
    async def activity():
        summary = runtime.summary()
        if summary["approvals"]:
            gateway = store.tools()["gateway"]
            url = f"http://{gateway['host']}:{gateway['port']}/guardrails/approvals"
            if urlsplit(url).hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("Approval previews require a local gateway.")
            try:
                async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
                    result = await client.get(url, headers={"Authorization": "Bearer " + runtime.admin_token("tools")})
                    result.raise_for_status()
                    payloads = result.json()["arguments"]
                for approval in summary["approvals"]:
                    approval["arguments"] = payloads.get(approval["id"])
            except Exception:
                for approval in summary["approvals"]:
                    approval["arguments"] = None
        return response(summary)

    @app.post("/api/guardrails/approvals/{approval_id}")
    async def decide(approval_id: str, request: Request):
        data = await request.json()
        if not isinstance(data.get("approve"), bool):
            raise ValueError("Choose approve or reject.")
        runtime.decide_approval(approval_id, data["approve"])
        return response({"saved": True})

    @app.post("/api/guardrails/stop")
    async def stop():
        runtime.stop()
        await chat.cancel()
        return response({"stopped": True})

    @app.post("/api/guardrails/resume")
    async def resume():
        idle()
        runtime.stop(False)
        return response({"stopped": False})

    @app.post("/api/guardrails/connections/{name}/review")
    async def review_connection(name: str, request: Request):
        idle()
        data = await request.json()
        spec = store.tools()["mcp_servers"].get(name)
        if not spec or spec.get("transport") != "stdio":
            raise ValueError("Choose a configured local stdio connection.")
        policy = runtime.policy()
        command = [spec["command"], *spec.get("args", [])]
        settings = load_settings(store.root)
        settings.approved_connections[name] = digest(spec)
        save_settings(settings, data.get("revision"))
        return response({"revision": store.revision()})
