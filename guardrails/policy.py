"""Strict, serialisable policy types. No model decides a permission."""
from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sandboxing.models import SandboxSettings


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def check_pattern(pattern):
    # Fixed-width patterns avoid combinatorial backtracking, including chains of
    # otherwise bounded variable repetitions. Deliberately keep the UI subset small.
    if not isinstance(pattern, str) or not pattern or len(pattern) > 256:
        raise ValueError("Use fixed-width patterns: literals, character classes and fixed repetitions such as [0-9]{4}.")
    # These shorthands each consume exactly one character. Inspect a placeholder
    # for their syntax, but compile and evaluate the original pattern unchanged.
    # All other escapes (including backreferences) still fail the safety check.
    restricted = re.sub(r"\\[dDsSwW]", "x", pattern)
    if any(c in restricted for c in "()*+?|\\") or re.search(r"\{[^}]*,[^}]*\}", restricted):
        raise ValueError("Use fixed-width patterns: literals, character classes and fixed repetitions such as [0-9]{4}.")
    counts = [int(v) for v in re.findall(r"\{([0-9]+)\}", pattern)]
    if any(v > 128 for v in counts) or sum(counts) > 512:
        raise ValueError("Pattern repetitions exceed the validation work limit.")
    try:
        re.compile(pattern)
    except (re.error, OverflowError):
        raise ValueError("Enter a valid fixed-width pattern.") from None


def check_schema(schema):
    """Never let an untrusted schema fetch references or run arbitrary regexes."""
    import jsonschema
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (not isinstance(item, str) or not item.startswith("#")):
                    raise ValueError("Schema references must be local fragments.")
                if key in {"pattern", "patternProperties"}:
                    patterns = item.keys() if isinstance(item, dict) else [item]
                    for pattern in patterns:
                        check_pattern(pattern)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(schema)
    jsonschema.Draft202012Validator.check_schema(schema)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


MAX_OUTPUT_TOKENS = 1000000000


class Restrictions(Strict):
    allowed_models: list[str] | None = None
    allowed_tools: list[str] | None = None
    max_input_bytes: int = Field(default=131072, ge=1024, le=1048576)
    max_output_bytes: int = Field(default=1048576, ge=1024, le=4194304)
    max_output_tokens: int | None = Field(default=None, ge=1, le=MAX_OUTPUT_TOKENS, strict=True)
    max_depth: int = Field(default=20, ge=1, le=64)
    max_inference_attempts: int = Field(default=30, ge=1, le=100)
    max_tool_calls: int = Field(default=50, ge=1, le=200)
    max_calls_per_minute: int = Field(default=60, ge=1, le=600)
    repeat_limit: int = Field(default=3, ge=1, le=10)
    timeout_seconds: int = Field(default=120, ge=1, le=180)
    per_run_gbp: Decimal | None = Field(default=None, gt=0)
    max_tokens_per_run: int | None = Field(default=None, ge=1, le=1000000000)
    blocked_fields: list[str] = Field(default_factory=lambda: ["bank_account", "card_number", "beneficiary_case", "ni_number"])
    blocked_patterns: list[str] = Field(default_factory=list, max_length=30)
    redact_patterns: list[str] = Field(default_factory=list, max_length=30)

    @model_validator(mode="after")
    def patterns(self):
        # Bound pattern syntax to a predictable subset: literals and character
        # classes with bounded repetitions. No nested/backtracking expressions.
        for pattern in self.blocked_patterns + self.redact_patterns:
            check_pattern(pattern)
        return self


class Budget(Strict):
    per_run_gbp: Decimal | None = Field(default=None, gt=0)
    daily_gbp: Decimal | None = Field(default=None, gt=0)
    monthly_gbp: Decimal | None = Field(default=None, gt=0)
    usd_to_gbp: Decimal | None = Field(default=None, gt=0)
    exchange_rate_revision: str = ""


class TokenLimits(Strict):
    per_run: int | None = Field(default=50000, ge=1, le=1000000000)
    daily: int | None = Field(default=200000, ge=1, le=1000000000)
    monthly: int | None = Field(default=1000000, ge=1, le=1000000000)


class ModelRule(Strict):
    deployment_hash: str = ""
    input_usd_per_million: Decimal | None = Field(default=None, ge=0)
    output_usd_per_million: Decimal | None = Field(default=None, ge=0)
    price_revision: str = ""
    free_local: bool = False
    approved_data_classes: list[Literal["public", "personal", "sensitive"]] = Field(default_factory=lambda: ["public"])
    purpose: str = ""
    provider_terms_reference: str = ""
    transfer_reference: str = ""


class ToolRule(Strict):
    classification: Literal["read", "draft", "update", "send", "publish", "destructive", "financial", "beneficiary_decision"]
    schema_hash: str
    configuration_hash: str = ""
    input_schema: dict
    output_schema: dict | None = None
    description: str = ""
    source_data_class: Literal["public", "personal", "sensitive"] = "public"
    approved_data_classes: list[Literal["public", "personal", "sensitive"]] = Field(default_factory=lambda: ["public"])
    autonomous: bool = False
    permitted_fields: list[str] = Field(default_factory=list)
    fixed_arguments: dict = Field(default_factory=dict)
    target_fields: list[str] = Field(default_factory=lambda: ["target_id"])
    max_items: int = Field(default=1, ge=1, le=1000)
    max_value_gbp: Decimal = Field(default=Decimal(0), ge=0)
    value_field: str = "amount_gbp"
    declared_cost_gbp: Decimal = Field(default=Decimal(0), ge=0)
    calls_per_day: int = Field(default=100, ge=1, le=10000)
    targets: list[str] = Field(default_factory=list)
    charity_workflow: Literal["none", "fundraising", "safeguarding", "campaigning", "financial", "gift_aid"] = "none"
    recipients_field: str = "recipients"
    campaign_reference: str = ""
    fund_reference: str = ""
    purpose_reference: str = ""
    fund_field: str = "fund_id"
    financial_recipient_field: str = "recipient_id"
    recipient_reference: str = ""
    due_diligence_reference: str = ""
    independent_authorisation_reference: str = ""
    requires_dual_authorisation: bool = False
    idempotency_field: str = ""


class Recipient(Strict):
    basis: Literal["consent", "charitable_soft_opt_in", "blocked"] = "blocked"
    evidence_reference: str = ""
    suppressed: bool = True
    review_required: bool = False
    contact_restricted: bool = False
    collected_on: str = ""
    collected_directly: bool = False
    interest_or_support: bool = False
    collection_opt_out: bool = False
    purpose_references: list[str] = Field(default_factory=list)


class Charity(Strict):
    jurisdictions: list[Literal["england_wales", "scotland", "northern_ireland"]] = Field(default_factory=lambda: ["england_wales", "scotland", "northern_ireland"])
    registered_charity: bool = False
    sender_identity: str = ""
    unsubscribe_url: str = ""
    safeguarding_instructions: str = "Refer concerns to your designated safeguarding lead. Do not send case information automatically."
    recipients: dict[str, Recipient] = Field(default_factory=dict)
    approved_campaigns: list[str] = Field(default_factory=list)
    approved_purposes: list[str] = Field(default_factory=list)
    approved_funds: list[str] = Field(default_factory=list)


class Policy(Strict):
    version: Literal[1] = 1
    workspace: Restrictions = Field(default_factory=Restrictions)
    budgets: Budget = Field(default_factory=Budget)
    token_limits: TokenLimits = Field(default_factory=TokenLimits)
    teams: dict[str, Restrictions] = Field(default_factory=dict)
    agents: dict[str, Restrictions] = Field(default_factory=dict)
    models: dict[str, ModelRule] = Field(default_factory=dict)
    tools: dict[str, ToolRule] = Field(default_factory=dict)
    model_restrictions: dict[str, Restrictions] = Field(default_factory=dict)
    tool_restrictions: dict[str, Restrictions] = Field(default_factory=dict)
    charity: Charity = Field(default_factory=Charity)
    audit_retention_days: int = Field(default=90, ge=1, le=3650)
    local_endpoints: list[str] = Field(default_factory=list)
    stdio_commands: list[list[str]] = Field(default_factory=list)
    profile: dict = Field(default_factory=dict)
    sandbox: SandboxSettings = Field(default_factory=SandboxSettings)

    @model_validator(mode="after")
    def schemas(self):
        try:
            for rule in self.tools.values():
                check_schema(rule.input_schema)
                if rule.output_schema is not None:
                    check_schema(rule.output_schema)
        except Exception:
            raise ValueError("Tool schemas must be valid JSON Schema with local references and fixed-width patterns.") from None
        return self

    @property
    def revision(self):
        from .authorizer import bundle_revision
        from sandboxing.models import PROFILE_REVISION
        return digest([self.model_dump(mode="json"), bundle_revision(), PROFILE_REVISION])

    def model_dump(self, *args, **kwargs):
        result = super().model_dump(*args, **kwargs)
        # Do not turn unspecified narrower settings into explicit defaults when
        # persisting a policy: that would change inheritance after a round trip.
        for field in ["teams", "agents", "model_restrictions", "tool_restrictions"]:
            if field in result:
                result[field] = {name: rule.model_dump(mode=kwargs.get("mode", "python"), exclude_unset=True) for name, rule in getattr(self, field).items()}
        return result

    def effective(self, identity: dict, *, model="", tool="") -> Restrictions:
        layers = [self.workspace]
        for mapping, key in [(self.teams, identity.get("team")), (self.agents, identity.get("agent")), (self.model_restrictions, model), (self.tool_restrictions, tool)]:
            if key in mapping:
                layers.append(mapping[key])
        merged = self.workspace.model_dump()
        for layer in layers[1:]:
            for name in layer.model_fields_set:
                value = getattr(layer, name)
                if name.startswith("allowed_"):
                    if value is not None:
                        merged[name] = value if merged[name] is None else sorted(set(merged[name]) & set(value))
                elif isinstance(value, list):
                    merged[name] = list(dict.fromkeys(merged[name] + value))
                elif value is not None:
                    merged[name] = value if merged[name] is None else min(merged[name], value)
        return Restrictions.model_validate(merged)


class Decision(Strict):
    action: Literal["allow", "redact", "block", "require_approval"]
    rule: str
    explanation: str
    revision: str


class PolicyDenied(ValueError):
    def __init__(self, rule: str, explanation: str):
        self.rule = rule
        super().__init__(f"{rule}: {explanation}")


class SemanticReviewer:
    """Extension only: future reviewers may add holds, never grant permission."""
    async def review(self, content, context) -> Decision:
        raise NotImplementedError
