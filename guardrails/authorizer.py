"""Local Cedar authorisation, validated once per immutable policy-bundle revision."""
from functools import lru_cache
import json
from pathlib import Path

import cedarpy

from .policy import PolicyDenied, digest

BUNDLE = Path(__file__).with_name("cedar")
FACTS = ("assigned", "scope_allowed", "workflow_enabled", "data_allowed", "schema_current", "arguments_valid", "autonomous_update_valid", "value_within_limit", "needs_review", "approved", "draft_only", "provider_terms", "purpose_approved", "has_recipients", "sender_matches", "recipients_eligible", "soft_opt_in_valid", "campaign_approved", "fund_approved", "due_diligence", "financial_target_matches", "value_known", "dual_authorisation_valid")


def bundle_revision():
    return digest({p.name: p.read_text() for p in sorted(BUNDLE.iterdir()) if p.suffix in {".cedar", ".json"}})


@lru_cache(maxsize=4)
def _load(revision):
    try:
        schema = json.loads((BUNDLE / "schema.json").read_text())
        source = "\n".join(p.read_text() for p in sorted(BUNDLE.glob("*.cedar")))
        result = cedarpy.validate_policies(source, schema)
        if not result.validation_passed:
            raise ValueError("Invalid maintained policy bundle")
        return cedarpy.PolicySet.from_str(source), cedarpy.Schema.from_json_str(json.dumps(schema)), json.loads((BUNDLE / "manifest.json").read_text())
    except Exception:
        raise PolicyDenied("cedar.invalid", "The maintained safety policies could not be validated.") from None


def authorise(identity, name, *, kind="tool", classification="read", workflow="none", action="Execute", **facts):
    policies, schema, manifest = _load(bundle_revision())
    context = {key: True for key in FACTS}
    context.update(needs_review=False, approved=False, draft_only=False)
    if set(facts) - set(FACTS) or any(type(v) is not bool for v in facts.values()):
        raise PolicyDenied("cedar.context", "Authorisation context is invalid.")
    context.update(facts)
    agent = {"type": "Kindred::Agent", "id": identity.get("agent", "") or "policy-test"}
    capability = {"type": "Kindred::Capability", "id": name}
    request = {"principal": agent, "action": f'Kindred::Action::"{action}"', "resource": capability, "context": context}
    entities = [{"uid": {"__entity": agent}, "attrs": {}, "parents": []}, {"uid": {"__entity": capability}, "attrs": {"name": name, "kind": kind, "classification": classification, "workflow": workflow}, "parents": []}]
    try:
        result = cedarpy.is_authorized(request, policies, entities, schema=schema)
        # Cedar normally skips erroneous policies. A gateway fails closed instead.
        if result.diagnostics.errors:
            raise ValueError("Cedar evaluation errors")
    except Exception:
        raise PolicyDenied("cedar.evaluation", "The safety policy could not evaluate this action.") from None
    if result.allowed:
        return None
    annotations = result.diagnostics.id_annotations_by_reason
    determining = set(annotations.values())
    # Hard denials take precedence over an approval hold in user explanations.
    for rule, explanation in manifest["rules"].items():
        if rule != "approval.required" and rule in determining:
            return PolicyDenied(rule, explanation)
    if "approval.required" in determining:
        return PolicyDenied("approval.required", manifest["rules"]["approval.required"])
    return PolicyDenied("access.denied", "No maintained policy permits this action.")
