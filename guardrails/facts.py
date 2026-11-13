"""Trusted fact adapters. These describe state; Cedar decides permission."""
from datetime import date, datetime
from zoneinfo import ZoneInfo
from decimal import Decimal, InvalidOperation


def access_facts(policy, identity, name, rule, limits):
    activities = policy.profile.get("activities", {})
    activity = {"fundraising": "fundraising", "campaigning": "campaigning", "financial": "finance", "gift_aid": "finance"}.get(rule.charity_workflow)
    enabled = not activity or activities.get(activity, not policy.profile.get("managed"))
    if identity["data_class"] != "public" or rule.source_data_class != "public":
        enabled &= activities.get("beneficiary_data", not policy.profile.get("managed"))
    classes = {"public": 0, "personal": 1, "sensitive": 2}
    return {"scope_allowed": limits.allowed_tools is None or name in limits.allowed_tools, "workflow_enabled": bool(enabled), "data_allowed": identity["data_class"] in rule.approved_data_classes and classes[rule.source_data_class] <= classes[identity["data_class"]]}


def tool_facts(policy, identity, name, arguments, rule, limits, schema_hash, approved):
    charity = policy.charity
    recipients = arguments.get(rule.recipients_field)
    has_recipients = isinstance(recipients, list) and bool(recipients)
    records = [charity.recipients.get(str(r)) for r in recipients] if has_recipients else []
    eligible = has_recipients and all(r and not r.suppressed and not r.contact_restricted and r.evidence_reference and r.basis != "blocked" and rule.purpose_reference in r.purpose_references for r in records)
    soft_opt_in_valid = True
    for record in records:
        if record and record.basis == "charitable_soft_opt_in":
            try:
                collected = date.fromisoformat(record.collected_on)
            except ValueError:
                collected = date.min
            soft_opt_in_valid &= bool(charity.registered_charity and date(2026, 2, 5) <= collected <= datetime.now(ZoneInfo("Europe/London")).date() and record.collected_directly and record.interest_or_support and record.collection_opt_out and rule.purpose_reference)
    automatic = rule.classification == "update" and rule.autonomous
    update_valid = not automatic or bool(rule.permitted_fields and set(arguments) <= set(rule.permitted_fields) and rule.targets and rule.target_fields and set(rule.target_fields) <= set(rule.fixed_arguments))
    needs_review = rule.classification not in {"read", "draft"} and not automatic
    if rule.charity_workflow != "none" and rule.classification not in {"read", "draft"}:
        needs_review = True
    value_valid = True
    if rule.value_field in arguments:
        try:
            value = Decimal(str(arguments[rule.value_field]))
            value_valid = not isinstance(arguments[rule.value_field], bool) and value.is_finite() and 0 <= value <= rule.max_value_gbp
        except (InvalidOperation, ValueError):
            value_valid = False
    return {
        **access_facts(policy, identity, name, rule, limits),
        "schema_current": schema_hash is None or schema_hash == rule.schema_hash,
        "arguments_valid": all(arguments.get(k) == v for k, v in rule.fixed_arguments.items()) and all(not isinstance(v, list) or len(v) <= rule.max_items for v in arguments.values()),
        "autonomous_update_valid": bool(update_valid), "value_within_limit": bool(value_valid),
        "needs_review": bool(needs_review), "approved": approved,
        "draft_only": policy.profile.get("mode") == "draft_only",
        "purpose_approved": rule.purpose_reference in charity.approved_purposes,
        "has_recipients": bool(has_recipients),
        "sender_matches": bool(charity.sender_identity and charity.unsubscribe_url and arguments.get("sender_identity") == charity.sender_identity and arguments.get("unsubscribe_url") == charity.unsubscribe_url),
        "recipients_eligible": bool(eligible), "soft_opt_in_valid": bool(soft_opt_in_valid),
        "campaign_approved": rule.campaign_reference in charity.approved_campaigns,
        "fund_approved": rule.fund_reference in charity.approved_funds,
        "due_diligence": bool(rule.purpose_reference in charity.approved_purposes and rule.recipient_reference and rule.due_diligence_reference),
        "financial_target_matches": arguments.get(rule.fund_field) == rule.fund_reference and arguments.get(rule.financial_recipient_field) == rule.recipient_reference,
        "value_known": rule.value_field in arguments,
        "dual_authorisation_valid": not rule.requires_dual_authorisation or bool(rule.independent_authorisation_reference),
    }
