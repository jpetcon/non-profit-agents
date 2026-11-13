// UK common controls. Jurisdiction packs add guidance/review requirements.
// Evidence is supplied by trusted adapters, never by model-generated claims.
@id("charity.purpose")
forbid(principal, action, resource)
when { (resource.workflow == "fundraising" || resource.workflow == "campaigning" || resource.workflow == "financial" || resource.workflow == "gift_aid" || resource.classification == "financial") && resource.classification != "draft" && resource.classification != "read" }
unless { context.purpose_approved };

@id("charity.marketing_evidence")
forbid(principal, action, resource)
when { resource.workflow == "fundraising" && resource.classification != "draft" && resource.classification != "read" }
unless { context.has_recipients && context.sender_matches };

@id("charity.suppression")
forbid(principal, action, resource)
when { resource.workflow == "fundraising" && resource.classification != "draft" && resource.classification != "read" }
unless { context.recipients_eligible };

@id("charity.soft_opt_in")
forbid(principal, action, resource)
when { resource.workflow == "fundraising" && resource.classification != "draft" && resource.classification != "read" }
unless { context.soft_opt_in_valid };

@id("charity.campaign")
forbid(principal, action, resource)
when { resource.workflow == "campaigning" && resource.classification != "draft" && resource.classification != "read" }
unless { context.campaign_approved };

@id("charity.financial_evidence")
forbid(principal, action, resource)
when { (resource.classification == "financial" || resource.workflow == "financial" || resource.workflow == "gift_aid") && resource.classification != "draft" && resource.classification != "read" }
unless { context.fund_approved && context.due_diligence };

@id("charity.financial_target")
forbid(principal, action, resource)
when { (resource.classification == "financial" || resource.workflow == "financial" || resource.workflow == "gift_aid") && resource.classification != "draft" && resource.classification != "read" }
unless { context.financial_target_matches };

@id("charity.financial_value")
forbid(principal, action, resource)
when { resource.classification == "financial" }
unless { context.value_known };

@id("charity.dual_authorisation")
forbid(principal, action, resource) unless { context.dual_authorisation_valid };
