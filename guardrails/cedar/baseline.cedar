// Maintained security floor. Dashboard choices supply trusted entity/context data.
@id("access.permitted")
permit(principal, action, resource);

@id("access.assignment")
forbid(principal, action, resource) unless { context.assigned };

@id("access.scope")
forbid(principal, action, resource) unless { context.scope_allowed };

@id("activity.disabled")
forbid(principal, action, resource) unless { context.workflow_enabled };

@id("data.destination")
forbid(principal, action, resource) unless { context.data_allowed };

@id("tool.changed")
forbid(principal, action, resource) unless { context.schema_current };

@id("tool.arguments")
forbid(principal, action, resource) unless { context.arguments_valid };

@id("tool.update_scope")
forbid(principal, action, resource) unless { context.autonomous_update_valid };

@id("tool.value")
forbid(principal, action, resource) unless { context.value_within_limit };

@id("mode.drafts_only")
forbid(principal, action, resource)
when { context.draft_only && context.needs_review };

@id("approval.required")
forbid(principal, action == Kindred::Action::"Execute", resource)
when { context.needs_review && !context.approved };

@id("model.processing_evidence")
forbid(principal, action, resource) unless { context.provider_terms };
