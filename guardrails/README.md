# Maintained guardrails

Version 3 settings express organisation preferences. `settings.py` compiles them
into the internal `Policy` types used by gateway protections. Expert overrides
and version 1 policies remain supported. Saving an expert change stores only
the change, rather than freezing generated definitions into overrides.

Authorisation runs locally through pinned `cedarpy` bindings to the Rust Cedar
engine. The Python binding is community maintained, not an official AWS SDK:
https://github.com/k9securityio/cedar-py. No remote policy service is used.

`cedar/baseline.cedar` and `cedar/charity.cedar` define permissions and prohibitions.
The schema is validated before a bundle is used. Evaluation errors cause denial,
overriding Cedar's normal skip-on-error behaviour. Bundle content participates
in the active policy revision. Stable `@id` annotations provide audit reasons.

`facts.py` converts trusted configuration and records into typed facts; Cedar
decides permission. Identity, assignments, source labels, schemas and evidence
come from trusted adapters. Model arguments such as `approved` do not become
authorisation facts.

Only a denial for `approval.required` can lead to a separately authorised
`RequestReview`. After consuming the exact-action approval, the gateway evaluates
`Execute` again with the trusted approval fact. All other prohibitions still apply.
`Discover` supports assignment checks and never grants execution permission.

Validation, redaction, transport restrictions, authentication, cancellation,
quotas and atomic token reservations remain application controls. Cedar is
stateless; checking a balance does not replace atomically reserving it. Input
and capped output tokens are reserved per attempt; reported prompt/completion
usage replaces the reservation. Completion usage already includes reasoning.
Uncertain calls keep their reservation. SQLite migration preserves historical
financial columns but does not invent token usage for past monetary records.
SDK retries cannot make additional unreserved dispatches.

Curated capabilities include installed Masterbrand handlers and known searches
from the exact pinned Brave command. Arbitrary MCP annotations and HTTP methods
cannot grant access. Other tools need a short review that pins their definition
automatically. Execution checks the live definition. Turning a capability off
also restricts curated defaults.

No pricing or currency metadata is fetched. Managed model definitions pin the
configured endpoint and routing, independently of token limits. Version 2
preferences drop old pricing snapshots when read and save as version 3. Pounds
are never interpreted as tokens: the monthly default is 1,000,000 tokens, with
an explicit old off switch preserved. Scope restrictions can tighten per-run
limits. Financial-action GBP value restrictions remain independent controls.

The UK pack provides common operational controls and guidance for selected
jurisdictions. It does not infer consent, donor capacity, safeguarding risk,
campaign legality or due diligence. Real CRM/payment evidence adapters are
extension work; built-ins cover public research and organisation context.
Enabling an activity cannot substitute for real evidence.

Run all tests without paid inference:

```sh
LITELLM_LOCAL_MODEL_COST_MAP=True uv run pytest tests -q
```

Tests cover actual Cedar evaluation, forbid precedence, errors, approvals,
migration, token limits, missing usage, unknown integrations and browser flows.
