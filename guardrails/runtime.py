"""Cross-process enforcement state; transactions serialize permission and cost checks."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from zoneinfo import ZoneInfo

import jsonschema
import yaml

from .policy import Decision, Policy, PolicyDenied, canonical, digest


def money(value):
    return int((Decimal(str(value)) * 1_000_000).to_integral_value(rounding=ROUND_CEILING))


def periods(now=None):
    local = datetime.fromtimestamp(time.time() if now is None else now, ZoneInfo("Europe/London"))
    return local.strftime("%Y-%m-%d"), local.strftime("%Y-%m")


def tool_hash(name, description, input_schema, output_schema=None):
    return digest([name, description or "", input_schema, output_schema])


class Runtime:
    def __init__(self, root, *, secret_resolver=None):
        self.root = Path(root).resolve()
        self.path = self.root / ".local/guardrails.sqlite"
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.secret_resolver = secret_resolver
        # Payloads exist only in the live gateway process. The DB holds safe previews.
        self.pending_payloads = {}
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS flags (name TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, conversation TEXT, team TEXT, data_class TEXT, revoked INTEGER DEFAULT 0, created REAL);
                CREATE TABLE IF NOT EXISTS credentials (hash TEXT PRIMARY KEY, run TEXT, agent TEXT, audience TEXT, role TEXT, expires REAL);
                CREATE TABLE IF NOT EXISTS calls (id TEXT PRIMARY KEY, run TEXT, agent TEXT, kind TEXT, name TEXT, signature TEXT, created REAL, day TEXT, month TEXT, reserved INTEGER, reported INTEGER, state TEXT, price_revision TEXT);
                CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, run TEXT, agent TEXT, binding TEXT, revision TEXT, owner TEXT, expires REAL, status TEXT, preview TEXT);
                CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, created REAL, run TEXT, agent TEXT, team TEXT, revision TEXT, action TEXT, rule TEXT, name TEXT, duration_ms INTEGER);
                CREATE INDEX IF NOT EXISTS calls_day ON calls(day);
                CREATE INDEX IF NOT EXISTS calls_run ON calls(run);
            """)
        # Keep historical financial records; token counters start independently.
        # BEGIN IMMEDIATE serialises migrations across the app and both gateways.
        with self.db() as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(calls)")}
            for name, declaration in [("reserved_tokens", "INTEGER NOT NULL DEFAULT 0"), ("reported_tokens", "INTEGER"), ("input_tokens", "INTEGER"), ("output_tokens", "INTEGER")]:
                if name not in columns:
                    db.execute(f"ALTER TABLE calls ADD COLUMN {name} {declaration}")
            db.execute("INSERT OR IGNORE INTO flags VALUES ('token_tracking_started',?)", (str(time.time()),))

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def policy(self):
        try:
            from .settings import load_policy
            return load_policy(self.root)
        except Exception:
            raise PolicyDenied("policy.invalid", "Guardrail configuration is invalid; restore a valid policy.") from None

    def start_run(self, conversation, team, data_class="public"):
        if data_class not in {"public", "personal", "sensitive"}:
            raise PolicyDenied("data.class", "Choose a recognised data class.")
        self.policy()
        run = secrets.token_hex(16)
        with self.db() as db:
            if db.execute("SELECT 1 FROM flags WHERE name='stopped' AND value='1'").fetchone():
                raise PolicyDenied("runtime.stopped", "Emergency stop is active. Resume from Guardrails.")
            db.execute("INSERT INTO runs(id,conversation,team,data_class,created) VALUES (?,?,?,?,?)", (run, conversation, team, data_class, time.time()))
        return run

    def issue(self, run, agent, audience, *, role="agent", ttl=3600):
        if audience not in {"tools", "inference"} or role not in {"agent", "admin"}:
            raise ValueError("Invalid credential scope.")
        token = "gr_" + secrets.token_urlsafe(32)
        with self.db() as db:
            row = db.execute("SELECT * FROM runs WHERE id=? AND revoked=0", (run,)).fetchone()
            if not row:
                raise PolicyDenied("auth.run", "The run is no longer active.")
            db.execute("INSERT INTO credentials VALUES (?,?,?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), run, agent, audience, role, time.time() + min(ttl, 3600)))
        return token

    def authenticate(self, token, audience):
        with self.db() as db:
            row = db.execute("SELECT c.*,r.conversation,r.team,r.data_class,r.revoked FROM credentials c JOIN runs r ON r.id=c.run WHERE c.hash=?", (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if not row or row["audience"] != audience or row["expires"] <= time.time() or row["revoked"]:
                raise PolicyDenied("auth.invalid", "A valid scoped gateway credential is required.")
            if row["role"] != "admin" and db.execute("SELECT 1 FROM flags WHERE name='stopped' AND value='1'").fetchone():
                raise PolicyDenied("runtime.stopped", "Emergency stop is active.")
            return dict(row)

    def active(self, identity):
        with self.db() as db:
            row = db.execute("SELECT revoked FROM runs WHERE id=?", (identity["run"],)).fetchone()
            stopped = db.execute("SELECT 1 FROM flags WHERE name='stopped' AND value='1'").fetchone()
            if not row or row[0] or (stopped and identity.get("role") != "admin") or identity.get("expires", 0) <= time.time():
                raise PolicyDenied("auth.revoked", "The run expired or was stopped.")

    async def guarded(self, identity, operation, timeout):
        """Cancel in-flight IO promptly when another process revokes a run."""
        task = asyncio.ensure_future(operation)
        try:
            deadline = time.monotonic() + timeout
            while not task.done():
                self.active(identity)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PolicyDenied("resource.timeout", "The operation exceeded its execution deadline.")
                await asyncio.wait({task}, timeout=min(.1, remaining))
            self.active(identity)
            return await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def revoke(self, run):
        with self.db() as db:
            db.execute("UPDATE runs SET revoked=1 WHERE id=?", (run,))
            db.execute("UPDATE approvals SET status='cancelled',preview='{}' WHERE run=? AND status IN ('pending','approved')", (run,))

    def revoke_conversation(self, conversation):
        """A context reset cannot revive an earlier credential or approval."""
        with self.db() as db:
            db.execute('UPDATE runs SET revoked=1 WHERE conversation=?',(conversation,))
            db.execute("UPDATE approvals SET status='cancelled',preview='{}' WHERE run IN (SELECT id FROM runs WHERE conversation=?) AND status IN ('pending','approved')",(conversation,))

    def stop(self, stopped=True):
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO flags VALUES ('stopped',?)", ("1" if stopped else "0",))
            if stopped:
                db.execute("UPDATE runs SET revoked=1 WHERE id IN (SELECT run FROM credentials WHERE role='agent')")
                db.execute("UPDATE approvals SET status='cancelled',preview='{}' WHERE status IN ('pending','approved')")

    def admin_token(self, audience):
        # Only trusted local code may mint this. The browser never receives it.
        run = secrets.token_hex(16)
        with self.db() as db:
            db.execute("INSERT INTO runs(id,conversation,team,data_class,created) VALUES (?,?,?,?,?)", (run, "diagnostics", "", "public", time.time()))
        return self.issue(run, "", audience, role="admin", ttl=60)

    def assigned(self, identity, *, tool="", model=""):
        if identity.get("role") == "admin":
            raise PolicyDenied("auth.admin_execution", "Administrative credentials cannot execute agent operations.")
        from agents.config import AppConfig
        config = AppConfig.model_validate(yaml.safe_load((self.root / "agents/config.yml").read_text()))
        agent = config.agents.get(identity["agent"])
        if not agent or config.team_for_agent(identity["agent"]) != identity["team"]:
            raise PolicyDenied("auth.agent", "The agent does not belong to this team.")
        if tool and tool not in agent.tools:
            from .authorizer import authorise
            raise authorise(identity, tool, action="Discover", assigned=False)
        if model:
            registry = yaml.safe_load((self.root / "models/model_config.yml").read_text())["models"]
            if model not in {registry[n]["model_type"] for n in agent.models}:
                from .authorizer import authorise
                raise authorise(identity, model, kind="model", action="Discover", assigned=False)
        from .authorizer import authorise
        denied = authorise(identity, tool or model, kind="tool" if tool else "model", action="Discover", assigned=True)
        if denied:
            raise denied

    def secret_values(self):
        from dotenv import dotenv_values
        stored = dotenv_values(self.root / ".env", interpolate=False)
        values = [v for v in stored.values() if v]
        from tools.mcp_auth import credential_secrets
        values.extend(credential_secrets(self.root))
        values.extend(v for k, v in os.environ.items() if v and (k.endswith(("_KEY", "_TOKEN", "_SECRET", "_PASSWORD")) or k.startswith("LITELLM_")))
        return sorted(set(v for v in values if len(v) >= 6), key=len, reverse=True)

    def inspect(self, value, limits, *, output=False, identity=None):
        """Validate all fields and scan all scalar strings before any persistence."""
        import re
        from .validation import contact_spans, payment_spans, field_name, inspection_text, PERSONAL_FIELDS, PAYMENT_FIELDS, SECRET, strict_json
        try:
            encoded = canonical(value)
            size = len(encoded.encode())
        except (ValueError, TypeError, RecursionError, UnicodeError):
            raise PolicyDenied("validation.invalid", "The payload must contain valid, finite JSON values.") from None
        if size > (limits.max_output_bytes if output else limits.max_input_bytes):
            raise PolicyDenied("payload.size", "The payload exceeds the configured size limit.")
        secret_values = self.secret_values()
        public = not identity or identity.get("data_class", "public") == "public"
        blocked_fields = {field_name(f) for f in limits.blocked_fields}
        field_labels = [re.compile(r'(?<!\w)' + r'[ _-]*'.join(re.escape(part) for part in re.split(r'[_\s-]+', f.strip())) + r'\s*[:=]', re.I) for f in limits.blocked_fields if f.strip()]
        changed = False
        def scan(text):
            text = inspection_text(text)
            if re.search(r"gr_[A-Za-z0-9_-]{43}", text):
                raise PolicyDenied("data.credential", "A scoped gateway credential was detected in content.")
            if any(s in text for s in secret_values) or SECRET.search(text):
                raise PolicyDenied("data.secret", "A secret was detected in content.")
            if any(re.search(p, text) for p in limits.blocked_patterns):
                raise PolicyDenied("data.pattern", "Content matches a prohibited data pattern.")
            if payment_spans(text):
                raise PolicyDenied('data.output' if output else 'data.payment', 'Payment details cannot be sent to models or tools.')
            if any(pattern.search(text) for pattern in field_labels):
                raise PolicyDenied('data.field', 'A prohibited labelled field is present.')
            contacts = contact_spans(text)
            if 'ninumber' in blocked_fields and any(kind == 'national_insurance' for _, _, kind in contacts):
                raise PolicyDenied('data.field', 'A prohibited government identifier is present.')
            if public and contacts:
                raise PolicyDenied("data.output" if output else "data.personal", "Recognisable personal or contact details need removal or an authorised data workflow.")
            # Structured records embedded in prose/code fences must not evade
            # field checks just because the whole string is not a JSON object.
            for match in re.finditer(r'"([^"\n]{1,80})"\s*:', text):
                try:
                    key = strict_json('"' + match[1] + '"')
                except ValueError:
                    continue
                if field_name(key) in PAYMENT_FIELDS:
                    raise PolicyDenied('data.output' if output else 'data.payment', 'A protected payment-data field is present.')
                if field_name(key) in blocked_fields:
                    raise PolicyDenied("data.field", "A prohibited structured field is present.")
                if public and field_name(key) in PERSONAL_FIELDS:
                    raise PolicyDenied('data.output' if output else 'data.personal', 'An embedded personal-data field needs an authorised workflow.')
        def walk(item, depth=0):
            nonlocal changed
            if depth > limits.max_depth:
                raise PolicyDenied("payload.depth", "The payload exceeds the configured nesting limit.")
            if isinstance(item, dict):
                if any(field_name(k) in PAYMENT_FIELDS for k in item):
                    raise PolicyDenied('data.output' if output else 'data.payment', 'A protected payment-data field is present.')
                if any(field_name(k) in blocked_fields for k in item):
                    raise PolicyDenied("data.field", "A prohibited structured field is present.")
                if public and any(field_name(k) in PERSONAL_FIELDS and v is not None and v != "" for k, v in item.items()):
                    raise PolicyDenied("data.output" if output else "data.personal", "A personal-data field needs an authorised data workflow.")
                result = {}
                for k, v in item.items():
                    if walk(k, depth + 1) != k:
                        raise PolicyDenied("data.field", "Redaction cannot rename structured fields.")
                    result[k] = walk(v, depth + 1)
                return result
            if isinstance(item, list):
                if item and all(isinstance(v, dict) and v.get("type") == "text" and isinstance(v.get("text"), str) for v in item):
                    scan(''.join(v['text'] for v in item))
                return [walk(v, depth + 1) for v in item]
            if type(item) is int and 13 <= len(str(item)) <= 19 and payment_spans(str(item)):
                raise PolicyDenied('data.output' if output else 'data.payment', 'A payment card number was detected in a numeric value.')
            if isinstance(item, str):
                scan(item)
                # Tool JSON may arrive inside a text block or function arguments.
                if item.lstrip().startswith(("{", "[")):
                    try:
                        parsed = strict_json(item)
                    except ValueError:
                        parsed = None
                    if isinstance(parsed, (dict, list)):
                        updated = walk(parsed, depth + 1)
                        if updated != parsed:
                            item = canonical(updated)
                for pattern in limits.redact_patterns:
                    updated = re.sub(pattern, "[REDACTED]", item)
                    changed |= updated != item
                    item = updated
            return item
        result = walk(value)
        return result, changed

    def data_allowed(self, identity, approved, rule):
        from .authorizer import authorise
        denied = authorise(identity, rule, data_allowed=identity["data_class"] in approved)
        if denied:
            raise denied

    def authorise_model(self, identity, name, rule):
        from .authorizer import authorise
        policy = self.policy()
        personal = identity["data_class"] != "public"
        enabled = not personal or policy.profile.get("activities", {}).get("beneficiary_data", not policy.profile.get("managed"))
        denied = authorise(identity, name, kind="model", data_allowed=identity["data_class"] in rule.approved_data_classes, workflow_enabled=enabled, provider_terms=not personal or bool(rule.purpose and rule.provider_terms_reference and rule.transfer_reference))
        if denied:
            raise denied

    def evaluate_tool(self, identity, name, arguments, schema_hash=None, *, approved=False):
        policy = self.policy()
        limits = policy.effective(identity, tool=name)
        rule = policy.tools.get(name)
        if not rule:
            raise PolicyDenied("tool.unreviewed", "Review and classify this tool in Guardrails before using it.")
        jsonschema.validate(arguments, rule.input_schema)
        clean, changed = self.inspect(arguments, limits, identity=identity)
        jsonschema.validate(clean, rule.input_schema)
        if rule.idempotency_field and (not isinstance(clean.get(rule.idempotency_field), str) or not 1 <= len(clean[rule.idempotency_field]) <= 128):
            raise PolicyDenied("tool.idempotency", "This action requires a bounded downstream idempotency key.")
        from .facts import tool_facts
        from .authorizer import authorise
        facts = tool_facts(policy, identity, name, clean, rule, limits, schema_hash, approved)
        denied = authorise(identity, name, classification=rule.classification, workflow=rule.charity_workflow, **facts)
        if denied and denied.rule == "approval.required":
            review_denial = authorise(identity, name, classification=rule.classification, workflow=rule.charity_workflow, action="RequestReview", **facts)
            if review_denial:
                raise review_denial
            decision = Decision(action="require_approval", rule="approval.required", explanation=str(denied), revision=policy.revision)
        elif denied:
            raise denied
        else:
            decision = Decision(action="redact" if changed else "allow", rule="data.redacted" if changed else "access.permitted", explanation="The maintained policies permit this action.", revision=policy.revision)
        return decision, clean, limits, rule

    def record(self, identity, decision, name="", duration_ms=0):
        with self.db() as db:
            db.execute("INSERT INTO events(created,run,agent,team,revision,action,rule,name,duration_ms) VALUES (?,?,?,?,?,?,?,?,?)", (time.time(), identity.get("run", ""), identity.get("agent", ""), identity.get("team", ""), decision.revision, decision.action, decision.rule, name, duration_ms))
            db.execute("DELETE FROM events WHERE created<?", (time.time() - self.policy().audit_retention_days * 86400,))

    def denial(self, identity, error, name=""):
        self.record(identity, Decision(action="block", rule=getattr(error, "rule", "validation.invalid"), explanation="The gateway rejected this operation.", revision=self.policy().revision), name)

    def remaining_tokens(self, identity, limits):
        """Read shared budgets before choosing a request's output reservation.

        reserve() repeats the checks in its dispatch transaction, so concurrent
        requests cannot overspend this advisory snapshot.
        """
        self.active(identity)
        budget = self.policy().token_limits
        if not all([budget.per_run, budget.daily, budget.monthly]):
            raise PolicyDenied('tokens.setup', 'Choose a monthly token allowance to enable AI responses.')
        day, month = periods()
        run_limit = min(budget.per_run, limits.max_tokens_per_run) if limits.max_tokens_per_run else budget.per_run
        result = {}
        with self.db() as db:
            for label, clause, args, maximum in [('run', 'run=?', (identity['run'],), run_limit), ('day', 'day=?', (day,), budget.daily), ('month', 'month=?', (month,), budget.monthly)]:
                used = db.execute(f"SELECT COALESCE(SUM(MAX(reserved_tokens,COALESCE(reported_tokens,0))),0) FROM calls WHERE kind='inference' AND {clause}", args).fetchone()[0]
                result[label] = maximum - used
        return result

    def reserve(self, identity, kind, name, signature, cost_gbp, limits, price_revision="", *, tokens=0):
        self.active(identity)
        cost = money(cost_gbp)
        policy = self.policy()
        day, month = periods()
        call = secrets.token_hex(16)
        with self.db() as db:
            # Revocation is checked again within the same transaction as dispatch accounting.
            if not db.execute("SELECT 1 FROM runs WHERE id=? AND revoked=0", (identity["run"],)).fetchone() or db.execute("SELECT 1 FROM flags WHERE name='stopped' AND value='1'").fetchone():
                raise PolicyDenied("auth.revoked", "The run was stopped.")
            count = db.execute("SELECT COUNT(*) FROM calls WHERE run=? AND kind=?", (identity["run"], kind)).fetchone()[0]
            if count >= (limits.max_tool_calls if kind == "tool" else limits.max_inference_attempts):
                raise PolicyDenied("resource.calls", "The run reached its call limit.")
            recent = db.execute("SELECT COUNT(*) FROM calls WHERE created>?", (time.time() - 60,)).fetchone()[0]
            if recent >= limits.max_calls_per_minute:
                raise PolicyDenied("resource.rate", "The workspace reached its calls-per-minute limit.")
            repeated = db.execute("SELECT COUNT(*) FROM calls WHERE run=? AND signature=?", (identity["run"], signature)).fetchone()[0]
            if repeated >= limits.repeat_limit:
                raise PolicyDenied("resource.repeated", "Repeated identical calls reached the configured limit.")
            if kind == "tool":
                tool = policy.tools[name]
                used = db.execute("SELECT COUNT(*) FROM calls WHERE kind='tool' AND name=? AND day=?", (name, day)).fetchone()[0]
                if used >= tool.calls_per_day:
                    raise PolicyDenied("resource.tool_quota", "This tool reached its daily quota.")
                if tool.classification not in {"read", "draft"} and db.execute("SELECT 1 FROM calls WHERE run=? AND signature=?", (identity["run"], signature)).fetchone():
                    raise PolicyDenied("tool.duplicate_action", "This consequential action has already been dispatched. Check its outcome before trying again.")
            if kind == "inference":
                if not isinstance(tokens, int) or isinstance(tokens, bool) or tokens < 1:
                    raise PolicyDenied("tokens.invalid", "A positive token reservation is required.")
                budget = policy.token_limits
                if not all([budget.per_run, budget.daily, budget.monthly]):
                    raise PolicyDenied("tokens.setup", "Choose a monthly token allowance to enable AI responses.")
                run_limit = min(budget.per_run, limits.max_tokens_per_run) if limits.max_tokens_per_run else budget.per_run
                for label, clause, args, maximum in [("run", "run=?", (identity["run"],), run_limit), ("day", "day=?", (day,), budget.daily), ("month", "month=?", (month,), budget.monthly)]:
                    used = db.execute(f"SELECT COALESCE(SUM(MAX(reserved_tokens,COALESCE(reported_tokens,0))),0) FROM calls WHERE kind='inference' AND {clause}", args).fetchone()[0]
                    if used + tokens > maximum:
                        raise PolicyDenied("tokens." + label, "This request would exceed the " + {"run": "total agent-turn", "day": "daily", "month": "monthly"}[label] + " token budget.")
            db.execute("INSERT INTO calls(id,run,agent,kind,name,signature,created,day,month,reserved,reported,state,price_revision,reserved_tokens) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (call, identity["run"], identity["agent"], kind, name, signature, time.time(), day, month, cost, None, "reserved", price_revision, tokens))
        return call

    def settle(self, call, reported_gbp=None, *, usage=None):
        input_tokens, output_tokens, reported_tokens = None, None, None
        if isinstance(usage, dict) and all(isinstance(usage.get(k), int) and not isinstance(usage[k], bool) and 0 <= usage[k] <= 1000000000 for k in ["prompt_tokens", "completion_tokens"]):
            total = usage["prompt_tokens"] + usage["completion_tokens"]
            # Completion usage already includes reasoning tokens. Never add
            # completion_tokens_details.reasoning_tokens a second time.
            declared = usage.get("total_tokens", total)
            if usage['prompt_tokens'] > 0 and isinstance(declared, int) and not isinstance(declared, bool) and total <= declared <= 1000000000:
                input_tokens, output_tokens = usage["prompt_tokens"], usage["completion_tokens"]
                reported_tokens = declared
        with self.db() as db:
            db.execute("UPDATE calls SET state='complete',reported=?,reserved=CASE WHEN ?=0 THEN reserved ELSE 0 END WHERE id=?", (None if reported_gbp is None else money(reported_gbp), int(reported_gbp is not None), call))
            if reported_tokens is not None:
                db.execute("UPDATE calls SET reported_tokens=?,input_tokens=?,output_tokens=?,reserved_tokens=0 WHERE id=?", (reported_tokens, input_tokens, output_tokens, call))

    async def approval(self, identity, name, arguments, rule, revision, preview):
        binding = digest([identity["run"], identity["agent"], name, arguments, rule.model_dump(mode="json"), revision])
        approval_id, owner = secrets.token_hex(16), str(os.getpid())
        with self.db() as db:
            db.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?)", (approval_id, identity["run"], identity["agent"], binding, revision, owner, time.time() + 300, "pending", canonical(preview)))
        self.pending_payloads[approval_id] = arguments
        try:
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                self.active(identity)
                if self.policy().revision != revision:
                    raise PolicyDenied("approval.policy_changed", "Policy changed while waiting for approval.")
                with self.db() as db:
                    row = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
                    if row["expires"] <= time.time():
                        break
                    if row["status"] == "approved":
                        db.execute("UPDATE approvals SET status='consumed',preview='{}' WHERE id=? AND status='approved'", (approval_id,))
                        return
                    if row["status"] != "pending":
                        raise PolicyDenied("approval.rejected", "The action was rejected or cancelled.")
                await asyncio.sleep(.2)
            raise PolicyDenied("approval.expired", "The approval request expired.")
        finally:
            self.pending_payloads.pop(approval_id, None)
            with self.db() as db:
                db.execute("UPDATE approvals SET status=CASE WHEN status IN ('pending','approved') THEN 'cancelled' ELSE status END,preview='{}' WHERE id=?", (approval_id,))

    def decide_approval(self, approval_id, approve):
        with self.db() as db:
            row = db.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not row or row["status"] != "pending" or row["expires"] <= time.time() or row["revision"] != self.policy().revision:
                raise PolicyDenied("approval.stale", "This approval is no longer available.")
            db.execute("UPDATE approvals SET status=? WHERE id=?", ("approved" if approve else "rejected", approval_id))

    def invalidate_pending(self):
        with self.db() as db:
            db.execute("UPDATE approvals SET status='cancelled',preview='{}' WHERE status IN ('pending','approved')")

    def summary(self):
        day, month = periods()
        with self.db() as db:
            db.execute("DELETE FROM events WHERE created<?", (time.time() - self.policy().audit_retention_days * 86400,))
            db.execute("UPDATE approvals SET status='expired',preview='{}' WHERE expires<? AND status IN ('pending','approved')", (time.time(),))
            usage = {}
            for label, clause, value in [("today", "day", day), ("month", "month", month)]:
                row = db.execute(f"SELECT COALESCE(SUM(reserved_tokens),0) AS reserved_tokens,COALESCE(SUM(reported_tokens),0) AS reported_tokens FROM calls WHERE kind='inference' AND {clause}=?", (value,)).fetchone()
                usage[label] = dict(row)
                usage[label]["used_tokens"] = sum(dict(row).values())
                usage[label]["limit"] = getattr(self.policy().token_limits, "daily" if label == "today" else "monthly")
            approvals = [dict(r) for r in db.execute("SELECT id,run,agent,revision,expires,status,preview FROM approvals WHERE status IN ('pending','approved')")]
            for row in approvals:
                row["preview"] = json.loads(row["preview"])
            events = [dict(r) for r in db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100")]
            stopped = bool(db.execute("SELECT 1 FROM flags WHERE name='stopped' AND value='1'").fetchone())
        return {"usage": usage, "approvals": approvals, "events": events, "stopped": stopped, "revision": self.policy().revision}
