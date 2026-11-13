"""Persistent transcripts and one cancellable ADK run at a time."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import sqlite3
import uuid

from .security import safe_markdown
from .activity import ActivityTracker
from .store import Conflict
from agents.config import AppConfig
from .issues import error_issue, ResponseTruncated


class Chat:
    def __init__(self, store, backend=None):
        self.store, self.backend = store, backend
        from guardrails.runtime import Runtime
        self.guardrails = Runtime(store.root)
        self.run_id = None
        self.path = store.local / "conversations.sqlite"
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS conversations (id TEXT PRIMARY KEY, agent TEXT, title TEXT, revision TEXT, created TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, conversation TEXT, payload TEXT)")
            db.execute('CREATE TABLE IF NOT EXISTS chat_sessions (conversation TEXT, session TEXT, PRIMARY KEY(conversation,session))')
            columns = {row[1] for row in db.execute("PRAGMA table_info(conversations)")}
            for column in ["team", "team_name", "agent_name", "data_class"]:
                if column not in columns:
                    db.execute(f"ALTER TABLE conversations ADD COLUMN {column} TEXT")
            if 'context_after' not in columns:
                db.execute('ALTER TABLE conversations ADD COLUMN context_after INTEGER NOT NULL DEFAULT 0')
            if 'session_id' not in columns:
                db.execute('ALTER TABLE conversations ADD COLUMN session_id TEXT')
            legacy = db.execute("SELECT id,agent,revision FROM conversations WHERE team IS NULL").fetchall()
            if legacy:
                try:
                    config = AppConfig.model_validate(store.agents())
                except (ValueError, OSError):
                    config = None
                for row in legacy:
                    team = config.team_for_agent(row["agent"]) if config and row["agent"] in config.agents else ""
                    agent_name = (config.agents[row["agent"]].display_name if config and row["agent"] in config.agents else "") or row["agent"].replace("_", " ").title()
                    team_name = config.teams[team].display_name if team else "Previous team"
                    db.execute("UPDATE conversations SET team=?,team_name=?,agent_name=? WHERE id=?", (team, team_name, agent_name, row["id"]))
                    if team and row["revision"] == store.agent_revision():
                        db.execute("UPDATE conversations SET revision=? WHERE id=?", (store.agent_revision(team), row["id"]))
        os.chmod(self.path, 0o600)
        self.active = None
        self.active_id = None
        self.sessions = None

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def list(self):
        with self.db() as db:
            return [dict(row) for row in db.execute("SELECT * FROM conversations ORDER BY created DESC")]

    def get(self, conversation):
        with self.db() as db:
            row = db.execute("SELECT * FROM conversations WHERE id=?", (conversation,)).fetchone()
            if row is None:
                raise ValueError("This conversation no longer exists.")
            result = dict(row)
            result["messages"] = [json.loads(r[0]) for r in db.execute("SELECT payload FROM messages WHERE conversation=? ORDER BY id", (conversation,))]
            for message in result["messages"]:
                if message.get("type") == "error" and "issue" not in message:
                    message["issue"] = error_issue(ValueError(message.get("text", "")))
                    message["text"] = message["issue"]["message"]
            config = AppConfig.model_validate(self.store.agents())
            result['outdated'] = result.get('team') not in config.teams or result['agent'] not in config.agents or config.team_for_agent(result['agent']) != result.get('team')
            result['settings_changed'] = result['revision'] != self.store.agent_revision(result.get('team') or None)
            return result

    def create(self, agent=None, team=None, data_class="public"):
        config = AppConfig.model_validate(self.store.agents())
        if agent is not None and agent not in config.agents:
            raise ValueError("Choose an existing agent.")
        team = team or (config.team_for_agent(agent) if agent else config.default_team)
        if team not in config.teams:
            raise ValueError("Choose an existing team.")
        agent = agent or config.teams[team].root
        if agent not in config.team_members(team):
            raise ValueError("Choose an agent from the selected team.")
        conversation = uuid.uuid4().hex
        if data_class not in {"public", "personal", "sensitive"}:
            raise ValueError("Choose a valid conversation data class.")
        with self.db() as db:
            db.execute("INSERT INTO conversations(id,agent,title,revision,created,team,team_name,agent_name) VALUES (?,?,?,?,?,?,?,?)", (conversation, agent, "New conversation", self.store.agent_revision(team), datetime.now(timezone.utc).isoformat(), team, config.teams[team].display_name, config.agents[agent].display_name or agent.replace("_", " ").title()))
            db.execute("UPDATE conversations SET data_class=? WHERE id=?", (data_class, conversation))
        return self.get(conversation)

    def append(self, conversation, payload):
        payload = self.store.redact(payload)
        with self.db() as db:
            db.execute("INSERT INTO messages(conversation,payload) VALUES (?,?)", (conversation, json.dumps(payload)))

    def context_messages(self, conversation):
        with self.db() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT payload FROM messages WHERE conversation=? AND id>? ORDER BY id', (conversation['id'], conversation.get('context_after') or 0))]

    def reset_context(self, conversation_id):
        """Keep the transcript, but never reuse the earlier ADK session/context."""
        if self.active and not self.active.done():
            raise Conflict('Finish or stop the current response before clearing its context.')
        conversation = self.get(conversation_id)
        if conversation['outdated']:
            raise Conflict('This conversation’s original team or agent is no longer available.')
        self.guardrails.revoke_conversation(conversation_id)
        session_id = uuid.uuid4().hex
        notice = self.store.redact({'type':'notice', 'text':'Earlier messages remain saved for reference. Future requests use only the conversation from this point onward.'})
        with self.db() as db:
            boundary = db.execute('SELECT COALESCE(MAX(id),0) FROM messages WHERE conversation=?', (conversation_id,)).fetchone()[0]
            for saved_session in [conversation.get('session_id') or conversation_id, session_id]:
                db.execute('INSERT OR IGNORE INTO chat_sessions VALUES (?,?)', (conversation_id, saved_session))
            db.execute('UPDATE conversations SET context_after=?,session_id=? WHERE id=?', (boundary, session_id, conversation_id))
            db.execute('INSERT INTO messages(conversation,payload) VALUES (?,?)', (conversation_id,json.dumps(notice)))
        return self.get(conversation_id)

    async def delete(self, conversation):
        if self.active_id == conversation:
            raise Conflict("Stop the current response before deleting this conversation.")
        if self.sessions is None and (self.store.local / "adk.sqlite").exists():
            self.session_service()
        saved = self.get(conversation)
        with self.db() as db:
            session_ids = {row[0] for row in db.execute('SELECT session FROM chat_sessions WHERE conversation=?',(conversation,))} | {conversation, saved.get('session_id') or conversation}
        if self.sessions:
            for session_id in session_ids:
                await self.sessions.delete_session(app_name="non_profit_agents", user_id="local", session_id=session_id)
        with self.db() as db:
            db.execute("DELETE FROM messages WHERE conversation=?", (conversation,))
            db.execute("DELETE FROM conversations WHERE id=?", (conversation,))
            db.execute('DELETE FROM chat_sessions WHERE conversation=?',(conversation,))

    def session_service(self):
        if self.sessions is None:
            from google.adk.sessions import DatabaseSessionService
            self.sessions = DatabaseSessionService(db_url=f"sqlite+aiosqlite:///{self.store.local / 'adk.sqlite'}")
        return self.sessions

    async def adk(self, conversation, prompt):
        # Imports are deliberately delayed until a user explicitly sends a message.
        from google.adk.runners import Runner
        from google.adk.agents.run_config import RunConfig, StreamingMode
        from google.genai import types
        from agents.agent_factory import AgentFactory
        from models.model_registry import Models
        from tools.tool_registry import ToolRegistry
        self.session_service()
        config = self.store.agents()
        selected = {}
        def collect(name):
            selected[name] = config["agents"][name]
            for child in selected[name]["sub_agents"]:
                collect(child)
        collect(conversation["agent"])
        config = {"root": conversation["agent"], "agents": selected}
        gateway = self.store.tools()["gateway"]
        run = self.run_id or self.guardrails.start_run(conversation["id"], conversation["team"], conversation.get("data_class") or "public")
        tokens = {}
        def credential(agent, audience):
            key = (agent, audience)
            if key not in tokens:
                tokens[key] = self.guardrails.issue(run, agent, audience)
            return tokens[key]
        tools = ToolRegistry(f"http://{gateway['host']}:{gateway['port']}/mcp", credential_provider=credential, revision_provider=lambda: self.guardrails.policy().revision)
        for agent_name, spec in selected.items():
            if spec.get("tools"):
                await tools.validate_available(spec["tools"], agent=agent_name)
        models = Models(self.store.root / "models/model_config.yml", credential_provider=credential)
        agent = AgentFactory(self.store.agents_path, models, tools, config_data=config).build()
        runner = Runner(app_name="non_profit_agents", agent=agent, session_service=self.sessions)
        session_id = conversation.get('session_id') or conversation['id']
        with self.db() as db:
            db.execute('INSERT OR IGNORE INTO chat_sessions VALUES (?,?)',(conversation['id'],session_id))
        try:
            session = await self.sessions.get_session(app_name="non_profit_agents", user_id="local", session_id=session_id)
            if session is None:
                await self.sessions.create_session(app_name="non_profit_agents", user_id="local", session_id=session_id)
            activity = ActivityTracker()
            async for event in runner.run_async(user_id="local", session_id=session_id, new_message=types.Content(role="user", parts=[types.Part(text=prompt)]), run_config=RunConfig(streaming_mode=StreamingMode.SSE, max_llm_calls=30)):
                for entry in activity.events(event):
                    yield entry
                text = "".join(part.text for part in (event.content.parts if event.content else []) or [] if part.text and not part.thought)
                if text:
                    if event.partial:
                        yield {"type": "delta", "text": text}
                    else:
                        yield {"type": "answer", "text": text, "agent": event.author}
                if event.error_code == types.FinishReason.MAX_TOKENS or event.finish_reason == types.FinishReason.MAX_TOKENS:
                    raise ResponseTruncated()
                if event.error_message:
                    raise ValueError(event.error_message)
        finally:
            await runner.close()
            self.guardrails.revoke(run)

    def start(self, conversation_id, prompt):
        if self.active and not self.active.done():
            raise Conflict("One response can run at a time. Stop it before starting another.")
        conversation = self.get(conversation_id)
        if conversation["outdated"]:
            raise Conflict('This conversation’s original team or agent is no longer available.')
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > 32000:
            raise ValueError("Enter a message of up to 32,000 characters.")
        policy = self.guardrails.policy()
        identity = {'team': conversation['team'], 'agent': conversation['agent'], 'data_class': conversation.get('data_class') or 'public'}
        limits = policy.effective(identity)
        # A cleaned new draft must never cause an old personal record to be
        # resent from the saved conversation or ADK session.
        from guardrails.policy import PolicyDenied
        try:
            history = [m.get('text', '') for m in self.context_messages(conversation) if m['type'] in {'user', 'answer'}]
            _, changed = self.guardrails.inspect(history, limits, output=True, identity=identity)
            if changed:
                raise PolicyDenied('data.history', 'The earlier context needs removal.')
        except PolicyDenied as error:
            denied = PolicyDenied('data.history', 'Review the current policy or continue without the earlier context.')
            self.guardrails.denial(identity, denied)
            raise denied from error
        try:
            prompt, _ = self.guardrails.inspect(prompt, limits, identity=identity)
        except PolicyDenied as error:
            self.guardrails.denial(identity, error)
            raise
        self.run_id = self.guardrails.start_run(conversation_id, conversation["team"], conversation.get("data_class") or "public")
        conversation = {**conversation, 'messages':self.context_messages(conversation)}
        queue = asyncio.Queue()
        self.append(conversation_id, {"type": "user", "text": prompt})
        with self.db() as db:
            db.execute("UPDATE conversations SET title=? WHERE id=? AND title='New conversation'", (self.store.redact(prompt[:70]), conversation_id))
            db.execute('UPDATE conversations SET revision=? WHERE id=?',(self.store.agent_revision(conversation['team']),conversation_id))

        async def work():
            partial, activity = "", []
            async def finish_partial():
                nonlocal partial
                if partial:
                    text, _ = self.guardrails.inspect(partial, limits, output=True, identity=identity)
                    answer = {"type": "answer", "text": text, "html": safe_markdown(text)}
                    self.append(conversation_id, answer)
                    await queue.put(answer)
                    partial = ""
            try:
                await queue.put({"type": "activity", "label": "Checking gateway policy and validating responses before release", "kind": "guardrail"})
                backend = self.backend or self.adk
                async for raw in backend(conversation, prompt):
                    event = raw
                    if event["type"] == "delta":
                        partial += event.get("text", "")
                        if len(partial.encode()) > limits.max_output_bytes:
                            raise PolicyDenied('payload.size', 'The buffered response exceeds its size limit.')
                        # A fragment may be only half a secret/contact detail.
                        # Hold it until the complete response can be checked.
                        continue
                    event, _ = self.guardrails.inspect(event, limits, output=True, identity=identity)
                    if event["type"] == "answer":
                        event["html"] = safe_markdown(event["text"])
                        self.append(conversation_id, event)
                        partial = ""
                    elif event["type"] == "activity":
                        activity.append(event)
                        self.append(conversation_id, event)
                    await queue.put(event)
                await finish_partial()
            except asyncio.CancelledError:
                event = {"type": "notice", "text": "Response stopped."}
                self.append(conversation_id, event)
                await queue.put(event)
            except Exception as error:
                if isinstance(error, ResponseTruncated):
                    try:
                        # The terminal limit signal makes this the last text
                        # available. Apply the same output checks as a complete
                        # answer before retaining or releasing any fragments.
                        await finish_partial()
                    except Exception as output_error:
                        error = output_error
                if isinstance(error, PolicyDenied):
                    self.guardrails.denial({**identity, 'run':self.run_id or ''}, error)
                problem = error_issue(error)
                event = {"type": "notice" if isinstance(error, ResponseTruncated) else "error", "text": problem["message"], "issue": problem}
                self.append(conversation_id, event)
                await queue.put(event)
            finally:
                if self.run_id:
                    self.guardrails.revoke(self.run_id)
                    self.run_id = None
                await queue.put({"type": "done"})
                self.active_id = None
        self.active_id = conversation_id
        self.active = asyncio.create_task(work())
        return queue

    async def cancel(self):
        if self.active and not self.active.done():
            self.active.cancel()
            await self.active

    async def close(self):
        await self.cancel()
        if self.sessions:
            await self.sessions.close()
