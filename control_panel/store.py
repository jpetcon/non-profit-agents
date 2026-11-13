"""Validated, revision-aware configuration and write-only secret storage."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any

from dotenv import dotenv_values
from dotenv.parser import parse_stream
from pydantic import BaseModel, ConfigDict, Field
import yaml

from agents.config import AppConfig


class Conflict(ValueError):
    pass


class Brand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    organisation_name: str = ""
    mission: str = ""
    values: list[str] = Field(default_factory=list)
    strategy: str = ""
    target_audience: str = ""
    brand_voice: str = ""


def atomic_write(path: Path, content: str, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        mode = 0o600 if private else 0o644
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, mode)
        else:  # Python 3.11/3.12 on Windows do not expose fchmod.
            os.chmod(name, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    if not value or not value[0].isalpha():
        value = "agent_" + value
    return value[:64]


class Store:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.local = self.root / ".local"
        self.local.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.local, 0o700)
        self.lock = threading.RLock()
        self._expected_revision: str | None = None
        self._redactions: set[str] = set()
        self.on_change = None
        self.agents_path = self.root / "agents/config.yml"
        self.tools_path = self.root / "tools/config.yml"
        self.brand_path = self.root / "tools/custom_tools/lib/strategy.json"
        self.env_path = self.root / ".env"
        self.policy_path = self.root / "guardrails/config.yml"
        if not self.policy_path.exists():
            from guardrails.settings import Settings
            atomic_write(self.policy_path, yaml.safe_dump(Settings().model_dump(mode="json", exclude_none=True), sort_keys=False))
        if self.env_path.exists():
            os.chmod(self.env_path, 0o600)
        self.paths = [self.agents_path, self.tools_path, self.brand_path, self.env_path, self.root / "models/model_config.yml", self.root / "inference/litellm-config.yml", self.policy_path]

    def yaml(self, path: str | Path) -> dict:
        path = Path(path)
        if not path.is_absolute():
            path = self.root / path
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{path.name} must contain a configuration object.")
        return value

    def revision(self) -> str:
        digest = hashlib.sha256()
        for path in self.paths:
            digest.update(str(path.relative_to(self.root)).encode())
            digest.update(path.read_bytes() if path.exists() else b"<missing>")
        return digest.hexdigest()

    def agent_revision(self, team: str | None = None) -> str:
        digest = hashlib.sha256()
        if team:
            config = AppConfig.model_validate(self.agents())
            if team not in config.teams:
                return "deleted-team"
            relevant = {"team": config.teams[team].model_dump(), "agents": {name: config.agents[name].model_dump() for name in config.team_members(team)}}
            digest.update(json.dumps(relevant, sort_keys=True).encode())
        else:
            digest.update(self.agents_path.read_bytes())
        for path in [self.tools_path, self.root / "models/model_config.yml", self.root / "inference/litellm-config.yml", self.env_path, self.policy_path]:
            digest.update(path.read_bytes() if path.exists() else b"")
        return digest.hexdigest()

    def agent_label(self, name: str, config: dict | None = None) -> str:
        app = AppConfig.model_validate(config or self.agents())
        label = app.agents[name].display_name or name.replace("_", " ").title()
        return app.teams[app.team_for_agent(name)].display_name + ": " + label if len(app.teams) > 1 else label

    @contextmanager
    def edit(self, expected: str | None):
        with self.lock:
            if not expected or expected != self.revision():
                raise Conflict("Settings changed in another window or file. Reload before saving.")
            previous = self._expected_revision
            self._expected_revision = expected
            try:
                yield
            finally:
                self._expected_revision = previous

    def check_revision(self):
        if self._expected_revision is not None and self._expected_revision != self.revision():
            raise Conflict("A configuration file changed while saving. Reload before trying again.")

    def save(self, path: Path, value: dict, *, json_file: bool = False) -> None:
        self.check_revision()
        if path.exists():
            backup = self.local / "backups" / (str(path.relative_to(self.root)).replace("/", "__") + ".bak")
            atomic_write(backup, path.read_text(), private=True)
        content = json.dumps(value, indent=2, ensure_ascii=False) + "\n" if json_file else yaml.safe_dump(value, sort_keys=False, allow_unicode=True)
        atomic_write(path, content)
        self.changed(path)

    def changed(self, *paths):
        if self.on_change:
            self.on_change(*paths)

    def agents(self) -> dict:
        return AppConfig.model_validate(self.yaml(self.agents_path)).model_dump()

    def save_many(self, values: dict[Path, dict]) -> None:
        """Save related YAML files together, rolling back a failed replacement."""
        self.check_revision()
        serialized = {path: yaml.safe_dump(value, sort_keys=False, allow_unicode=True) for path, value in values.items()}
        for path, value in values.items():
            if path.name == "litellm-config.yml" and any(entry.get("litellm_params", {}).get("api_base") == "https://openrouter.ai/api/v1" for entry in value.get("model_list", [])):
                serialized[path] = "# Temporary development setting: global OpenRouter routing is enabled.\n" + serialized[path]
        self._save_contents(serialized)

    def save_with_new_secrets(self, values: dict[Path, dict], updates: dict[str, str]) -> None:
        """Publish references only after their new secrets exist; notify once.

        A crash between replacements can leave an unused secret, never a newly
        enabled connection referring to a secret that has not yet been written.
        Existing/shared secrets cannot be replaced through guided setup.
        """
        existing = self.values()
        content = self.env_path.read_text() if self.env_path.exists() else ""
        if content and not content.endswith("\n"):
            content += "\n"
        for name, value in updates.items():
            if name in existing or self.secret(name) or not re.fullmatch(r"MCP_[A-Z0-9_]{1,70}", name):
                raise ValueError("This private key reference is already in use. Try again.")
            if not isinstance(value, str) or not value or len(value) > 16384 or "\x00" in value:
                raise ValueError("Enter a non-empty API key of at most 16 KB.")
            escaped = value.replace("\\", "\\\\").replace("'", "\\'")
            content += f"{name}='{escaped}'\n"
            self._redactions.add(value)
        contents = {self.env_path: content} if updates else {}
        contents.update({p: yaml.safe_dump(v, sort_keys=False, allow_unicode=True) for p, v in values.items()})
        self._save_contents(contents, private={self.env_path})

    def _save_contents(self, serialized: dict[Path, str], *, private=frozenset()) -> None:
        self.check_revision()
        originals = {path: path.read_text() if path.exists() else None for path in serialized}
        for path, content in originals.items():
            if content is None or path in private:
                continue
            backup = self.local / "backups" / (str(path.relative_to(self.root)).replace("/", "__") + ".bak")
            atomic_write(backup, content, private=True)
        self.check_revision()
        written = []
        try:
            for path, content in serialized.items():
                atomic_write(path, content, private=path in private)
                written.append(path)
        except OSError:
            for path in reversed(written):
                if originals[path] is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic_write(path, originals[path], private=path in private)
            raise ValueError("Could not save the configuration. Previous settings were restored.") from None
        self.changed(*serialized)

    def tools(self) -> dict:
        value = self.yaml(self.tools_path)
        for section in ["custom_tools", "http_tools", "mcp_servers"]:
            value.setdefault(section, {})
        return value

    def models(self) -> dict:
        return self.yaml("models/model_config.yml")["models"]

    def brand(self) -> dict:
        raw = json.loads(self.brand_path.read_text()) if self.brand_path.exists() else {}
        return Brand.model_validate(raw).model_dump()

    def validate_agents(self, value: dict) -> dict:
        app = AppConfig.model_validate(value)
        seen: set[str] = set()
        models = set(self.models())
        tools = self.tools()
        known_tools = set(tools["custom_tools"]) | set(tools["http_tools"]) | {t["name"] for t in self.catalog()}
        # Existing remote selections can be retained while a connection is offline.
        current = self.agents() if self.agents_path.exists() else {"agents": {}}
        known_tools |= {t for agent in current["agents"].values() for t in agent.get("tools", [])}

        def visit(name: str):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
                raise ValueError("Agent identifiers must start with a letter and use letters, numbers or underscores.")
            if name in seen:
                raise ValueError(f"{name} has more than one parent or creates a loop.")
            if name not in app.agents:
                raise ValueError(f"The referenced agent {name} does not exist.")
            seen.add(name)
            agent = app.agents[name]
            if set(agent.models) - models:
                raise ValueError(f"Choose configured models for {name}.")
            if set(agent.tools) - known_tools:
                raise ValueError(f"Connect or create the selected tools for {name} first.")
            for child in agent.sub_agents:
                visit(child)
        for team in app.teams.values():
            visit(team.root)
        if seen != set(app.agents):
            raise ValueError("Every specialist needs a supervising agent connected to a team coordinator.")
        return app.model_dump()

    def values(self) -> dict[str, str]:
        return {key: value for key, value in dotenv_values(self.env_path, interpolate=False).items() if value is not None} if self.env_path.exists() else {}

    def secret(self, name: str) -> str:
        return self.values().get(name, os.environ.get(name, ""))

    def redact(self, value: Any) -> Any:
        # Snapshot once for the entire payload. Tool schemas contain thousands
        # of fields; rereading YAML and .env at every leaf stalls the dashboard.
        secrets = set(self.values().values()) | {os.environ.get(key, "") for key in self.secret_references()}
        from tools.mcp_auth import credential_secrets
        secrets.update(credential_secrets(self.root))
        self._redactions.update(v for v in secrets if v)
        redactions = sorted(self._redactions, key=len, reverse=True)
        def walk(item):
            if isinstance(item, str):
                for secret in redactions:
                    item = item.replace(secret, "[REDACTED]")
                item = re.sub(r"(?i)(Bearer\s+)[^\s\"'<>]+", r"\1[REDACTED]", item)
                return re.sub(r"gr_[A-Za-z0-9_-]{43}", "[REDACTED]", item)
            if isinstance(item, dict):
                return {key: walk(child) for key, child in item.items()}
            if isinstance(item, list):
                return [walk(child) for child in item]
            return item
        return walk(value)

    def secret_references(self) -> dict[str, list[str]]:
        references: dict[str, list[str]] = {}
        def add(key: str, label: str):
            references.setdefault(key, []).append(label)
        try:
            inference = self.yaml("inference/litellm-config.yml")
            for model in inference.get("model_list", []):
                key = model["litellm_params"].get("api_key", "")
                if key.startswith("os.environ/"):
                    add(key.split("/", 1)[1], "Model: " + model["model_name"])
            tools = self.tools()
            for name, spec in tools["mcp_servers"].items():
                for key in (spec.get("native") or {}).get("secret_refs", {}).values():
                    add(key, spec.get("display_name") or name)
                for key in spec.get("env_vars", []):
                    add(key, spec.get("display_name") or name)
                for key in spec.get("env_secrets", {}).values():
                    add(key, spec.get("display_name") or name)
                if spec.get("token_env"):
                    add(spec["token_env"], spec.get("display_name") or name)
                for key in spec.get("header_secrets", {}).values():
                    add(key, spec.get("display_name") or name)
                if (spec.get("auth") or {}).get("client_secret_env"):
                    add(spec["auth"]["client_secret_env"], spec.get("display_name") or name)
            for name, spec in tools["http_tools"].items():
                for header in spec.get("headers", []):
                    if header.get("secret"):
                        add(header["secret"], spec.get("display_name") or name)
        except (ValueError, OSError, KeyError):
            pass
        return {key: sorted(set(labels)) for key, labels in references.items()}

    def secret_metadata(self) -> list[dict]:
        refs = self.secret_references()
        names = set(self.values()) | set(refs)
        names.discard("LITELLM_PROXY_API_KEY")
        return [{"name": name, "configured": bool(self.secret(name)), "used_by": refs.get(name, []), "local_gateway": name == "LITELLM_MASTER_KEY"} for name in sorted(names)]

    def write_secrets(self, updates: dict[str, str | None]) -> None:
        self.check_revision()
        self._redactions.update(v for v in self.values().values() if v)
        reserved = {"PATH", "HOME", "USER", "SHELL", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "DEBUG"}
        for name, value in updates.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", name) or name in reserved or name.startswith("DYLD_"):
                raise ValueError("Choose a secret name such as CRM_API_KEY; system environment names are reserved.")
            if value is not None and (not value or len(value) > 16384 or "\x00" in value):
                raise ValueError("Enter a non-empty secret of at most 16 KB.")
        original = self.env_path.read_text() if self.env_path.exists() else ""
        remaining = updates.copy()
        chunks = []
        def line(name, value):
            escaped = value.replace("\\", "\\\\").replace("'", "\\'")
            return f"{name}='{escaped}'\n"
        for binding in parse_stream(io.StringIO(original)):
            if binding.key in updates:
                if binding.key in remaining:
                    value = remaining.pop(binding.key)
                    if value is not None:
                        chunks.append(line(binding.key, value))
            else:
                chunks.append(binding.original.string)
        content = "".join(chunks)
        if content and not content.endswith("\n"):
            content += "\n"
        for name, value in remaining.items():
            if value is not None:
                content += line(name, value)
        atomic_write(self.env_path, content, private=True)
        self.changed(self.env_path)

    def process_environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update({key: value for key, value in self.values().items() if key not in {"PATH", "HOME", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD"} and not key.startswith("DYLD_")})
        env["DEBUG"] = "false"
        env["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONPATH"] = str(self.root)
        return env

    def catalog(self) -> list[dict]:
        path = self.local / "catalog.json"
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return []

    def remember_catalog(self, server: str, tools: list[dict]) -> None:
        with self.lock:
            before = self.catalog()
            retained = [tool for tool in before if tool.get("server") != server]
            if retained + tools != before:
                atomic_write(self.local / "catalog.json", json.dumps(retained + tools), private=True)
                self.changed(self.local / "catalog.json")
