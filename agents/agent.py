
import os
from pathlib import Path

from models.model_registry import Models
from tools.tool_registry import ToolRegistry

from .agent_factory import AgentFactory
from .config import AppConfig
from guardrails.runtime import Runtime
import atexit
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = Path(__file__).resolve().parent
runtime = Runtime(PROJECT_ROOT)
config = AppConfig.model_validate(yaml.safe_load((AGENT_DIR / "config.yml").read_text()))
team = os.getenv("AGENT_TEAM") or config.default_team
run = runtime.start_run("standalone", team)
atexit.register(runtime.revoke, run)
tokens = {}
def credential(agent, audience):
    key = (agent, audience)
    if key not in tokens:
        tokens[key] = runtime.issue(run, agent, audience)
    return tokens[key]

root_agent = AgentFactory(
    config_path=AGENT_DIR / "config.yml",
    models=Models(
        PROJECT_ROOT / "models" / "model_config.yml", credential_provider=credential
    ),
    tools=ToolRegistry(
        gateway_url=os.getenv(
            "MCP_GATEWAY_URL",
            "http://127.0.0.1:9000/mcp",
        ),
        credential_provider=credential,
        revision_provider=lambda: runtime.policy().revision,
    ),
    team=os.getenv("AGENT_TEAM") or None,
).build()
