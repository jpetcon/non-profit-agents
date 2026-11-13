
from pathlib import Path

import yaml
from google.adk.agents import Agent

from models.model_registry import Models
from tools.tool_registry import ToolRegistry

from .config import AppConfig


class AgentFactory:
    def __init__(
        self,
        config_path: str | Path,
        models: Models,
        tools: ToolRegistry,
        config_data: dict | None = None,
        team: str | None = None,
    ):
        self.config = AppConfig.model_validate(
            config_data if config_data is not None else yaml.safe_load(Path(config_path).read_text())
        )
        self.models = models
        self.tools = tools
        self.team = team or self.config.default_team

    def build(self) -> Agent:
        """Build the configured agent hierarchy."""
        visited = set()

        def create(name: str) -> Agent:
            if name in visited:
                raise ValueError(
                    f"Duplicate or cyclic agent: {name}"
                )

            spec = self.config.agents.get(name)
            if spec is None:
                raise ValueError(f"Unknown agent: {name}")

            visited.add(name)

            return Agent(
                name=name,
                description=spec.description,
                instruction=spec.instruction,
                model=self.models.resolve(spec.models, agent=name),
                tools=self.tools.resolve(spec.tools, agent=name),
                mode=spec.mode,
                sub_agents=[
                    create(child)
                    for child in spec.sub_agents
                ],
            )

        members = set(self.config.team_members(self.team))
        root = create(self.config.teams[self.team].root)

        unused = members - visited
        if unused:
            raise ValueError(
                f"Unreachable agents: {sorted(unused)}"
            )

        return root
