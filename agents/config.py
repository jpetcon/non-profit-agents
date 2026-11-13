from typing import Literal

import re

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction: str = Field(min_length=1)
    description: str = ""
    display_name: str = ""
    models: list[str] = Field(min_length=1)
    tools: list[str] = Field(default_factory=list)
    sub_agents: list[str] = Field(default_factory=list)
    mode: Literal["chat", "single_turn", "task"] | None = None


class TeamConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=120)
    description: str = ""
    root: str


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: str
    agents: dict[str, AgentConfig] = Field(min_length=1)
    default_team: str = "charity_team"
    teams: dict[str, TeamConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_teams(self):
        # Legacy single-root files become one team without writing on import.
        if not self.teams:
            self.teams = {self.default_team: TeamConfig(display_name="Charity team", root=self.root)}
        if self.default_team not in self.teams:
            raise ValueError("Choose an existing default team.")
        if self.teams[self.default_team].root != self.root:
            raise ValueError("The default team coordinator must match the workspace root.")
        seen = set()
        def visit(name):
            if name not in self.agents:
                raise ValueError(f"The referenced agent {name} does not exist.")
            if name in seen:
                raise ValueError(f"{name} has more than one parent, belongs to multiple teams, or creates a loop.")
            seen.add(name)
            for child in self.agents[name].sub_agents:
                visit(child)
        for name in [*self.teams, *self.agents]:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name):
                raise ValueError("Team and agent identifiers must start with a letter and use letters, numbers or underscores.")
        for team in self.teams.values():
            visit(team.root)
        if seen != set(self.agents):
            raise ValueError("Every specialist needs a supervising agent connected to a team coordinator.")
        return self

    def team_members(self, team: str) -> list[str]:
        if team not in self.teams:
            raise ValueError("Choose an existing team.")
        members = []
        def collect(name):
            members.append(name)
            for child in self.agents[name].sub_agents:
                collect(child)
        collect(self.teams[team].root)
        return members

    def team_for_agent(self, agent: str) -> str:
        for team in self.teams:
            if agent in self.team_members(team):
                return team
        raise ValueError("Choose an existing agent.")
