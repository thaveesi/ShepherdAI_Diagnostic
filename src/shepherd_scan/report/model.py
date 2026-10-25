"""Data the report is built from: what was found on this computer and what the checks flagged."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """How urgently a flagged item deserves a closer look."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Sort key: lower means more urgent."""
        return list(Severity).index(self)


class SkillFlag(BaseModel):
    """One automated finding in a skill. Unconfirmed until reviewed."""

    category: str
    severity: Severity
    location: str
    detail: str
    evidence: str | None = None


class SkillResult(BaseModel):
    """A skill (an add-on of instructions and scripts) and what the rules flagged in it."""

    name: str
    path: str
    agents: list[str]
    flags: list[SkillFlag] = Field(default_factory=list)
    error: str | None = None

    @property
    def worst(self) -> Severity | None:
        """The most urgent severity among this skill's flags, if any."""
        return min((flag.severity for flag in self.flags), key=lambda s: s.rank, default=None)


class SecretFinding(BaseModel):
    """A credential written into an agent setting or add-on file. Never holds the value."""

    kind: str
    where: str
    location: str


class ToolInfo(BaseModel):
    """One tool an agent can call through a connected server."""

    name: str
    description: str
    packs: list[str] = Field(default_factory=list)


ServerKind = Literal["local", "remote", "account connector"]
ToolSource = Literal["started", "catalog", "session record", "none"]


class ServerResult(BaseModel):
    """An MCP server or account connector an agent is connected to."""

    name: str
    agent: str
    kind: ServerKind
    config_path: str | None = None
    launch: str | None = None
    credentials: list[str] = Field(default_factory=list)
    tools: list[ToolInfo] = Field(default_factory=list)
    tools_source: ToolSource = "none"
    catalog_name: str | None = None
    error: str | None = None


class AgentResult(BaseModel):
    """An AI agent app found on this computer.

    ``seen_inside`` is False for apps whose settings this scan does not read; ``note`` then says
    why, and ``can_do`` describes the app from its published features rather than this computer.
    """

    name: str
    path: str
    servers: int
    skills: int
    found_by: list[str] = Field(default_factory=list)
    seen_inside: bool = True
    note: str | None = None
    can_do: str | None = None
    site_access: list[str] = Field(default_factory=list)


ReachPart = Literal["acts", "logins", "control", "shared"]
# What a finding rests on: a setting found on this computer, the app's default when nothing is
# set, or the app's published features (for apps whose settings cannot be read offline).
ReachBasis = Literal["setting", "default", "published"]


class ReachFinding(BaseModel):
    """One way an agent can go further than the person meant.

    Parts: ``acts`` (acts without asking), ``logins`` (logins and keys it can pick up),
    ``control`` (every signed-in website, or the whole computer), ``shared`` (someone else's
    access).
    """

    part: ReachPart
    app: str
    what: str
    where: str | None = None
    basis: ReachBasis = "setting"


class Report(BaseModel):
    """Everything the offline scan found, ready to render."""

    generated_at: datetime
    tool_version: str
    agents: list[AgentResult] = Field(default_factory=list)
    servers: list[ServerResult] = Field(default_factory=list)
    skills: list[SkillResult] = Field(default_factory=list)
    secrets: list[SecretFinding] = Field(default_factory=list)
    reach: list[ReachFinding] = Field(default_factory=list)
    command_agents: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    kept_elsewhere: list[str] = Field(default_factory=list)
    local_servers_started: bool = False

    @property
    def flagged_skills(self) -> list[SkillResult]:
        """Skills with at least one flag, most urgent first."""
        flagged = [skill for skill in self.skills if skill.flags]
        return sorted(flagged, key=lambda s: (s.worst.rank if s.worst else 99, s.name.lower()))

    def reach_part(self, part: ReachPart) -> list[ReachFinding]:
        """The findings of one part of the reach section, in report order."""
        return [finding for finding in self.reach if finding.part == part]

    @property
    def labelled_tool_count(self) -> int:
        """How many discovered tools carry at least one outcome label."""
        return sum(1 for server in self.servers for tool in server.tools if tool.packs)
