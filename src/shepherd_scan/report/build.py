"""Turn discovery results and check results into one report."""

import re
from datetime import UTC, datetime
from pathlib import Path

from shepherd_scan import __version__
from shepherd_scan._vendor.discovery.models import InspectedPath, InspectedSkill, ScanError
from shepherd_scan._vendor.discovery.utils import get_relative_path
from shepherd_scan.apps.catalog import AppEntry
from shepherd_scan.apps.installed import FoundApp
from shepherd_scan.carry_on import NOT_CHECKED, attempt
from shepherd_scan.catalog import Catalog
from shepherd_scan.checks.secrets import merge_secret_findings, secrets_in_skill
from shepherd_scan.checks.servers import connector_result, server_result
from shepherd_scan.checks.skills import check_skill
from shepherd_scan.discovery import AccountConnector, Discovery
from shepherd_scan.names import agent_name
from shepherd_scan.reach.assemble import (
    command_agents,
    control_findings,
    login_findings,
    plaintext_findings,
    shared_findings,
)
from shepherd_scan.report.model import AgentResult, Report, SecretFinding, SkillResult

# A file or folder path inside a message, absolute or relative to the home folder.
PATH_IN_MESSAGE = re.compile(r"(?:~|[A-Za-z]:)?[/\\][^\s'\":,;]+")
NOT_READ = "This scan does not read its settings."
EXTENSION_NOTE = "Only its permissions, read from the browser, are shown."


def readable_problems(messages: list[str]) -> list[str]:
    """One entry per place that could not be read, with paths shown from the home folder.

    Messages that name no file or folder say nothing a reader can act on and are dropped.
    """
    home = str(Path.home())
    seen_paths: set[str] = set()
    kept: list[str] = []
    for message in messages:
        text = message.replace(home, "~")
        if text.startswith(NOT_CHECKED):
            if text not in kept:
                kept.append(text)
            continue
        match = PATH_IN_MESSAGE.search(text)
        if match is None or match.group(0) in seen_paths:
            continue
        seen_paths.add(match.group(0))
        kept.append(text)
    return kept


def build_report(
    discovery: Discovery, catalog: Catalog, *, local_servers_started: bool = False
) -> Report:
    """Run the checks over everything discovered and assemble the report.

    Args:
        discovery: What was found on this computer.
        catalog: Known servers and connectors, for tool lists and labels.
        local_servers_started: Whether local servers were started to read their tools.

    Returns:
        The finished report.
    """
    report = Report(
        generated_at=datetime.now(tz=UTC),
        tool_version=__version__,
        local_servers_started=local_servers_started,
    )
    skill_secrets: list[SecretFinding] = []
    skills_by_path: dict[str, SkillResult] = {}
    failures: list[dict[str, str]] = []
    for path in discovery.paths:
        attempt(
            f"the settings at {get_relative_path(path.path)}",
            lambda path=path: _add_path(report, path, catalog, skills_by_path, skill_secrets),
            None,
            failures,
        )
    for connector in discovery.connectors:
        attempt(
            f"the {connector.name} connector",
            lambda connector=connector: _add_connector(report, connector, catalog),
            None,
            failures,
        )
    for found in discovery.apps:
        attempt(
            f"the app {found.entry.name}",
            lambda found=found: report.agents.append(_app_result(found)),
            None,
            failures,
        )
    report.agents = attempt("the agent list", lambda: _merge_agents(report.agents),
                            report.agents, failures)  # fmt: skip
    report.skills = sorted(skills_by_path.values(), key=lambda s: s.name.lower())
    report.secrets = attempt(
        "exposed keys",
        lambda: merge_secret_findings(skill_secrets, plaintext_findings(discovery.credentials)),
        [],
        failures,
    )
    report.reach = [
        *discovery.acts,
        *attempt("saved sign-ins", lambda: login_findings(discovery.logins), [], failures),
        *attempt("wide control", lambda: control_findings(discovery.apps), [], failures),
        *attempt("shared accounts",
                 lambda: shared_findings(discovery.credentials, Path.home()), [], failures),
    ]  # fmt: skip
    clients = {path.client for path in discovery.paths if path.client}
    report.command_agents = attempt(
        "agents that run commands", lambda: command_agents(discovery.apps, clients), [], failures
    )
    report.kept_elsewhere = discovery.notes
    not_checked = [f"{NOT_CHECKED} {f['part']} ({f['reason']})" for f in failures]
    report.problems = readable_problems([*report.problems, *discovery.warnings, *not_checked])
    return report


def _add_path(
    report: Report,
    path: InspectedPath,
    catalog: Catalog,
    skills_by_path: dict[str, SkillResult],
    skill_secrets: list[SecretFinding],
) -> None:
    """One agent's settings file or folder: its row, problems, servers and skills."""
    agent = agent_name(path.client)
    report.agents.append(_agent_result(path, agent))
    report.problems.extend(_path_problems(path, agent))
    report.servers.extend(server_result(inspected, agent, catalog) for inspected in path.servers)
    for skill in path.skills:
        skill_secrets.extend(_add_skill(skills_by_path, skill, agent))


def _add_connector(report: Report, connector: AccountConnector, catalog: Catalog) -> None:
    report.servers.append(connector_result(connector.name, connector.app, connector.tools, catalog))
    report.agents.append(AgentResult(name=connector.app, path="", servers=1, skills=0))


def _agent_result(path: InspectedPath, agent: str) -> AgentResult:
    return AgentResult(
        name=agent,
        path=get_relative_path(path.path),
        servers=len(path.servers),
        skills=len(path.skills),
    )


def _app_result(found: FoundApp) -> AgentResult:
    """A row for an installed app; apps with a settings reader merge into the reader's row."""
    entry = found.entry
    access = sorted({item for install in found.extensions for item in install.access})
    return AgentResult(
        name=agent_name(entry.agent) if entry.agent else entry.name,
        path="",
        servers=0,
        skills=0,
        found_by=[sighting.describe() for sighting in found.sightings],
        seen_inside=entry.agent is not None,
        note=None if entry.agent else entry.kept_elsewhere or _not_read(entry),
        can_do=entry.can_do,
        site_access=access,
    )


def _not_read(entry: AppEntry) -> str:
    return EXTENSION_NOTE if entry.browser_extensions else NOT_READ


def _merge_agents(agents: list[AgentResult]) -> list[AgentResult]:
    """One row per agent app, adding up what was found for it in different places."""
    merged: dict[str, AgentResult] = {}
    for agent in agents:
        existing = merged.get(agent.name)
        if existing is None:
            merged[agent.name] = agent.model_copy(deep=True)
            continue
        existing.servers += agent.servers
        existing.skills += agent.skills
        existing.path = existing.path or agent.path
        existing.found_by.extend(item for item in agent.found_by if item not in existing.found_by)
        existing.site_access.extend(
            item for item in agent.site_access if item not in existing.site_access
        )
        existing.seen_inside = existing.seen_inside or agent.seen_inside
        existing.note = None if existing.seen_inside else existing.note or agent.note
        existing.can_do = existing.can_do or agent.can_do
    return sorted(merged.values(), key=lambda a: a.name.lower())


def _add_skill(
    skills_by_path: dict[str, SkillResult], skill: InspectedSkill, agent: str
) -> list[SecretFinding]:
    """Record a skill once even when several agents load it; return secrets found in it."""
    key = skill.installation_path
    if key in skills_by_path:
        existing = skills_by_path[key]
        if agent not in existing.agents:
            existing.agents.append(agent)
        return []
    if skill.error is not None:
        skills_by_path[key] = SkillResult(
            name=skill.name,
            path=get_relative_path(key),
            agents=[agent],
            error=_error_text(skill.error),
        )
        return []
    check = check_skill(skill.name, key)
    skills_by_path[key] = SkillResult(
        name=skill.name,
        path=get_relative_path(key),
        agents=[agent],
        flags=check.flags,
        error=check.error,
    )
    return [*secrets_in_skill(skill), *check.secrets]


def _path_problems(path: InspectedPath, agent: str) -> list[str]:
    if path.error is None or not path.error.is_failure:
        return []
    message = (path.error.message or "could not be read").splitlines()[0]
    return [f"{agent}: {message}"]


def _error_text(error: ScanError) -> str:
    """First line of an error, for a reader rather than a developer, with paths from home."""
    text = str(error.exception) if error.exception else (error.message or "")
    first_line = text.strip().splitlines()[0] if text.strip() else ""
    return first_line.replace(str(Path.home()), "~") or "Could not read this skill."
