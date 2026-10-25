"""Render the report as one self-contained HTML page."""

import base64
import logging
from dataclasses import dataclass
from functools import cache
from importlib.resources import files

from jinja2 import Environment, PackageLoader, StrictUndefined

from shepherd_scan.report.model import AgentResult, ReachPart, Report, ServerResult, ToolInfo

logger = logging.getLogger(__name__)

# Order the consequence groups the way they are explained to customers.
PACK_ORDER = ("CHANGE", "DATA", "AUTHORITY", "FINANCIAL")
PACK_LABELS: dict[str, str] = {
    "CHANGE": "Changes or deletes records",
    "DATA": "Sends information outside",
    "AUTHORITY": "Changes who has access",
    "FINANCIAL": "Commits money",
}
UNLABELLED = "UNLABELLED"
KIND_LABELS: dict[str, str] = {
    "local": "runs on this computer",
    "remote": "online service",
    "account connector": "connector on the person's AI account",
}
MAX_FLAGS_SHOWN = 5
MAX_REACH_ROWS = 12
FOUND_BY_SHOWN = 3


@dataclass(frozen=True)
class ReachPartText:
    """Heading and explanation of one part of the reach section."""

    key: ReachPart
    title: str
    lead: str
    what_heading: str


# The four parts, worded as agreed for the report.
REACH_PARTS = (
    ReachPartText(
        "acts",
        "Acts without asking",
        "Agents set to run commands or make changes without checking with you, including where "
        "that is the app's default and where pre-approved commands let it run anything.",
        "What it does without asking",
    ),
    ReachPartText(
        "logins",
        "Logins and keys it can pick up",
        "Saved logins and keys on this computer, such as SSH keys, that any agent able to run "
        "commands could use. Only whether they exist is shown, never the values.",
        "What is saved",
    ),
    ReachPartText(
        "control",
        "Every signed-in website, or the whole computer",
        "Browser agents that can act on any site you're logged into, and apps that can control "
        "your whole computer.",
        "What it can do",
    ),
    ReachPartText(
        "shared",
        "Someone else's access",
        "Agent settings that use a shared bot or company account, so whoever asks the agent gets "
        "that account's rights.",
        "What it uses",
    ),
)


def group_tools(tools: list[ToolInfo]) -> list[tuple[str, list[ToolInfo]]]:
    """Group a server's tools by outcome label; unlabelled tools come last.

    A tool with several labels appears under each of them.
    """
    groups: list[tuple[str, list[ToolInfo]]] = []
    for pack in PACK_ORDER:
        members = [tool for tool in tools if pack in tool.packs]
        if members:
            groups.append((pack, members))
    unlabelled = [tool for tool in tools if not tool.packs]
    if unlabelled:
        groups.append((UNLABELLED, unlabelled))
    return groups


def no_tools_reason(server: ServerResult) -> str:
    """Why a server's tools are not listed."""
    if server.kind == "remote":
        return (
            "Online services are not contacted by this offline scan, so its tools are not listed."
        )
    if server.kind == "account connector":
        return "No tool list was recorded for this connector."
    return "Not started during this scan, so its tools are not listed."


def found_by_text(agent: AgentResult) -> str:
    """How an app was recognised, shortened for the apps table."""
    shown = "; ".join(agent.found_by[:FOUND_BY_SHOWN])
    extra = len(agent.found_by) - FOUND_BY_SHOWN
    return f"{shown}; and {extra} more" if extra > 0 else shown


def _described_apps(report: Report) -> list[AgentResult]:
    """Apps whose settings are not read, described by their access or published features."""
    return [
        agent
        for agent in report.agents
        if not agent.seen_inside and (agent.can_do or agent.site_access)
    ]


def _sort_servers(servers: list[ServerResult]) -> list[ServerResult]:
    """Servers with credentials and labelled tools first, so the most capable lead."""

    def key(server: ServerResult) -> tuple[int, int, str]:
        labelled = sum(1 for tool in server.tools if tool.packs)
        return (-labelled, -len(server.credentials) - len(server.tools), server.name.lower())

    return sorted(servers, key=key)


@cache
def logo_uri() -> str:
    """The Shepherd logo as a data URI, so the page loads nothing from outside; "" if unreadable."""
    try:
        data = files("shepherd_scan.report").joinpath("logo.png").read_bytes()
    except OSError as error:  # the report is still drawn, without the logo
        logger.warning("Could not read the logo: %s", error)
        return ""
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii")


def _environment() -> Environment:
    environment = Environment(
        loader=PackageLoader("shepherd_scan", "report"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return environment


def render_html(report: Report) -> str:
    """Render the full report page.

    Args:
        report: The finished report.

    Returns:
        A complete HTML document that loads nothing from the network.
    """
    template = _environment().get_template("template.html.j2")
    return template.render(
        report=report,
        logo=logo_uri(),
        generated=report.generated_at.astimezone().strftime("%d %B %Y, %H:%M"),
        flagged=report.flagged_skills,
        unchecked=[skill for skill in report.skills if skill.error],
        servers=_sort_servers(report.servers),
        described_apps=_described_apps(report),
        reach_parts=REACH_PARTS,
        found_by_text=found_by_text,
        labels_present=report.labelled_tool_count > 0,
        pack_labels=PACK_LABELS,
        kind_labels=KIND_LABELS,
        max_flags=MAX_FLAGS_SHOWN,
        max_reach_rows=MAX_REACH_ROWS,
        group_tools=group_tools,
        no_tools_reason=no_tools_reason,
    )
