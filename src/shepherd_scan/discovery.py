"""Find the AI agents on this computer, their MCP servers, skills and account connectors.

Discovery reads configuration and add-on files only. It never contacts a remote server, and it
starts local MCP servers only when asked to, so their tool lists can be read.
"""

import asyncio
import logging
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shepherd_scan._vendor.discovery.agents.claude_desktop import ClaudeDesktopDiscoverer
from shepherd_scan._vendor.discovery.models import InspectedPath, StdioServer
from shepherd_scan._vendor.discovery.pipelines import (
    InspectArgs,
    discover_clients_to_inspect,
    inspect_pipeline,
)
from shepherd_scan._vendor.discovery.utils import get_readable_home_directories
from shepherd_scan.apps.catalog import load_apps
from shepherd_scan.apps.installed import FoundApp, find_installed_apps
from shepherd_scan.carry_on import PART_SECONDS, attempt
from shepherd_scan.checks.plaintext import CredentialSetting, credential_settings, provider_keys
from shepherd_scan.reach.acts import acts_without_asking, grok_bot_setting
from shepherd_scan.reach.assemble import elsewhere_notes
from shepherd_scan.reach.logins import LoginFile, find_login_files
from shepherd_scan.readers import register_readers
from shepherd_scan.report.model import ReachFinding

logger = logging.getLogger(__name__)

SERVER_START_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class AccountConnector:
    """A connector from someone's AI account, as recorded by a desktop app."""

    app: str
    name: str
    tools: list[dict[str, Any]]


@dataclass(frozen=True)
class LocalServer:
    """A local MCP server that would be started to read its tools."""

    agent: str
    name: str
    command: str


@dataclass
class Discovery:
    """Everything found on this computer, and what could not be read."""

    paths: list[InspectedPath] = field(default_factory=list)
    connectors: list[AccountConnector] = field(default_factory=list)
    credentials: list[CredentialSetting] = field(default_factory=list)
    apps: list[FoundApp] = field(default_factory=list)
    acts: list[ReachFinding] = field(default_factory=list)
    logins: list[LoginFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# Discovery and the local checks report unreadable folders and files as log warnings under this
# namespace; they are collected for the report's "Could not be checked" section.
WARNING_LOGGER = "shepherd_scan"
MAX_WARNINGS = 25


class _WarningCollector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage().splitlines()[0].strip()
        if message and message not in self.messages and len(self.messages) < MAX_WARNINGS:
            self.messages.append(message)


@contextmanager
def collect_warnings() -> Generator[list[str]]:
    """Collect warnings logged during the block, without printing them in quiet mode.

    Yields:
        The list that receives each distinct warning's first line.
    """
    collector = _WarningCollector()
    scan_logger = logging.getLogger(WARNING_LOGGER)
    saved_level, saved_propagate = scan_logger.level, scan_logger.propagate
    if not scan_logger.isEnabledFor(logging.WARNING):
        scan_logger.setLevel(logging.WARNING)
        scan_logger.propagate = False
    scan_logger.addHandler(collector)
    try:
        yield collector.messages
    finally:
        scan_logger.removeHandler(collector)
        scan_logger.setLevel(saved_level)
        scan_logger.propagate = saved_propagate


def _inspect_args() -> InspectArgs:
    return InspectArgs(timeout=SERVER_START_TIMEOUT_SECONDS, tokens=[], paths=[], scan_skills=True)


def list_local_servers() -> list[LocalServer]:
    """Local MCP servers configured on this computer, without starting any of them."""
    register_readers()
    clients, _unresolved, _users = asyncio.run(discover_clients_to_inspect(_inspect_args()))
    found: list[LocalServer] = []
    for client in clients:
        for servers in client.mcp_configs.values():
            if not isinstance(servers, list):
                continue
            for name, config in servers:
                if isinstance(config, StdioServer):
                    found.append(LocalServer(agent=client.name, name=name, command=config.command))
    return found


def discover(*, start_local_servers: bool = False) -> Discovery:
    """Run discovery for the current user.

    Args:
        start_local_servers: Start local MCP servers to read their tool lists. Remote
            servers are never contacted either way.

    Returns:
        Agents, servers, skills, account connectors, credential settings, installed AI apps,
        "acts without asking" settings and saved logins found on this computer, and the places
        that could not be read.
    """
    home = Path.home()
    with collect_warnings() as warnings:
        attempt("the agent readers", register_readers, None)
        args = _inspect_args()
        clients, unresolved, users = attempt(
            "agents and their settings",
            lambda: asyncio.run(discover_clients_to_inspect(args)),
            ([], [], []),
            seconds=PART_SECONDS,
        )
        # Settings values are blanked during inspection, so credentials are classified first.
        credentials = attempt(
            "keys written in settings",
            lambda: [*credential_settings(clients), *provider_keys(home)],
            [],
            seconds=PART_SECONDS,
        )
        paths, _users = attempt(
            "servers and skills",
            lambda: asyncio.run(
                inspect_pipeline(
                    args,
                    clients_to_inspect=clients,
                    unresolved_paths=unresolved,
                    scanned_usernames=users,
                    do_stdio_handshake=start_local_servers,
                    allow_network=False,
                )
            ),
            ([], []),
            seconds=PART_SECONDS,
        )
        connectors = attempt(
            "Claude Desktop connectors", _account_connectors, [], seconds=PART_SECONDS
        )
        app_list = attempt("the list of AI apps", load_apps, ())
        apps = attempt(
            "AI apps", lambda: find_installed_apps(home, app_list), [], seconds=PART_SECONDS
        )
        present = {found.entry.id for found in apps}
        present.update(found.entry.agent for found in apps if found.entry.agent)
        present.update(path.client for path in paths if path.client)
        acts = attempt(
            "settings that act without asking",
            lambda: acts_without_asking(home, present),
            [],
            seconds=PART_SECONDS,
        )
        logins = attempt(
            "saved sign-ins", lambda: find_login_files(home, app_list), [], seconds=PART_SECONDS
        )
        notes = attempt(
            "notes about AI apps",
            lambda: elsewhere_notes(apps, grok_setting_found=grok_bot_setting(home)[0] is not None),
            [],
            seconds=PART_SECONDS,
        )
    return Discovery(
        paths=paths,
        connectors=connectors,
        credentials=credentials,
        apps=apps,
        acts=acts,
        logins=logins,
        notes=notes,
        warnings=list(warnings),
    )


def _account_connectors() -> list[AccountConnector]:
    connectors: list[AccountConnector] = []
    for home, _user in get_readable_home_directories(all_users=False):
        try:
            recorded = ClaudeDesktopDiscoverer(home).discover_logged_mcp_servers()
        except Exception:
            logger.exception("Could not read Claude Desktop session records under %s", home)
            continue
        for entries in recorded.values():
            connectors.extend(_connector(entry) for entry in entries)
    return _unique_by_name(connectors)


def _connector(entry: dict[str, Any]) -> AccountConnector:
    listed = entry.get("tools")
    tools = [tool for tool in listed if isinstance(tool, dict)] if isinstance(listed, list) else []
    return AccountConnector(
        app="Claude Desktop", name=str(entry.get("name") or "Unnamed connector"), tools=tools
    )


def _unique_by_name(connectors: list[AccountConnector]) -> list[AccountConnector]:
    """One entry per connector name, keeping the record with the most tools."""
    best: dict[str, AccountConnector] = {}
    for connector in connectors:
        key = connector.name.lower()
        if key not in best or len(connector.tools) > len(best[key].tools):
            best[key] = connector
    return sorted(best.values(), key=lambda c: c.name.lower())
