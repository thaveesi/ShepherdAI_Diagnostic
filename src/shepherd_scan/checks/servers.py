"""Describe each connected server: how it runs, which credentials it holds, which tools it has."""

import re
from typing import Any

from shepherd_scan._vendor.discovery.models import InspectedServer, RemoteServer, StdioServer
from shepherd_scan._vendor.discovery.utils import get_relative_path
from shepherd_scan.catalog import Catalog
from shepherd_scan.checks.secrets import hide_blanked_values
from shepherd_scan.report.model import ServerKind, ServerResult, ToolInfo, ToolSource

# Setting names that hold a credential. Values are never read: they are blanked during collection.
CREDENTIAL_NAME = re.compile(
    r"TOKEN|SECRET|PASSW|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTHORIZATION|BEARER"
    r"|CREDENTIAL|COOKIE|(^|[_-])AUTH($|[_-])|(^|[_-])PAT($|[_-])|(^|[_-])KEY$",
    re.IGNORECASE,
)
DESCRIPTION_LIMIT = 200
LAUNCH_LIMIT = 160


def credential_settings(server: StdioServer | RemoteServer) -> list[str]:
    """Names of settings that pass a credential to the server, never their values."""
    names = list(server.env or {}) if isinstance(server, StdioServer) else list(server.headers)
    return sorted(name for name in names if CREDENTIAL_NAME.search(name))


def describe_launch(server: StdioServer | RemoteServer) -> str:
    """The command or address used to reach the server, already free of credentials."""
    if isinstance(server, RemoteServer):
        text = server.url
    else:
        text = " ".join([server.command, *server.args])
    text = hide_blanked_values(text)
    return text if len(text) <= LAUNCH_LIMIT else text[: LAUNCH_LIMIT - 1] + "…"


def tool_infos(raw_tools: list[Any], catalog: Catalog, catalog_name: str | None) -> list[ToolInfo]:
    """Tool names, short descriptions and any known outcome labels."""
    tools: list[ToolInfo] = []
    for raw in raw_tools:
        name = _field(raw, "name")
        if not name:
            continue
        tools.append(
            ToolInfo(
                name=name,
                description=_short(_field(raw, "description")),
                packs=catalog.packs_for(catalog_name, name),
            )
        )
    return sorted(tools, key=lambda tool: tool.name.lower())


def server_result(inspected: InspectedServer, agent: str, catalog: Catalog) -> ServerResult:
    """Build the report entry for a server found in an agent's settings."""
    config = inspected.server
    kind: ServerKind = "remote" if isinstance(config, RemoteServer) else "local"
    entry = catalog.match_server(config)
    catalog_name = entry.name if entry else None
    source: ToolSource = "none"
    raw_tools: list[Any] = []
    if inspected.signature is not None and inspected.signature.tools:
        raw_tools, source = list(inspected.signature.tools), "started"
    elif entry is not None and entry.tools:
        raw_tools, source = entry.tool_records(), "catalog"
    return ServerResult(
        name=inspected.name,
        agent=agent,
        kind=kind,
        config_path=get_relative_path(inspected.config_path) if inspected.config_path else None,
        launch=describe_launch(config),
        credentials=credential_settings(config),
        tools=tool_infos(raw_tools, catalog, catalog_name),
        tools_source=source,
        catalog_name=catalog_name,
        error=_error_text(inspected),
    )


def connector_result(
    name: str, app: str, raw_tools: list[dict[str, Any]], catalog: Catalog
) -> ServerResult:
    """Build the report entry for an account connector recorded by a desktop app."""
    entry = catalog.match_connector(name)
    catalog_name = entry.name if entry else None
    return ServerResult(
        name=name,
        agent=app,
        kind="account connector",
        tools=tool_infos(raw_tools, catalog, catalog_name),
        tools_source="session record" if raw_tools else "none",
        catalog_name=catalog_name,
    )


def _error_text(inspected: InspectedServer) -> str | None:
    if inspected.error is None or inspected.error.category == "user_declined":
        return None
    return inspected.error.message or "Could not read this server."


def _field(raw: Any, key: str) -> str:
    value = raw.get(key) if isinstance(raw, dict) else getattr(raw, key, None)
    return value.strip() if isinstance(value, str) else ""


def _short(text: str) -> str:
    first_line = text.splitlines()[0] if text else ""
    if len(first_line) <= DESCRIPTION_LIMIT:
        return first_line
    return first_line[: DESCRIPTION_LIMIT - 1] + "…"
