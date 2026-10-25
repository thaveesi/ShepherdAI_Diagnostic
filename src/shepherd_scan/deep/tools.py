"""Prepare the tool descriptions found by discovery for the tool-description judge.

Each tool is written in the judge's original input format (name, description, parameters) and
wrapped in delimiters with a random id chosen per run, so text inside a description cannot close
the untrusted block and pose as instructions.
"""

import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shepherd_scan.discovery import Discovery
from shepherd_scan.names import agent_name


@dataclass(frozen=True)
class ToolEntry:
    """One tool, with the server or connector that offers it."""

    server: str
    app: str
    name: str
    description: str
    parameters: dict[str, Any]


def tools_on_this_computer(discovery: Discovery) -> list[ToolEntry]:
    """Tools whose descriptions are known: recorded connectors and servers started in the scan."""
    entries = [
        _entry(connector.name, connector.app, tool)
        for connector in discovery.connectors
        for tool in connector.tools
    ]
    for path in discovery.paths:
        for server in path.servers:
            for tool in server.signature.tools if server.signature else []:
                entries.append(_entry(server.name, agent_name(path.client), tool))
    return [entry for entry in entries if entry.name]


def format_tool(entry: ToolEntry) -> str:
    """The tool in the judge's input format."""
    lines = [f"Tool Name: {entry.name}"]
    if entry.description:
        lines.append(f"Description: {entry.description}")
    lines.append("Parameters:")
    if entry.parameters:
        for name, info in entry.parameters.items():
            details = info if isinstance(info, dict) else {}
            kind = details.get("type", "unknown")
            text = details.get("description", "No description")
            lines.append(f"  - {name} ({kind}): {text}")
    else:
        lines.append("  No parameters")
    return "\n".join(lines)


def write_tool_packet(entries: list[ToolEntry], tools_dir: Path) -> dict[str, Any]:
    """Write each tool to its own text file inside this run's delimiters, plus an index."""
    marker = secrets.token_hex(16)
    start_tag = f"<!---UNTRUSTED_INPUT_START_{marker}--->"
    end_tag = f"<!---UNTRUSTED_INPUT_END_{marker}--->"
    tools_dir.mkdir(parents=True, exist_ok=True)
    tools: list[dict[str, Any]] = []
    for number, entry in enumerate(entries, start=1):
        tool_id = f"tool-{number:03d}"
        content = format_tool(entry)
        (tools_dir / f"{tool_id}.txt").write_text(
            f"{start_tag}\n{content}\n{end_tag}\n", encoding="utf-8"
        )
        tools.append(
            {
                "id": tool_id,
                "server": entry.server,
                "app": entry.app,
                "name": entry.name,
                "delimiter_in_input": start_tag in content or end_tag in content,
            }
        )
    packet = {"start_tag": start_tag, "end_tag": end_tag, "tools": tools}
    (tools_dir / "tools.json").write_text(json.dumps(packet, indent=1), encoding="utf-8")
    return packet


def _entry(server: str, app: str, tool: Any) -> ToolEntry:
    """A tool record from a session file (a dict) or a started server (an object)."""
    if isinstance(tool, dict):
        name, description, schema = (
            tool.get("name"),
            tool.get("description"),
            tool.get("inputSchema"),
        )
    else:
        name = getattr(tool, "name", None)
        description = getattr(tool, "description", None)
        schema = getattr(tool, "inputSchema", None)
    properties = schema.get("properties") if isinstance(schema, dict) else None
    return ToolEntry(
        server=server,
        app=app,
        name=name if isinstance(name, str) else "",
        description=description.strip() if isinstance(description, str) else "",
        parameters=properties if isinstance(properties, dict) else {},
    )
