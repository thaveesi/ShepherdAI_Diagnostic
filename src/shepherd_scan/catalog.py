"""Known servers and connectors: how to recognise them, their tools and their outcome labels.

The catalog is a JSON file shipped with the scanner (``data/servers.json``)::

    {
      "version": 1,
      "labels_from": "<where the labels came from, or null>",
      "servers": [
        {
          "name": "GitHub",
          "match": {
            "urls": ["api.githubcopilot.com/mcp"],
            "packages": ["@modelcontextprotocol/server-github"],
            "connector_names": ["GitHub"]
          },
          "tools": {"merge_pull_request": {"description": "...", "packs": ["CHANGE"]}}
        }
      ]
    }

A server matches when its address contains one of ``urls``, or its launch command names one of
``packages``; an account connector matches by name. ``packs`` are Shepherd outcome labels.
"""

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import PurePosixPath
from typing import Any

from shepherd_scan._vendor.discovery.models import RemoteServer, StdioServer

PACKS = ("AUTHORITY", "FINANCIAL", "DATA", "CHANGE")
SUPPORTED_VERSION = 1


class CatalogError(ValueError):
    """The catalog file does not have the expected shape."""


@dataclass(frozen=True)
class CatalogTool:
    """A known tool's description and outcome labels."""

    description: str
    packs: tuple[str, ...]


@dataclass(frozen=True)
class CatalogEntry:
    """One known server or connector."""

    name: str
    urls: tuple[str, ...]
    packages: tuple[str, ...]
    connector_names: tuple[str, ...]
    tools: dict[str, CatalogTool]

    def tool_records(self) -> list[dict[str, str]]:
        """The entry's tools in the same shape as tools read from a running server."""
        return [
            {"name": name, "description": tool.description} for name, tool in self.tools.items()
        ]


class Catalog:
    """Lookup over the known servers and connectors."""

    def __init__(self, entries: list[CatalogEntry], labels_from: str | None = None) -> None:
        """Create a catalog from parsed entries.

        Args:
            entries: Known servers and connectors.
            labels_from: Where the outcome labels came from, or None if there are none.
        """
        self.entries = entries
        self.labels_from = labels_from
        self._by_name = {entry.name: entry for entry in entries}

    @classmethod
    def load(cls) -> "Catalog":
        """Load the catalog shipped with the scanner."""
        text = resources.files("shepherd_scan").joinpath("data/servers.json").read_text("utf-8")
        return cls.from_json(json.loads(text))

    @classmethod
    def from_json(cls, data: Any) -> "Catalog":
        """Parse catalog data, failing with a clear message if it is malformed.

        Raises:
            CatalogError: If the data does not follow the documented shape.
        """
        if not isinstance(data, dict) or data.get("version") != SUPPORTED_VERSION:
            raise CatalogError(f"catalog must be an object with version {SUPPORTED_VERSION}")
        servers = data.get("servers")
        if not isinstance(servers, list):
            raise CatalogError("catalog 'servers' must be a list")
        labels_from = data.get("labels_from")
        return cls([_parse_entry(raw) for raw in servers], labels_from=labels_from or None)

    def match_server(self, server: StdioServer | RemoteServer) -> CatalogEntry | None:
        """The catalog entry for a configured server, if it is a known one."""
        if isinstance(server, RemoteServer):
            address = server.url.lower().split("://", 1)[-1]
            return next((e for e in self.entries if any(u in address for u in e.urls)), None)
        tokens = [server.command, *server.args]
        return next(
            (
                e
                for e in self.entries
                if any(_names_package(t, p) for t in tokens for p in e.packages)
            ),
            None,
        )

    def match_connector(self, name: str) -> CatalogEntry | None:
        """The catalog entry for an account connector, matched by its name."""
        wanted = name.strip().lower()
        return next((e for e in self.entries if wanted in e.connector_names), None)

    def packs_for(self, entry_name: str | None, tool_name: str) -> list[str]:
        """Outcome labels for a tool of a known server; empty when unknown."""
        entry = self._by_name.get(entry_name) if entry_name else None
        tool = entry.tools.get(tool_name) if entry else None
        return list(tool.packs) if tool else []


def _parse_entry(raw: Any) -> CatalogEntry:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
        raise CatalogError("each catalog server needs a 'name'")
    match = raw.get("match", {})
    if not isinstance(match, dict):
        raise CatalogError(f"catalog server {raw['name']!r}: 'match' must be an object")
    tools = raw.get("tools", {})
    if not isinstance(tools, dict):
        raise CatalogError(f"catalog server {raw['name']!r}: 'tools' must be an object")
    return CatalogEntry(
        name=raw["name"],
        urls=_lowered(match.get("urls")),
        packages=_lowered(match.get("packages")),
        connector_names=_lowered(match.get("connector_names")),
        tools={name: _parse_tool(raw["name"], name, tool) for name, tool in tools.items()},
    )


def _parse_tool(server: str, name: str, raw: Any) -> CatalogTool:
    if not isinstance(raw, dict):
        raise CatalogError(f"catalog tool {server}/{name} must be an object")
    packs = tuple(raw.get("packs") or ())
    unknown = [pack for pack in packs if pack not in PACKS]
    if unknown:
        raise CatalogError(f"catalog tool {server}/{name} has unknown packs {unknown}")
    return CatalogTool(description=str(raw.get("description", "")), packs=packs)


def _lowered(values: Any) -> tuple[str, ...]:
    if values is None:
        return ()
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise CatalogError("catalog match values must be lists of strings")
    return tuple(value.strip().lower() for value in values if value.strip())


def _names_package(token: str, package: str) -> bool:
    """Whether one launch-command word names a package, allowing versions, tags and paths."""
    word = token.strip().lower()
    if word == package or word.startswith((package + "@", package + ":")):
        return True
    return PurePosixPath(word.split(":", 1)[0]).name == package
