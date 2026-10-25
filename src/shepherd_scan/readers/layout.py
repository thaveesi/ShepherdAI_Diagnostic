"""Shared base for readers of agent apps that keep their files at fixed places.

Each concrete reader only declares where its app keeps things: folders that show it is
installed, the files that list its MCP servers (and their format), and its skills folders.
Reading is built on the discovery framework's base class, so size caps, unreadable files,
permission errors and malformed content are handled the same way as for the built-in agents.
"""

import logging
import shutil
import sys
import tomllib
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

import yaml

from shepherd_scan._vendor.discovery.agents.base import (
    _MAX_CONFIG_FILE_BYTES,
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
    _canonicalize_keys,
)
from shepherd_scan._vendor.discovery.models import CouldNotParseMCPConfig, RemoteServer, StdioServer
from shepherd_scan._vendor.discovery.utils import is_special_file
from shepherd_scan._vendor.discovery.well_known_clients import expand_path

logger = logging.getLogger(__name__)

ServerList = list[tuple[str, StdioServer | RemoteServer]]
ParseResult = ServerList | CouldNotParseMCPConfig | None

# Transport spellings seen across apps, folded onto the two remote transports.
HTTP_TRANSPORTS = frozenset(
    {"http", "https", "streamable-http", "streamablehttp", "streamable_http"}
)


def _as_text_map(value: Any) -> dict[str, str]:
    """Environment and header maps with every value as text (YAML may hold numbers)."""
    if not isinstance(value, dict):
        return {}
    return {str(key): "" if item is None else str(item) for key, item in value.items()}


def normalize_server(raw: dict[str, Any]) -> dict[str, Any] | None:
    """One server entry in the shape the server models accept, or None if unusable."""
    entry = dict(raw)
    transport = str(entry.get("type") or entry.get("transport") or "").strip().lower()
    entry.pop("transport", None)
    if "env" in entry:
        entry["env"] = _as_text_map(entry["env"])
    if "headers" in entry:
        entry["headers"] = _as_text_map(entry["headers"])
    if entry.get("command"):
        entry["type"] = "stdio"
        return entry
    if any(entry.get(key) for key in ("url", "serverUrl", "httpUrl")):
        entry["type"] = (
            "sse" if transport == "sse" else "http" if transport in HTTP_TRANSPORTS else None
        )
        return entry
    return None


def server_map_from(data: Any) -> dict[str, Any] | None:
    """The ``{name: server}`` map inside common MCP file shapes, or None if there is none."""
    if not isinstance(data, dict):
        return None
    for key in ("mcpServers", "servers"):
        if isinstance(data.get(key), dict):
            return data[key]
    nested = data.get("mcp")
    if isinstance(nested, dict) and isinstance(nested.get("servers"), dict):
        return nested["servers"]
    return None


def load_yaml_file(path: Path) -> dict | CouldNotParseMCPConfig | None:
    """YAML counterpart of the framework's JSON loader, with the same failure semantics."""
    try:
        if not path.exists() or is_special_file(path):
            return None
        if path.stat().st_size > _MAX_CONFIG_FILE_BYTES:
            logger.warning("Skipping oversized config %s", path.as_posix())
            return None
        content = path.read_text(encoding="utf-8")
        loaded = yaml.safe_load(content) if content.strip() else {}
    except PermissionError:
        logger.warning("Permission denied reading %s", path.as_posix())
        return None
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        logger.warning("Could not read %s", path.as_posix())
        return CouldNotParseMCPConfig(
            message=f"could not parse file {path.as_posix()}",
            traceback=traceback.format_exc(),
            is_failure=True,
        )
    return loaded if isinstance(loaded, dict) else {}


def load_toml_file(path: Path) -> dict | CouldNotParseMCPConfig | None:
    """TOML counterpart of the framework's JSON loader, with the same failure semantics."""
    try:
        if not path.exists() or is_special_file(path):
            return None
        if path.stat().st_size > _MAX_CONFIG_FILE_BYTES:
            logger.warning("Skipping oversized config %s", path.as_posix())
            return None
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except PermissionError:
        logger.warning("Permission denied reading %s", path.as_posix())
        return None
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        logger.warning("Could not read %s", path.as_posix())
        return CouldNotParseMCPConfig(
            message=f"could not parse file {path.as_posix()}",
            traceback=traceback.format_exc(),
            is_failure=True,
        )


def _named_entries(entries: Any) -> dict[str, Any]:
    """A list of server entries that carry their own ``name``, as a ``{name: entry}`` map."""
    servers: dict[str, Any] = {}
    for index, entry in enumerate(entries if isinstance(entries, list) else [], start=1):
        if isinstance(entry, dict):
            servers[str(entry.get("name") or f"server {index}")] = entry
    return servers


def goose_server_map(data: dict) -> dict[str, Any]:
    """Read goose ``extensions``: local commands and web addresses become server entries."""
    servers: dict[str, Any] = {}
    for key, extension in (data.get("extensions") or {}).items():
        if not isinstance(extension, dict):
            continue
        name = str(extension.get("name") or key)
        env = _as_text_map(extension.get("envs"))
        env.update(dict.fromkeys(extension.get("env_keys") or [], ""))
        if extension.get("cmd"):
            servers[name] = {"command": extension["cmd"], "args": extension.get("args"), "env": env}
        elif extension.get("uri"):
            servers[name] = {
                "url": extension["uri"],
                "headers": extension.get("headers"),
                "type": extension.get("type"),
            }
    return servers


def continue_server_map(data: dict) -> dict[str, Any]:
    """Continue ``mcpServers``: a list of named entries (a map is also accepted)."""
    entries = data.get("mcpServers")
    if isinstance(entries, dict):
        return entries
    return _named_entries(entries)


def zeptoclaw_server_map(data: dict) -> dict[str, Any]:
    """ZeptoClaw ``mcp.servers``: a list of named entries with a command or a ``url``."""
    mcp = data.get("mcp")
    return _named_entries(mcp.get("servers")) if isinstance(mcp, dict) else {}


def opencode_server_map(data: dict) -> dict[str, Any]:
    """OpenCode-style ``mcp`` map: ``local`` entries with a command list, or ``remote`` ones."""
    servers: dict[str, Any] = {}
    for name, entry in (data.get("mcp") or {}).items():
        if not isinstance(entry, dict):
            continue
        command = entry.get("command")
        if entry.get("type") == "local" and isinstance(command, list) and command:
            servers[name] = {
                "command": command[0],
                "args": command[1:],
                "env": entry.get("environment"),
            }
        elif entry.get("url"):
            servers[name] = {"url": entry["url"], "headers": entry.get("headers"), "type": "http"}
    return servers


def toml_server_map(data: dict) -> dict[str, Any] | None:
    """``[mcp_servers.<name>]`` tables with a command or a ``url``."""
    servers = data.get("mcp_servers")
    return servers if isinstance(servers, dict) else None


def zed_server_map(data: dict) -> dict[str, Any]:
    """Zed ``context_servers``: current flat entries and the older nested command form."""
    servers: dict[str, Any] = {}
    for name, entry in (data.get("context_servers") or {}).items():
        if not isinstance(entry, dict):
            continue
        command = entry.get("command")
        if isinstance(command, dict):
            servers[name] = {
                "command": command.get("path"),
                "args": command.get("args"),
                "env": command.get("env"),
            }
        else:
            servers[name] = entry
    return servers


def yaml_server_map(data: dict) -> dict[str, Any] | None:
    """A server map under ``mcp_servers``, ``mcpServers`` or ``mcp.servers`` in a YAML config."""
    for key in ("mcp_servers", "mcpServers"):
        if isinstance(data.get(key), dict):
            return data[key]
    return server_map_from(data)


# How each declared file format is turned into a server map.
JSON_FORMATS: dict[str, Callable[[dict], dict[str, Any] | None]] = {
    "mcp-json": server_map_from,
    "settings-json": server_map_from,
    "zed-json": zed_server_map,
    "zeptoclaw-json": zeptoclaw_server_map,
    "opencode-json": opencode_server_map,
}
YAML_FORMATS: dict[str, Callable[[dict], dict[str, Any] | None]] = {
    "goose-yaml": goose_server_map,
    "continue-yaml": continue_server_map,
    "generic-yaml": yaml_server_map,
}
TOML_FORMATS: dict[str, Callable[[dict], dict[str, Any] | None]] = {
    "toml-mcp": toml_server_map,
}


def platform_paths(mac: tuple[str, ...], windows: tuple[str, ...], linux: tuple[str, ...]) -> tuple:
    """The entries for the platform this scan runs on."""
    if sys.platform == "darwin":
        return mac
    if sys.platform == "win32":
        return windows
    return linux


class LayoutDiscoverer(AgentDiscoverer, abstract=True):
    """Reader for an app whose install, MCP files and skills sit at fixed home-relative paths."""

    install_paths: ClassVar[tuple[str, ...]] = ()
    install_binaries: ClassVar[tuple[str, ...]] = ()
    mcp_files: ClassVar[tuple[tuple[str, str], ...]] = ()
    skills_dirs: ClassVar[tuple[str, ...]] = ()

    def _expand(self, raw: str) -> Path:
        return expand_path(Path(raw), self.home_directory)

    def client_exists(self) -> str | None:
        """The first install folder found, or the app's command on this user's PATH."""
        for raw in self.install_paths:
            path = self._expand(raw)
            try:
                if path.exists():
                    return path.as_posix()
            except OSError:
                logger.warning("Permission error for path %s", path.as_posix())
        if self._scans_own_home():
            for binary in self.install_binaries:
                found = shutil.which(binary)
                if found:
                    return found
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        """Servers from every declared MCP file that exists, keyed by file path."""
        result: McpConfigsResult = {}
        for raw, file_format in self.mcp_files:
            path = self._expand(raw)
            parsed = self.parse_servers_file(path, file_format)
            if parsed:
                result[path.as_posix()] = parsed
        return _canonicalize_keys(result)

    def discover_skills(self) -> SkillsDirsResult:
        """Skills in every declared skills folder that exists."""
        result: SkillsDirsResult = {}
        for raw in self.skills_dirs:
            path = self._expand(raw)
            entries = self._scan_skills_dir(path)
            if entries is not None:
                result[path.as_posix()] = entries
        return _canonicalize_keys(result)

    def parse_servers_file(self, path: Path, file_format: str) -> ParseResult:
        """Read one MCP file in its declared format; None when absent or holding no servers."""
        if file_format in YAML_FORMATS:
            data: Any = load_yaml_file(path)
            to_map = YAML_FORMATS[file_format]
        elif file_format in TOML_FORMATS:
            data = load_toml_file(path)
            to_map = TOML_FORMATS[file_format]
        elif file_format in JSON_FORMATS:
            data = self._load_json_file(path)
            to_map = JSON_FORMATS[file_format]
        else:
            raise ValueError(f"unknown MCP file format {file_format!r} for {path}")
        if data is None or isinstance(data, CouldNotParseMCPConfig):
            return data
        server_map = to_map(data) if isinstance(data, dict) else None
        if not server_map:
            return None
        return self.validate_each(server_map, path.as_posix())

    def validate_each(self, server_map: dict[str, Any], source: str) -> ServerList:
        """Validate servers one at a time so one unusable entry does not hide the others."""
        servers: ServerList = []
        for name, raw in server_map.items():
            entry = normalize_server(raw) if isinstance(raw, dict) else None
            validated = self._validate_servers({str(name): entry}, source) if entry else None
            if isinstance(validated, list):
                servers.extend(validated)
            else:
                logger.warning("Could not read server %r in %s", name, source)
        return servers
