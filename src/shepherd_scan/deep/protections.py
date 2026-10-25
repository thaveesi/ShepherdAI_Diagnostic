"""Protection settings with their values, the safe ones as well as the risky ones (read C).

The scan's report names a setting only when it lets an agent act without asking, so the deep
review could not tell "checked and protective" from "not known". Each row names the agent and
surface, the file (``~`` path) and scope, the key and its value: an enum, a boolean or a count,
never free text. ``state`` says whether that value protects or relaxes; an unset key carries its
documented default and the source that documents it. Command prefixes, tool names and allowed
values travel blanked in ``items``. Only the keys named in this module are read, and a project
folder is named only when the package already names it.
"""

import ast
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from shepherd_scan._vendor.discovery.agents.vscode.cursor import CursorDiscoverer
from shepherd_scan._vendor.discovery.utils import get_relative_path
from shepherd_scan.deep.blank import clean
from shepherd_scan.reach.acts import (
    FACTORY_SETTINGS,
    GEMINI_SETTINGS,
    PATTERN_LIST,
    PREFIX_RULE,
    VSCODE_SETTINGS,
    _editor_user_settings,
)
from shepherd_scan.settings_files import exists, home_path, load_settings, lookup, read_text

MANAGED_PREFERENCES = Path("/Library/Managed Preferences")
SHORT_VALUE = 40


@dataclass(frozen=True)
class Key:
    """A documented key: the values that relax or protect, and the default when it is unset.

    A value outside both lists is sent as "other", so a name someone typed (a custom profile,
    say) never travels.
    """

    name: str
    relaxing: frozenset[str]
    protective: frozenset[str]
    default: str
    basis: str = "documented default"


@dataclass(frozen=True)
class Row:
    """One protection setting as found, or its documented default when it is unset."""

    agent: str
    surface: str
    file: str
    scope: str
    key: str
    value: str
    state: str
    default: str = ""
    basis: str = "setting"
    items: tuple[str, ...] = ()


@dataclass(frozen=True)
class Place:
    """Where a setting lives: the agent and surface it governs, its file and scope."""

    agent: str
    surface: str
    file: str
    scope: str

    def row(self, key: str, value: str, state: str, **extra: Any) -> Row:
        """A row for one key in this file."""
        return Row(self.agent, self.surface, self.file, self.scope, key, value, state, **extra)

    def unset(self, key: str, default: str, basis: str = "documented default") -> Row:
        """A row for a key no file sets, with its documented default."""
        return self.row(key, "", "unset", default=default, basis=basis)


def protection_rows(home: Path, known_folders: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Every read C row, as plain data.

    Args:
        home: The person's home folder.
        known_folders: ``~`` paths of the project folders the package already names; any other
            folder is counted, never named.
    """
    known = frozenset(known_folders)
    rows = [*_codex(home, known), *_cursor(home, known), *_desktop_policy(home), *_tables(home)]
    return [asdict(row) for row in rows]


def _simple(raw: Any) -> str:
    """A value as sent: booleans and numbers as text, short strings as written, else "other"."""
    if isinstance(raw, bool):
        return str(raw).lower()
    if isinstance(raw, int | float):
        return str(raw)
    if isinstance(raw, str) and len(raw) <= SHORT_VALUE:
        return raw
    return "other"


def _state(value: str, key: Key) -> str:
    lowered = value.lower()
    if lowered in key.relaxing:
        return "relaxing"
    return "protective" if lowered in key.protective else "neutral"


def _value_row(place: Place, key: Key, name: str, raw: Any) -> Row:
    value = _simple(raw)
    if value.lower() not in key.relaxing | key.protective:
        value = "other"
    return place.row(name, value, _state(value, key))


def _key_row(
    place: Place, key: Key, data: dict[str, Any], *, skip_unset: bool = False
) -> list[Row]:
    raw = lookup(data, key.name)
    if raw is None:
        return [] if skip_unset else [place.unset(key.name, key.default, key.basis)]
    return [_value_row(place, key, key.name, raw)]


def _items(values: Iterable[Any]) -> tuple[str, ...]:
    return tuple(sorted({clean(value) for value in values if isinstance(value, str)}))


def _shown(path: Path, known: frozenset[str]) -> str:
    """A workspace file's ``~`` path when the package already names its folder."""
    folder = get_relative_path(str(path.parent.parent))
    if folder in known:
        return get_relative_path(str(path))
    return f"(workspace)/{path.parent.name}/{path.name}"


# --- Codex ---------------------------------------------------------------------------------

CODEX = "Codex"
CODEX_SURFACE = "CLI, IDE extension and ChatGPT app"
CODEX_KEYS = (
    Key("approval_policy", frozenset({"never"}),
        frozenset({"on-request", "on-failure", "granular"}),
        "on-request; where the folder's trust entry is untrusted, every command no rule allows "
        "prompts (CX-01)"),
    Key("sandbox_mode", frozenset({"danger-full-access"}),
        frozenset({"read-only", "workspace-write"}),
        "read-only, or workspace-write in a folder with a trust entry (CX-02)"),
    Key("sandbox_workspace_write.network_access", frozenset({"true"}), frozenset({"false"}),
        "false: no network inside the workspace-write sandbox (CX-02)"),
    Key("default_permissions", frozenset({":danger-full-access"}),
        frozenset({":read-only", ":workspace"}),
        "no permission profile, so sandbox_mode applies (Codex permissions page)"),
    Key("approvals_reviewer", frozenset({"auto_review", "guardian_subagent"}),
        frozenset({"user"}), "user (Codex configuration reference)"),
)  # fmt: skip
TOOL_MODES = Key(
    "default_tools_approval_mode",
    frozenset({"approve"}),
    frozenset({"auto", "prompt", "writes"}),
    "auto: asks for tools annotated destructive and for unannotated tools (CX-04)",
)
APP_TOOL_DEFAULT = "the apps._default mode, else auto (CX-04)"
DECISION = re.compile(r"decision\s*=\s*[\"'](allow|prompt|forbidden)[\"']")
RULE_STATES = {"allow": "relaxing", "prompt": "protective", "forbidden": "protective"}
TRUST_STATES = {"trusted": "relaxing", "untrusted": "protective"}


def _codex(home: Path, known: frozenset[str]) -> list[Row]:
    codex_home = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
    if not exists(codex_home):
        return []
    config = codex_home / "config.toml"
    place = Place(CODEX, CODEX_SURFACE, get_relative_path(str(config)), "user")
    data = load_settings(config)
    values = _codex_values(data or {})
    rows = [row for key in CODEX_KEYS for row in _key_row(place, key, values)]
    if data is not None:
        rows += _codex_roots(place, data)
        rows += _codex_tool_modes(place, data)
        rows += _codex_trust(place, data, known)
    return [*rows, *_codex_rules(codex_home), *_codex_requirements()]


def _codex_values(data: dict[str, Any]) -> dict[str, Any]:
    """The config with a granular approval policy shown by its kind rather than its table."""
    policy = data.get("approval_policy")
    if isinstance(policy, dict) and set(policy) == {"granular"}:
        return {**data, "approval_policy": "granular"}
    return data


def _codex_roots(place: Place, data: dict[str, Any]) -> list[Row]:
    """Extra writable folders for the workspace-write sandbox, counted (CX-02)."""
    roots = lookup(data, "sandbox_workspace_write.writable_roots")
    count = len(roots) if isinstance(roots, list) else 0
    state = "relaxing" if count else "neutral"
    return [place.row("sandbox_workspace_write.writable_roots", str(count), state)]


def _codex_sections(data: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Every configured MCP server and app, by its section name."""
    for group in ("mcp_servers", "apps"):
        entries = data.get(group)
        for name, entry in entries.items() if isinstance(entries, dict) else []:
            if isinstance(entry, dict):
                yield f"{group}.{clean(str(name))}", entry
    plugins = data.get("plugins")
    for plugin, body in plugins.items() if isinstance(plugins, dict) else []:
        servers = body.get("mcp_servers") if isinstance(body, dict) else None
        for name, entry in servers.items() if isinstance(servers, dict) else []:
            if isinstance(entry, dict):
                yield f"plugins.{clean(str(plugin))}.mcp_servers.{clean(str(name))}", entry


def _codex_tool_modes(place: Place, data: dict[str, Any]) -> list[Row]:
    """Each server's and app's tool approval mode, and per-tool modes counted (CX-04)."""
    rows: list[Row] = []
    for section, entry in _codex_sections(data):
        name = f"{section}.{TOOL_MODES.name}"
        mode = entry.get(TOOL_MODES.name)
        if mode is None:
            default = APP_TOOL_DEFAULT if section.startswith("apps.") else TOOL_MODES.default
            rows.append(place.unset(name, default))
        else:
            rows.append(_value_row(place, TOOL_MODES, name, mode))
        rows += _per_tool_modes(place, section, entry.get("tools"))
    return rows


def _per_tool_modes(place: Place, section: str, tools: Any) -> list[Row]:
    found = [
        _value_row(place, TOOL_MODES, "", tool.get("approval_mode"))
        for tool in (tools.values() if isinstance(tools, dict) else [])
        if isinstance(tool, dict) and tool.get("approval_mode") is not None
    ]
    counts = Counter((row.value, row.state) for row in found)
    return [
        place.row(f"{section}.tools.approval_mode={value}", str(count), state)
        for (value, state), count in sorted(counts.items())
    ]


def _codex_trust(place: Place, data: dict[str, Any], known: frozenset[str]) -> list[Row]:
    """Folders marked trusted or untrusted, counted; a folder is named only if already known.

    Trust loads the folder's own Codex layers and makes workspace-write the default sandbox;
    untrusted makes every command no rule allows prompt (CX-01, CX-02).
    """
    projects = data.get("projects")
    levels: dict[str, list[str]] = {level: [] for level in TRUST_STATES}
    for folder, entry in projects.items() if isinstance(projects, dict) else []:
        level = entry.get("trust_level") if isinstance(entry, dict) else None
        if isinstance(level, str) and level in levels:
            levels[level].append(get_relative_path(str(folder)))
    return [
        place.row(f"projects.{level}", str(len(folders)),
                  TRUST_STATES[level] if folders else "neutral",
                  items=tuple(sorted(f for f in folders if f in known)))
        for level, folders in levels.items()
    ]  # fmt: skip


def _codex_rules(codex_home: Path) -> list[Row]:
    """Command rules by decision, with their blanked prefixes (CX-03).

    ``allow`` runs the command with no prompt and outside the sandbox; ``prompt`` asks;
    ``forbidden`` blocks even when approvals are off.
    """
    folder = codex_home / "rules"
    place = Place(CODEX, CODEX_SURFACE, get_relative_path(str(folder)), "user")
    found: dict[str, list[str]] = {decision: [] for decision in RULE_STATES}
    for path in sorted(folder.glob("*.rules")) if exists(folder) else []:
        for decision, prefix in prefix_rules(read_text(path) or ""):
            found[decision].append(prefix)
    return [
        place.row(f"rules.{decision}", str(len(prefixes)),
                  RULE_STATES[decision] if prefixes else "neutral", items=_items(prefixes))
        for decision, prefixes in found.items()
    ]  # fmt: skip


def prefix_rules(text: str) -> list[tuple[str, str]]:
    """(decision, command prefix) for each ``prefix_rule``; a rule without a decision allows."""
    rules: list[tuple[str, str]] = []
    starts = [match.end() for match in PREFIX_RULE.finditer(text)]
    ends = [*starts[1:], len(text)] if starts else []
    for start, end in zip(starts, ends, strict=True):
        body = text[start:end]
        decision = DECISION.search(body)
        rules.append((decision.group(1) if decision else "allow", _pattern_prefix(body)))
    return rules


def _pattern_prefix(body: str) -> str:
    """The leading plain words of a rule's ``pattern`` list."""
    match = PATTERN_LIST.search(body)
    if match is None:
        return ""
    try:
        tokens = ast.literal_eval(match.group(1))
    except (ValueError, SyntaxError, RecursionError, TypeError, MemoryError):
        return ""
    words: list[str] = []
    for token in tokens if isinstance(tokens, list) else []:
        if not isinstance(token, str):
            break
        words.append(token)
    return " ".join(words)


def _requirements_path() -> Path:
    if sys.platform == "win32":
        program_data = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
        return program_data / "OpenAI" / "Codex" / "requirements.toml"
    return Path("/etc/codex/requirements.toml")


def _codex_requirements() -> list[Row]:
    """Whether an admin requirements file constrains Codex, and its ``allowed_*`` lists."""
    path = _requirements_path()
    place = Place(CODEX, CODEX_SURFACE, str(path), "managed")
    if not exists(path):
        default = "no admin requirements constrain these settings (Codex managed configuration)"
        return [place.row("requirements.toml", "absent", "unset", default=default,
                          basis="documented default")]  # fmt: skip
    data = load_settings(path)
    if data is None:
        return [place.row("requirements.toml", "unreadable", "neutral")]
    rows = [place.row("requirements.toml", "present", "neutral")]
    for key in sorted(str(k) for k in data if str(k).startswith("allowed_")):
        values = data[key]
        if isinstance(values, list):
            rows.append(place.row(key, str(len(values)), "protective", items=_items(values)))
    return rows


# --- Cursor --------------------------------------------------------------------------------

CURSOR = "Cursor"
CURSOR_SANDBOX_KEYS = (
    Key("type", frozenset({"insecure_none"}),
        frozenset({"workspace_readwrite", "workspace_readonly"}),
        "workspace_readwrite: commands are sandboxed with read and write access to the "
        "workspace (CU-01)"),
    Key("networkPolicy.default", frozenset({"allow"}), frozenset({"deny"}),
        "deny, though the app's default network mode adds Cursor's own list of domains "
        "(CU-01)"),
    Key("readBoundary", frozenset({"system"}), frozenset({"workspace"}),
        "system: commands can read outside the workspace (Cursor sandbox reference)"),
)  # fmt: skip
CURSOR_ALLOWLISTS = ("terminalAllowlist", "mcpAllowlist")
CURSOR_IN_APP = "the in-app list applies; it is not stored in a documented file (CU-02)"
CURSOR_MODES = Key("approvalMode", frozenset({"unrestricted"}),
                   frozenset({"allowlist", "auto-review"}), "not documented (CU-02)",
                   basis="default not documented")  # fmt: skip
CURSOR_RUN_MODE = (
    "Auto-review is the app's default; the mode chosen in the app is not stored in a "
    "documented file, so the mode in use is unknown (CU-02)"
)
TOKEN = re.compile(r"^(\w+)\((.*)\)$")


def _cursor(home: Path, known: frozenset[str]) -> list[Row]:
    folder = home_path(home, "~/.cursor")
    if not exists(folder):
        return []
    rows: list[Row] = []
    for name, read in CURSOR_USER_FILES:
        rows += read(folder / name, "user", get_relative_path(str(folder / name)))
    for workspace in CursorDiscoverer(home)._discover_project_folders():
        for name, read in CURSOR_WORKSPACE_FILES:
            path = workspace / ".cursor" / name
            if exists(path):
                rows += read(path, "project", _shown(path, known))
    rows.append(Place(CURSOR, "IDE", "app", "app").unset("IDE run mode", CURSOR_RUN_MODE))
    return rows


def _cursor_sandbox(path: Path, scope: str, shown: str) -> list[Row]:
    """Sandbox type, network default and read boundary (CU-01); a workspace file overrides."""
    place = Place(CURSOR, "IDE", shown, scope)
    data = load_settings(path) or {}
    return [row for key in CURSOR_SANDBOX_KEYS
            for row in _key_row(place, key, data, skip_unset=scope == "project")]  # fmt: skip


def _cursor_allowlists(path: Path, scope: str, shown: str) -> list[Row]:
    """Commands and MCP tools that run without approval, counted with blanked entries (CU-02)."""
    place = Place(CURSOR, "IDE", shown, scope)
    data = load_settings(path) or {}
    rows = []
    for name in CURSOR_ALLOWLISTS:
        entries = data.get(name)
        if not isinstance(entries, list):
            rows.append(place.unset(name, CURSOR_IN_APP))
            continue
        state = "relaxing" if entries else "neutral"
        rows.append(place.row(name, str(len(entries)), state, items=_items(entries)))
    return rows


def _cursor_cli(path: Path, scope: str, shown: str) -> list[Row]:
    """The CLI's approval mode, and its allow and deny tokens counted by type (CU-02)."""
    data = load_settings(path)
    if data is None:
        return []
    place = Place(CURSOR, "CLI", shown, scope)
    rows = [] if scope == "project" else _key_row(place, CURSOR_MODES, data)
    for kind, state in (("allow", "relaxing"), ("deny", "protective")):
        tokens = lookup(data, f"permissions.{kind}")
        by_type: dict[str, list[str]] = {}
        for token in tokens if isinstance(tokens, list) else []:
            match = TOKEN.match(token) if isinstance(token, str) else None
            name, inner = (match.group(1), match.group(2)) if match else ("other", "")
            by_type.setdefault(name, []).append(inner)
        for name, inner in sorted(by_type.items()):
            items = _items(inner) if name == "Shell" else ()
            key = f"permissions.{kind}.{name}"
            rows.append(place.row(key, str(len(inner)), state, items=items))
    return rows


CURSOR_USER_FILES = (
    ("sandbox.json", _cursor_sandbox),
    ("permissions.json", _cursor_allowlists),
    ("cli-config.json", _cursor_cli),
)
CURSOR_WORKSPACE_FILES = (
    ("sandbox.json", _cursor_sandbox),
    ("permissions.json", _cursor_allowlists),
    ("cli.json", _cursor_cli),
)


# --- Claude Desktop device policy ----------------------------------------------------------

DESKTOP = "Claude Desktop"
DESKTOP_POLICY = "com.anthropic.claudefordesktop.plist"
DESKTOP_SWITCHES = (
    ("secureVmFeaturesEnabled", "Cowork"),
    ("isLocalDevMcpEnabled", "Desktop"),
    ("isDesktopExtensionEnabled", "Desktop"),
    ("isClaudeCodeForDesktopEnabled", "Code tab"),
)
FOLDERS_DEFAULT = "unrestricted: any folder the user can open can be attached to Cowork (CW-03)"
SWITCH_DEFAULT = "true: the feature is on (CW-03)"


def _desktop_policy(home: Path) -> list[Row]:
    """The documented device-policy keys (CW-03), from macOS managed-preferences profiles.

    A profile exists only on computers an organisation manages; with none, every key reads as
    its documented default. Other platforms keep the policy in the registry, which is not read.
    """
    if sys.platform != "darwin":
        return []
    profiles = (
        (MANAGED_PREFERENCES / DESKTOP_POLICY, str(MANAGED_PREFERENCES / DESKTOP_POLICY)),
        (MANAGED_PREFERENCES / home.name / DESKTOP_POLICY,
         f"{MANAGED_PREFERENCES}/<user>/{DESKTOP_POLICY}"),
    )  # fmt: skip
    present = [(data, shown) for path, shown in profiles if (data := load_settings(path))]
    if not present:
        return _policy_rows({}, str(MANAGED_PREFERENCES / DESKTOP_POLICY))
    return [row for data, shown in present for row in _policy_rows(data, shown)]


def _policy_rows(data: dict[str, Any], shown: str) -> list[Row]:
    folders = _folder_count(data.get("allowedWorkspaceFolders"))
    cowork = Place(DESKTOP, "Cowork", shown, "managed")
    rows = [cowork.unset("allowedWorkspaceFolders", FOLDERS_DEFAULT) if folders is None
            else cowork.row("allowedWorkspaceFolders", str(folders), "protective")]  # fmt: skip
    for key, surface in DESKTOP_SWITCHES:
        place = Place(DESKTOP, surface, shown, "managed")
        value = data.get(key)
        if isinstance(value, bool):
            rows.append(place.row(key, str(value).lower(), "neutral" if value else "protective"))
        else:
            rows.append(place.unset(key, SWITCH_DEFAULT))
    return rows


def _folder_count(value: Any) -> int | None:
    """How many folders the policy allows; a profile may hold a list or JSON text of one."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            return None
    return len(value) if isinstance(value, list) else None


# --- the value tables the scan checks for other agents ---------------------------------------

PROTECTIVE_VALUES = {"sessionDefaultSettings.autonomyLevel": frozenset({"off"})}
TABLE_DEFAULTS = {
    "sessionDefaultSettings.autonomyLevel": ("off (Factory settings documentation)",
                                             "documented default"),
}  # fmt: skip
TABLE_FILES = (
    ("Gemini CLI", "CLI", "~/.gemini/settings.json", GEMINI_SETTINGS),
    ("Factory", "Droid CLI", "~/.factory/settings.json", FACTORY_SETTINGS),
    ("Factory", "Droid CLI", "~/.factory/settings.local.json", FACTORY_SETTINGS),
)


def _table_keys(table: tuple[tuple[str, frozenset[str], str], ...]) -> list[Key]:
    keys = []
    for name, relaxing, _ in table:
        default, basis = TABLE_DEFAULTS.get(name, ("not documented", "default not documented"))
        keys.append(Key(name, relaxing, PROTECTIVE_VALUES.get(name, frozenset()), default, basis))
    return keys


def _tables(home: Path) -> list[Row]:
    """VS Code, Gemini CLI and Factory: the keys of the scan's value tables, every value."""
    files = [("VS Code", "Copilot in VS Code", path, VSCODE_SETTINGS)
             for editor in ("Code", "Code - Insiders")
             for path in _editor_user_settings(home, editor)]  # fmt: skip
    files += [(agent, surface, home_path(home, raw), table)
              for agent, surface, raw, table in TABLE_FILES]  # fmt: skip
    rows = []
    for agent, surface, path, table in files:
        data = load_settings(path)
        if data is None:
            continue
        place = Place(agent, surface, get_relative_path(str(path)), "user")
        rows += [row for key in _table_keys(table) for row in _key_row(place, key, data)]
    return rows
