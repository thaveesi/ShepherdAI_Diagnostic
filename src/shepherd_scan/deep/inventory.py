"""What the deep check needs from the scan's discovery, as plain data.

Claude Desktop session records are read for metadata only, through an allowlist: the approval
mode, the browser mode, whether a scheduled task started the session, the Claude Code version
recorded, which tools each connector offered, the tool switches and the rules added during the
session (blanked), and which project settings the session's folder picks up. The folder itself
is never sent: it is matched against the settings files already in the package and otherwise
reduced to a hash with a random salt made for this scan. Titles, prompts, messages, account names
and email addresses are never copied.

The installed Claude Code versions (``claude_versions``, read B) and the protection settings of
Codex, Cursor, Claude Desktop's device policy and the scan's value tables, written with
their values whether they protect or relax (``protections``, read C), come from their own
modules.

Company signals come from one approved exception to "never read values in oauth fields"
(2026-10-16): Claude Code's organization name, type and role, and the sign-in email's domain.
Tokens and the address itself are never read. Approved-command rules and hook commands are
blanked for secrets as they are collected, before anything is written or sent.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import sys
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

from shepherd_scan._vendor.discovery.agents.claude_desktop import ClaudeDesktopDiscoverer
from shepherd_scan._vendor.discovery.models.mcp import RemoteServer, StdioServer
from shepherd_scan._vendor.discovery.utils import get_relative_path, is_special_file
from shepherd_scan.apps.installed import FoundApp
from shepherd_scan.carry_on import attempt
from shepherd_scan.claude_versions import claude_code_versions
from shepherd_scan.deep.blank import clean
from shepherd_scan.deep.protections import protection_rows
from shepherd_scan.discovery import Discovery
from shepherd_scan.names import agent_name
from shepherd_scan.reach.acts import (
    CLAUDE_MANAGED,
    CLAUDE_MANAGED_OTHER,
    _claude_settings_files,
    grok_bot_setting,
)
from shepherd_scan.settings_files import load_settings

logger = logging.getLogger(__name__)

SESSION_FOLDERS = {
    "claude-code-sessions": "Claude Code in Claude Desktop",
    "local-agent-mode-sessions": "Claude Desktop agent mode",
}
# Desktop's own worktrees live under the project they belong to.
DESKTOP_WORKTREES = "/.claude/worktrees/"
TOOL_HINTS = ("readOnlyHint", "destructiveHint", "openWorldHint")
# Paths to recognise in launch commands, never used to create files.
TEMP_FOLDERS = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")  # noqa: S108
PACKAGE_LAUNCHERS = ("npx", "bunx", "pnpx", "uvx", "pipx")
PYTHON_LAUNCHERS = ("uvx", "pipx")
# Options that take a value, from each launcher's own help, so that value is not taken for the
# package. "--option=value" carries its value with it.
VALUE_OPTIONS = {
    "npx": {"-p", "--package", "-c", "--call", "-w", "--workspace", "--registry", "--cache",
            "--userconfig", "--prefix", "--loglevel", "--node-options", "--shell"},
    "bunx": {"-p", "--package"},
    "pnpx": {"--package", "--allow-build"},
    "uvx": {"--from", "-w", "--with", "--with-editable", "--with-requirements", "-c",
            "--constraints", "-b", "--build-constraints", "--overrides", "--env-file",
            "--python-platform", "--torch-backend", "--index", "--default-index", "-i",
            "--index-url", "--extra-index-url", "-f", "--find-links", "--index-strategy",
            "--keyring-provider", "-P", "--upgrade-package", "--resolution", "--prerelease",
            "--fork-strategy", "--exclude-newer", "--exclude-newer-package",
            "--no-sources-package", "--reinstall-package", "--link-mode", "-C",
            "--config-setting", "--config-settings-package", "--no-build-isolation-package",
            "--no-build-package", "--no-binary-package", "--cache-dir", "--refresh-package",
            "-p", "--python", "--color", "--allow-insecure-host", "--directory", "--project",
            "--config-file"},
    "pipx": {"--python-args", "--with", "--spec", "--python", "--fetch-python", "-i",
             "--index-url", "--pip-args", "--cooldown", "--backend"},
}  # fmt: skip
# Options that name the package when the command run has another name.
PACKAGE_OPTIONS = {
    "npx": ("--package", "-p"),
    "bunx": ("--package", "-p"),
    "pnpx": ("--package",),
    "uvx": ("--from",),
    "pipx": ("--spec",),
}
REMOTE_SOURCES = ("git+", "git:", "github:", "gitlab:", "bitbucket:", "gist:", "http:", "https:")
# A source given in place of a registry package, alone or after "name@" / "name @ ".
SOURCE = re.compile(r"(?:^|@\s*)((?:git\+|git:|github:|gitlab:|bitbucket:|gist:|https?:|file:)\S*)")
LOCAL_SOURCE = re.compile(r"[/~.]|file:|[A-Za-z]:[\\/]")
NPM_EXACT = re.compile(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
PYTHON_REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
    r"(?P<asked>(?:[=<>!~][^;]*?)?)\s*(?:;.*)?"
)
PLUGIN_PATH = re.compile(
    r"/plugins/cache/(?P<marketplace>[^/]+)/(?P<plugin>[^/]+)/(?P<version>[^/]+)/"
)
MANAGED_DEVICE_FOLDER = Path("/Library/Managed Preferences")
ORG_FIELDS = ("organizationName", "organizationType", "organizationRole")
EMAIL_ADDRESS = re.compile(r"[\w.+'-]+@([\w-]+(?:\.[\w-]+)+)")
# Claude Code guard settings whose value is copied (gate A, read C); nothing else in a file is.
GUARD_KEYS = (
    "permissions.disableBypassPermissionsMode",
    "permissions.disableAutoMode",
    "permissions.blockReadsOutsideWorkingDirectories",
    "disableAutoMode",
    "disableAllHooks",
    "skipDangerousModePermissionPrompt",
    "allowManagedPermissionRulesOnly",
    "allowManagedHooksOnly",
    "allowManagedMcpServersOnly",
)
SANDBOX_FLAGS = {
    "enabled": "enabled",
    "autoAllowBashIfSandboxed": "auto_allow",
    "allowUnsandboxedCommands": "allow_unsandboxed",
    "failIfUnavailable": "fail_if_unavailable",
}
SANDBOX_LISTS = {
    ("filesystem", "denyRead"): "deny_read",
    ("filesystem", "allowRead"): "allow_read",
    ("filesystem", "allowWrite"): "allow_write",
    ("filesystem", "denyWrite"): "deny_write",
    ("network", "allowedDomains"): "allowed_domains",
    ("network", "deniedDomains"): "denied_domains",
}
CREDENTIAL_FIELDS = ("credential_files", "credential_vars")
CREDENTIAL_MODES = ("deny", "mask")
CLAUDE_DEVICE_PROFILE = "com.anthropic.claudecode.plist"
READS = ("A", "B", "C")


@dataclass(frozen=True)
class SessionContext:
    """Which Claude Code settings files a Desktop session's folder picks up (read A).

    The folder is never sent. ``shared`` and ``cwd_local`` name the session folder's own
    settings files, and ``root_local`` its git root's local file, but only when those files are
    already in the package; ``folder`` is a hash that groups sessions of one folder. ``read`` is
    False for packages made before read A, so "unknown" is never mistaken for "none".
    """

    read: bool = False
    folder: str = ""
    home: bool = False
    shared: str = ""
    cwd_local: str = ""
    root_local: str = ""
    git: str = "unknown"


@dataclass(frozen=True)
class SessionTools:
    """The tools one connector offered a session: each tool's name and publisher annotations.

    ``uuid`` is the connector's id, which permission rules for app-delivered connectors use.
    """

    connector: str
    tools: tuple[dict[str, Any], ...]
    uuid: str = ""


@dataclass(frozen=True)
class SessionRule:
    """A permission change made during a session, its rules blanked, folders counted."""

    type: str
    destination: str
    behavior: str
    rules: tuple[str, ...]
    directories: int


@dataclass(frozen=True)
class Session:
    """One Claude Desktop session, metadata only."""

    kind: str
    permission_mode: str
    browser_mode: str
    scheduled: bool
    archived: bool
    last_active_ms: int
    connectors: tuple[str, ...]
    saved_approvals: int
    context: SessionContext = SessionContext()
    version: str = ""
    tools: tuple[SessionTools, ...] = ()
    tool_switches: tuple[tuple[str, bool], ...] = ()
    unmatched_switches: int = 0
    session_rules: tuple[SessionRule, ...] = ()


@dataclass(frozen=True)
class Connector:
    """A connector from the person's AI account, with its tool list."""

    app: str
    name: str
    tools: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class LocalServer:
    """An MCP server an agent starts or connects to, as configured."""

    agent: str
    name: str
    launcher: str
    package: str
    version: str
    location: str
    url_host: str = ""
    present: bool | None = None

    @property
    def pinned(self) -> bool:
        """Whether the configuration fixes the code a package launcher fetches.

        Only an exact release version or a full commit counts: tags such as latest or next,
        ranges such as ^1.2.0 or >=1.0, and branch or tag refs all follow new releases.
        """
        if self.launcher not in PACKAGE_LAUNCHERS:
            return False
        if self.package.startswith(REMOTE_SOURCES):
            return COMMIT.fullmatch(self.version) is not None
        if self.launcher in PYTHON_LAUNCHERS:
            return (
                self.version[:1].isalnum()
                and self.version != "latest"
                and not (set(self.version) & set("*,"))
            )
        return NPM_EXACT.fullmatch(self.version) is not None

    @property
    def from_temp_folder(self) -> bool:
        """Whether the program runs from a temporary folder."""
        return self.launcher == "path" and any(
            self.package.startswith(prefix) for prefix in TEMP_FOLDERS
        )


@dataclass(frozen=True)
class Sandbox:
    """A settings file's sandbox block: flags as written (None when unset), lists blanked.

    ``credential_files`` and ``credential_vars`` are the ``sandbox.credentials`` entries, each as
    (path or variable name, mode), where the mode is ``deny`` or ``mask``.
    """

    enabled: bool | None = None
    auto_allow: bool | None = None
    allow_unsandboxed: bool | None = None
    fail_if_unavailable: bool | None = None
    filesystem_disabled: bool | None = None
    strict_allowlist: bool | None = None
    excluded: tuple[str, ...] = ()
    deny_read: tuple[str, ...] = ()
    allow_read: tuple[str, ...] = ()
    allow_write: tuple[str, ...] = ()
    deny_write: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    denied_domains: tuple[str, ...] = ()
    credential_files: tuple[tuple[str, str], ...] = ()
    credential_vars: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ClaudeSettings:
    """One Claude Code settings file: approval mode, rules, hooks, sandbox and guards."""

    path: str
    project: bool
    default_mode: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    hooks: tuple[tuple[str, str, str], ...]
    all_project_servers: bool
    ask: tuple[str, ...] = ()
    managed: bool = False
    sandbox: Sandbox = Sandbox()
    guards: tuple[tuple[str, str], ...] = ()
    enabled_mcpjson: tuple[str, ...] = ()
    disabled_mcpjson: tuple[str, ...] = ()
    additional_directories: int = 0


@dataclass(frozen=True)
class Company:
    """Signals that the computer or the agent's account belongs to a company."""

    managed_device: bool = False
    claude_managed_settings: bool = False
    claude_org_name: str = ""
    claude_org_type: str = ""
    claude_org_role: str = ""
    email_domain: str = ""


@dataclass(frozen=True)
class AgentApp:
    """An AI app on the scan's app list found on this computer, as the list describes it.

    ``read`` is True when the scan also reads the app's own settings files, so it is in
    ``agents`` too. ``settings`` holds the permission settings the scan reads for the app.
    """

    name: str
    kind: str
    runs_commands: bool
    control: str
    can_do: str
    kept_elsewhere: str
    found: tuple[str, ...]
    read: bool
    settings: tuple[tuple[str, str], ...] = ()


@dataclass
class Inventory:
    """Everything the review reads, before any analysis.

    ``reads`` lists the gate A reads this scanner made ("A", "B", "C"); a package from an
    older scanner has none, so their fields read as unknown rather than empty. ``apps`` is None
    in a package from a scanner that did not send its app list.
    """

    sessions: list[Session] = field(default_factory=list)
    connectors: list[Connector] = field(default_factory=list)
    servers: list[LocalServer] = field(default_factory=list)
    claude_settings: list[ClaudeSettings] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    company: Company = field(default_factory=Company)
    logins: list[tuple[str, str]] = field(default_factory=list)
    reads: tuple[str, ...] = ()
    platform: str = ""
    claude_code_versions: dict[str, list[str]] = field(default_factory=dict)
    project_trust: dict[str, bool] = field(default_factory=dict)
    protections: list[dict[str, Any]] = field(default_factory=list)
    apps: list[AgentApp] | None = None

    def to_json(self) -> dict[str, Any]:
        """A JSON-ready copy, for the run folder (connector tool definitions included)."""
        return asdict(self)

    @classmethod
    def from_json(
        cls, data: dict[str, Any], failures: list[dict[str, str]] | None = None
    ) -> "Inventory":
        """Read back what ``to_json`` wrote, including packages from older scanners.

        Each field, and each entry of a list, is read on its own: one that does not read is
        left out and recorded in ``failures``.
        """

        def field(name: str, read: Callable[[], Any], default: Any) -> Any:
            return attempt(f"inventory: {name}", read, default, failures)

        def each(name: str, key: str, parse: Callable[[Any], Any]) -> list[Any]:
            parsed = []
            for item in data.get(key) or []:
                value = field(name, lambda item=item: parse(item), None)
                if value is not None:
                    parsed.append(value)
            return parsed

        return cls(
            sessions=each("a session", "sessions", _session_from),
            connectors=each("a connector", "connectors", lambda c: Connector(
                app=c["app"], name=c["name"], tools=tuple(c["tools"]))),
            servers=each("an MCP server", "servers", lambda server: LocalServer(**server)),
            claude_settings=each("a settings file", "claude_settings", _settings_from),
            agents=field("agents", lambda: list(data.get("agents") or []), []),
            company=field("company signals", lambda: Company(**data.get("company", {})), Company()),
            logins=field("saved sign-ins", lambda: [(str(what), str(where))
                                                    for what, where in data.get("logins", [])], []),
            reads=field("reads", lambda: tuple(str(read) for read in data.get("reads", ())), ()),
            platform=str(data.get("platform") or ""),
            claude_code_versions=field("Claude Code versions", lambda: {
                str(k): [str(v) for v in versions]
                for k, versions in (data.get("claude_code_versions") or {}).items()
            }, {}),
            project_trust=field("project trust", lambda: {
                str(k): bool(v) for k, v in (data.get("project_trust") or {}).items()}, {}),
            protections=field("protection settings",
                              lambda: [dict(row) for row in data.get("protections") or []], []),
            apps=field("AI apps", lambda: None if data.get("apps") is None
                       else [_app_from(a) for a in data["apps"]], None),
        )  # fmt: skip


def _app_from(data: dict[str, Any]) -> AgentApp:
    return AgentApp(
        name=str(data["name"]),
        kind=str(data["kind"]),
        runs_commands=bool(data["runs_commands"]),
        control=str(data.get("control") or ""),
        can_do=str(data.get("can_do") or ""),
        kept_elsewhere=str(data.get("kept_elsewhere") or ""),
        found=tuple(str(where) for where in data.get("found") or ()),
        read=bool(data.get("read")),
        settings=tuple((str(key), str(value)) for key, value in data.get("settings") or ()),
    )


def _settings_from(data: dict[str, Any]) -> ClaudeSettings:
    return ClaudeSettings(
        path=str(data["path"]),
        project=bool(data["project"]),
        default_mode=str(data["default_mode"]),
        allow=tuple(str(rule) for rule in data["allow"]),
        deny=tuple(str(rule) for rule in data["deny"]),
        hooks=tuple((str(e), str(m), str(c)) for e, m, c in data["hooks"]),
        all_project_servers=bool(data["all_project_servers"]),
        ask=tuple(str(rule) for rule in data.get("ask", ())),
        managed=bool(data.get("managed")),
        sandbox=_sandbox_from(data),
        guards=tuple((str(k), str(v)) for k, v in data.get("guards", ())),
        enabled_mcpjson=tuple(str(name) for name in data.get("enabled_mcpjson", ())),
        disabled_mcpjson=tuple(str(name) for name in data.get("disabled_mcpjson", ())),
        additional_directories=int(data.get("additional_directories") or 0),
    )


def _sandbox_from(data: dict[str, Any]) -> Sandbox:
    """The sandbox block, from this format or the older flat ``sandbox_*`` fields."""
    block = data.get("sandbox")
    if not isinstance(block, dict):
        auto = True if data.get("sandbox_auto_allow") else None
        return Sandbox(
            enabled=data.get("sandbox_enabled"),
            auto_allow=auto,
            excluded=tuple(str(c) for c in data.get("sandbox_excluded", ())),
        )
    values = {key: block[key] for key in Sandbox.__dataclass_fields__ if key in block}
    for key, value in values.items():
        if key in CREDENTIAL_FIELDS:
            values[key] = tuple((str(name), str(mode)) for name, mode in value)
        elif isinstance(value, list):
            values[key] = tuple(str(item) for item in value)
    return Sandbox(**values)


def _session_from(data: dict[str, Any]) -> Session:
    context = data.get("context")
    return Session(
        kind=str(data["kind"]),
        permission_mode=str(data["permission_mode"]),
        browser_mode=str(data["browser_mode"]),
        scheduled=bool(data["scheduled"]),
        archived=bool(data["archived"]),
        last_active_ms=int(data["last_active_ms"]),
        connectors=tuple(str(name) for name in data["connectors"]),
        saved_approvals=int(data["saved_approvals"]),
        context=SessionContext(**context) if isinstance(context, dict) else SessionContext(),
        version=str(data.get("version") or ""),
        tools=tuple(
            SessionTools(str(item["connector"]), tuple(item["tools"]), str(item.get("uuid") or ""))
            for item in data.get("tools") or []
        ),
        tool_switches=tuple((str(name), bool(on)) for name, on in data.get("tool_switches", ())),
        unmatched_switches=int(data.get("unmatched_switches") or 0),
        session_rules=tuple(
            SessionRule(
                str(rule["type"]),
                str(rule["destination"]),
                str(rule["behavior"]),
                tuple(str(r) for r in rule["rules"]),
                int(rule["directories"]),
            )
            for rule in data.get("session_rules") or []
        ),
    )


def build_inventory(
    discovery: Discovery, home: Path, failures: list[dict[str, str]] | None = None
) -> Inventory:
    """Read sessions, connectors, servers and Claude Code settings for one person.

    Each reader runs on its own: one that fails leaves its field empty and is recorded in
    ``failures`` as ``"inventory: <what>"``.
    """

    def read(part: str, run: Callable[[], Any], default: Any) -> Any:
        return attempt(f"inventory: {part}", run, default, failures)

    agents = read("agents", lambda: sorted({agent_name(p.client) for p in discovery.paths
                                            if p.client}), [])  # fmt: skip
    settings = read("Claude Code settings", lambda: claude_settings(home), [])
    return Inventory(
        sessions=read("Claude Desktop sessions",
                      lambda: desktop_sessions(home, [s.path for s in settings]), []),
        connectors=read("connectors", lambda: [
            Connector(app=c.app, name=c.name, tools=tuple(c.tools)) for c in discovery.connectors
        ], []),
        servers=read("MCP servers", lambda: local_servers(discovery), []),
        claude_settings=settings,
        agents=agents,
        company=read("company signals", lambda: company_signals(home), Company()),
        logins=read("saved sign-ins",
                    lambda: [(login.what, login.where) for login in discovery.logins], []),
        reads=READS,
        platform=sys.platform,
        claude_code_versions=read("Claude Code versions", lambda: claude_code_versions(home), {}),
        project_trust=read("project trust", lambda: project_trust(home, settings), {}),
        protections=read("protection settings",
                         lambda: protection_rows(home, project_folders(settings)), []),
        apps=read("AI apps", lambda: [agent_app(found, home) for found in discovery.apps], []),
    )  # fmt: skip


def _grok_bot_settings(home: Path) -> tuple[tuple[str, str], ...]:
    value, cap = grok_bot_setting(home)
    return (("localToolPermission", value or "not set"),
            ("localToolPermissionCeiling", cap or "not set"))  # fmt: skip


APP_SETTINGS: dict[str, Callable[[Path], tuple[tuple[str, str], ...]]] = {
    "grok-bot": _grok_bot_settings,
}


def agent_app(found: FoundApp, home: Path) -> AgentApp:
    """An installed app as the app list describes it, with the settings the scan reads for it."""
    entry = found.entry
    read_settings = APP_SETTINGS.get(entry.id)
    return AgentApp(
        name=entry.name,
        kind=entry.kind,
        runs_commands=entry.runs_commands,
        control=entry.control or "",
        can_do=entry.can_do or "",
        kept_elsewhere=entry.kept_elsewhere or "",
        found=tuple(sighting.describe() for sighting in found.sightings),
        read=entry.agent is not None,
        settings=read_settings(home) if read_settings else (),
    )


def project_folders(settings: list[ClaudeSettings]) -> set[str]:
    """The ``~`` paths of the project folders whose settings files are in the package."""
    return {s.path.split("/.claude/", 1)[0] for s in settings if s.project}


# --- Claude Desktop session records (read A) -------------------------------------------------


@dataclass(frozen=True)
class _Reader:
    """What reading session records needs: the home folder, known settings files, the salt."""

    home: Path
    settings_paths: frozenset[str]
    salt: bytes


def desktop_sessions(home: Path, settings_paths: Iterable[str] = ()) -> list[Session]:
    """Claude Desktop's session records under ``home``, metadata only.

    Args:
        home: The home folder being scanned.
        settings_paths: The ``~`` paths of the Claude Code settings files in the package; a
            session's folder is named only through these.
    """
    install_dir = ClaudeDesktopDiscoverer(home)._install_dir()
    if install_dir is None:
        return []
    reader = _Reader(home, frozenset(settings_paths), secrets.token_bytes(16))
    sessions: list[Session] = []
    for folder, kind in SESSION_FOLDERS.items():
        for path in sorted(install_dir.glob(f"{folder}/*/*/local_*.json")):
            if _checked(path, Path.is_symlink, default=True) or is_special_file(path):
                continue
            session = _session(path, kind, reader)
            if session is not None:
                sessions.append(session)
    return sessions


def _session(path: Path, kind: str, reader: _Reader) -> Session | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        logger.warning("Could not read a Claude Desktop session record: %s", path.name)
        return None
    if not isinstance(data, dict):
        return None
    servers = _list(data.get("remoteMcpServersConfig"))
    names = tuple(str(entry.get("name")) for entry in servers if entry.get("name"))
    approvals = [data.get("alwaysAllowedReasons"), data.get("sessionPermissionUpdates")]
    last_active = data.get("lastActivityAt")
    tools, keys = _session_tools(servers)
    switches, unmatched = _switches(data.get("enabledMcpTools"), keys)
    return Session(
        kind=kind,
        permission_mode=str(data.get("permissionMode") or ""),
        browser_mode=str(data.get("chromePermissionMode") or ""),
        scheduled=bool(data.get("scheduledTaskId")),
        archived=bool(data.get("isArchived")),
        last_active_ms=last_active if isinstance(last_active, int) else 0,
        connectors=names,
        saved_approvals=sum(len(value) for value in approvals if isinstance(value, list)),
        context=_context(data.get("cwd"), reader),
        version=_recorded_version(data),
        tools=tools,
        tool_switches=switches,
        unmatched_switches=unmatched,
        session_rules=_session_rules(data.get("sessionPermissionUpdates")),
    )


def _list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _recorded_version(data: dict[str, Any]) -> str:
    """The Claude Code version a session record names, from its tool or prompt snapshot."""
    for snapshot in ("toolSurfaceSnapshot", "promptAppendSnapshot"):
        block = data.get(snapshot)
        version = block.get("cliVersion") if isinstance(block, dict) else None
        if isinstance(version, str) and re.fullmatch(r"\d+(?:\.\d+){1,3}", version):
            return version
    return ""


def _session_tools(
    servers: list[dict[str, Any]],
) -> tuple[tuple[SessionTools, ...], dict[str, str]]:
    """Each connector's offered tools (name, title, hints) and the switch keys of its tools."""
    offered: list[SessionTools] = []
    keys: dict[str, str] = {}
    for server in servers:
        tools = []
        for tool in _list(server.get("tools")):
            name = tool.get("name")
            if not isinstance(name, str):
                continue
            raw = tool.get("annotations")
            annotations: dict[str, Any] = raw if isinstance(raw, dict) else {}
            kept = {h: annotations[h] for h in TOOL_HINTS if isinstance(annotations.get(h), bool)}
            if isinstance(annotations.get("title"), str):
                kept["title"] = annotations["title"]
            tools.append({"name": name, "annotations": kept})
            if isinstance(tool.get("enabledKey"), str):
                keys[tool["enabledKey"]] = name
        if tools:
            uuid = server.get("uuid")
            offered.append(SessionTools(str(server.get("name") or ""), tuple(tools),
                                        uuid if isinstance(uuid, str) else ""))  # fmt: skip
    return tuple(offered), keys


def _switches(value: Any, keys: dict[str, str]) -> tuple[tuple[tuple[str, bool], ...], int]:
    """Tool switches flipped in a session, by tool name, and how many named no known tool."""
    if not isinstance(value, dict):
        return (), 0
    found = [(keys[key], on) for key, on in value.items() if key in keys and isinstance(on, bool)]
    return tuple(sorted(found)), sum(1 for key in value if key not in keys)


def _session_rules(value: Any) -> tuple[SessionRule, ...]:
    """Permission changes made during a session: their kind and blanked rules, folders counted."""
    rules = []
    for update in _list(value):
        written = [_rule_text(rule) for rule in _list(update.get("rules"))]
        directories = update.get("directories")
        rules.append(
            SessionRule(
                type=str(update.get("type") or ""),
                destination=str(update.get("destination") or ""),
                behavior=str(update.get("behavior") or ""),
                rules=tuple(clean(text) for text in written if text),
                directories=len(directories) if isinstance(directories, list) else 0,
            )
        )
    return tuple(rules)


def _rule_text(rule: dict[str, Any]) -> str:
    """A rule in settings-file form, such as ``Bash(npm test)``."""
    tool = rule.get("toolName")
    content = rule.get("ruleContent")
    if not isinstance(tool, str):
        return ""
    return f"{tool}({content})" if isinstance(content, str) and content else tool


def _context(cwd: Any, reader: _Reader) -> SessionContext:
    """The settings files a session's folder picks up, named only when already in the package."""
    if not isinstance(cwd, str) or not cwd.startswith("/"):
        return SessionContext(read=True)
    folder = Path(cwd)
    root, git = _git_root(folder, reader.home)
    return SessionContext(
        read=True,
        folder=hashlib.sha256(reader.salt + cwd.encode("utf-8", "surrogatepass")).hexdigest()[:16],
        home=folder == reader.home,
        shared=_known(folder, "settings.json", reader),
        cwd_local=_known(folder, "settings.local.json", reader),
        root_local=_known(root, "settings.local.json", reader) if root and root != folder else "",
        git=git,
    )


def _known(folder: Path, name: str, reader: _Reader) -> str:
    """The ``~`` path of a folder's settings file, if that file is in the package."""
    path = get_relative_path(str(folder / ".claude" / name))
    return path if path in reader.settings_paths else ""


def _git_root(folder: Path, home: Path) -> tuple[Path | None, str]:
    """The git repository root at or above a folder, up to the home folder, and how it sits.

    Only the presence and owner of ``.git`` entries are checked; nothing is read from them. A
    worktree's main checkout is known only for Desktop's own worktrees, from their path. The
    search stops at the home folder, so folders outside it are never probed.
    """
    text = folder.as_posix()
    if DESKTOP_WORKTREES in text:
        return Path(text.split(DESKTOP_WORKTREES, 1)[0]), "worktree"
    parents = [p for p in folder.parents if p == home or home in p.parents]
    for candidate in (folder, *parents):
        marker = candidate / ".git"
        try:
            if not marker.exists():
                continue
            if marker.is_file():
                return None, "worktree"
            owner = getattr(os, "getuid", None)
            if owner is not None and marker.stat().st_uid != owner():
                return None, "none"
        except OSError:
            return None, "unknown"
        return candidate, "root" if candidate == folder else "inside"
    return None, "none"


def project_trust(home: Path, settings: list[ClaudeSettings]) -> dict[str, bool]:
    """Recorded workspace trust for the project folders whose settings files are in the package.

    Only ``projects.<folder>.hasTrustDialogAccepted`` is read from ``~/.claude.json``.
    """
    projects = (_read_json(home / ".claude.json") or {}).get("projects")
    if not isinstance(projects, dict):
        return {}
    wanted = project_folders(settings)
    trust: dict[str, bool] = {}
    for folder, entry in projects.items():
        if not isinstance(folder, str) or not isinstance(entry, dict):
            continue
        accepted = entry.get("hasTrustDialogAccepted")
        masked = get_relative_path(folder)
        if masked in wanted and isinstance(accepted, bool):
            trust[masked] = accepted
    return trust


# --- MCP servers ------------------------------------------------------------------------------


def local_servers(discovery: Discovery) -> list[LocalServer]:
    """Every configured MCP server, with how it is launched."""
    servers: list[LocalServer] = []
    for path in discovery.paths:
        for server in path.servers:
            location = get_relative_path(server.config_path or path.path)
            servers.append(
                _local_server(agent_name(path.client), server.name, server.server, location)
            )
    return servers


def _local_server(
    agent: str, name: str, config: StdioServer | RemoteServer, location: str
) -> LocalServer:
    if isinstance(config, RemoteServer):
        host = _host(config.url)
        return LocalServer(agent, name, "remote", host, "", location, url_host=host)
    program = config.command
    launcher = PurePosixPath(program).name
    if launcher in PACKAGE_LAUNCHERS:
        package, version = package_spec(launcher, config.args)
        if not LOCAL_SOURCE.match(package):
            return LocalServer(agent, name, launcher, package, version, location)
        program = _file_path(package) if package.startswith("file:") else package
    return LocalServer(
        agent, name, "path", get_relative_path(program), "", location, present=_present(program)
    )


def _host(url: str) -> str:
    """The host a remote server's address names, or "" when the address does not parse."""
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""


def _file_path(source: str) -> str:
    """The path a ``file:`` package source names; the source itself when it does not parse."""
    try:
        return urlsplit(source).path
    except ValueError:
        return source


def _present(program: str) -> bool | None:
    """Whether an absolute program path exists; None when relative or when it can't be checked."""
    try:
        path = Path(program).expanduser()
        return path.exists() if path.is_absolute() else None
    except (OSError, RuntimeError, ValueError):
        return None


def package_spec(launcher: str, args: list[str]) -> tuple[str, str]:
    """The package a launcher runs and the version, range, tag or ref it asks for.

    Returns ("", "") when no package is named. A source URL is returned without any login it
    carries. A folder on this computer is returned as written, with no version.
    """
    options, command = _launcher_args(launcher, args)
    named = (options[option] for option in PACKAGE_OPTIONS.get(launcher, ()) if option in options)
    spec = next(named, command).strip()
    if found := SOURCE.search(spec):
        source = found[1]
        return (source, "") if source.startswith("file:") else _source_ref(source)
    if LOCAL_SOURCE.match(spec):
        return spec, ""
    if launcher in PYTHON_LAUNCHERS:
        return _python_spec(spec)
    if "/" in spec and not spec.startswith("@"):
        return _source_ref(f"github:{spec}")
    at = spec.rfind("@")
    return (spec[:at], spec[at + 1 :]) if at > 0 else (spec, "")


def _python_spec(spec: str) -> tuple[str, str]:
    """A Python requirement's name, and the version after == or @ or else the range (">=1.0")."""
    head, at, version = spec.partition("@")
    match = PYTHON_REQUIREMENT.fullmatch(head.strip())
    if match is None:
        return spec, ""
    if at:
        return match["name"], version.strip()
    asked = match["asked"].replace(" ", "")
    if asked.startswith("==") and "," not in asked:
        return match["name"], asked.lstrip("=")
    return match["name"], asked


def _launcher_args(launcher: str, args: list[str]) -> tuple[dict[str, str], str]:
    """The launcher's own options with their values, and the first argument after them."""
    rest = args[1:] if launcher == "pipx" and args[:1] == ["run"] else args
    takes_value = VALUE_OPTIONS.get(launcher, set())
    options: dict[str, str] = {}
    index = 0
    while index < len(rest):
        arg = rest[index]
        if arg == "--" or not arg.startswith("-"):
            after = rest[index + 1 :] if arg == "--" else rest[index:]
            return options, after[0] if after else ""
        option, has_value, value = arg.partition("=")
        if not has_value and option in takes_value:
            index += 1
            value = rest[index] if index < len(rest) else ""
        options.setdefault(option, value)
        index += 1
    return options, ""


def _source_ref(spec: str) -> tuple[str, str]:
    """A git or archive source without its login or query, and the ref it asks for."""
    source, _, fragment = spec.partition("#")
    try:
        parts = urlsplit(source)
    except ValueError:
        return re.sub(r"//[^/@]*@", "//", source.partition("?")[0]), ""
    path, at, ref = parts.path.rpartition("@")
    if not at:
        path, ref = parts.path, ""
    if not ref and "=" not in fragment:
        ref = fragment
    host = parts.netloc.rpartition("@")[2]
    return urlunsplit((parts.scheme, host, path, "", "")), ref


# --- Claude Code settings files ---------------------------------------------------------------


def claude_settings(home: Path) -> list[ClaudeSettings]:
    """Claude Code's settings files: user, managed and every recorded project.

    Managed policy also comes from drop-in files beside ``managed-settings.json`` and, on macOS,
    from the ``com.anthropic.claudecode`` device profile (CC-22); each becomes a managed entry.
    """
    managed = Path(CLAUDE_MANAGED.get(sys.platform, CLAUDE_MANAGED_OTHER))
    found: list[ClaudeSettings] = []
    for path, project in _claude_settings_files(home):
        data = _read_json(path)
        if data is not None:
            found.append(settings_entry(path, project, data, managed=path == managed))
    for path, shown in _managed_sources(home, managed):
        data = load_settings(path)
        if data is not None:
            entry = settings_entry(path, False, data, managed=True)
            found.append(replace(entry, path=shown))
    return found


def _managed_sources(home: Path, managed: Path) -> list[tuple[Path, str]]:
    """Drop-in policy files, in the order Claude Code merges them, and the device profiles.

    A per-user profile's folder carries the account name, which is replaced before it is sent.
    """
    folder = managed.parent / "managed-settings.d"
    try:
        drop_ins = sorted(folder.glob("*.json")) if folder.is_dir() else []
    except OSError:
        drop_ins = []
    sources = [(path, get_relative_path(str(path))) for path in drop_ins]
    if sys.platform == "darwin":
        computer = MANAGED_DEVICE_FOLDER / CLAUDE_DEVICE_PROFILE
        user = MANAGED_DEVICE_FOLDER / home.name / CLAUDE_DEVICE_PROFILE
        sources.append((computer, str(computer)))
        sources.append((user, f"{MANAGED_DEVICE_FOLDER}/<user>/{CLAUDE_DEVICE_PROFILE}"))
    return sources


def settings_entry(
    path: Path, project: bool, data: dict[str, Any], *, managed: bool = False
) -> ClaudeSettings:
    """One settings file as the deep check records it: only the allowlisted keys, blanked."""
    raw = data.get("permissions")
    permissions: dict[str, Any] = raw if isinstance(raw, dict) else {}
    directories = permissions.get("additionalDirectories")
    return ClaudeSettings(
        path=get_relative_path(str(path)),
        project=project,
        default_mode=str(permissions.get("defaultMode") or ""),
        allow=_strings(permissions.get("allow")),
        deny=_strings(permissions.get("deny")),
        hooks=tuple(_hooks(data.get("hooks"))),
        all_project_servers=data.get("enableAllProjectMcpServers") is True,
        ask=_strings(permissions.get("ask")),
        managed=managed,
        sandbox=_sandbox(data.get("sandbox")),
        guards=_guards(data),
        enabled_mcpjson=_strings(data.get("enabledMcpjsonServers")),
        disabled_mcpjson=_strings(data.get("disabledMcpjsonServers")),
        additional_directories=len(directories) if isinstance(directories, list) else 0,
    )


def _sandbox(value: Any) -> Sandbox:
    """The documented sandbox keys of a settings file; anything else in the block is ignored."""
    block: dict[str, Any] = value if isinstance(value, dict) else {}
    flags = {
        name: block[key] for key, name in SANDBOX_FLAGS.items() if isinstance(block.get(key), bool)
    }
    lists = {}
    for (group, key), name in SANDBOX_LISTS.items():
        section = block.get(group)
        lists[name] = _strings(section.get(key)) if isinstance(section, dict) else ()
    filesystem = block.get("filesystem")
    network = block.get("network")
    disabled = filesystem.get("disabled") if isinstance(filesystem, dict) else None
    strict = network.get("strictAllowlist") if isinstance(network, dict) else None
    credentials = block.get("credentials")
    return Sandbox(
        **flags,
        **lists,
        filesystem_disabled=disabled if isinstance(disabled, bool) else None,
        strict_allowlist=strict if isinstance(strict, bool) else None,
        excluded=_strings(block.get("excludedCommands")),
        credential_files=_credential_entries(credentials, "files", "path"),
        credential_vars=_credential_entries(credentials, "envVars", "name"),
    )


def _credential_entries(block: Any, key: str, field_name: str) -> tuple[tuple[str, str], ...]:
    """``sandbox.credentials`` entries as (path or variable, mode); mask options are not read.

    An entry with any other mode is ignored, as Claude Code drops it.
    """
    entries = block.get(key) if isinstance(block, dict) else None
    found = []
    for item in entries if isinstance(entries, list) else []:
        if not isinstance(item, dict) or item.get("mode") not in CREDENTIAL_MODES:
            continue
        if isinstance(item.get(field_name), str):
            found.append((clean(item[field_name]), str(item["mode"])))
    return tuple(found)


def _guards(data: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """The guard settings a file sets, each as (key, value) with simple values only."""
    found = []
    for key in GUARD_KEYS:
        value = _dotted(data, key)
        if isinstance(value, bool):
            found.append((key, str(value).lower()))
        elif isinstance(value, str) and len(value) <= 20:
            found.append((key, value))
    return tuple(found)


def _dotted(data: dict[str, Any], key: str) -> Any:
    head, _, rest = key.partition(".")
    value = data.get(head)
    if not rest:
        return value
    return value.get(rest) if isinstance(value, dict) else None


def company_signals(home: Path) -> Company:
    """Whether the computer is company-managed, and which organization Claude Code signs in to."""
    managed = Path(CLAUDE_MANAGED.get(sys.platform, CLAUDE_MANAGED_OTHER))
    account = (_read_json(home / ".claude.json") or {}).get("oauthAccount")
    fields: dict[str, Any] = account if isinstance(account, dict) else {}
    email = fields.get("emailAddress")
    return Company(
        managed_device=_checked(MANAGED_DEVICE_FOLDER, Path.is_dir),
        claude_managed_settings=_checked(managed, Path.is_file),
        claude_org_name=EMAIL_ADDRESS.sub(r"@\1", str(fields.get(ORG_FIELDS[0]) or "")),
        claude_org_type=str(fields.get(ORG_FIELDS[1]) or ""),
        claude_org_role=str(fields.get(ORG_FIELDS[2]) or ""),
        email_domain=email.rsplit("@", 1)[-1].lower()
        if isinstance(email, str) and "@" in email
        else "",
    )


def _checked(path: Path, check: Callable[[Path], bool], *, default: bool = False) -> bool:
    """A file-type check, or ``default`` when the terminal may not look (macOS privacy)."""
    try:
        return check(path)
    except OSError:
        logger.warning("Could not check %s", get_relative_path(str(path)))
        return default


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        logger.warning("Could not read Claude Code settings: %s", get_relative_path(str(path)))
        return None
    return data if isinstance(data, dict) else None


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(clean(item) for item in value if isinstance(item, str))


def _hooks(value: Any) -> list[tuple[str, str, str]]:
    """(event, matcher, command) for every command hook."""
    hooks: list[tuple[str, str, str]] = []
    if not isinstance(value, dict):
        return hooks
    for event, entries in value.items():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            matcher = str(entry.get("matcher") or "*")
            listed = entry.get("hooks")
            for hook in listed if isinstance(listed, list) else []:
                if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                    hooks.append((str(event), matcher, clean(hook["command"])))
    return hooks


def plugin_of(install_location: str) -> dict[str, str] | None:
    """Marketplace, plugin and version for a skill installed from a plugin marketplace."""
    match = PLUGIN_PATH.search(install_location)
    if match is None:
        return None
    root = install_location[: match.end()].rstrip("/")
    return {**match.groupdict(), "root": root}
