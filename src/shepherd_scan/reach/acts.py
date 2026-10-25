"""Part 1 of the reach section: agents set to act without asking.

Each app's settings files are compared against a fixed table of settings and defaults taken
from the app's documentation and source code.
Only the named settings are looked up. Pre-approved commands are checked against a fixed list
of programs that can start any other program (see ``commands``). Nothing is run.
"""

import ast
import logging
import os
import re
import sys
from collections.abc import Callable, Iterable, Sized
from pathlib import Path
from typing import Any

from shepherd_scan._vendor.discovery.agents.claude_code import ClaudeCodeDiscoverer
from shepherd_scan._vendor.discovery.utils import get_relative_path
from shepherd_scan.claude_versions import active_terminal_version, start_mode_warning
from shepherd_scan.names import agent_name
from shepherd_scan.reach.commands import (
    approval_runs_any_program,
    command_prefix,
    describe,
    regex_prefix,
    runs_any_program,
)
from shepherd_scan.report.model import ReachFinding
from shepherd_scan.settings_files import exists, home_path, load_settings, lookup, read_text

logger = logging.getLogger(__name__)

PROGRAMS_SHOWN = 6
Present = set[str]
Check = Callable[[Path, Present], list[ReachFinding]]


def acts_without_asking(home: Path, present: Present) -> list[ReachFinding]:
    """Every "acts without asking" finding for the apps on this computer.

    Args:
        home: The home folder being scanned.
        present: Identifiers of the apps found (app list ids and discovery identifiers).

    Returns:
        Findings in a fixed app order.
    """
    findings: list[ReachFinding] = []
    for app, check in CHECKS:
        try:
            findings.extend(check(home, present))
        except Exception as error:  # one app's unexpected settings must not stop the scan
            logger.warning("Could not check %s settings under %s (%s)", app, home.as_posix(), error)
    return merge_repeats(findings)


PLACES_SHOWN = 3


def merge_repeats(findings: list[ReachFinding]) -> list[ReachFinding]:
    """One row per app and finding, listing every settings file it was found in."""
    groups: dict[tuple[str, str, str, str], list[ReachFinding]] = {}
    for finding in findings:
        key = (finding.part, finding.app, finding.what, finding.basis)
        groups.setdefault(key, []).append(finding)
    merged: list[ReachFinding] = []
    for group in groups.values():
        places = list(dict.fromkeys(finding.where for finding in group if finding.where))
        if len(places) <= 1:
            merged.append(group[0])
            continue
        shown = "; ".join(places[:PLACES_SHOWN])
        more = f"; and {len(places) - PLACES_SHOWN} more" if len(places) > PLACES_SHOWN else ""
        what = f"{group[0].what} (set in {len(places)} settings files)"
        merged.append(group[0].model_copy(update={"what": what, "where": shown + more}))
    return merged


# --- shared helpers -------------------------------------------------------------------------


def _finding(
    app: str, what: str, where: Path | str | None, *, default: bool = False
) -> ReachFinding:
    location = get_relative_path(where.as_posix()) if isinstance(where, Path) else where
    basis = "default" if default else "setting"
    return ReachFinding(part="acts", app=app, what=what, where=location, basis=basis)


def _texts(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _approved_programs(
    app: str, prefixes: Iterable[str], where: Path, total: int
) -> list[ReachFinding]:
    """One finding when pre-approved command prefixes include any that can run every program."""
    cleaned = ["" if prefix.strip() in ("*", ":*") else prefix.strip() for prefix in prefixes]
    risky = sorted({describe(prefix) for prefix in cleaned if runs_any_program(prefix)})
    if not risky:
        return []
    shown = ", ".join(risky[:PROGRAMS_SHOWN]) + (", …" if len(risky) > PROGRAMS_SHOWN else "")
    if "any command" in risky:
        what = "Runs any command without asking"
    else:
        noun = "command" if total == 1 else "commands"
        what = (
            f"{total} pre-approved {noun}, including {len(risky)} that can start any program "
            f"({shown})"
        )
    return [_finding(app, what, where)]


def _matching_values(
    app: str, data: dict[str, Any], table: tuple[tuple[str, frozenset[str], str], ...], where: Path
) -> list[ReachFinding]:
    """Findings for settings whose value is one of the listed "acts without asking" values."""
    findings: list[ReachFinding] = []
    for key, values, what in table:
        value = lookup(data, key)
        if isinstance(value, bool):
            value = str(value).lower()
        if isinstance(value, str) and value.lower() in values:
            findings.append(_finding(app, f"{what} ({key}: {value})", where))
    return findings


def _editor_user_settings(home: Path, editor: str) -> list[Path]:
    """A VS Code-family editor's user settings file and its profiles' settings files."""
    if sys.platform == "darwin":
        root = home_path(home, f"~/Library/Application Support/{editor}/User")
    elif sys.platform == "win32":
        root = home_path(home, f"~/AppData/Roaming/{editor}/User")
    else:
        root = home_path(home, f"~/.config/{editor}/User")
    paths = [root / "settings.json"]
    try:
        profiles = sorted((root / "profiles").iterdir()) if exists(root / "profiles") else []
    except OSError:
        profiles = []
    paths.extend(profile / "settings.json" for profile in profiles)
    return paths


# --- Claude Code ----------------------------------------------------------------------------

CLAUDE_MODES = {
    "bypassPermissions": "Runs every action without asking",
    "auto": "An automatic check approves actions instead of asking you",
    "acceptEdits": "Edits files and runs file commands such as mkdir and mv without asking",
}
CLAUDE_MANAGED = {
    "darwin": "/Library/Application Support/ClaudeCode/managed-settings.json",
    "win32": "C:/Program Files/ClaudeCode/managed-settings.json",
}
CLAUDE_MANAGED_OTHER = "/etc/claude-code/managed-settings.json"
CLAUDE_APPROVAL_HOOKS = ("PreToolUse", "PermissionRequest")
MCP_SERVER_RULE = re.compile(r"^mcp__([^_*]+(?:_[^_*]+)*)(?:__\*)?$")


def _claude_code(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("claude code")
    findings: list[ReachFinding] = []
    mode_chosen = auto_disabled = False
    for path, is_project in _claude_settings_files(home):
        data = load_settings(path)
        if not data:
            continue
        if not is_project:
            mode_chosen = mode_chosen or lookup(data, "permissions.defaultMode") is not None
            auto_disabled = auto_disabled or _claude_auto_disabled(data)
        findings.extend(_claude_file(app, data, path, project=is_project))
    warning = start_mode_warning(active_terminal_version(home))
    if (
        warning
        and not (mode_chosen or auto_disabled)
        and ({"claude-code", "claude code"} & present)
    ):
        findings.append(
            _finding(
                app,
                warning,
                "~/.claude/settings.json (permissions.defaultMode not set)",
                default=True,
            )
        )
    return findings


def _claude_settings_files(home: Path) -> list[tuple[Path, bool]]:
    """Each Claude Code settings file once, with whether it is a project's file.

    User and managed files come first: when the home folder is itself one of the recorded
    projects, its ``.claude/settings.json`` is the user file. ``settings.local.json`` is always
    a project's file, including the home folder's.
    """
    user = [
        home_path(home, "~/.claude/settings.json"),
        Path(CLAUDE_MANAGED.get(sys.platform, CLAUDE_MANAGED_OTHER)),
    ]
    projects = [
        folder / ".claude" / name
        for folder in [home, *ClaudeCodeDiscoverer(home)._discover_project_folders()]
        for name in ("settings.json", "settings.local.json")
    ]
    files: dict[Path, tuple[Path, bool]] = {}
    for path in user:
        files.setdefault(_same_file_key(path), (path, False))
    for path in projects:
        files.setdefault(_same_file_key(path), (path, True))
    return list(files.values())


def _same_file_key(path: Path) -> Path:
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        return path


def _claude_auto_disabled(data: dict[str, Any]) -> bool:
    values = (lookup(data, "disableAutoMode"), lookup(data, "permissions.disableAutoMode"))
    return "disable" in values


def _claude_file(
    app: str, data: dict[str, Any], path: Path, *, project: bool
) -> list[ReachFinding]:
    findings: list[ReachFinding] = []
    mode = lookup(data, "permissions.defaultMode")
    # Since v2.1.257, auto and bypass modes in project files are ignored.
    if mode in CLAUDE_MODES and not (project and mode in ("auto", "bypassPermissions")):
        findings.append(_finding(app, f"{CLAUDE_MODES[mode]} (permission mode: {mode})", path))
    findings.extend(_claude_allow_rules(app, _texts(lookup(data, "permissions.allow")), path))
    if lookup(data, "skipDangerousModePermissionPrompt") is True:
        findings.append(
            _finding(
                app, "Bypass mode was switched on and its warning accepted on this computer", path
            )
        )
    if lookup(data, "sandbox.autoAllowBashIfSandboxed") is True:
        findings.append(_finding(app, "Runs commands without asking when they are sandboxed", path))
    if lookup(data, "enableAllProjectMcpServers") is True:
        findings.append(
            _finding(app, "Starts every MCP server a project lists without asking", path)
        )
    findings.extend(_claude_hooks(app, data, path))
    return findings


def _claude_allow_rules(app: str, rules: list[str], path: Path) -> list[ReachFinding]:
    findings: list[ReachFinding] = []
    commands = [rule for rule in rules if rule == "Bash" or rule.startswith("Bash(")]
    specs = [
        rule[5:-1] if rule.endswith(")") and rule.startswith("Bash(") else "*" for rule in commands
    ]
    risky = [spec for spec in specs if approval_runs_any_program(spec)]
    findings.extend(
        _approved_programs(app, [_prefix_of(spec) for spec in risky], path, len(commands))
    )
    servers = sorted({match.group(1) for rule in rules if (match := MCP_SERVER_RULE.match(rule))})
    if servers:
        findings.append(
            _finding(
                app,
                f"Every tool of {len(servers)} MCP server(s) runs without asking: "
                f"{', '.join(servers)}",
                path,
            )
        )
    if {"WebFetch", "WebFetch(*)", "WebFetch(domain:*)"} & set(rules):
        findings.append(_finding(app, "Fetches any web address without asking", path))
    if {"Edit", "Write", "Edit(*)", "Edit(**)", "Write(*)", "Write(**)"} & set(rules):
        findings.append(_finding(app, "Edits any file without asking", path))
    return findings


def _patterns_as_prefixes(patterns: list[str]) -> list[str]:
    """Command prefixes covered by allow patterns; a pattern that is not a regex is a prefix."""
    prefixes: list[str] = []
    for pattern in patterns:
        prefix = regex_prefix(pattern)
        prefixes.append(pattern if prefix is None else prefix)
    return prefixes


def _prefix_of(spec: str) -> str:
    return command_prefix(spec)[0]


def _claude_hooks(app: str, data: dict[str, Any], path: Path) -> list[ReachFinding]:
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return []
    events = [event for event in CLAUDE_APPROVAL_HOOKS if hooks.get(event)]
    if not events:
        return []
    count = sum(_hook_count(hooks[event]) for event in events)
    return [
        _finding(
            app,
            f"{count} hook(s) run before actions and can approve them without asking "
            f"({', '.join(events)})",
            path,
        )
    ]


def _hook_count(entries: Any) -> int:
    if not isinstance(entries, list):
        return 0
    listed = [entry.get("hooks") or [] for entry in entries if isinstance(entry, dict)]
    return sum(len(hooks) for hooks in listed if isinstance(hooks, Sized)) or len(entries)


# --- Codex and the ChatGPT app --------------------------------------------------------------

CODEX_SETTINGS = (
    ("approval_policy", frozenset({"never"}), "Runs actions without asking"),
    (
        "sandbox_mode",
        frozenset({"danger-full-access"}),
        "Runs outside the sandbox with full access to this computer",
    ),
    (
        "default_permissions",
        frozenset({":danger-full-access"}),
        "Runs with full access to this computer",
    ),
    (
        "approvals_reviewer",
        frozenset({"auto_review", "guardian_subagent"}),
        "An AI reviewer answers approval requests instead of you",
    ),
)
PREFIX_RULE = re.compile(r"prefix_rule\s*\(")
PATTERN_LIST = re.compile(r"pattern\s*=\s*(\[[^\]]*(?:\[[^\]]*\][^\]]*)*\])")
ALLOW_DECISION = re.compile(r"decision\s*=\s*[\"']allow[\"']")


def _codex(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("codex")
    codex_home = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
    path = codex_home / "config.toml"
    findings: list[ReachFinding] = []
    data = load_settings(path)
    if data:
        findings.extend(_matching_values(app, data, CODEX_SETTINGS, path))
        servers = _codex_auto_approved(data)
        if servers:
            findings.append(
                _finding(
                    app,
                    f"Tools of {len(servers)} server(s) or app(s) run without asking: "
                    f"{', '.join(servers)}",
                    path,
                )
            )
    rules_folder = codex_home / "rules"
    for rules_file in sorted(rules_folder.glob("*.rules")) if exists(rules_folder) else []:
        prefixes = _codex_allowed_prefixes(read_text(rules_file) or "")
        findings.extend(_approved_programs(app, prefixes, rules_file, len(prefixes)))
    return findings


def _codex_auto_approved(data: dict[str, Any]) -> list[str]:
    """Servers and apps whose tools are set to run without approval."""
    sections: dict[str, Any] = {}
    for group in ("mcp_servers", "apps"):
        for name, entry in (data.get(group) or {}).items():
            sections[name] = entry
    for plugin in (data.get("plugins") or {}).values():
        if isinstance(plugin, dict):
            sections.update(plugin.get("mcp_servers") or {})
    return sorted(name for name, entry in sections.items() if _codex_approves(entry))


def _codex_approves(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("default_tools_approval_mode") == "approve":
        return True
    tools = entry.get("tools")
    return isinstance(tools, dict) and any(
        isinstance(tool, dict) and tool.get("approval_mode") == "approve" for tool in tools.values()
    )


def _codex_allowed_prefixes(text: str) -> list[str]:
    """Command prefixes from ``prefix_rule(pattern=[...], decision="allow")`` entries."""
    prefixes: list[str] = []
    starts = [match.end() for match in PREFIX_RULE.finditer(text)]
    ends = [*starts[1:], len(text)] if starts else []
    for start, end in zip(starts, ends, strict=True):
        body = text[start:end]
        pattern = PATTERN_LIST.search(body)
        if pattern is None or not ALLOW_DECISION.search(body):
            continue
        try:
            tokens = ast.literal_eval(pattern.group(1))
        except (ValueError, SyntaxError):
            continue
        words: list[str] = []
        for token in tokens if isinstance(tokens, list) else []:
            if not isinstance(token, str):
                break
            words.append(token)
        prefixes.append(" ".join(words))
    return prefixes


# --- Cursor ---------------------------------------------------------------------------------


def _cursor(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("cursor")
    findings: list[ReachFinding] = []
    permissions_path = home_path(home, "~/.cursor/permissions.json")
    permissions = load_settings(permissions_path) or {}
    terminal = _texts(permissions.get("terminalAllowlist"))
    findings.extend(_approved_programs(app, terminal, permissions_path, len(terminal)))
    mcp = _texts(permissions.get("mcpAllowlist"))
    if any(entry.split(":")[-1].strip() == "*" for entry in mcp):
        findings.append(
            _finding(app, "Every tool of some MCP servers runs without asking", permissions_path)
        )
    sandbox_path = home_path(home, "~/.cursor/sandbox.json")
    if (load_settings(sandbox_path) or {}).get("type") == "insecure_none":
        findings.append(
            _finding(app, "Sandbox switched off: commands run with full access", sandbox_path)
        )
    findings.extend(_cursor_cli(app, home))
    if "cursor" in present:
        findings.append(
            _finding(
                app,
                "Cursor's default run mode, Auto-review, lets an automatic check approve actions "
                "instead of asking you",
                "app default (the mode chosen in the app is not stored in a readable file)",
                default=True,
            )
        )
    return findings


def _cursor_cli(app: str, home: Path) -> list[ReachFinding]:
    path = home_path(home, "~/.cursor/cli-config.json")
    data = load_settings(path)
    if not data:
        return []
    findings = _matching_values(
        app,
        data,
        (
            (
                "approvalMode",
                frozenset({"unrestricted"}),
                "The Cursor CLI runs everything without asking",
            ),
        ),
        path,
    )
    shell = [
        token[6:-1]
        for token in _texts(lookup(data, "permissions.allow"))
        if token.startswith("Shell(") and token.endswith(")")
    ]
    # Shell(git) approves every git command, so each entry is a command prefix.
    findings.extend(_approved_programs(app, [_prefix_of(spec) for spec in shell], path, len(shell)))
    return findings


# --- VS Code (GitHub Copilot) and Roo Code ----------------------------------------------------

VSCODE_SETTINGS = (
    (
        "chat.permissions.default",
        frozenset({"autoapprove", "autopilot"}),
        "The agent runs without asking",
    ),
)


def _vscode(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("vscode")
    findings: list[ReachFinding] = []
    for editor in ("Code", "Code - Insiders"):
        for path in _editor_user_settings(home, editor):
            data = load_settings(path)
            if data is None:
                continue
            findings.extend(_vscode_file(app, data, path))
            findings.extend(_roo_allowed_commands(data, path))
            if _copilot_in_use(data, present) and _edits_auto_approved(data):
                findings.append(
                    _finding(
                        app,
                        "Copilot edits files without asking, except sensitive files such as .env "
                        "(the default)",
                        path,
                        default=True,
                    )
                )
    return findings


def _vscode_file(app: str, data: dict[str, Any], path: Path) -> list[ReachFinding]:
    findings = _matching_values(app, data, VSCODE_SETTINGS, path)
    for key in ("chat.tools.global.autoApprove", "chat.tools.autoApprove"):
        value = lookup(data, key)
        if value is True:
            findings.append(_finding(app, f"Every tool runs without asking ({key}: true)", path))
        elif isinstance(value, dict) and (
            count := sum(1 for item in value.values() if item is True)
        ):
            findings.append(_finding(app, f"{count} tool(s) run without asking ({key})", path))
    if lookup(data, "chat.tools.terminal.enableAutoApprove") is not False:
        approved = lookup(data, "chat.tools.terminal.autoApprove")
        prefixes = _vscode_terminal_prefixes(approved) if isinstance(approved, dict) else []
        findings.extend(_approved_programs(app, prefixes, path, len(prefixes)))
    return findings


def _vscode_terminal_prefixes(approved: dict[str, Any]) -> list[str]:
    prefixes: list[str] = []
    for key, value in approved.items():
        allowed = value is True or (isinstance(value, dict) and value.get("approve") is True)
        if not allowed:
            continue
        if key.startswith("/") and key.endswith("/"):
            prefix = regex_prefix(key)
            if prefix is not None:
                prefixes.append(prefix)
        else:
            prefixes.append(key)
    return prefixes


def _copilot_in_use(data: dict[str, Any], present: Present) -> bool:
    return "github-copilot" in present or any(str(key).startswith("chat.") for key in data)


def _edits_auto_approved(data: dict[str, Any]) -> bool:
    value = lookup(data, "chat.tools.edits.autoApprove")
    if value is None:
        return True
    return value is True or (isinstance(value, dict) and value.get("**/*") is True)


def _roo_allowed_commands(data: dict[str, Any], path: Path) -> list[ReachFinding]:
    commands = _texts(lookup(data, "roo-cline.allowedCommands"))
    return _approved_programs(agent_name("roo code"), commands, path, len(commands))


# --- GitHub Copilot CLI ---------------------------------------------------------------------


def _copilot_cli(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("github copilot")
    findings: list[ReachFinding] = []
    settings_path = home_path(home, "~/.copilot/settings.json")
    if lookup(load_settings(settings_path) or {}, "stayInAutopilot") is True:
        findings.append(
            _finding(app, "Stays in autopilot: works through tasks without asking", settings_path)
        )
    path = home_path(home, "~/.copilot/permissions-config.json")
    approvals = _copilot_approvals(lookup(load_settings(path) or {}, "locations"))
    commands = [
        identifier.removesuffix(":*")
        for approval in approvals
        if approval.get("kind") == "commands"
        for identifier in _texts(approval.get("commandIdentifiers"))
    ]
    findings.extend(_approved_programs(app, commands, path, len(commands)))
    writes = sum(1 for approval in approvals if approval.get("kind") == "write")
    if writes:
        findings.append(_finding(app, f"Edits files without asking in {writes} folder(s)", path))
    servers = {
        str(approval.get("serverName") or approval.get("server") or "a server")
        for approval in approvals
        if approval.get("kind") == "mcp" and approval.get("toolName") is None
    }
    if servers:
        findings.append(
            _finding(app, f"Every tool of {len(servers)} MCP server(s) runs without asking", path)
        )
    return findings


def _copilot_approvals(locations: Any) -> list[dict[str, Any]]:
    """Every saved tool approval, across all the folders they were saved for."""
    approvals: list[dict[str, Any]] = []
    for location in locations.values() if isinstance(locations, dict) else []:
        saved = location.get("tool_approvals") if isinstance(location, dict) else None
        approvals.extend(item for item in saved or [] if isinstance(item, dict))
    return approvals


# --- Gemini CLI -----------------------------------------------------------------------------

GEMINI_SETTINGS = (
    ("general.defaultApprovalMode", frozenset({"auto_edit"}), "Edits files without asking"),
)
SHELL_TOOL = re.compile(r"^run_shell_command(?:\((.*)\))?$")


def _gemini(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("gemini cli")
    path = home_path(home, "~/.gemini/settings.json")
    data = load_settings(path)
    findings: list[ReachFinding] = []
    if data:
        findings.extend(_matching_values(app, data, GEMINI_SETTINGS, path))
        allowed = _texts(lookup(data, "tools.allowed"))
        prefixes = [match.group(1) or "" for tool in allowed if (match := SHELL_TOOL.match(tool))]
        findings.extend(_approved_programs(app, prefixes, path, len(prefixes)))
        findings.extend(_gemini_servers(app, data, path))
    policies = home_path(home, "~/.gemini/policies")
    for policy in sorted(policies.glob("*.toml")) if exists(policies) else []:
        rules = (load_settings(policy) or {}).get("rule")
        allowed_rules = (
            [rule for rule in rules if isinstance(rule, dict) and rule.get("decision") == "allow"]
            if isinstance(rules, list)
            else []
        )
        prefixes = [
            str(rule.get("commandPrefix") or "")
            for rule in allowed_rules
            if rule.get("toolName") == "run_shell_command" and not rule.get("commandRegex")
        ]
        findings.extend(_approved_programs(app, prefixes, policy, len(allowed_rules)))
    return findings


def _gemini_servers(app: str, data: dict[str, Any], path: Path) -> list[ReachFinding]:
    findings: list[ReachFinding] = []
    allowed = _texts(lookup(data, "mcp.allowed"))
    if "*" in allowed:
        findings.append(
            _finding(app, "Every MCP server's tools run without asking (mcp.allowed: *)", path)
        )
    elif allowed:
        findings.append(
            _finding(
                app,
                f"Tools of {len(allowed)} MCP server(s) run without asking: {', '.join(allowed)}",
                path,
            )
        )
    servers = data.get("mcpServers")
    trusted = (
        sorted(
            name
            for name, entry in (servers or {}).items()
            if isinstance(entry, dict) and entry.get("trust") is True
        )
        if isinstance(servers, dict)
        else []
    )
    if trusted:
        findings.append(
            _finding(
                app, f"Trusted servers run their tools without asking: {', '.join(trusted)}", path
            )
        )
    return findings


# --- Kiro, Amazon Q -------------------------------------------------------------------------

KIRO_BROAD_CAPABILITIES = ("all", "shell", "fs_write", "mcp")


def _kiro(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("kiro")
    findings: list[ReachFinding] = []
    mcp_path = home_path(home, "~/.kiro/settings/mcp.json")
    servers = (load_settings(mcp_path) or {}).get("mcpServers")
    everything = (
        sorted(
            name
            for name, entry in (servers or {}).items()
            if isinstance(entry, dict) and "*" in _texts(entry.get("autoApprove"))
        )
        if isinstance(servers, dict)
        else []
    )
    if everything:
        findings.append(
            _finding(app, f"Every tool runs without asking on: {', '.join(everything)}", mcp_path)
        )
    permissions_path = home_path(home, "~/.kiro/settings/permissions.yaml")
    rules = (load_settings(permissions_path) or {}).get("rules")
    for rule in rules if isinstance(rules, list) else []:
        if isinstance(rule, dict) and rule.get("effect") == "allow" and not rule.get("match"):
            capability = str(rule.get("capability"))
            if capability in KIRO_BROAD_CAPABILITIES:
                findings.append(
                    _finding(
                        app,
                        f"Every '{capability}' action is allowed without asking",
                        permissions_path,
                    )
                )
    findings.extend(_kiro_autopilot(app, home, present))
    return findings


def _kiro_autopilot(app: str, home: Path, present: Present) -> list[ReachFinding]:
    """Kiro's IDE runs in Autopilot unless set to Supervised."""
    if "kiro" not in present or sys.platform != "darwin":
        return []
    path = home_path(home, "~/Library/Application Support/Kiro/User/settings.json")
    autonomy = lookup(load_settings(path) or {}, "kiroAgent.agentAutonomy")
    if isinstance(autonomy, str) and "supervised" in autonomy.lower():
        return []
    chosen = isinstance(autonomy, str)
    return [
        _finding(
            app,
            "The agent acts without asking in Autopilot" + ("" if chosen else ", the default"),
            path if chosen else "app default (kiroAgent.agentAutonomy not set)",
            default=not chosen,
        )
    ]


def _amazon_q(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("amazon_q")
    folder = home_path(home, "~/.aws/amazonq")
    agents = [folder / "agents" / "default.json"]
    cli_agents = folder / "cli-agents"
    agents.extend(sorted(cli_agents.glob("*.json")) if exists(cli_agents) else [])
    findings: list[ReachFinding] = []
    for path in agents:
        data = load_settings(path)
        if not data:
            continue
        tools = _texts(data.get("allowedTools"))
        if "*" in tools:
            findings.append(_finding(app, "Every tool runs without asking (allowedTools: *)", path))
        elif "execute_bash" in tools:
            findings.append(
                _finding(app, "Runs any command without asking (allowedTools: execute_bash)", path)
            )
        commands = _texts(lookup(data, "toolsSettings.execute_bash.allowedCommands"))
        findings.extend(
            _approved_programs(app, _patterns_as_prefixes(commands), path, len(commands))
        )
    return findings


# --- Devin and legacy Windsurf ----------------------------------------------------------------

EXEC_RULE = re.compile(r"^Exec(?:\((.*)\))?$")


def _devin(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("devin")
    path = home_path(home, "~/.config/devin/config.json")
    rules = _texts(lookup(load_settings(path) or {}, "permissions.allow"))
    prefixes = [match.group(1) or "" for rule in rules if (match := EXEC_RULE.match(rule))]
    findings = _approved_programs(app, prefixes, path, len(prefixes))
    if {"Write", "Write(**)", "Write(*)"} & set(rules):
        findings.append(_finding(app, "Edits any file without asking", path))
    if "mcp__*" in rules:
        findings.append(_finding(app, "Every MCP tool runs without asking", path))
    for editor in ("Windsurf", "Devin"):
        for settings in _editor_user_settings(home, editor):
            data = load_settings(settings) or {}
            for key in ("windsurf.cascadeCommandsAllowList", "devin.cascadeCommandsAllowList"):
                commands = _texts(lookup(data, key))
                findings.extend(
                    _approved_programs(agent_name("windsurf"), commands, settings, len(commands))
                )
    return findings


# --- goose, Cline, Zed ----------------------------------------------------------------------


def _goose(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("goose")
    config_root = (
        "~/AppData/Roaming/Block/goose/config" if sys.platform == "win32" else "~/.config/goose"
    )
    path = home_path(home, f"{config_root}/config.yaml")
    data = load_settings(path)
    findings: list[ReachFinding] = []
    if data is not None:
        mode = data.get("GOOSE_MODE")
        if mode is None:
            findings.append(
                _finding(
                    app,
                    "Acts without asking: auto mode is goose's default when no mode is set",
                    f"{get_relative_path(path.as_posix())} (GOOSE_MODE not set)",
                    default=True,
                )
            )
        elif str(mode).lower() == "auto":
            findings.append(_finding(app, "Acts without asking (GOOSE_MODE: auto)", path))
    permission_path = home_path(home, f"{config_root}/permission.yaml")
    always = _texts(lookup(load_settings(permission_path) or {}, "user.always_allow"))
    if always:
        findings.append(
            _finding(app, f"{len(always)} tool(s) always run without asking", permission_path)
        )
    return findings


CLINE_ACTIONS = {
    "executeSafeCommands": "runs every command (Cline 4 treats all commands as safe here)",
    "useMcp": "runs every MCP tool",
    "editFiles": "edits files",
    "useBrowser": "uses the browser",
}


def _cline(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("cline")
    path = home_path(home, "~/.cline/data/globalState.json")
    data = load_settings(path)
    findings: list[ReachFinding] = []
    if data is not None:
        actions = lookup(data, "autoApprovalSettings.actions")
        if isinstance(actions, dict):
            enabled = [text for key, text in CLINE_ACTIONS.items() if actions.get(key) is True]
            if enabled:
                findings.append(_finding(app, "Without asking, it " + "; ".join(enabled), path))
        else:
            findings.append(
                _finding(
                    app,
                    "Without asking, it edits files, uses the browser and runs every MCP tool "
                    "(Cline 4 defaults)",
                    path,
                    default=True,
                )
            )
        if data.get("yoloModeToggled") is True:
            findings.append(_finding(app, "YOLO mode is on: everything runs without asking", path))
    cli_path = home_path(home, "~/.cline/data/settings/global-settings.json")
    cli = load_settings(cli_path)
    if cli is not None and cli.get("toolAutoApprove") is not False:
        findings.append(
            _finding(
                app,
                "The Cline CLI runs tools without asking",
                cli_path,
                default="toolAutoApprove" not in cli,
            )
        )
    return findings


ZED_AGENT_MODES = frozenset({"bypasspermissions", "full-access", "yolo"})


def _zed(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("zed")
    raw = (
        "~/AppData/Roaming/Zed/settings.json"
        if sys.platform == "win32"
        else "~/.config/zed/settings.json"
    )
    path = home_path(home, raw)
    data = load_settings(path)
    if not data:
        return []
    findings: list[ReachFinding] = []
    default = lookup(data, "agent.tool_permissions.default") or lookup(
        data, "agent.tool_permissions.default_mode"
    )
    if default == "allow" or lookup(data, "agent.always_allow_tool_actions") is True:
        findings.append(_finding(app, "Every agent tool runs without asking", path))
    terminal = lookup(data, "agent.tool_permissions.tools.terminal.always_allow")
    prefixes = [
        prefix for pattern in _texts(terminal) if (prefix := regex_prefix(pattern)) is not None
    ]
    findings.extend(_approved_programs(app, prefixes, path, len(_texts(terminal))))
    servers = lookup(data, "agent_servers")
    for name, entry in (servers or {}).items() if isinstance(servers, dict) else []:
        mode = entry.get("default_mode") if isinstance(entry, dict) else None
        if isinstance(mode, str) and mode.lower() in ZED_AGENT_MODES:
            findings.append(
                _finding(
                    app, f"External agent {name} runs without asking (default_mode: {mode})", path
                )
            )
    return findings


# --- Factory, Augment, Continue, Junie, Warp, Grok Bot ----------------------------------------

FACTORY_SETTINGS = (
    (
        "sessionDefaultSettings.autonomyLevel",
        frozenset({"low", "medium", "high"}),
        "Acts without asking up to its autonomy level",
    ),
)


def _factory(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("factory")
    findings: list[ReachFinding] = []
    for raw in ("~/.factory/settings.json", "~/.factory/settings.local.json"):
        path = home_path(home, raw)
        data = load_settings(path)
        if not data:
            continue
        findings.extend(_matching_values(app, data, FACTORY_SETTINGS, path))
        rules = lookup(data, "permissionRules.rules")
        allowed = (
            [rule for rule in rules if isinstance(rule, dict) and rule.get("decision") == "allow"]
            if isinstance(rules, list)
            else []
        )
        commands = [str(rule.get("command") or rule.get("pattern") or "") for rule in allowed]
        commands.extend(_texts(data.get("commandAllowlist")))
        findings.extend(_approved_programs(app, commands, path, len(commands)))
    return findings


def _augment(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("augment")
    path = home_path(home, "~/.augment/settings.json")
    data = load_settings(path)
    if data is None:
        return []
    rules = data.get("toolPermissions")
    if not isinstance(rules, list) or not rules:
        return [
            _finding(
                app,
                "Tools run without asking: that is Auggie's default when no rule is set",
                f"{get_relative_path(path.as_posix())} (toolPermissions not set)",
                default=True,
            )
        ]
    allowed = [
        rule
        for rule in rules
        if isinstance(rule, dict) and lookup(rule, "permission.type") == "allow"
    ]
    shell = [rule for rule in allowed if rule.get("toolName") in ("terminal", "launch-process")]
    prefixes = [
        "" if not rule.get("shellInputRegex") else regex_prefix(str(rule["shellInputRegex"]))
        for rule in shell
    ]
    return _approved_programs(
        app, [prefix for prefix in prefixes if prefix is not None], path, len(shell)
    )


def _continue(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("continue")
    path = home_path(home, "~/.continue/permissions.yaml")
    allowed = _texts((load_settings(path) or {}).get("allow"))
    specs = [
        entry[5:-1] if entry.startswith("Bash(") and entry.endswith(")") else "*"
        for entry in allowed
        if entry.startswith("Bash")
    ]
    risky = [_prefix_of(spec) for spec in specs if approval_runs_any_program(spec)]
    return _approved_programs(app, risky, path, len(specs))


def _junie(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("junie")
    findings: list[ReachFinding] = []
    config_path = home_path(home, "~/.junie/config.json")
    if (load_settings(config_path) or {}).get("brave") is True:
        findings.append(
            _finding(
                app, "Brave mode is on: runs commands and edits files without asking", config_path
            )
        )
    path = home_path(home, "~/.junie/allowlist.json")
    groups = lookup(load_settings(path) or {}, "rules")
    prefixes: list[str] = []
    for group in groups.values() if isinstance(groups, dict) else []:
        entries = group.get("rules") if isinstance(group, dict) else None
        for entry in entries if isinstance(entries, list) else []:
            if isinstance(entry, dict) and entry.get("action") == "allow":
                prefix = entry.get("prefix")
                if prefix is None and entry.get("pattern"):
                    prefix = regex_prefix(str(entry["pattern"]))
                if prefix is not None:
                    prefixes.append(str(prefix))
    findings.extend(_approved_programs(app, prefixes, path, len(prefixes)))
    return findings


WARP_PERMISSIONS = {
    "execute_commands": "runs commands",
    "apply_code_diffs": "applies code changes",
    "read_files": "reads files",
    "mcp_permissions": "runs MCP tools",
}


def _warp(home: Path, present: Present) -> list[ReachFinding]:
    app = agent_name("warp")
    raw = (
        "~/.config/warp-terminal/settings.toml"
        if sys.platform.startswith("linux")
        else "~/.warp/settings.toml"
    )
    path = home_path(home, raw)
    profiles = lookup(load_settings(path) or {}, "agents.execution_profiles")
    findings: list[ReachFinding] = []
    for name, profile in profiles.items() if isinstance(profiles, dict) else []:
        if not isinstance(profile, dict):
            continue
        always = [
            text for key, text in WARP_PERMISSIONS.items() if profile.get(key) == "always_allow"
        ]
        if always:
            findings.append(
                _finding(app, f"Profile {name}: always {', '.join(always)} without asking", path)
            )
        commands = _texts(profile.get("command_allowlist"))
        prefixes = [prefix for command in commands if (prefix := regex_prefix(command)) is not None]
        findings.extend(_approved_programs(app, prefixes, path, len(commands)))
    return findings


GROK_ALWAYS = "always"
GROK_CAPS = frozenset({"ask", "never"})
GROK_SETTINGS = "~/.grokbot/settings.json"


def grok_bot_setting(home: Path) -> tuple[str | None, str | None]:
    """Grok Bot's ``localToolPermission`` and its admin cap, if set (values ask/always/never)."""
    data = load_settings(home_path(home, GROK_SETTINGS)) or {}
    value, cap = data.get("localToolPermission"), data.get("localToolPermissionCeiling")
    return (
        value if isinstance(value, str) else None,
        cap if isinstance(cap, str) else None,
    )


def _grok_bot(home: Path, present: Present) -> list[ReachFinding]:
    value, cap = grok_bot_setting(home)
    if value is None or value.lower() != GROK_ALWAYS or (cap or "").lower() in GROK_CAPS:
        return []
    return [
        _finding(
            "Grok Bot",
            "Runs commands and reads files on this computer without asking "
            f"(localToolPermission: {value})",
            home_path(home, GROK_SETTINGS),
        )
    ]


CHECKS: tuple[tuple[str, Check], ...] = (
    ("Claude Code", _claude_code),
    ("Codex", _codex),
    ("Cursor", _cursor),
    ("VS Code", _vscode),
    ("GitHub Copilot CLI", _copilot_cli),
    ("Gemini CLI", _gemini),
    ("Kiro", _kiro),
    ("Amazon Q", _amazon_q),
    ("Devin", _devin),
    ("goose", _goose),
    ("Cline", _cline),
    ("Zed", _zed),
    ("Factory", _factory),
    ("Augment", _augment),
    ("Continue", _continue),
    ("Junie", _junie),
    ("Warp", _warp),
    ("Grok Bot", _grok_bot),
)
