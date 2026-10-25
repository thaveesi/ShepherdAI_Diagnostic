import json
import logging
from pathlib import Path

import pytest

from shepherd_scan.reach import acts
from shepherd_scan.reach.acts import acts_without_asking, merge_repeats
from shepherd_scan.report.model import ReachFinding


@pytest.fixture(autouse=True)
def mac(monkeypatch):
    """Rules read macOS locations, and managed files are kept out of the real system."""
    monkeypatch.setattr(acts.sys, "platform", "darwin")
    monkeypatch.setitem(acts.CLAUDE_MANAGED, "darwin", "/nonexistent/managed-settings.json")


def _write(home: Path, raw: str, content) -> Path:
    path = home / raw.removeprefix("~/")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = content if isinstance(content, str) else json.dumps(content)
    path.write_text(text, encoding="utf-8")
    return path


def _found(home: Path, present: set[str] | None = None) -> list[tuple[str, str, str]]:
    return [
        (finding.app, finding.what, finding.basis)
        for finding in acts_without_asking(home, present or set())
    ]


def _whats(home: Path, app: str, present: set[str] | None = None) -> list[str]:
    return [what for name, what, _ in _found(home, present) if name == app]


# --- Claude Code ------------------------------------------------------------------------------


def test_claude_mode_and_allow_rules(tmp_path: Path):
    _write(
        tmp_path,
        "~/.claude/settings.json",
        {
            "permissions": {
                "defaultMode": "bypassPermissions",
                "allow": [
                    "Bash(git status)",
                    "Bash(npm run test:*)",
                    "Bash(uv run:*)",
                    "Bash(npx:*)",
                    "mcp__github__*",
                    "mcp__linear",
                    "mcp__slack__post_message",
                    "WebFetch",
                ],
            },
            "skipDangerousModePermissionPrompt": True,
            "enableAllProjectMcpServers": True,
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": [{"command": "x"}, {"command": "y"}]}]
            },
        },
    )
    assert _whats(tmp_path, "Claude Code") == [
        "Runs every action without asking (permission mode: bypassPermissions)",
        "4 pre-approved commands, including 2 that can start any program (npx, uv run)",
        "Every tool of 2 MCP server(s) runs without asking: github, linear",
        "Fetches any web address without asking",
        "Bypass mode was switched on and its warning accepted on this computer",
        "Starts every MCP server a project lists without asking",
        "2 hook(s) run before actions and can approve them without asking (PreToolUse)",
    ]


def test_claude_bash_rule_alone_allows_any_command(tmp_path: Path):
    _write(tmp_path, "~/.claude/settings.json", {"permissions": {"allow": ["Bash"]}})
    assert "Runs any command without asking" in _whats(tmp_path, "Claude Code")


def test_claude_specific_commands_alone_are_not_reported(tmp_path: Path):
    rules = ["Bash(git status)", "Bash(npm run test:*)", "Read(**)"]
    _write(
        tmp_path,
        "~/.claude/settings.json",
        {"permissions": {"defaultMode": "default", "allow": rules}},
    )
    assert _whats(tmp_path, "Claude Code", {"claude-code"}) == []


def test_claude_default_is_auto_only_when_no_mode_is_chosen(tmp_path: Path):
    (tmp_path / ".claude").mkdir()
    assert _found(tmp_path, {"claude-code"})[-1][2] == "default"
    assert _found(tmp_path, set()) == []
    _write(tmp_path, "~/.claude/settings.json", {"permissions": {"disableAutoMode": "disable"}})
    assert _found(tmp_path, {"claude-code"}) == []


def test_claude_project_files_read_once_and_project_bypass_ignored(tmp_path: Path):
    project = tmp_path / "work" / "app"
    _write(tmp_path, "~/.claude.json", {"projects": {str(tmp_path): {}, str(project): {}}})
    _write(tmp_path, "~/.claude/settings.local.json", {"permissions": {"allow": ["Bash(bash:*)"]}})
    _write(
        tmp_path,
        "~/work/app/.claude/settings.local.json",
        {"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(python3:*)"]}},
    )
    found = acts_without_asking(tmp_path, set())
    assert [(finding.what, finding.where) for finding in found] == [
        (
            "1 pre-approved command, including 1 that can start any program (bash)",
            f"{tmp_path.as_posix()}/.claude/settings.local.json",
        ),
        (
            "1 pre-approved command, including 1 that can start any program (python3)",
            f"{project.as_posix()}/.claude/settings.local.json",
        ),
    ]


def test_the_same_setting_in_several_projects_is_one_row(tmp_path: Path):
    projects = [tmp_path / "work" / name for name in ("a", "b")]
    _write(tmp_path, "~/.claude.json", {"projects": {str(path): {} for path in projects}})
    for name in ("a", "b"):
        _write(
            tmp_path,
            f"~/work/{name}/.claude/settings.local.json",
            {"enableAllProjectMcpServers": True},
        )
    [finding] = acts_without_asking(tmp_path, set())
    assert finding.what == (
        "Starts every MCP server a project lists without asking (set in 2 settings files)"
    )
    assert finding.where is not None
    assert finding.where.count(".claude/settings.local.json") == 2


# --- Codex, Cursor, VS Code, Copilot CLI, Gemini ----------------------------------------------


def test_codex_settings_servers_and_saved_command_rules(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("CODEX_HOME", raising=False)
    _write(
        tmp_path,
        "~/.codex/config.toml",
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        'approvals_reviewer = "auto_review"\n'
        '[mcp_servers.github]\ncommand = "npx"\ndefault_tools_approval_mode = "approve"\n'
        '[mcp_servers.docs]\nurl = "https://docs.invalid/mcp"\n'
        '[apps.gmail.tools.send]\napproval_mode = "approve"\n',
    )
    _write(
        tmp_path,
        "~/.codex/rules/default.rules",
        'prefix_rule(pattern=["git", "status"], decision="allow")\n'
        'prefix_rule(pattern=["bash"], decision="allow")\n'
        'prefix_rule(pattern=["rm"], decision="forbidden")\n',
    )
    assert _whats(tmp_path, "Codex / ChatGPT app") == [
        "Runs actions without asking (approval_policy: never)",
        "Runs outside the sandbox with full access to this computer "
        "(sandbox_mode: danger-full-access)",
        "An AI reviewer answers approval requests instead of you (approvals_reviewer: auto_review)",
        "Tools of 2 server(s) or app(s) run without asking: github, gmail",
        "2 pre-approved commands, including 1 that can start any program (bash)",
    ]


def test_cursor_files_and_default(tmp_path: Path):
    _write(
        tmp_path,
        "~/.cursor/permissions.json",
        "// comments are allowed\n"
        + json.dumps({"terminalAllowlist": ["git status", "npx"], "mcpAllowlist": ["*:*"]}),
    )
    _write(tmp_path, "~/.cursor/sandbox.json", {"type": "insecure_none"})
    _write(
        tmp_path,
        "~/.cursor/cli-config.json",
        {"approvalMode": "unrestricted", "permissions": {"allow": ["Shell(bash)", "Shell(ls)"]}},
    )
    found = _found(tmp_path, {"cursor"})
    assert [what for _, what, _ in found] == [
        "2 pre-approved commands, including 1 that can start any program (npx)",
        "Every tool of some MCP servers runs without asking",
        "Sandbox switched off: commands run with full access",
        "The Cursor CLI runs everything without asking (approvalMode: unrestricted)",
        "2 pre-approved commands, including 1 that can start any program (bash)",
        "Cursor's default run mode, Auto-review, lets an automatic check approve actions instead "
        "of asking you",
    ]
    assert found[-1][2] == "default"


def test_vscode_copilot_settings(tmp_path: Path):
    _write(
        tmp_path,
        "~/Library/Application Support/Code/User/settings.json",
        {
            "chat.tools.global.autoApprove": True,
            "chat.permissions.default": "autopilot",
            "chat.tools.terminal.autoApprove": {"npm": True, "/^bash\\s/": True, "rm": False},
            "roo-cline.allowedCommands": ["*"],
        },
    )
    assert _whats(tmp_path, "VS Code") == [
        "The agent runs without asking (chat.permissions.default: autopilot)",
        "Every tool runs without asking (chat.tools.global.autoApprove: true)",
        "2 pre-approved commands, including 2 that can start any program (bash, npm)",
        "Copilot edits files without asking, except sensitive files such as .env (the default)",
    ]
    assert _whats(tmp_path, "Roo Code") == ["Runs any command without asking"]


def test_vscode_edits_default_only_when_copilot_is_used(tmp_path: Path):
    _write(
        tmp_path, "~/Library/Application Support/Code/User/settings.json", {"editor.fontSize": 14}
    )
    assert _whats(tmp_path, "VS Code") == []
    _write(
        tmp_path,
        "~/Library/Application Support/Code/User/settings.json",
        {"chat.tools.edits.autoApprove": {"**/*": False}},
    )
    assert _whats(tmp_path, "VS Code", {"github-copilot"}) == []


def test_copilot_cli_saved_approvals(tmp_path: Path):
    _write(tmp_path, "~/.copilot/settings.json", {"stayInAutopilot": True})
    _write(
        tmp_path,
        "~/.copilot/permissions-config.json",
        {
            "locations": {
                "/work/app": {
                    "tool_approvals": [
                        {"kind": "commands", "commandIdentifiers": ["git:*", "node:*"]},
                        {"kind": "write"},
                        {"kind": "mcp", "serverName": "github", "toolName": None},
                        {"kind": "mcp", "serverName": "linear", "toolName": "list"},
                    ]
                }
            }
        },
    )
    assert _whats(tmp_path, "GitHub Copilot") == [
        "Stays in autopilot: works through tasks without asking",
        "2 pre-approved commands, including 1 that can start any program (node)",
        "Edits files without asking in 1 folder(s)",
        "Every tool of 1 MCP server(s) runs without asking",
    ]


def test_gemini_settings_servers_and_policies(tmp_path: Path):
    _write(
        tmp_path,
        "~/.gemini/settings.json",
        {
            "general": {"defaultApprovalMode": "auto_edit"},
            "tools": {"allowed": ["run_shell_command(git)", "run_shell_command(npx)", "read_file"]},
            "mcp": {"allowed": ["*"]},
            "mcpServers": {"files": {"command": "x", "trust": True}},
        },
    )
    _write(
        tmp_path,
        "~/.gemini/policies/mine.toml",
        '[[rule]]\ntoolName = "run_shell_command"\ndecision = "allow"\n',
    )
    assert _whats(tmp_path, "Gemini CLI (now Antigravity CLI)") == [
        "Edits files without asking (general.defaultApprovalMode: auto_edit)",
        "2 pre-approved commands, including 1 that can start any program (npx)",
        "Every MCP server's tools run without asking (mcp.allowed: *)",
        "Trusted servers run their tools without asking: files",
        "Runs any command without asking",
    ]


# --- Kiro, Amazon Q, Devin ----------------------------------------------------------------------


def test_kiro_auto_approve_permissions_and_autopilot(tmp_path: Path):
    _write(
        tmp_path,
        "~/.kiro/settings/mcp.json",
        {"mcpServers": {"aws": {"command": "x", "autoApprove": ["*"]}, "b": {"command": "y"}}},
    )
    _write(
        tmp_path,
        "~/.kiro/settings/permissions.yaml",
        "rules:\n  - capability: shell\n    effect: allow\n"
        "  - capability: fs_write\n    effect: allow\n    match: src/**\n",
    )
    assert _whats(tmp_path, "Kiro", {"kiro"}) == [
        "Every tool runs without asking on: aws",
        "Every 'shell' action is allowed without asking",
        "The agent acts without asking in Autopilot, the default",
    ]
    _write(
        tmp_path,
        "~/Library/Application Support/Kiro/User/settings.json",
        {"kiroAgent.agentAutonomy": "Supervised"},
    )
    assert "The agent acts without asking in Autopilot, the default" not in _whats(
        tmp_path, "Kiro", {"kiro"}
    )


def test_amazon_q_agent_tools(tmp_path: Path):
    _write(tmp_path, "~/.aws/amazonq/agents/default.json", {"allowedTools": ["*"]})
    _write(
        tmp_path,
        "~/.aws/amazonq/cli-agents/dev.json",
        {
            "allowedTools": ["execute_bash"],
            "toolsSettings": {"execute_bash": {"allowedCommands": [".*", "git status"]}},
        },
    )
    assert _whats(tmp_path, "Amazon Q Developer") == [
        "Every tool runs without asking (allowedTools: *)",
        "Runs any command without asking (allowedTools: execute_bash)",
        "Runs any command without asking",
    ]


def test_devin_permissions_and_legacy_windsurf_list(tmp_path: Path):
    _write(
        tmp_path,
        "~/.config/devin/config.json",
        {"permissions": {"allow": ["Exec(git)", "Exec(python3)", "Write(**)", "mcp__*"]}},
    )
    _write(
        tmp_path,
        "~/Library/Application Support/Windsurf/User/settings.json",
        {"windsurf.cascadeCommandsAllowList": ["ls", "bash"]},
    )
    assert _whats(tmp_path, "Devin") == [
        "2 pre-approved commands, including 1 that can start any program (python3)",
        "Edits any file without asking",
        "Every MCP tool runs without asking",
    ]
    assert _whats(tmp_path, "Windsurf (now Devin Desktop)") == [
        "2 pre-approved commands, including 1 that can start any program (bash)"
    ]


# --- goose, Cline, Zed ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (
            "extensions: {}\n",
            ["Acts without asking: auto mode is goose's default when no mode is set"],
        ),
        ("GOOSE_MODE: auto\n", ["Acts without asking (GOOSE_MODE: auto)"]),
        ("GOOSE_MODE: approve\n", []),
        ("GOOSE_MODE: smart_approve\n", []),
    ],
)
def test_goose_mode(tmp_path: Path, config, expected):
    _write(tmp_path, "~/.config/goose/config.yaml", config)
    assert _whats(tmp_path, "goose") == expected


def test_goose_always_allowed_tools(tmp_path: Path):
    _write(tmp_path, "~/.config/goose/config.yaml", "GOOSE_MODE: approve\n")
    _write(
        tmp_path, "~/.config/goose/permission.yaml", "user:\n  always_allow: [dev__shell, x__y]\n"
    )
    assert _whats(tmp_path, "goose") == ["2 tool(s) always run without asking"]


def test_cline_switches_defaults_and_cli(tmp_path: Path):
    _write(
        tmp_path,
        "~/.cline/data/globalState.json",
        {"autoApprovalSettings": {"actions": {"executeSafeCommands": True, "useMcp": True}}},
    )
    _write(tmp_path, "~/.cline/data/settings/global-settings.json", {})
    found = [(what, basis) for app, what, basis in _found(tmp_path) if app == "Cline"]
    assert found == [
        (
            "Without asking, it runs every command (Cline 4 treats all commands as safe here); "
            "runs every MCP tool",
            "setting",
        ),
        ("The Cline CLI runs tools without asking", "default"),
    ]


def test_cline_defaults_when_no_switches_are_saved(tmp_path: Path):
    _write(tmp_path, "~/.cline/data/globalState.json", {"other": 1})
    _write(tmp_path, "~/.cline/data/settings/global-settings.json", {"toolAutoApprove": False})
    assert _found(tmp_path) == [
        (
            "Cline",
            "Without asking, it edits files, uses the browser and runs every MCP tool "
            "(Cline 4 defaults)",
            "default",
        )
    ]


def test_zed_tool_permissions_and_external_agents(tmp_path: Path):
    _write(
        tmp_path,
        "~/.config/zed/settings.json",
        "// Zed allows comments\n"
        + json.dumps(
            {
                "agent": {
                    "tool_permissions": {
                        "default": "allow",
                        "tools": {"terminal": {"always_allow": ["^npx\\s", "^git (status|diff)"]}},
                    }
                },
                "agent_servers": {"claude": {"default_mode": "bypassPermissions"}},
            }
        ),
    )
    assert _whats(tmp_path, "Zed") == [
        "Every agent tool runs without asking",
        "2 pre-approved commands, including 1 that can start any program (npx)",
        "External agent claude runs without asking (default_mode: bypassPermissions)",
    ]


# --- Factory, Augment, Continue, Junie, Warp, Grok Bot ------------------------------------------


def test_factory_autonomy_and_rules(tmp_path: Path):
    _write(
        tmp_path,
        "~/.factory/settings.json",
        {
            "sessionDefaultSettings": {"autonomyLevel": "high"},
            "permissionRules": {"rules": [{"command": "docker", "decision": "allow"}]},
        },
    )
    assert _whats(tmp_path, "Factory (Droid)") == [
        "Acts without asking up to its autonomy level (sessionDefaultSettings.autonomyLevel: high)",
        "1 pre-approved command, including 1 that can start any program (docker)",
    ]


def test_augment_default_and_unrestricted_shell(tmp_path: Path):
    _write(tmp_path, "~/.augment/settings.json", {"model": "x"})
    assert [basis for app, _, basis in _found(tmp_path) if app == "Augment (Auggie)"] == ["default"]
    _write(
        tmp_path,
        "~/.augment/settings.json",
        {"toolPermissions": [{"toolName": "terminal", "permission": {"type": "allow"}}]},
    )
    assert _whats(tmp_path, "Augment (Auggie)") == ["Runs any command without asking"]


def test_continue_cli_permissions(tmp_path: Path):
    _write(tmp_path, "~/.continue/permissions.yaml", "allow:\n  - Bash(npx *)\n  - Read\n")
    assert _whats(tmp_path, "Continue") == [
        "1 pre-approved command, including 1 that can start any program (npx)"
    ]


def test_junie_brave_mode_and_allowlist(tmp_path: Path):
    _write(tmp_path, "~/.junie/config.json", {"brave": True, "byok": {"openai": "not read here"}})
    _write(
        tmp_path,
        "~/.junie/allowlist.json",
        {
            "rules": {
                "shell": {
                    "rules": [
                        {"prefix": "bash", "action": "allow"},
                        {"prefix": "ls", "action": "allow"},
                    ]
                }
            }
        },
    )
    assert _whats(tmp_path, "JetBrains Junie") == [
        "Brave mode is on: runs commands and edits files without asking",
        "2 pre-approved commands, including 1 that can start any program (bash)",
    ]


def test_warp_execution_profiles(tmp_path: Path):
    _write(
        tmp_path,
        "~/.warp/settings.toml",
        '[agents.execution_profiles.default]\nexecute_commands = "always_allow"\n'
        'read_files = "agent_decides"\ncommand_allowlist = ["^npm\\\\s", "^ls"]\n',
    )
    assert _whats(tmp_path, "Warp") == [
        "Profile default: always runs commands without asking",
        "2 pre-approved commands, including 1 that can start any program (npm)",
    ]


@pytest.mark.parametrize(
    ("settings", "reported"),
    [
        ({"localToolPermission": "always"}, True),
        ({"localToolPermission": "ask"}, False),
        ({"localToolPermission": "never"}, False),
        ({"localToolPermission": "always", "localToolPermissionCeiling": "ask"}, False),
        ({}, False),
    ],
)
def test_grok_bot_local_command_permission(tmp_path: Path, settings, reported):
    _write(tmp_path, "~/.grokbot/settings.json", settings)
    assert bool(_whats(tmp_path, "Grok Bot")) is reported


# --- robustness ---------------------------------------------------------------------------------


def test_malformed_settings_are_skipped_with_a_warning(tmp_path: Path, caplog):
    _write(tmp_path, "~/.claude/settings.json", "{ not json")
    _write(tmp_path, "~/.codex/config.toml", "approval_policy = ")
    _write(tmp_path, "~/.config/goose/config.yaml", "GOOSE_MODE: [unclosed\n")
    with caplog.at_level(logging.WARNING):
        assert _found(tmp_path) == []
    assert sum("Could not parse" in message for message in caplog.messages) == 3


def test_settings_of_the_wrong_shape_do_not_stop_other_checks(tmp_path: Path):
    _write(
        tmp_path, "~/.claude/settings.json", {"permissions": {"allow": "Bash", "defaultMode": 3}}
    )
    _write(tmp_path, "~/.kiro/settings/mcp.json", {"mcpServers": ["not", "a", "map"]})
    _write(
        tmp_path, "~/.copilot/permissions-config.json", {"locations": {"a": {"tool_approvals": 5}}}
    )
    _write(tmp_path, "~/.config/goose/config.yaml", "GOOSE_MODE: auto\n")
    assert _whats(tmp_path, "goose") == ["Acts without asking (GOOSE_MODE: auto)"]


def test_an_unexpected_error_in_one_rule_is_reported_and_others_still_run(
    tmp_path: Path, monkeypatch, caplog
):
    def broken(home, present):
        raise RuntimeError("unexpected shape")

    monkeypatch.setattr(acts, "CHECKS", (("Broken app", broken), *acts.CHECKS))
    _write(tmp_path, "~/.config/goose/config.yaml", "GOOSE_MODE: auto\n")
    with caplog.at_level(logging.WARNING):
        assert _whats(tmp_path, "goose") == ["Acts without asking (GOOSE_MODE: auto)"]
    assert any("Could not check Broken app settings" in message for message in caplog.messages)


def test_merge_repeats_lists_every_place_once():
    finding = ReachFinding(part="acts", app="Claude Code", what="Starts servers", where="a")
    merged = merge_repeats(
        [
            finding,
            finding.model_copy(update={"where": "b"}),
            finding.model_copy(update={"where": "c"}),
            finding.model_copy(update={"where": "d"}),
            finding.model_copy(update={"where": "a"}),
            finding.model_copy(update={"what": "Other"}),
        ]
    )
    assert [(item.what, item.where) for item in merged] == [
        ("Starts servers (set in 4 settings files)", "a; b; c; and 1 more"),
        ("Other", "a"),
    ]
