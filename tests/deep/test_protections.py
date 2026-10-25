"""Read C (gate A): protection values both ways, documented defaults, and nothing else copied.

Each agent gets a protective value, a relaxing value and an unset key, and every row must say
which it is. Credential canaries sit in the files read C opens, next to the keys it reads; none
may reach any byte of the package. Folders reach the package only when it already names them.
"""

import json
import plistlib
import sys
from pathlib import Path
from typing import Any

import pytest

from shepherd_scan.deep.collect import collect_bundle
from shepherd_scan.deep.inventory import Inventory, claude_settings
from shepherd_scan.deep.protections import prefix_rules, protection_rows
from shepherd_scan.discovery import discover

TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"  # made-up value
BEARER = "sk-" + "canaryCanaryCanary0123456789abcdef"  # made-up value
SYSTEM = Path("system")


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def rows_by_key(rows: list[dict[str, Any]], agent: str) -> dict[str, dict[str, Any]]:
    return {(row["key"] if row["scope"] != "project" else f"project:{row['key']}"): row
            for row in rows if row["agent"] == agent}  # fmt: skip


def codex_config(home: Path) -> None:
    write(home / ".codex" / "config.toml", f"""
approval_policy = "never"
sandbox_mode = "workspace-write"
default_permissions = "my-secret-profile"

[sandbox_workspace_write]
network_access = true
writable_roots = ["/Users/someone/private-a", "/Users/someone/private-b"]

[mcp_servers.github]
command = "npx"
bearer_token = "{BEARER}"
default_tools_approval_mode = "approve"
env = {{ GITHUB_TOKEN = "{TOKEN}" }}
http_headers = {{ Authorization = "Bearer {BEARER}" }}

[mcp_servers.github.tools.create_issue]
approval_mode = "prompt"

[mcp_servers.docs]
command = "uvx"

[apps.gmail]
enabled = true

[projects."{home}/work/app"]
trust_level = "trusted"

[projects."{home}/clients/acme-confidential"]
trust_level = "untrusted"
""")  # fmt: skip
    write(home / ".codex" / "rules" / "default.rules", f"""
prefix_rule(pattern=["git", "status"], decision="allow")
prefix_rule(pattern=["curl", "-H", "Authorization: Bearer {TOKEN}"])
prefix_rule(pattern=["rm", "-rf"], decision="forbidden")
prefix_rule(pattern=["git", "push"], decision="prompt")
""")  # fmt: skip


def test_codex_rows_carry_relaxing_protective_and_default_values(fake_home):
    codex_config(fake_home)
    rows = protection_rows(fake_home, {"~/work/app"})
    codex = rows_by_key(rows, "Codex")
    assert (codex["approval_policy"]["value"], codex["approval_policy"]["state"]) == (
        "never", "relaxing")  # fmt: skip
    assert codex["sandbox_mode"]["state"] == "protective"
    assert (codex["default_permissions"]["value"], codex["default_permissions"]["state"]) == (
        "other", "neutral")  # fmt: skip
    reviewer = codex["approvals_reviewer"]
    assert (reviewer["state"], reviewer["basis"]) == ("unset", "documented default")
    assert reviewer["default"].startswith("user")
    assert codex["sandbox_workspace_write.network_access"]["state"] == "relaxing"
    assert codex["sandbox_workspace_write.writable_roots"]["value"] == "2"
    assert codex["mcp_servers.github.default_tools_approval_mode"]["state"] == "relaxing"
    assert codex["mcp_servers.github.tools.approval_mode=prompt"]["state"] == "protective"
    docs = codex["mcp_servers.docs.default_tools_approval_mode"]
    assert (docs["state"], docs["default"][:5]) == ("unset", "auto:")
    assert "apps._default" in codex["apps.gmail.default_tools_approval_mode"]["default"]
    assert codex["projects.trusted"]["items"] == ("~/work/app",)
    assert (codex["projects.untrusted"]["value"], codex["projects.untrusted"]["items"]) == ("1", ())
    assert (codex["rules.allow"]["value"], codex["rules.forbidden"]["state"]) == ("2", "protective")
    assert codex["rules.prompt"]["items"] == ("git push",)
    assert codex["requirements.toml"]["value"] == "absent"


def test_a_codex_rule_without_a_decision_allows():
    text = 'prefix_rule(pattern=["ls"])\nprefix_rule(pattern=["rm"], decision="forbidden")'
    assert prefix_rules(text) == [("allow", "ls"), ("forbidden", "rm")]


def test_codex_granular_policy_and_admin_requirements(fake_home, tmp_path):
    write(fake_home / ".codex" / "config.toml",
          "[approval_policy.granular]\nsandbox_approval = true\nrules = false\n")  # fmt: skip
    write(tmp_path / SYSTEM / "codex" / "requirements.toml",
          'allowed_approval_policies = ["on-request"]\nallowed_sandbox_modes = ["read-only"]\n'
          '[rules]\nprefix_rules = []\n')  # fmt: skip
    codex = rows_by_key(protection_rows(fake_home), "Codex")
    assert (codex["approval_policy"]["value"], codex["approval_policy"]["state"]) == (
        "granular", "protective")  # fmt: skip
    assert codex["requirements.toml"]["value"] == "present"
    allowed = codex["allowed_approval_policies"]
    assert (allowed["value"], allowed["state"], allowed["items"]) == (
        "1", "protective", ("on-request",))  # fmt: skip
    assert codex["allowed_sandbox_modes"]["scope"] == "managed"


def cursor_workspace(home: Path, folder: Path) -> None:
    storage = home / "Library/Application Support/Cursor/User/workspaceStorage/abc123"
    if sys.platform != "darwin":
        storage = home / ".config/Cursor/User/workspaceStorage/abc123"
    write(storage / "workspace.json", json.dumps({"folder": folder.as_uri()}))


def test_cursor_rows_user_files_workspace_files_and_the_unknown_run_mode(fake_home):
    cursor = fake_home / ".cursor"
    write(
        cursor / "sandbox.json", json.dumps({"type": "insecure_none", "readBoundary": "workspace"})
    )
    write(cursor / "permissions.json", json.dumps(
        {"terminalAllowlist": ["git", f"curl -H 'Authorization: Bearer {TOKEN}'"]}))  # fmt: skip
    write(cursor / "cli-config.json", json.dumps({"approvalMode": "allowlist", "permissions": {
        "allow": ["Shell(git)", "Read(**)"], "deny": ["Shell(rm)"]}}))  # fmt: skip
    client = fake_home / "clients" / "acme-confidential"
    write(client / ".cursor" / "sandbox.json", json.dumps({"networkPolicy": {"default": "allow"}}))
    cursor_workspace(fake_home, client)
    rows = protection_rows(fake_home)
    found = rows_by_key(rows, "Cursor")
    assert found["type"]["state"] == "relaxing"
    assert found["readBoundary"]["state"] == "protective"
    assert found["networkPolicy.default"]["basis"] == "documented default"
    allow = found["terminalAllowlist"]
    assert (allow["value"], allow["state"]) == ("2", "relaxing")
    assert all(TOKEN not in item for item in allow["items"])
    assert found["mcpAllowlist"]["state"] == "unset"
    assert found["approvalMode"]["state"] == "protective"
    assert found["permissions.allow.Shell"]["items"] == ("git",)
    assert (found["permissions.allow.Read"]["value"], found["permissions.allow.Read"]["items"]) == (
        "1", ())  # fmt: skip
    assert found["permissions.deny.Shell"]["state"] == "protective"
    workspace = found["project:networkPolicy.default"]
    assert (workspace["state"], workspace["file"]) == (
        "relaxing", "(workspace)/.cursor/sandbox.json")  # fmt: skip
    run_mode = found["IDE run mode"]
    assert run_mode["state"] == "unset" and "unknown" in run_mode["default"]
    assert "acme" not in json.dumps(rows)


@pytest.mark.skipif(sys.platform != "darwin", reason="device profiles are macOS files")
def test_desktop_policy_reads_the_profile_or_states_the_documented_defaults(fake_home, tmp_path):
    defaults = rows_by_key(protection_rows(fake_home), "Claude Desktop")
    assert {row["state"] for row in defaults.values()} == {"unset"}
    assert all("(CW-03)" in row["default"] for row in defaults.values())
    profile = tmp_path / SYSTEM / "Managed Preferences" / fake_home.name
    profile.mkdir(parents=True)
    policy = {"allowedWorkspaceFolders": '["/Users/someone/clients/acme-confidential", "/b"]',
              "secureVmFeaturesEnabled": False, "isLocalDevMcpEnabled": True}  # fmt: skip
    with (profile / "com.anthropic.claudefordesktop.plist").open("wb") as handle:
        plistlib.dump(policy, handle, fmt=plistlib.FMT_BINARY)
    rows = protection_rows(fake_home)
    found = rows_by_key(rows, "Claude Desktop")
    folders = found["allowedWorkspaceFolders"]
    assert (folders["value"], folders["state"]) == ("2", "protective")
    assert found["secureVmFeaturesEnabled"]["state"] == "protective"
    assert found["isLocalDevMcpEnabled"]["state"] == "neutral"
    assert found["isClaudeCodeForDesktopEnabled"]["state"] == "unset"
    assert found["secureVmFeaturesEnabled"]["file"].endswith(
        "/<user>/com.anthropic.claudefordesktop.plist")  # fmt: skip
    text = json.dumps(rows)
    assert "acme" not in text and f"/{fake_home.name}/com.anthropic" not in text


def test_the_other_agents_value_tables_are_written_with_every_value(fake_home):
    write(fake_home / ".factory" / "settings.json",
          json.dumps({"sessionDefaultSettings": {"autonomyLevel": "off"}}))  # fmt: skip
    write(fake_home / ".factory" / "settings.local.json", json.dumps({}))
    write(fake_home / ".gemini" / "settings.json",
          json.dumps({"general": {"defaultApprovalMode": "auto_edit"}}))  # fmt: skip
    rows = protection_rows(fake_home)
    factory = [row for row in rows if row["agent"] == "Factory"]
    assert [(row["state"], row["basis"]) for row in factory] == [
        ("protective", "setting"), ("unset", "documented default")]  # fmt: skip
    [gemini] = [row for row in rows if row["agent"] == "Gemini CLI"]
    assert gemini["state"] == "relaxing"


def test_claude_managed_drop_ins_device_profile_and_sandbox_credentials(fake_home, tmp_path):
    managed = tmp_path / SYSTEM / "ClaudeCode"
    write(
        managed / "managed-settings.json", json.dumps({"permissions": {"deny": ["Bash(sudo *)"]}})
    )
    write(managed / "managed-settings.d" / "20-team.json",
          json.dumps({"permissions": {"deny": ["Read(~/.ssh/**)"]}}))  # fmt: skip
    write(fake_home / ".claude" / "settings.json", json.dumps({"sandbox": {"enabled": True,
        "credentials": {"files": [{"path": "~/.aws/credentials", "mode": "deny"},
                                  {"path": "~/.config/gh/hosts.yml", "mode": "mask",
                                   "extract": f"oauth_token: ({TOKEN})"},
                                  {"path": "~/.netrc", "mode": "bogus"}],
                        "envVars": [{"name": "GITHUB_TOKEN", "mode": "mask"}]}}}))  # fmt: skip
    if sys.platform == "darwin":
        profiles = tmp_path / SYSTEM / "Managed Preferences"
        profiles.mkdir(parents=True)
        with (profiles / "com.anthropic.claudecode.plist").open("wb") as handle:
            plistlib.dump({"permissions": {"ask": ["Bash(git push *)"]}}, handle)
    settings = claude_settings(fake_home)
    managed_entries = {entry.path.rsplit("/", 1)[-1]: entry for entry in settings if entry.managed}
    assert managed_entries["20-team.json"].deny == ("Read(~/.ssh/**)",)
    assert managed_entries["managed-settings.json"].deny == ("Bash(sudo *)",)
    if sys.platform == "darwin":
        assert managed_entries["com.anthropic.claudecode.plist"].ask == ("Bash(git push *)",)
    [user] = [entry for entry in settings if entry.path == "~/.claude/settings.json"]
    assert user.sandbox.credential_files == (
        ("~/.aws/credentials", "deny"), ("~/.config/gh/hosts.yml", "mask"))  # fmt: skip
    assert user.sandbox.credential_vars == (("GITHUB_TOKEN", "mask"),)


def test_read_c_sources_never_carry_a_credential_or_unknown_folder(fake_home, no_network):
    codex_config(fake_home)
    write(fake_home / ".cursor" / "permissions.json",
          json.dumps({"mcpAllowlist": [f"server:{TOKEN}"]}))  # fmt: skip
    masked = {"path": "~/.aws/credentials", "mode": "mask", "extract": f"({BEARER})"}
    write(fake_home / ".claude" / "settings.json",
          json.dumps({"sandbox": {"credentials": {"files": [masked]}}}))  # fmt: skip
    out = fake_home.parent / "upload"
    collect_bundle(out, discover(), fake_home)
    text = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in sorted(out.rglob("*")) if p.is_file())  # fmt: skip
    for canary in (TOKEN, BEARER, "my-secret-profile", "acme-confidential", "private-a"):
        assert canary not in text, canary
    inventory = Inventory.from_json(json.loads((out / "inventory.json").read_text()))
    assert inventory.reads == ("A", "B", "C")
    assert any(row["agent"] == "Codex" for row in inventory.protections)
    [user] = [s for s in inventory.claude_settings if s.path == "~/.claude/settings.json"]
    assert user.sandbox.credential_files == (("~/.aws/credentials", "mask"),)
    assert no_network == []


def test_an_older_package_reads_b_and_c_as_not_read():
    data = {"sessions": [], "connectors": [], "servers": [], "claude_settings": [], "agents": []}
    inventory = Inventory.from_json(data)
    assert (inventory.reads, inventory.claude_code_versions, inventory.protections) == ((), {}, [])
