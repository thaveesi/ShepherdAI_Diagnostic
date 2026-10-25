"""Read A (gate A): a Desktop session's folder, version, tools and rules, by allowlist only.

The records hold conversation text, titles, prompts and account details next to the metadata the
deep check needs. These tests plant a unique marker in every key the scanner must never copy and
check that none reaches any byte of the package, that the session's folder is named only through
settings files already in the package, and that sessions still map to the right settings.
"""

import json
from pathlib import Path
from typing import Any

from shepherd_scan.deep.collect import collect_bundle
from shepherd_scan.deep.inventory import Inventory
from shepherd_scan.discovery import discover

DESKTOP = Path("Library/Application Support/Claude")
TOKEN = "ghp_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"  # made-up value
NEVER_COPIED: dict[str, Any] = {
    "title": "CANARY-TITLE",
    "previousTitles": ["CANARY-PREVIOUS-TITLE"],
    "titleSource": "CANARY-TITLE-SOURCE",
    "initialMessage": "CANARY-INITIAL-MESSAGE",
    "systemPrompt": "CANARY-SYSTEM-PROMPT",
    "systemPromptRendererAppends": ["CANARY-RENDERER"],
    "memoryGuidelinesTemplate": "CANARY-MEMORY",
    "emailAddress": "canary.person@example.invalid",
    "accountName": "CANARY-ACCOUNT-NAME",
    "promptSuggestion": "CANARY-SUGGESTION",
    "postTurnSummary": {"status_detail": "CANARY-SUMMARY"},
    "publishedArtifacts": [{"title": "CANARY-ARTIFACT", "url": "https://canary.invalid/a"}],
    "scratchPromptRecents": ["CANARY-SCRATCH"],
    "rewindEdges": [{"cwd": "/canary/rewind"}],
    "transcriptModelStates": {"state": "CANARY-TRANSCRIPT"},
    "spawnSeed": {"prompt": "CANARY-SPAWN-SEED"},
    "spawnedFrom": {"title": "CANARY-SPAWNED-FROM"},
    "slashCommands": ["CANARY-SLASH"],
    "messages": [{"role": "user", "content": "CANARY-MESSAGE"}],
}
GMAIL = {
    "uuid": "gmail-uuid",
    "name": "Gmail",
    "tools": [
        {"name": "send_message", "enabledKey": "gmail-uuid:send_message-1",
         "annotations": {"readOnlyHint": False, "title": "Send message"}},
        {"name": "get_message", "enabledKey": "gmail-uuid:get_message-1",
         "annotations": {"readOnlyHint": True}},
    ],
}  # fmt: skip


def write_record(home: Path, folder: str, name: str, record: dict[str, Any]) -> None:
    path = home / DESKTOP / folder / "account" / "org" / f"local_{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record), encoding="utf-8")


def code_session(cwd: Path, **fields: Any) -> dict[str, Any]:
    return {
        "cwd": str(cwd),
        "originCwd": str(cwd),
        "permissionMode": "default",
        "remoteMcpServersConfig": [GMAIL],
        "lastActivityAt": 100,
        "toolSurfaceSnapshot": {"cliVersion": "2.1.280"},
        **fields,
    }


def project(home: Path, relative: str, *, git: str = "dir", files: tuple[str, ...] = ()) -> Path:
    folder = home / relative
    (folder / ".claude").mkdir(parents=True, exist_ok=True)
    for name in files:
        (folder / ".claude" / name).write_text(json.dumps({"permissions": {"allow": []}}))
    if git == "dir":
        (folder / ".git").mkdir(exist_ok=True)
    return folder


def record_projects(home: Path, trusted: dict[Path, bool]) -> None:
    config = home / ".claude.json"
    data = json.loads(config.read_text()) if config.is_file() else {}
    data["projects"] = {str(p): {"hasTrustDialogAccepted": t} for p, t in trusted.items()}
    config.write_text(json.dumps(data))


def bundle(home: Path) -> tuple[Path, Inventory]:
    out = home.parent / "upload"
    collect_bundle(out, discover(), home)
    inventory = Inventory.from_json(json.loads((out / "inventory.json").read_text()))
    return out, inventory


def package_text(out: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace")
                     for p in sorted(out.rglob("*")) if p.is_file())  # fmt: skip


def test_no_conversation_title_prompt_or_account_value_reaches_the_package(fake_home, no_network):
    app = project(fake_home, "work/app", files=("settings.json",))
    record_projects(fake_home, {app: True})
    write_record(fake_home, "claude-code-sessions", "code", code_session(app, **NEVER_COPIED))
    write_record(fake_home, "local-agent-mode-sessions", "cowork",
                 code_session(app, **NEVER_COPIED) | {"egressAllowedDomains": ["CANARY.invalid"],
                                                      "hostLoopMode": True})  # fmt: skip
    out, inventory = bundle(fake_home)
    assert {s.kind for s in inventory.sessions if s.version == "2.1.280"} == {
        "Claude Code in Claude Desktop", "Claude Desktop agent mode"}  # fmt: skip
    text = package_text(out)
    leaked = [key for key, value in NEVER_COPIED.items() if json.dumps(value).strip('"') in text
              or (isinstance(value, str) and value in text)]  # fmt: skip
    assert leaked == []
    assert "CANARY" not in text
    assert no_network == []


def test_a_session_names_its_folder_only_through_settings_files_in_the_package(
    fake_home, no_network
):
    app = project(fake_home, "work/app", files=("settings.json", "settings.local.json"))
    client = fake_home / "clients" / "acme-confidential"
    client.mkdir(parents=True)
    record_projects(fake_home, {app: True, client: False})
    write_record(fake_home, "claude-code-sessions", "a", code_session(app, lastActivityAt=501))
    write_record(fake_home, "claude-code-sessions", "b", code_session(client, lastActivityAt=502))
    out, inventory = bundle(fake_home)
    by_record = {s.last_active_ms: s.context for s in inventory.sessions}
    known = by_record[501]
    assert (known.shared, known.cwd_local, known.git, known.home) == (
        "~/work/app/.claude/settings.json", "~/work/app/.claude/settings.local.json", "root",
        False)  # fmt: skip
    unknown = by_record[502]
    assert (unknown.shared, unknown.cwd_local, unknown.git) == ("", "", "none")
    assert len(unknown.folder) == 16 and unknown.folder != known.folder
    assert "acme-confidential" not in package_text(out)
    assert inventory.project_trust == {"~/work/app": True}
    assert str(fake_home) not in package_text(out)


def test_subfolders_worktrees_and_home_map_to_the_files_claude_code_reads(fake_home, no_network):
    app = project(fake_home, "work/app", files=("settings.json", "settings.local.json"))
    (app / "sub").mkdir()
    worktree = app / ".claude" / "worktrees" / "feature"
    worktree.mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: elsewhere\n")
    record_projects(fake_home, {app: True})
    for name, cwd in (("sub", app / "sub"), ("tree", worktree), ("home", fake_home)):
        write_record(fake_home, "claude-code-sessions", name, code_session(cwd))
    _, inventory = bundle(fake_home)
    contexts = sorted((s.context.git, s.context.root_local, s.context.home)
                      for s in inventory.sessions)  # fmt: skip
    local = "~/work/app/.claude/settings.local.json"
    assert ("inside", local, False) in contexts
    assert ("worktree", local, False) in contexts
    assert any(home for _, _, home in contexts)


def test_tools_switches_versions_and_session_rules_are_kept_and_blanked(fake_home, no_network):
    app = project(fake_home, "work/app", files=("settings.json",))
    record_projects(fake_home, {app: True})
    updates = [{"type": "addRules", "destination": "session", "behavior": "allow",
                "rules": [{"toolName": "Bash",
                           "ruleContent": f"curl -H 'Authorization: Bearer {TOKEN}' x"}]},
               {"type": "addDirectories", "destination": "session",
                "directories": ["/Users/someone/private-folder"]}]  # fmt: skip
    record = code_session(app, enabledMcpTools={"gmail-uuid:send_message-1": False, "gone": True},
                          sessionPermissionUpdates=updates)  # fmt: skip
    write_record(fake_home, "claude-code-sessions", "one", record)
    out, inventory = bundle(fake_home)
    [session] = inventory.sessions
    assert session.version == "2.1.280"
    [gmail] = session.tools
    assert (gmail.connector, gmail.uuid) == ("Gmail", "gmail-uuid")
    assert gmail.tools[0] == {
        "name": "send_message",
        "annotations": {"readOnlyHint": False, "title": "Send message"},
    }
    assert all(set(tool) == {"name", "annotations"} for tool in gmail.tools)
    assert (session.tool_switches, session.unmatched_switches) == ((("send_message", False),), 1)
    allow, folders = session.session_rules
    assert allow.behavior == "allow" and TOKEN not in allow.rules[0]
    assert allow.rules[0].startswith("Bash(curl")
    assert folders.directories == 1
    assert "private-folder" not in package_text(out)
    assert TOKEN not in package_text(out)


def test_an_older_package_without_read_a_reads_as_unknown_not_as_none():
    old = {"kind": "Claude Code in Claude Desktop", "permission_mode": "default",
           "browser_mode": "", "scheduled": False, "archived": False, "last_active_ms": 0,
           "connectors": ["Gmail"], "saved_approvals": 0}  # fmt: skip
    data = {"sessions": [old], "connectors": [], "servers": [], "claude_settings": [],
            "agents": []}  # fmt: skip
    [session] = Inventory.from_json(data).sessions
    assert session.context.read is False and session.context.git == "unknown"
    assert session.tools == () and session.version == ""
