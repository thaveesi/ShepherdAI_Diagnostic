from pathlib import Path

from shepherd_scan.names import agent_name
from shepherd_scan.report.build import _merge_agents, readable_problems
from shepherd_scan.report.model import AgentResult


def test_agent_names_are_display_names():
    assert agent_name("claude code") == "Claude Code"
    assert agent_name("vscode") == "VS Code"
    assert agent_name("new-agent") == "new-agent"
    assert agent_name(None) == "Unknown agent"


def test_problems_are_one_per_place_relative_to_home(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/someone")
    messages = [
        "Cursor: could not parse file /Users/someone/.cursor/mcp.json",
        "Error processing config file",
        "Error parsing MCP config file /Users/someone/.cursor/mcp.json: bad",
        "Skipping unreadable skill dir: /Users/someone/.claude/skills/locked",
    ]
    assert readable_problems(messages) == [
        "Cursor: could not parse file ~/.cursor/mcp.json",
        "Skipping unreadable skill dir: ~/.claude/skills/locked",
    ]


def test_windows_paths_are_recognised():
    assert readable_problems([r"Error reading C:\Users\x\.cursor\mcp.json"]) == [
        r"Error reading C:\Users\x\.cursor\mcp.json"
    ]


def test_home_relative_paths_are_kept(monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/nowhere")))
    assert readable_problems(["could not read ~/.codex/config.toml"]) == [
        "could not read ~/.codex/config.toml"
    ]


def test_rows_for_the_same_app_are_merged_and_settings_read_win():
    read = AgentResult(name="Cursor", path="~/.cursor", servers=2, skills=1, found_by=["settings"])
    unseen = AgentResult(
        name="Cursor",
        path="",
        servers=0,
        skills=0,
        found_by=["app", "settings"],
        seen_inside=False,
        note="not read",
        can_do="edits code",
    )
    for rows in ([read, unseen], [unseen, read]):
        [merged] = _merge_agents(rows)
        assert (merged.servers, merged.skills, merged.path) == (2, 1, "~/.cursor")
        assert merged.seen_inside is True
        assert merged.note is None
        assert sorted(merged.found_by) == ["app", "settings"]
        assert merged.can_do == "edits code"
