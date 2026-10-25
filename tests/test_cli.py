"""End-to-end: run the command on a fake computer and check what it writes."""

import json
import re
import tomllib
from pathlib import Path

import pytest

from shepherd_scan import __version__
from shepherd_scan._vendor.discovery.agents import claude_desktop
from shepherd_scan.cli import main
from tests.conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, FAKE_SLACK_BOT_TOKEN

BRANDS = re.compile(
    r"snyk|invariant|cisco|defenseclaw|sentry|mcp-scan|agent[ -]scan", re.IGNORECASE
)


@pytest.fixture
def scan(fake_home: Path, no_network: list[object], monkeypatch, capsys):
    """Run a full offline scan of the fake computer; return the report, JSON and output."""
    monkeypatch.setattr(claude_desktop.sys, "platform", "darwin")
    html_path = fake_home.parent / "report.html"
    json_path = fake_home.parent / "report.json"
    exit_code = main(["--no-open", "-o", str(html_path), "--json", str(json_path)])
    captured = capsys.readouterr()
    return {
        "exit_code": exit_code,
        "html": html_path.read_text(encoding="utf-8"),
        "data": json.loads(json_path.read_text(encoding="utf-8")),
        "terminal": captured.out + captured.err,
        "network_attempts": no_network,
    }


def test_scan_succeeds_without_any_network_use(scan):
    assert scan["exit_code"] == 0
    assert scan["network_attempts"] == []


def test_agents_servers_and_connector_are_found(scan):
    data = scan["data"]
    agents = {agent["name"] for agent in data["agents"]}
    assert {"Claude Code", "Cursor"} <= agents
    servers = {(server["name"], server["kind"]) for server in data["servers"]}
    assert ("github", "local") in servers
    assert ("crm", "remote") in servers
    assert ("files", "local") in servers
    assert ("Gmail", "account connector") in servers


def test_connector_tools_come_from_the_session_record(scan):
    gmail = next(s for s in scan["data"]["servers"] if s["name"] == "Gmail")
    assert gmail["tools_source"] == "session record"
    assert [tool["name"] for tool in gmail["tools"]] == ["search_email", "send_email"]


def test_credential_names_listed_without_values(scan):
    github = next(s for s in scan["data"]["servers"] if s["name"] == "github")
    assert github["credentials"] == ["GITHUB_PERSONAL_ACCESS_TOKEN"]
    crm = next(s for s in scan["data"]["servers"] if s["name"] == "crm")
    assert crm["credentials"] == ["Authorization"]


def test_no_secret_value_reaches_any_output(scan):
    for output in (scan["html"], json.dumps(scan["data"]), scan["terminal"]):
        for value in (
            FAKE_AWS_KEY,
            FAKE_GITHUB_TOKEN,
            FAKE_SLACK_BOT_TOKEN,
            "secret-value",
            "abc123",
        ):
            assert value not in output


def test_risky_skill_flagged_and_benign_skill_clean(scan):
    skills = {skill["name"]: skill for skill in scan["data"]["skills"]}
    assert skills["helpful-setup"]["flags"]
    assert skills["weekly-summary"]["flags"] == []


def test_key_in_skill_script_reported_by_place(scan):
    places = {(s["where"], s["location"]) for s in scan["data"]["secrets"]}
    assert ("helpful-setup", "scripts/setup.py:4") in places


def test_html_escapes_skill_names(scan):
    assert "<script>alert(1)</script>" not in scan["html"]


def test_no_brand_names_in_anything_the_customer_sees(scan):
    for output in (scan["html"], json.dumps(scan["data"]), scan["terminal"]):
        assert not BRANDS.search(output)


def test_terminal_summary_points_to_report(scan):
    assert "Scan finished" in scan["terminal"]
    assert "report.html" in scan["terminal"]


def test_unwritable_output_gives_a_clear_message(fake_home: Path, no_network, capsys):
    missing_folder = fake_home / "no" / "such" / "folder" / "report.html"
    assert main(["--no-open", "-o", str(missing_folder)]) == 1
    assert "Could not save the report" in capsys.readouterr().out


def test_start_servers_without_terminal_does_not_start_them(
    fake_home: Path, no_network, monkeypatch, capsys
):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    html_path = fake_home.parent / "r.html"
    assert main(["--no-open", "--start-local-servers", "-o", str(html_path)]) == 0
    assert "Not starting them" in capsys.readouterr().out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as stop:
        main(["--version"])
    assert stop.value.code == 0
    assert "shepherd-scan" in capsys.readouterr().out


def test_connector_counts_toward_its_app(scan):
    desktop = next(a for a in scan["data"]["agents"] if a["name"] == "Claude Desktop")
    assert desktop["servers"] == 1


def test_blanked_values_read_plainly_everywhere(scan):
    for output in (scan["html"], json.dumps(scan["data"])):
        assert "REDACTED" not in output
    assert "[hidden]" in scan["html"]


def test_unreadable_skill_folder_is_listed_not_hidden(fake_home: Path, no_network, monkeypatch):
    monkeypatch.setattr(claude_desktop.sys, "platform", "darwin")
    locked = fake_home / ".claude" / "skills" / "locked"
    locked.mkdir()
    (locked / "SKILL.md").write_text("---\nname: locked\ndescription: x\n---\n")
    locked.chmod(0)
    json_path = fake_home.parent / "out.json"
    try:
        assert (
            main(["--no-open", "-o", str(fake_home.parent / "o.html"), "--json", str(json_path)])
            == 0
        )
    finally:
        locked.chmod(0o755)
    problems = json.loads(json_path.read_text())["problems"]
    assert any("locked" in problem for problem in problems)


def test_package_and_module_versions_agree():
    project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    assert project["project"]["version"] == __version__


def test_keys_written_in_settings_are_reported_by_place(scan):
    places = {(s["kind"], s["where"], s["location"]) for s in scan["data"]["secrets"]}
    assert (
        "GitHub personal access token",
        "github (Claude Code)",
        "~/.claude.json → GITHUB_PERSONAL_ACCESS_TOKEN",
    ) in places
    assert (
        "Slack bot token",
        "team-slack (Cursor)",
        "~/.cursor/mcp.json → SLACK_BOT_TOKEN",
    ) in places
    assert (
        "Key in plain text",
        "crm (Claude Code)",
        "~/.claude.json → header Authorization",
    ) in places


def _part(scan, part: str) -> list[dict]:
    return [finding for finding in scan["data"]["reach"] if finding["part"] == part]


def test_reach_section_covers_all_four_parts(scan):
    acts = [finding["what"] for finding in _part(scan, "acts")]
    assert "Runs every action without asking (permission mode: bypassPermissions)" in acts
    assert "1 pre-approved command, including 1 that can start any program (npx)" in acts
    assert [finding["what"] for finding in _part(scan, "logins")] == [
        "1 SSH private key (id_ed25519)"
    ]
    control = {finding["app"]: finding for finding in _part(scan, "control")}
    assert set(control) == {"Claude Desktop", "Claude in Chrome"}
    assert control["Claude Desktop"]["basis"] == "published"
    chrome = control["Claude in Chrome"]
    assert chrome["where"] == "Chrome (Default profile)"
    assert chrome["what"].startswith("Can read and change data on all websites")
    [shared] = _part(scan, "shared")
    assert shared["app"] == "Cursor"
    assert "Slack bot token" in shared["what"]
    assert scan["data"]["command_agents"] == ["Claude Code", "Claude Desktop", "Cursor"]


def test_reach_section_and_card_are_on_the_page(scan):
    html = scan["html"]
    assert 'id="reach"' in html
    assert "Where your agents can go further than you meant" in html
    assert "Ways agents can go further than you meant" in html
    assert html.index('id="keys"') < html.index('id="reach"') < html.index('id="servers"')


def test_installed_apps_appear_in_every_section_they_feed(scan):
    agents = {agent["name"]: agent for agent in scan["data"]["agents"]}
    slack = agents["Slack (Slackbot)"]
    assert slack["seen_inside"] is False
    assert slack["found_by"][0].startswith("app: ")
    assert "Slack workspace" in slack["note"]
    assert "Can read and change data on all websites" in agents["Claude in Chrome"]["site_access"]
    assert any(note.startswith("Slack (Slackbot):") for note in scan["data"]["kept_elsewhere"])
    assert "Slackbot acts in connected apps" in scan["html"]
    assert "Can't see inside" in scan["html"]
