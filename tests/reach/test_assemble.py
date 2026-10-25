from pathlib import Path
from typing import Any

from shepherd_scan.apps.browsers import ExtensionInstall
from shepherd_scan.apps.catalog import load_apps
from shepherd_scan.apps.installed import FoundApp, Sighting
from shepherd_scan.checks.plaintext import CredentialSetting
from shepherd_scan.reach.assemble import (
    command_agents,
    control_findings,
    elsewhere_notes,
    in_project_repository,
    plaintext_findings,
    shared_findings,
)


def _app(app_id: str, *sightings: Sighting, extensions=()) -> FoundApp:
    entry = next(app for app in load_apps() if app.id == app_id)
    return FoundApp(entry=entry, sightings=list(sightings), extensions=list(extensions))


def test_control_from_extension_access_and_from_published_features():
    install = ExtensionInstall(
        "fcoeoabgfenejglbffodgkkbkcdhcgfn", "Chrome", "Default profile", ("Can read all",)
    )
    apps = [
        _app(
            "claude-in-chrome", Sighting("browser extension", install.where), extensions=[install]
        ),
        _app("muse", Sighting("app", "/Applications/Muse.app")),
        _app("slack", Sighting("app", "/Applications/Slack.app")),
    ]
    findings = control_findings(apps)
    assert [(item.app, item.what, item.where, item.basis) for item in findings] == [
        ("Claude in Chrome", "Can read all", "Chrome (Default profile)", "setting"),
        ("Muse (Meta)", apps[1].entry.can_do, "app: /Applications/Muse.app", "published"),
    ]


def _credential(path: str, **fields: Any) -> CredentialSetting:
    values: dict[str, Any] = {
        "client": "cursor",
        "server": "slack",
        "setting": "SLACK_TOKEN",
        "written": True,
    }
    values.update(fields)
    return CredentialSetting(config_path=path, **values)


def test_plaintext_findings_name_every_app_that_reads_the_file(tmp_path: Path):
    path = (tmp_path / ".mcp.json").as_posix()
    credentials = [
        _credential(path, client="claude code", server="exa", setting="EXA_API_KEY"),
        _credential(path, client="vscode", server="exa", setting="EXA_API_KEY"),
        _credential(path, server="slack", setting="SLACK_TOKEN", written=False, shared=True),
    ]
    [finding] = plaintext_findings(credentials)
    assert finding.kind == "Key in plain text"
    assert finding.where == "exa (Claude Code, VS Code)"
    assert finding.location.endswith(".mcp.json → EXA_API_KEY")


def test_shared_accounts_and_keys_in_shared_project_files(tmp_path: Path):
    project = tmp_path / "work" / "app"
    (project / ".git").mkdir(parents=True)
    in_repo = (project / ".cursor" / "mcp.json").as_posix()
    personal = (tmp_path / ".cursor" / "mcp.json").as_posix()
    credentials = [
        _credential(personal, kind="Slack bot token", shared=True),
        _credential(in_repo, server="exa", setting="EXA_API_KEY"),
        _credential(personal, server="exa", setting="EXA_API_KEY"),
    ]
    findings = shared_findings(credentials, tmp_path)
    assert [item.what for item in findings] == [
        "slack uses a Slack bot token: whoever asks the agent acts with that account's access, "
        "not their own",
        "exa uses a key written into a project file that everyone with the repository has, so the "
        "agent can act with whoever's key it is",
    ]


def test_repository_check_ignores_the_home_folder_itself(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "work" / ".git").mkdir(parents=True)
    assert not in_project_repository(tmp_path / ".cursor" / "mcp.json", tmp_path)
    assert in_project_repository(tmp_path / "work" / "app" / ".mcp.json", tmp_path)
    assert not in_project_repository(tmp_path / "plain" / "app" / ".mcp.json", tmp_path)
    assert not in_project_repository(Path("/somewhere/else/.mcp.json"), tmp_path)
    (tmp_path / ".config" / "tool" / ".git").mkdir(parents=True)
    assert not in_project_repository(tmp_path / ".config" / "tool" / "mcp.json", tmp_path)


def test_command_agents_and_notes():
    apps = [_app("claude-code"), _app("slack"), _app("grok-bot"), _app("cursor")]
    assert command_agents(apps, {"zed", "unknown"}) == ["Claude Code", "Cursor", "Grok Bot", "Zed"]
    notes = elsewhere_notes(apps, grok_setting_found=False)
    assert (
        "Slack (Slackbot): Slackbot's connections and skills are kept in your Slack workspace."
        in notes
    )
    assert any(note.startswith("Grok Bot: Newer versions") for note in notes)
    assert any(note.startswith("Cursor: The run mode") for note in notes)
    assert not any(
        note.startswith("Grok Bot: Newer")
        for note in elsewhere_notes(apps, grok_setting_found=True)
    )
