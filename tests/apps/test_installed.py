import json
import plistlib
from pathlib import Path

import pytest

from shepherd_scan.apps import browsers, installed
from shepherd_scan.apps.browsers import site_access
from shepherd_scan.apps.catalog import load_apps
from shepherd_scan.apps.installed import find_installed_apps

CLAUDE_IN_CHROME = "fcoeoabgfenejglbffodgkkbkcdhcgfn"


@pytest.fixture
def computer(tmp_path: Path, monkeypatch) -> Path:
    """A home folder on a Mac with its own Applications folder and an empty command path."""
    monkeypatch.setattr(installed.sys, "platform", "darwin")
    applications = tmp_path / "Applications"
    applications.mkdir()
    monkeypatch.setattr(installed, "SYSTEM_APP_FOLDERS", (applications,))
    commands = tmp_path / "bin"
    commands.mkdir()
    monkeypatch.setenv("PATH", str(commands))
    home = tmp_path / "home"
    home.mkdir()
    return home


def _app(folder: Path, name: str, bundle_id: str | None) -> Path:
    contents = folder / name / "Contents"
    contents.mkdir(parents=True)
    if bundle_id is not None:
        with (contents / "Info.plist").open("wb") as handle:
            plistlib.dump({"CFBundleIdentifier": bundle_id}, handle)
    return folder / name


def _found(home: Path) -> dict[str, list[str]]:
    return {
        found.entry.id: [sighting.describe() for sighting in found.sightings]
        for found in find_installed_apps(home, load_apps())
    }


def test_apps_found_by_bundle_id_even_when_renamed(computer: Path):
    applications = computer.parent / "Applications"
    slack = _app(applications, "Work Chat.app", "com.tinyspeck.slackmacgap")
    nested = _app(applications / "Setapp", "Grok Bot.app", "com.anysphere.sand")
    assert _found(computer) == {
        "slack": [f"app: {slack.as_posix()}"],
        "grok-bot": [f"app: {nested.as_posix()}"],
    }


def test_new_chatgpt_app_is_not_mistaken_for_the_classic_one(computer: Path):
    _app(computer.parent / "Applications", "ChatGPT.app", "com.openai.codex")
    assert list(_found(computer)) == ["chatgpt"]


def test_app_names_match_only_entries_without_a_bundle_id(computer: Path):
    applications = computer.parent / "Applications"
    _app(applications, "Agent!.app", None)
    _app(applications, "Slack.app", "com.example.not-slack")
    assert list(_found(computer)) == ["agent-macos"]


def test_malformed_app_descriptions_do_not_stop_the_scan(computer: Path):
    applications = computer.parent / "Applications"
    broken = applications / "Game.app" / "Contents"
    broken.mkdir(parents=True)
    (broken / "Info.plist").write_text(
        "<?xml version='1.0'?><plist><dict><key>x</key>\x01", "utf-8"
    )
    _app(applications, "Granola.app", "com.granola.app")
    assert list(_found(computer)) == ["granola"]


def test_commands_folders_and_editor_extensions(computer: Path):
    command = computer.parent / "bin" / "aider"
    command.write_text("#!/bin/sh\n", encoding="utf-8")
    command.chmod(0o755)
    (computer / ".grokbot").mkdir()
    (computer / ".vscode" / "extensions" / "saoudrizwan.claude-dev-3.1.0").mkdir(parents=True)
    (computer / ".cursor" / "extensions" / "saoudrizwan.claude-devtools-1.0.0").mkdir(parents=True)
    found = _found(computer)
    assert found["aider"] == [f"command: {command.as_posix()}"]
    assert found["grok-bot"] == ["settings: ~/.grokbot"]
    assert found["cline"] == ["VS Code extension: saoudrizwan.claude-dev"]


def test_unrelated_programs_with_common_names_are_not_reported(computer: Path):
    for name in ("goose", "q", "agent", "copilot", "hermes", "cn"):
        command = computer.parent / "bin" / name
        command.write_text("#!/bin/sh\n", encoding="utf-8")
        command.chmod(0o755)
    assert _found(computer) == {}


def _extension(home: Path, root: str, profile: str, manifest: dict) -> None:
    folder = home / root / profile / "Extensions" / CLAUDE_IN_CHROME / "1.2.0_0"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_browser_extension_found_in_every_profile_with_its_access(computer: Path, monkeypatch):
    monkeypatch.setattr(browsers.sys, "platform", "darwin")
    chrome = "Library/Application Support/Google/Chrome"
    manifest = {"host_permissions": ["<all_urls>"], "permissions": ["debugger", "tabs"]}
    _extension(computer, chrome, "Default", manifest)
    _extension(computer, chrome, "Profile 2", {"permissions": ["storage"]})
    opera = computer / "Library/Application Support/com.operasoftware.Opera/Extensions"
    (opera / CLAUDE_IN_CHROME / "1.0").mkdir(parents=True)
    [found] = [
        app
        for app in find_installed_apps(computer, load_apps())
        if app.entry.id == "claude-in-chrome"
    ]
    assert [(install.where, install.access) for install in found.extensions] == [
        (
            "Chrome (Default profile)",
            ("Can read and change data on all websites", "Can take full control of browser tabs"),
        ),
        ("Chrome (Profile 2)", ()),
        ("Opera (com.operasoftware.Opera)", ()),
    ]


@pytest.mark.parametrize(
    ("manifest", "expected"),
    [
        ({"permissions": ["<all_urls>"]}, ["Can read and change data on all websites"]),
        (
            {"content_scripts": [{"matches": ["*://*/*"]}]},
            ["Can read and change data on all websites"],
        ),
        (
            {
                "host_permissions": [
                    "https://a.invalid/*",
                    "https://b.invalid/*",
                    "https://c.invalid/*",
                    "https://d.invalid/*",
                ]
            },
            [
                "Can read and change data on https://a.invalid/*, https://b.invalid/*, "
                "https://c.invalid/* and 1 more"
            ],
        ),
        (
            {"permissions": ["cookies", "nativeMessaging"]},
            [
                "Can read and change cookies, including sign-ins, on the sites it can reach",
                "Can exchange messages with an app installed on this computer",
            ],
        ),
        ({"permissions": "debugger", "host_permissions": {"x": 1}, "content_scripts": "x"}, []),
        ({}, []),
    ],
)
def test_site_access_in_plain_words(manifest, expected):
    assert site_access(manifest) == expected
