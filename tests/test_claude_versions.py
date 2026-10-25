"""Read B (gate A): installed Claude Code versions, and the version-aware start-mode warning."""

import json
import os
from pathlib import Path

import pytest

from shepherd_scan import claude_versions
from shepherd_scan.claude_versions import (
    active_terminal_version,
    claude_code_versions,
    start_mode_warning,
)
from shepherd_scan.reach.acts import acts_without_asking

SYSTEM = Path("system")
DEFINITE = "starts in auto mode"


def folders(root: Path, *names: str) -> None:
    for name in names:
        (root / name).mkdir(parents=True, exist_ok=True)


def link_claude(home: Path, version: str) -> None:
    target = home / ".local" / "share" / "claude" / "versions" / version
    target.mkdir(parents=True, exist_ok=True)
    link = home / ".local" / "bin" / "claude"
    link.parent.mkdir(parents=True, exist_ok=True)
    if link.is_symlink():
        link.unlink()
    os.symlink(target, link)


def test_each_surface_reports_the_versions_its_folders_hold(fake_home, tmp_path):
    folders(fake_home / ".local" / "share" / "claude" / "versions", "2.1.280", "notes")
    link_claude(fake_home, "2.1.226")
    npm = tmp_path / SYSTEM / "node_modules" / "@anthropic-ai" / "claude-code"
    npm.mkdir(parents=True)
    (npm / "package.json").write_text(json.dumps({"version": "2.1.250", "name": "x"}))
    folders(tmp_path / SYSTEM / "Caskroom" / "claude-code", "2.1.270")
    desktop = claude_versions._desktop_dir(fake_home)
    folders(desktop / "claude-code", "2.1.258", "2.1.280")
    folders(desktop / "claude-code-vm", "2.1.280")
    folders(fake_home / ".vscode" / "extensions", "anthropic.claude-code-2.1.279-darwin-arm64",
            "anthropic.other-1.0.0")  # fmt: skip
    folders(fake_home / ".cursor" / "extensions", "anthropic.claude-code-2.1.250")
    assert claude_code_versions(fake_home) == {
        "terminal": ["2.1.226", "2.1.250", "2.1.270", "2.1.280"],
        "terminal_active": ["2.1.226"],
        "desktop": ["2.1.258", "2.1.280"],
        "cowork": ["2.1.280"],
        "ide": ["2.1.250", "2.1.279"],
    }
    assert active_terminal_version(fake_home) == "2.1.226"


def test_a_missing_or_unrecognised_source_gives_no_version_never_a_guess(fake_home, tmp_path):
    assert claude_code_versions(fake_home) == {}
    assert active_terminal_version(fake_home) == ""
    copied = fake_home / ".local" / "bin" / "claude"
    copied.parent.mkdir(parents=True)
    copied.write_text("a copied binary, not a link")
    npm = tmp_path / SYSTEM / "node_modules" / "@anthropic-ai" / "claude-code"
    npm.mkdir(parents=True)
    (npm / "package.json").write_text(json.dumps({"version": "latest"}))
    assert claude_code_versions(fake_home) == {}
    assert active_terminal_version(fake_home) == ""


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.1.227", ""),
        ("2.1.228", "may start in auto mode on Pro, Max and Team plans"),
        ("2.1.283", "may start in auto mode on Pro, Max and Team plans"),
        ("2.1.284", f"Claude Code 2.1.284 {DEFINITE}"),
        ("2.1.301", f"Claude Code 2.1.301 {DEFINITE}"),
        ("", "depending on its version and plan"),
        ("2.1", "depending on its version and plan"),
        ("latest", "depending on its version and plan"),
    ],
)
def test_the_warning_is_definite_only_from_the_version_every_plan_starts_in_auto(version, expected):
    warning = start_mode_warning(version)
    if not expected:
        assert warning == ""
        return
    assert expected in warning
    if DEFINITE not in expected:
        assert DEFINITE not in warning


def claude_warnings(home: Path) -> list[str]:
    settings = home / ".claude" / "settings.json"
    settings.write_text(json.dumps({"permissions": {"allow": []}}))
    findings = acts_without_asking(home, {"claude-code"})
    return [f.what for f in findings if f.where and "defaultMode not set" in f.where]


def test_d1_words_its_warning_for_the_version_claude_runs(fake_home):
    assert [DEFINITE not in w for w in claude_warnings(fake_home)] == [True]
    link_claude(fake_home, "2.1.226")
    assert claude_warnings(fake_home) == []
    link_claude(fake_home, "2.1.290")
    [warning] = claude_warnings(fake_home)
    assert f"Claude Code 2.1.290 {DEFINITE}" in warning
