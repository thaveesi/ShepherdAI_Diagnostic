"""Ordinary but unusual things on a customer's computer must not stop the scan or empty a check.

Folders macOS keeps from the terminal (the person declined its prompt) are stood in for by a
folder whose permissions are removed; Python raises the same PermissionError for both.
"""

import asyncio
import glob
import io
import json
import os
import plistlib
import random
import re
import sys
import threading
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import pytest
from detect_secrets.settings import default_settings
from rich.console import Console

from shepherd_scan import cli
from shepherd_scan._vendor import skillrules
from shepherd_scan._vendor.discovery import pipelines
from shepherd_scan._vendor.discovery.inspect import (
    _resolve_glob_with_depth,
    get_mcp_config_per_home_directory,
)
from shepherd_scan._vendor.discovery.models.inspect import CandidateClient
from shepherd_scan._vendor.discovery.redact import _detect_keyword
from shepherd_scan._vendor.discovery.utils import ensure_unicode_console
from shepherd_scan.apps import installed
from shepherd_scan.checks.secrets import format_kind
from shepherd_scan.discovery import LocalServer, discover
from shepherd_scan.reach import acts
from shepherd_scan.report.build import readable_problems
from shepherd_scan.settings_files import load_settings

BAD_DATE_PLIST = (
    '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
    "<key>CFBundleIdentifier</key><string>com.example.odd</string>"
    "<key>Built</key><date>{{BUILD_DATE}}</date></dict></plist>"
)
KEY_ONLY_PLIST = '<?xml version="1.0"?><plist version="1.0"><key>a</key></plist>'


def test_a_folder_in_applications_that_cannot_be_opened_is_skipped(tmp_path: Path):
    applications, elsewhere = tmp_path / "Applications", tmp_path / "elsewhere"
    (applications / "Good.app").mkdir(parents=True)
    (elsewhere / "Games").mkdir(parents=True)
    (applications / "Games").symlink_to(elsewhere / "Games")
    elsewhere.chmod(0)
    try:
        candidates = installed._app_candidates(applications)
    finally:
        elsewhere.chmod(0o755)
    assert candidates == [applications / "Good.app"]


def test_an_app_with_a_malformed_info_plist_is_matched_by_name_only(tmp_path: Path):
    for name, text in (("Dated.app", BAD_DATE_PLIST), ("Keyed.app", KEY_ONLY_PLIST)):
        contents = tmp_path / name / "Contents"
        contents.mkdir(parents=True)
        (contents / "Info.plist").write_text(text)
        assert installed._bundle_id(tmp_path / name) == ""


def test_a_malformed_xml_preferences_file_reads_as_unreadable(tmp_path: Path):
    for number, text in enumerate(("<plist><dict><key>a&b</key></dict></plist>", "<plist><dict>",
                                   BAD_DATE_PLIST, KEY_ONLY_PLIST)):  # fmt: skip
        path = tmp_path / f"com.example.{number}.plist"
        path.write_text(text)
        assert load_settings(path) is None
    good = tmp_path / "good.plist"
    good.write_bytes(plistlib.dumps({"a": 1}))
    assert load_settings(good) == {"a": 1}


def test_a_codex_rules_file_without_rules_leaves_the_codex_findings(fake_home: Path):
    codex = fake_home / ".codex"
    (codex / "rules").mkdir(parents=True, exist_ok=True)
    (codex / "rules" / "default.rules").write_text("# saved approvals were cleared\n")
    (codex / "config.toml").write_text('approval_policy = "never"\n')
    found = acts.acts_without_asking(fake_home, {"codex"})
    assert any("approval_policy: never" in finding.what for finding in found)


def test_a_hooks_entry_that_is_not_a_list_leaves_the_claude_code_findings(fake_home: Path):
    settings = fake_home / ".claude" / "settings.json"
    settings.write_text(json.dumps({
        "permissions": {"defaultMode": "bypassPermissions"},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": 1}]},
    }))  # fmt: skip
    found = acts.acts_without_asking(fake_home, {"claude-code"})
    claude_code = [finding.what for finding in found if finding.app == "Claude Code"]
    assert any("bypassPermissions" in what for what in claude_code)


SKILL = "---\nname: mine\ndescription: Kept.\n---\nBody.\n"


@contextmanager
def locked(folder: Path) -> Generator[None]:
    """A folder the terminal may not open, as when the person declines macOS's prompt."""
    folder.chmod(0)
    try:
        yield
    finally:
        folder.chmod(0o755)


def report_written(home: Path) -> bool:
    out = home.parent / "report.html"
    return cli.main(["--no-open", "--no-deep", "-o", str(out)]) == 0 and out.stat().st_size > 0


def test_a_skills_folder_linked_into_a_folder_the_terminal_may_not_open(fake_home, no_network):
    target = fake_home / "Documents" / "claude-skills"
    (target / "mine").mkdir(parents=True)
    (target / "mine" / "SKILL.md").write_text(SKILL)
    skills = fake_home / ".claude" / "skills"
    skills.rename(fake_home / ".claude" / "skills-before")
    skills.symlink_to(target)
    with locked(fake_home / "Documents"):
        assert report_written(fake_home)


def test_a_skills_folder_that_is_a_file_or_cannot_be_listed(fake_home, no_network):
    (fake_home / ".cursor").mkdir(exist_ok=True)
    (fake_home / ".cursor" / "skills").write_text("not a folder\n")
    gemini = fake_home / ".gemini" / "skills"
    gemini.mkdir(parents=True)
    gemini.chmod(0o311)
    try:
        assert report_written(fake_home)
    finally:
        gemini.chmod(0o755)


def test_an_mcp_settings_file_linked_into_a_folder_the_terminal_may_not_open(fake_home, no_network):
    repo = fake_home / "Documents" / "dotfiles"
    repo.mkdir(parents=True)
    (repo / "cursor-mcp.json").write_text(json.dumps({"mcpServers": {}}))
    mcp = fake_home / ".cursor" / "mcp.json"
    mcp.parent.mkdir(exist_ok=True)
    mcp.unlink(missing_ok=True)
    mcp.symlink_to(repo / "cursor-mcp.json")
    with locked(fake_home / "Documents"):
        assert report_written(fake_home)


def test_a_plugin_skills_folder_linked_into_a_folder_the_terminal_may_not_open(
    fake_home, no_network
):
    target = fake_home / "Documents" / "plugin-skills"
    target.mkdir(parents=True)
    plugin = fake_home / ".claude" / "plugins" / "cache" / "market" / "plug" / "1.0.0"
    plugin.mkdir(parents=True)
    (plugin / "skills").symlink_to(target)
    with locked(fake_home / "Documents"):
        assert report_written(fake_home)


def test_an_emoji_written_as_escaped_halves_does_not_empty_the_report(fake_home, no_network):
    config = fake_home / ".continue" / "config.yaml"
    config.parent.mkdir(parents=True)
    name = json.dumps("Calendar \U0001f4c5")
    config.write_text(f'mcpServers:\n  - name: {name}\n    command: npx\n    args: ["-y", "c"]\n')
    assert report_written(fake_home)


def test_a_connector_whose_tools_are_a_number_is_listed_without_tools(fake_home, no_network):
    session = (
        fake_home / "Library" / "Application Support" / "Claude" / "claude-code-sessions"
        / "account" / "org" / "local_two.json"
    )  # fmt: skip
    session.parent.mkdir(parents=True, exist_ok=True)
    session.write_text(json.dumps({"remoteMcpServersConfig": [
        {"uuid": "d-1", "name": "Drive", "url": "https://drive.example.invalid/mcp", "tools": 12}
    ]}))  # fmt: skip
    assert report_written(fake_home)


def test_closing_the_server_question_means_no(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(cli, "list_local_servers", lambda: [LocalServer("cursor", "s", "npx s")])
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    console = Console(file=io.StringIO())

    def closed(*_args: object, **_kwargs: object) -> str:
        raise EOFError

    monkeypatch.setattr(console, "input", closed)
    assert cli._confirm_server_start(console, assume_yes=False) is False


def test_server_names_that_look_like_terminal_markup_are_printed_as_written(
    monkeypatch: pytest.MonkeyPatch,
):
    server = LocalServer("cursor", "tools [/x]", "npx [/y] [bold]")
    monkeypatch.setattr(cli, "list_local_servers", lambda: [server])
    out = io.StringIO()
    assert cli._confirm_server_start(Console(file=out), assume_yes=True) is True
    assert "tools [/x]" in out.getvalue() and "npx [/y] [bold]" in out.getvalue()


def test_one_agent_whose_settings_cannot_be_read_does_not_stop_the_scan(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    real = pipelines.get_mcp_config_per_client
    calls: list[str] = []

    async def first_fails(client, *args, **kwargs):
        calls.append(client.name)
        if len(calls) == 1:
            raise RuntimeError("settings in a shape no reader expects")
        return await real(client, *args, **kwargs)

    monkeypatch.setattr(pipelines, "get_mcp_config_per_client", first_fails)
    assert report_written(fake_home) and len(calls) > 1


def test_an_unexpected_error_naming_markup_is_reported_as_written(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    def stops(*_args: object) -> int:
        raise RuntimeError("a folder named [/x] could not be read")

    monkeypatch.setattr(cli, "_run", stops)
    assert cli.main(["--no-open", "--no-deep"]) == cli.EXIT_ERROR
    output = " ".join(capsys.readouterr().out.split())  # long messages wrap onto indented lines
    assert "a folder named [/x] could not be read" in output


def test_one_place_of_an_agent_the_terminal_may_not_open_leaves_its_other_places(
    tmp_path: Path,
):
    home = tmp_path / "home"
    agent = home / ".agent"
    (agent / "skills" / "mine").mkdir(parents=True)
    (agent / "skills" / "mine" / "SKILL.md").write_text(SKILL)
    servers = {"mcpServers": {"kept": {"command": "npx", "args": ["kept-server"]}}}
    (agent / "mcp.json").write_text(json.dumps(servers))
    documents = home / "Documents"
    (documents / "skills").mkdir(parents=True)
    (documents / "mcp.json").write_text(json.dumps(servers))
    (agent / "linked.json").symlink_to(documents / "mcp.json")
    (agent / "linked-skills").symlink_to(documents / "skills")
    (agent / "plugins" / "p").mkdir(parents=True)
    (agent / "plugins" / "p" / "skills").symlink_to(documents / "skills")
    client = CandidateClient(
        name="agent",
        client_exists_paths=["~/.agent"],
        mcp_config_paths=["~/.agent/linked.json", "~/.agent/mcp.json"],
        skills_dir_paths=["~/.agent/linked-skills", "~/.agent/skills"],
        skills_dir_globs=["~/.agent/plugins/*/skills"],
    )
    with locked(documents):
        found = asyncio.run(get_mcp_config_per_home_directory(client, home))
    assert found is not None
    assert [name for name, _ in found.mcp_configs[(agent / "mcp.json").as_posix()]] == ["kept"]
    assert (agent / "skills").as_posix() in found.skills_dirs


def finishes(run, seconds: float = 60) -> bool:
    """Run ``run`` in the background; whether it finished within ``seconds``."""
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    return not worker.is_alive()


def test_pipes_where_settings_files_are_expected_do_not_stall_the_scan(fake_home: Path, no_network):
    for place in (fake_home / ".codex" / "config.toml", fake_home / ".cursor" / "mcp.json",
                  fake_home / ".continue" / "config.yaml"):  # fmt: skip
        place.parent.mkdir(parents=True, exist_ok=True)
        place.unlink(missing_ok=True)
        os.mkfifo(place)
    out = fake_home.parent / "report.html"
    codes: list[int] = []
    assert finishes(lambda: codes.append(cli.main(["--no-open", "--no-deep", "-o", str(out)])))
    assert codes == [0]


def test_an_info_plist_that_is_a_pipe_reads_as_no_bundle_id(tmp_path: Path):
    contents = tmp_path / "Odd.app" / "Contents"
    contents.mkdir(parents=True)
    os.mkfifo(contents / "Info.plist")
    found: list[str] = []
    assert finishes(lambda: found.append(installed._bundle_id(tmp_path / "Odd.app")), 10)
    assert found == [""]


def test_a_minified_script_line_is_checked_quickly_with_the_same_answers():
    rng = random.Random(3)  # noqa: S311 - reproducible test data, not security
    words = ["open(", "write", "Path", "subprocess", "nc ", "shell=True", "os.environ[", "KEY",
             "SECRET", "TOKEN", ".ssh", "~", "HOME", "settings.json", ".claude", ".git/hooks",
             "codecs.decode(", "rot", "compile(", "exec", "credentials", ".env", "x", " ", ".",
             "(", "[", "\r"]  # fmt: skip
    for _ in range(300):
        line = "".join(rng.choice(words) for _ in range(rng.randint(400, 1200)))
        for pattern, _description, _severity in skillrules.DANGEROUS_SCRIPT_PATTERNS:
            assert skillrules._line_matches(pattern, line) == bool(re.search(pattern, line)), (
                pattern
            )
    bundle = "var a=open(b);" * 80_000
    patterns = [pattern for pattern, _d, _s in skillrules.DANGEROUS_SCRIPT_PATTERNS]
    assert finishes(lambda: [skillrules._line_matches(p, bundle) for p in patterns], 10)


def test_the_plugin_cache_walk_matches_glob_and_ends_on_looping_links(tmp_path: Path):
    cache = tmp_path / "cache"
    for path in ("m/p/1.0/skills/s", "m/p/1.0/a/b/c/d/skills", "m/q/2.0/skills",
                 "m/p/1.0/.hidden/skills"):  # fmt: skip
        (cache / path).mkdir(parents=True)
    (cache / "m" / "p" / "1.0" / ".mcp.json").write_text("{}")
    (cache / "m" / "q" / "2.0" / "linked").symlink_to(cache / "m" / "q" / "2.0" / "skills")
    for suffix in ("skills", ".mcp.json"):
        pattern = f"{cache}/**/{suffix}"
        expected = [m for m in glob.glob(pattern, recursive=True)
                    if len(Path(m).parts) - len(cache.parts) <= 6]  # fmt: skip
        assert _resolve_glob_with_depth(pattern, 6) == expected
    plugin = cache / "m" / "p" / "1.0"
    (plugin / "x").symlink_to(plugin.parent)
    (plugin / "y").symlink_to(plugin.parent)
    assert finishes(lambda: _resolve_glob_with_depth(f"{cache}/**/skills", 6), 10)


def test_a_terminal_set_to_a_legacy_encoding_does_not_stop_the_scan(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="ascii"))
    ensure_unicode_console()
    print("Looking for AI agents\u2026")


def test_a_start_folder_that_is_gone_saves_the_report_in_the_home_folder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    def gone(_cls: type) -> Path:
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(Path, "cwd", classmethod(gone))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert cli._default_output().parent == tmp_path


def test_a_browser_helper_that_breaks_does_not_stop_the_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    def broken(_url: str) -> bool:
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(cli.webbrowser, "open", broken)
    cli._open_in_browser(tmp_path / "report.html")


def test_a_report_folder_named_like_terminal_markup_is_printed_as_written(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("COLUMNS", "1000")
    folder = fake_home.parent / "a[" / "b]"
    folder.mkdir(parents=True)
    assert cli.main(["--no-open", "--no-deep", "-o", str(folder / "report.html")]) == 0
    assert "a[/b]" in capsys.readouterr().out


def test_secret_shaped_values_with_half_an_emoji_are_checked_without_stopping():
    with default_settings():
        assert format_kind("https://user:pa\ud83dss@example.com") in (
            None,
            "Basic Auth Credentials",
        )
    _detect_keyword("password", "abc\ud83d123456789")


def test_a_yaml_tag_on_text_that_is_not_a_date_reads_as_unreadable(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("models:\n  k: !!timestamp bogus\n")
    assert load_settings(path) is None


def test_numbers_longer_than_pythons_default_limit_do_not_stop_the_scan(
    fake_home: Path, no_network
):
    session = (
        fake_home / "Library" / "Application Support" / "Claude" / "claude-code-sessions"
        / "account" / "org" / "local_long.json"
    )  # fmt: skip
    session.parent.mkdir(parents=True, exist_ok=True)
    session.write_text(
        '{"remoteMcpServersConfig": [{"uuid": "u", "url": "https://g.example.invalid/mcp", '
        '"tools": [{"name": "send"}], "name": 0x' + "f" * 4000 + "}]}"
    )
    assert report_written(fake_home)


def test_an_agent_whose_settings_cannot_be_read_is_listed_under_could_not_be_checked(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    real = pipelines.get_mcp_config_per_client

    async def windsurf_fails(client, *args, **kwargs):
        if client.name == "windsurf":
            raise RuntimeError("settings in a shape no reader expects")
        return await real(client, *args, **kwargs)

    monkeypatch.setattr(pipelines, "get_mcp_config_per_client", windsurf_fails)
    problems = readable_problems(discover().warnings)
    assert any("Could not read the settings of windsurf under ~/" in p for p in problems)
