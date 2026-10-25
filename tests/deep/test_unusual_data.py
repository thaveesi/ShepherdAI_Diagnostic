"""Ordinary but unusual data on a customer's computer must not stop the deep check."""

import json
import os
import shutil
import sys
import threading
from datetime import date
from pathlib import Path

import pytest

from shepherd_scan import claude_versions
from shepherd_scan._vendor.discovery.agents.vscode.base import _file_uri_to_path
from shepherd_scan._vendor.discovery.models.mcp import RemoteServer
from shepherd_scan._vendor.discovery.models.skill import SkillFile
from shepherd_scan.deep import collect, inventory, protections, skills
from shepherd_scan.deep import run as deep_check
from shepherd_scan.deep.blank import clean
from shepherd_scan.deep.inventory import (
    LocalServer,
    _local_server,
    _present,
    _read_json,
    _source_ref,
)
from shepherd_scan.deep.skills import SkillSource, _blank, static_scan
from shepherd_scan.deep.usage import tidy
from shepherd_scan.discovery import discover
from shepherd_scan.reach import acts


def test_a_skill_header_with_a_date_is_packaged_as_text(fake_home: Path, no_network):
    skill = fake_home / ".claude" / "skills" / "dated"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: dated\ndescription: A dated skill.\nupdated: 2025-10-01\n---\nDo things.\n"
    )
    out = fake_home.parent / "upload"
    collect.collect_bundle(out, discover(), fake_home)
    packets = [json.loads(p.read_text()) for p in (out / "skills").glob("skill-*/packet.json")]
    [dated] = [p for p in packets if p["name"] == "dated"]
    assert dated["static_scan"]["frontmatter"]["updated"] == "2025-10-01"


def test_a_settings_file_the_terminal_may_not_open_reads_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def refuse(self: Path) -> bool:
        raise PermissionError(1, "Operation not permitted", str(self))

    monkeypatch.setattr(Path, "is_file", refuse)
    assert _read_json(tmp_path / "Desktop" / "proj" / ".claude" / "settings.json") is None


def test_a_remote_address_with_a_placeholder_host_is_read_without_a_host():
    config = RemoteServer(url="http://[YOUR_HOST]:3000/mcp")
    server = _local_server("Cursor", "mine", config, "~/.cursor/mcp.json")
    assert (server.launcher, server.package) == ("remote", "")


def test_a_program_path_that_cannot_be_checked_is_unknown():
    assert _present("~no-such-user-shepherd/bin/x") is None
    assert _present("relative/x") is None
    assert _present("/no-such-folder-shepherd/x") is False


def test_a_scoped_package_cached_by_bun_keeps_its_version(tmp_path: Path):
    folder = tmp_path / ".bun" / "install" / "cache" / "@babel" / "code-frame@7.24.2@@@1"
    folder.mkdir(parents=True)
    assert collect._cached_versions("@babel/code-frame", tmp_path) == [("7.24.2", folder)]


def test_a_package_manifest_that_is_not_an_object_or_not_utf8_has_no_version(tmp_path: Path):
    listed, binary = tmp_path / "a.json", tmp_path / "b.json"
    listed.write_text("[1, 2]")
    binary.write_bytes(b"\xff\xfe{")
    assert collect._package_version(listed) == collect._package_version(binary) == ""


def test_a_file_that_cannot_be_read_is_left_out(tmp_path: Path):
    (tmp_path / "ok.js").write_text("ok")
    locked = tmp_path / "locked.js"
    locked.write_text("locked")
    locked.chmod(0)
    try:
        files, skipped = collect._text_files(tmp_path)
    finally:
        locked.chmod(0o644)
    assert list(files) == ["ok.js"] and skipped == 1


def test_two_server_packages_with_the_same_folder_name_are_packaged_once(tmp_path: Path):
    home, skills_dir = tmp_path / "home", tmp_path / "upload" / "skills"
    servers = []
    for number, package in enumerate(("@a/b.js", "@a/b-js"), start=1):
        folder = home / ".npm" / "_npx" / f"h{number}" / "node_modules" / package
        folder.mkdir(parents=True)
        (folder / "package.json").write_text(json.dumps({"name": package, "version": "1.0.0"}))
        (folder / "index.js").write_text("// server\n")
        servers.append(LocalServer("Claude Code", f"s{number}", "npx", package, "", "~/.mcp.json"))
    assert list(collect._server_packets(servers, skills_dir, home)) == ["server-a-b-js"]


def test_a_skill_that_disappears_while_packaging_is_listed_as_unreadable(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    real = collect.write_packet
    calls: list[str] = []

    def vanishing(source, skill_id, skills_dir, folder_name):
        calls.append(skill_id)
        if len(calls) == 1:
            raise FileNotFoundError(2, "No such file or directory", str(source.folder))
        return real(source, skill_id, skills_dir, folder_name=folder_name)

    monkeypatch.setattr(collect, "write_packet", vanishing)
    manifest = collect.collect_bundle(fake_home.parent / "upload", discover(), fake_home)
    assert manifest["skills"] == len(calls) - 1 >= 1
    assert manifest["skills_not_readable"]


def test_a_date_used_as_a_key_in_a_skill_header_is_packaged(fake_home: Path, no_network):
    skill = fake_home / ".claude" / "skills" / "history"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: history\ndescription: Kept.\nhistory:\n  2025-01-15: first\n---\nBody.\n"
    )
    out = fake_home.parent / "upload"
    collect.collect_bundle(out, discover(), fake_home)
    packets = [json.loads(p.read_text()) for p in (out / "skills").glob("skill-*/packet.json")]
    [kept] = [p for p in packets if p["name"] == "history"]
    assert kept["static_scan"]["frontmatter"]["history"] == {"2025-01-15": "first"}


def test_a_dotted_account_name_is_hidden_in_usage_text():
    text = tidy("Large context in -Users-john-smith-Desktop-app today", "john.smith")
    assert "john" not in text and "smith" not in text and "~/Desktop-app" in text


def test_a_package_source_with_a_placeholder_host_is_read_without_its_login():
    source, ref = _source_ref("https://me:secret@[YOUR_HOST]/tool.tgz?token=abc#v1")
    assert "secret" not in source and "token" not in source and ref == ""


def test_a_path_whose_type_cannot_be_checked_is_not_copied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def refuse(self: Path) -> bool:
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "is_file", refuse)
    assert collect._copyable(tmp_path / "a.js", Path("a.js")) is False


def test_the_scanner_copy_stops_before_reading_past_its_size_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    root, target = tmp_path / "pkg", tmp_path / "copy"
    root.mkdir()
    (root / "a.js").write_text("aaa")
    (root / "b.js").write_text("b" * 50)
    monkeypatch.setattr(collect, "SCAN_COPY_LIMIT", 10)
    read: list[str] = []
    real = Path.read_text

    def recording(self: Path, *args, **kwargs) -> str:
        read.append(self.name)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", recording)
    collect._write_scan_copy(target, root)
    assert read == ["a.js"] and (target / "a.js").is_file() and not (target / "b.js").exists()


HUGE_NUMBER = '{"version": "1.0.0", "n": ' + "9" * 5000 + "}"


def test_a_codex_rules_file_without_rules_counts_no_rules(tmp_path: Path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "default.rules").write_text("# saved approvals were cleared\n")
    rows = protections._codex_rules(tmp_path)
    assert {row.key: row.value for row in rows} == {
        f"rules.{decision}": "0" for decision in protections.RULE_STATES
    }


def test_a_codex_trust_level_that_is_not_text_is_not_counted():
    place = protections.Place("Codex", "terminal", "~/.codex/config.toml", "user")
    data = {"projects": {"/a": {"trust_level": ["trusted"]}}}
    rows = protections._codex_trust(place, data, frozenset())
    assert [row.value for row in rows] == ["0"] * len(protections.TRUST_STATES)


def test_policy_folders_the_person_may_not_open_read_as_no_policy(fake_home: Path):
    policy = Path(acts.CLAUDE_MANAGED[sys.platform])
    policy.parent.mkdir(parents=True)
    policy.write_text("{}")
    inventory.MANAGED_DEVICE_FOLDER.mkdir(parents=True)
    system = policy.parent.parent
    assert inventory.MANAGED_DEVICE_FOLDER.parent == system
    system.chmod(0)
    try:
        company = inventory.company_signals(fake_home)
    finally:
        system.chmod(0o755)
    assert (company.managed_device, company.claude_managed_settings) == (False, False)


def test_a_hooks_entry_that_is_not_a_list_has_no_hooks():
    assert inventory._hooks({"PreToolUse": [{"matcher": "Bash", "hooks": 1}]}) == []


def test_a_session_folder_that_cannot_be_entered_is_skipped(tmp_path: Path):
    folder = tmp_path / "Library" / "Application Support" / "Claude" / "claude-code-sessions"
    folder = folder / "org" / "project"
    folder.mkdir(parents=True)
    (folder / "local_1.json").write_text("{}")
    folder.chmod(0o444)
    try:
        sessions = inventory.desktop_sessions(tmp_path)
    finally:
        folder.chmod(0o755)
    assert sessions == []


def test_a_json_file_with_a_number_too_long_to_read_is_unreadable(tmp_path: Path):
    path = tmp_path / "settings.json"
    path.write_text(HUGE_NUMBER)
    assert inventory._read_json(path) is None
    assert claude_versions._manifest_version(path) == ""
    folder = tmp_path / "Library" / "Application Support" / "Claude" / "claude-code-sessions"
    (folder / "org" / "project").mkdir(parents=True)
    (folder / "org" / "project" / "local_1.json").write_text(HUGE_NUMBER)
    assert inventory.desktop_sessions(tmp_path) == []


SKILL_TEXT = "---\nname: node-tool\ndescription: Runs a bundled tool.\n---\nRun it.\n"


def test_a_skill_holding_a_package_json_that_is_not_an_object_does_not_stop_the_package(
    tmp_path: Path,
):
    skill = tmp_path / "node-tool"
    (skill / "examples" / "broken").mkdir(parents=True)
    (skill / "SKILL.md").write_text(SKILL_TEXT)
    (skill / "examples" / "broken" / "package.json").write_text("[]")
    assert static_scan(skill) == {
        "findings": [], "total_findings": 0, "not_scanned": "AttributeError"
    }  # fmt: skip


@pytest.mark.parametrize("header", [
    "description:\n  Work with GitHub. Use when: a repository is named.",
    "description:\n  - Work with issues\n  - Review pull requests",
    "description: Work with GitHub.\nupdated: 2025-02-30",
])  # fmt: skip
def test_a_package_whose_skill_header_has_an_odd_shape_does_not_stop_the_package(
    tmp_path: Path, header: str
):
    (tmp_path / "index.js").write_text("console.log('server');\n")
    (tmp_path / "SKILL.md").write_text(f"---\nname: github\n{header}\n---\n# Using it\n")
    result = static_scan(tmp_path)
    assert isinstance(result["findings"], list)


def test_a_rule_scan_that_fails_marks_the_packet_not_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def fails(folder: Path) -> dict[str, object]:
        raise AttributeError(str(folder))

    monkeypatch.setattr(skills.skillrules, "scan_skill", fails)
    assert static_scan(tmp_path) == {
        "findings": [], "total_findings": 0, "not_scanned": "AttributeError"
    }  # fmt: skip


def test_a_claude_config_folder_the_terminal_may_not_open_does_not_stop_the_package(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    target = fake_home / "Documents" / "claude-config"
    target.mkdir(parents=True)
    (target / ".claude.json").write_text("{}")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(target))
    found = discover()
    (fake_home / "Documents").chmod(0)
    try:
        manifest = collect.collect_bundle(fake_home.parent / "upload", found, fake_home)
    finally:
        (fake_home / "Documents").chmod(0o755)
    assert manifest["skills"] >= 1


def test_a_workspace_address_that_does_not_parse_names_no_folder():
    assert _file_uri_to_path("file://[not-a-host]/x") is None


def test_half_an_escaped_emoji_in_a_setting_is_blanked_without_stopping():
    cleaned = clean("Bash(API_KEY=abc\ud83d npm test)")
    assert "\ud83d" not in cleaned and cleaned.startswith("Bash(")


def test_a_skill_that_fails_to_package_for_any_reason_is_listed_as_unreadable(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    def odd(*_args: object, **_kwargs: object) -> None:
        raise AttributeError("'list' object has no attribute 'get'")

    monkeypatch.setattr(collect, "write_packet", odd)
    manifest = collect.collect_bundle(fake_home.parent / "upload", discover(), fake_home)
    assert manifest["skills"] == 0 and manifest["skills_not_readable"]
    assert all(entry.endswith("(AttributeError)") for entry in manifest["skills_not_readable"])


def finishes(run, seconds: float = 30) -> bool:
    """Run ``run`` in the background; whether it finished within ``seconds``."""
    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    return not worker.is_alive()


def test_a_project_path_with_a_nul_character_is_compared_as_written():
    odd = Path("~/a\0b")
    assert acts._same_file_key(odd) == odd


def test_codex_rule_and_policy_values_of_an_odd_shape_are_skipped():
    assert protections.prefix_rules('prefix_rule(pattern = [{{}: 1}], decision = "allow")') == [
        ("allow", "")
    ]
    assert protections._folder_count("9" * 5000) is None
    assert protections._folder_count("[" * 100_000) is None


def test_a_session_folder_with_half_an_escaped_emoji_is_read(tmp_path: Path):
    folder = tmp_path / "Library" / "Application Support" / "Claude" / "claude-code-sessions"
    (folder / "org" / "project").mkdir(parents=True)
    (folder / "org" / "project" / "local_1.json").write_text('{"cwd": "/code/\\ud83d"}')
    assert len(inventory.desktop_sessions(tmp_path)) == 1


def test_server_sources_and_paths_that_do_not_parse_are_kept_as_written():
    config = inventory.StdioServer(command="npx", args=["-y", "file://[bad/tool"])
    server = inventory._local_server("Cursor", "mine", config, "~/.cursor/mcp.json")
    assert server.launcher == "path"
    assert inventory._present("~x\0/bin/tool") is None


def test_a_skill_file_name_with_half_an_escaped_emoji_has_a_fingerprint(tmp_path: Path):
    source = SkillSource("s", tmp_path, [SkillFile(path="a\ud83d.md", content="x")])
    assert len(source.digest) == 64


def test_header_keys_are_written_as_json_writes_them():
    blanked = _blank({True: 1, None: 2, 3: 4, date(2025, 1, 15): 5})
    assert json.dumps(blanked) == '{"true": 1, "null": 2, "3": 4, "2025-01-15": 5}'


def test_hook_counts_read_as_before_and_odd_values_do_not_stop_the_check():
    assert acts._hook_count([{"hooks": {"a": 1, "b": 2}}]) == 2
    assert acts._hook_count([{"hooks": 1}]) == 1


def test_a_package_manifest_that_is_a_pipe_has_no_version(tmp_path: Path):
    manifest = tmp_path / "package.json"
    os.mkfifo(manifest)
    found: list[str] = []
    assert finishes(lambda: found.append(collect._package_version(manifest)), 10)
    assert found == [""]


def test_a_plugin_that_cannot_be_packaged_is_left_out_and_the_rest_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    home, skills_dir = tmp_path / "home", tmp_path / "upload" / "skills"
    cache = "~/.claude/plugins/cache/market/tool"
    (home / cache.removeprefix("~/") / "1.0.0" / "scripts").mkdir(parents=True)
    (home / cache.removeprefix("~/") / "1.0.0" / "scripts" / "run.js").write_text("// tool\n")
    (skills_dir / "skill-001").mkdir(parents=True)
    (skills_dir / "skill-001" / "packet.json").write_text("{}")

    def too_long(target: Path, *_args: object) -> None:
        target.mkdir(parents=True)
        raise OSError(63, "File name too long")

    monkeypatch.setattr(collect, "_write_code_packet", too_long)
    ids = {"skill-001": [f"{cache}/1.0.0/skills/run"]}
    assert collect._plugin_packets({"ids": ids}, skills_dir, home) == {}
    assert not (skills_dir / "plugin-market-tool").exists()


@pytest.mark.parametrize("writer", ["_write_code_packet", "_write_scan_copy"])
def test_a_server_whose_copy_cannot_be_written_is_left_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, writer: str
):
    home, skills_dir = tmp_path / "home", tmp_path / "upload" / "skills"
    folder = home / ".npm" / "_npx" / "h1" / "node_modules" / "tool"
    folder.mkdir(parents=True)
    (folder / "package.json").write_text(json.dumps({"name": "tool", "version": "1.0.0"}))
    (folder / "index.js").write_text("// server\n")

    def full(target: Path, *_args: object) -> None:
        target.mkdir(parents=True)
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(collect, writer, full)
    servers = [LocalServer("Claude Code", "s", "npx", "tool", "", "~/.mcp.json")]
    assert collect._server_packets(servers, skills_dir, home) == {}
    assert not (skills_dir / "server-tool").exists()


def test_a_copy_that_cannot_be_kept_never_removes_a_folder_it_did_not_make(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    preparation = deep_check.prepare(discover())
    preparation.wait()
    other_run = fake_home.parent / "report-deep-check"
    other_run.mkdir()
    (other_run / "manifest.json").write_text("{}")

    def refuse(*_args: object) -> None:
        raise shutil.Error("copystat: Operation not permitted")

    monkeypatch.setattr(deep_check.shutil, "move", refuse)
    assert preparation.keep(other_run) is False
    assert (other_run / "manifest.json").is_file()


def test_a_session_record_that_is_a_pipe_is_skipped(tmp_path: Path):
    folder = tmp_path / "Library" / "Application Support" / "Claude" / "claude-code-sessions"
    (folder / "org" / "project").mkdir(parents=True)
    os.mkfifo(folder / "org" / "project" / "local_1.json")
    found: list[object] = []
    assert finishes(lambda: found.append(inventory.desktop_sessions(tmp_path)), 10)
    assert found == [[]]
