import json
from pathlib import Path

from shepherd_scan.catalog import Catalog
from shepherd_scan.deep.collect import (
    FORMAT,
    _plugin_packets,
    add_usage,
    collect_bundle,
    strip_home,
)
from shepherd_scan.deep.inventory import Inventory
from shepherd_scan.discovery import discover
from shepherd_scan.report.build import build_report
from tests.conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN, FAKE_SLACK_BOT_TOKEN


def bundle_text(folder: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in sorted(folder.rglob("*"))
        if path.is_file()
    )


def test_the_upload_holds_what_the_review_reads_and_no_secret_values(fake_home: Path, no_network):
    out = fake_home.parent / "upload"
    manifest = collect_bundle(out, discover(), fake_home)
    assert manifest["format"] == FORMAT
    assert {"inventory.json", "acts.json", "manifest.json"} <= {p.name for p in out.iterdir()}
    assert manifest["skills"] == len(list((out / "skills").glob("skill-*/packet.json")))
    inventory = Inventory.from_json(json.loads((out / "inventory.json").read_text()))
    assert [s.default_mode for s in inventory.claude_settings] == ["bypassPermissions"]
    text = bundle_text(out)
    for secret in (FAKE_GITHUB_TOKEN, FAKE_SLACK_BOT_TOKEN, FAKE_AWS_KEY, "secret-value"):
        assert secret not in text
    assert "not read by the scan" not in text
    assert no_network == []


def write_cached_server(home: Path, package: str, version: str) -> Path:
    root = home / ".npm" / "_npx" / "abc123"
    folder = root / "node_modules" / package
    folder.mkdir(parents=True)
    (folder / "package.json").write_text(json.dumps({"name": package, "version": version}))
    (folder / "index.js").write_text("console.log('server');\n")
    (root / "package-lock.json").write_text('{"lockfileVersion": 3}')
    nested = root / "node_modules" / "dep" / "package-lock.json"
    nested.parent.mkdir(parents=True)
    nested.write_text("{}")
    return root


def test_lockfiles_are_copied_with_their_original_location(fake_home: Path, no_network):
    write_cached_server(fake_home, "@modelcontextprotocol/server-github", "1.2.3")
    out = fake_home.parent / "upload"
    manifest = collect_bundle(out, discover(), fake_home)
    copied = "lockfiles/server-modelcontextprotocol-server-github/package-lock.json"
    assert manifest["lockfiles"] == {copied: "~/.npm/_npx/abc123/package-lock.json"}
    assert (out / copied).read_text() == '{"lockfileVersion": 3}'
    packet = json.loads((out / "skills/server-modelcontextprotocol-server-github/packet.json")
                        .read_text())  # fmt: skip
    assert packet["versions_seen"] == ["1.2.3"]


def test_a_server_package_is_also_sent_whole_for_the_package_scanners(fake_home, no_network):
    package = "@modelcontextprotocol/server-github"
    root = write_cached_server(fake_home, package, "1.2.3")
    bundle = root / "node_modules" / package / ".smithery" / "index.cjs"
    bundle.parent.mkdir()
    bundle.write_text("const token = 'x';\n" * 15_000 + f"key = '{FAKE_GITHUB_TOKEN}'\n")
    out = fake_home.parent / "upload"
    collect_bundle(out, discover(), fake_home)
    packet = out / "skills" / "server-modelcontextprotocol-server-github"
    assert not (packet / "files" / ".smithery" / "index.cjs").exists()
    assert json.loads((packet / "packet.json").read_text())["skipped_files"] == 1
    whole = out / "packages" / "server-modelcontextprotocol-server-github"
    assert (whole / "index.js").is_file()
    copied = (whole / ".smithery" / "index.cjs").read_text()
    assert len(copied) > 200_000 and FAKE_GITHUB_TOKEN not in copied
    assert not (whole / "node_modules").exists()


def test_a_path_launched_server_records_whether_its_program_exists(fake_home: Path, no_network):
    program = fake_home / "tools" / "graph"
    program.parent.mkdir()
    program.write_text("#!/bin/sh\n")
    gone = fake_home / "removed" / "bin" / "server"
    config = {"mcpServers": {"graph": {"command": str(program)}, "gone": {"command": str(gone)}}}
    (fake_home / ".cursor" / "mcp.json").write_text(json.dumps(config))
    out = fake_home.parent / "upload"
    collect_bundle(out, discover(), fake_home)
    servers = json.loads((out / "inventory.json").read_text())["servers"]
    present = {s["name"]: s["present"] for s in servers if s["launcher"] == "path"}
    assert present == {"graph": True, "gone": False}


def test_usage_is_added_to_a_collected_upload_without_changing_its_counts(fake_home, no_network):
    out = fake_home.parent / "upload"
    collected = collect_bundle(out, discover(), fake_home)
    assert collected["engines"] == {}
    assert not (out / "engines").exists()
    usage = {"ok": True, "note": "measured", "data": {"monthly": {"monthly": []}}}
    manifest = add_usage(out, usage)
    assert json.loads((out / "engines" / "ccusage-codeburn.json").read_text()) == usage
    assert manifest["engines"] == {"ccusage + CodeBurn": "measured"}
    assert {k: v for k, v in manifest.items() if k != "engines"} == {
        k: v for k, v in collected.items() if k != "engines"
    }
    assert json.loads((out / "manifest.json").read_text()) == manifest
    failed = add_usage(out, {"ok": False, "note": "node download blocked", "data": {}})
    assert failed["engines"] == {"ccusage + CodeBurn": "FAILED: node download blocked"}


def test_the_keys_the_report_lists_are_sent_by_type_and_place_only(fake_home: Path, no_network):
    discovery = discover()
    keys = build_report(discovery, Catalog.load()).secrets
    assert keys, "the fake home holds keys the report lists"
    out = fake_home.parent / "upload"
    manifest = collect_bundle(out, discovery, fake_home, keys)
    sent = json.loads((out / "keys.json").read_text())
    assert sent == [key.model_dump() for key in keys] and manifest["keys"] == len(keys)
    assert set(sent[0]) == {"kind", "where", "location"}
    text = (out / "keys.json").read_text()
    for secret in (FAKE_GITHUB_TOKEN, FAKE_SLACK_BOT_TOKEN, FAKE_AWS_KEY):
        assert secret not in text
    empty = collect_bundle(fake_home.parent / "no-keys", discovery, fake_home)
    assert json.loads((fake_home.parent / "no-keys" / "keys.json").read_text()) == []
    assert empty["keys"] == 0


def test_the_upload_carries_no_user_name_email_or_git_name(fake_home: Path, no_network):
    settings = fake_home / ".claude" / "settings.json"
    settings.parent.mkdir(exist_ok=True)
    rules = ["Bash(git config user.email someone@example.com)",
             "Bash(git config user.name 'Some One')",
             f"Bash(git -C {fake_home}/Desktop/app pull)",
             "Bash(ssh -T git@github.com)"]  # fmt: skip
    settings.write_text(json.dumps({"permissions": {"allow": rules}}))
    out = fake_home.parent / "upload"
    collect_bundle(out, discover(), fake_home)
    text = bundle_text(out)
    for personal in (str(fake_home), "someone@example.com", "Some One"):
        assert personal not in text
    allow = Inventory.from_json(json.loads((out / "inventory.json").read_text())).claude_settings
    sent = [rule for item in allow for rule in item.allow]
    assert "Bash(git config user.email <email>)" in sent
    assert "Bash(git config user.name <name>)" in sent
    assert not any(str(fake_home) in rule for rule in sent)
    assert "Bash(ssh -T git@github.com)" in sent


def test_only_the_home_folder_itself_becomes_a_tilde(tmp_path: Path):
    home = tmp_path / "pat"
    folder = tmp_path / "upload"
    folder.mkdir()
    (folder / "a.json").write_text(json.dumps({"p": f"{home}/x", "q": f"{home}rick/y"}))
    strip_home(folder, home)
    assert json.loads((folder / "a.json").read_text()) == {"p": "~/x", "q": f"{home}rick/y"}


def test_the_home_folder_is_hidden_before_a_full_stop_escaped_or_in_any_case(tmp_path: Path):
    home = tmp_path / "pat"
    folder = tmp_path / "upload"
    folder.mkdir()
    escaped = str(home).replace("/", "\\/")
    text = f"See {home}. Logs in {escaped}\\/x and {str(home).upper()}/y, not {home}.c/z\n"
    (folder / "a.txt").write_text(text)
    strip_home(folder, home)
    assert (folder / "a.txt").read_text() == f"See ~. Logs in ~\\/x and ~/y, not {home}.c/z\n"


def test_claude_s_dashed_project_names_lose_the_home_folder_too(tmp_path: Path):
    home = tmp_path / "pat.c"
    dashed = "".join(c if c.isascii() and c.isalnum() else "-" for c in str(home))
    folder = tmp_path / "upload"
    folder.mkdir()
    rule = f"Bash(grep x ~/.claude/projects/{dashed}-Desktop-work/a.jsonl)"
    (folder / "a.json").write_text(json.dumps({"p": rule, "q": f"{dashed}rick-y"}))
    strip_home(folder, home)
    assert json.loads((folder / "a.json").read_text()) == {
        "p": "Bash(grep x ~/.claude/projects/~-Desktop-work/a.jsonl)",
        "q": f"{dashed}rick-y",
    }


def test_a_copied_lockfile_shows_the_home_folder_as_a_tilde(fake_home: Path, no_network):
    root = write_cached_server(fake_home, "@modelcontextprotocol/server-github", "1.2.3")
    (root / "package-lock.json").write_text(json.dumps({"path": f"{fake_home}/work/app"}))
    out = fake_home.parent / "upload"
    collect_bundle(out, discover(), fake_home)
    copied = out / "lockfiles/server-modelcontextprotocol-server-github/package-lock.json"
    assert json.loads(copied.read_text()) == {"path": "~/work/app"}


def test_the_ai_apps_found_are_sent_with_what_they_can_do(fake_home: Path, no_network):
    (fake_home / ".grokbot").mkdir()
    (fake_home / ".grokbot" / "settings.json").write_text('{"localToolPermission": "ask"}')
    (fake_home / "Library" / "Application Support" / "com.meta.endo").mkdir(parents=True)
    out = fake_home.parent / "upload"
    collect_bundle(out, discover(), fake_home)
    inventory = Inventory.from_json(json.loads((out / "inventory.json").read_text()))
    apps = {app.name: app for app in inventory.apps or []}
    grok, muse = apps["Grok Bot"], apps["Muse (Meta)"]
    assert grok.runs_commands and grok.control == "computer" and not grok.read
    assert ("localToolPermission", "ask") in grok.settings
    assert any("~/.grokbot" in where for where in grok.found)
    assert "Full Disk Access" in muse.can_do and muse.settings == ()


def test_a_package_from_an_older_scanner_says_its_app_list_was_not_sent():
    older = Inventory().to_json()
    del older["apps"]
    assert Inventory.from_json(older).apps is None
    assert Inventory.from_json(Inventory(apps=[]).to_json()).apps == []


def test_a_plugin_cached_in_two_versions_is_packaged_once_from_the_newest(tmp_path: Path):
    home, skills_dir = tmp_path / "home", tmp_path / "upload" / "skills"
    cache = "~/.claude/plugins/cache/claude-plugins-official/vercel"
    ids = {}
    for number, version in enumerate(("1.2.0", "1.10.0"), start=1):
        scripts = home / cache.removeprefix("~/") / version / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "deploy.js").write_text(f"// {version}\n")
        skill_id = f"skill-{number:03d}"
        (skills_dir / skill_id).mkdir(parents=True)
        (skills_dir / skill_id / "packet.json").write_text("{}")
        ids[skill_id] = [f"{cache}/{version}/skills/deploy"]
    packet_id = "plugin-claude-plugins-official-vercel"
    written = _plugin_packets({"ids": ids}, skills_dir, home)
    assert written == {packet_id: home / cache.removeprefix("~/") / "1.10.0"}
    packet = json.loads((skills_dir / packet_id / "packet.json").read_text())
    assert packet["install_locations"] == [f"{cache}/1.10.0"]
    for skill_id in ids:
        assert json.loads((skills_dir / skill_id / "packet.json").read_text())["plugin_packet"] == (
            packet_id
        )
