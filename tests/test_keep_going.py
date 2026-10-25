"""Whatever part breaks or hangs, the scan writes its report and the deep check has a package.

Each part is replaced, one at a time, by one that fails in a way nobody foresaw.
"""

import json
import time
from pathlib import Path
from types import ModuleType

import pytest

from shepherd_scan import cli
from shepherd_scan import discovery as discovery_module
from shepherd_scan._vendor import skillrules
from shepherd_scan.catalog import Catalog
from shepherd_scan.checks import skills
from shepherd_scan.deep import collect, inventory
from shepherd_scan.deep import run as deep_check
from shepherd_scan.discovery import discover
from shepherd_scan.report import build


def broken(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("a part that breaks in a way nobody foresaw")


def hangs(*_args: object, **_kwargs: object) -> None:
    time.sleep(60)


SCAN_PARTS: list[tuple[ModuleType, str]] = [
    *[(discovery_module, name) for name in (
        "register_readers", "discover_clients_to_inspect", "credential_settings",
        "provider_keys", "inspect_pipeline", "_account_connectors", "load_apps",
        "find_installed_apps", "acts_without_asking", "find_login_files", "elsewhere_notes",
    )],
    *[(build, name) for name in (
        "_add_path", "_app_result", "_add_connector", "_merge_agents", "merge_secret_findings",
        "login_findings", "control_findings", "shared_findings", "command_agents",
    )],
    (cli, "render_html"),
    (cli, "print_summary"),
]  # fmt: skip

COLLECTION_PARTS: list[tuple[ModuleType, str, str]] = [
    (collect, "build_inventory", "the inventory"),
    (collect, "save_inventory", "the inventory file"),
    (collect, "_skill_packets", "skills"),
    (collect, "_plugin_packets", "plugin code"),
    (collect, "_server_packets", "server packages"),
    (collect, "_tool_packet", "connector tools"),
    (collect, "copy_lockfiles", "lockfiles"),
    (inventory, "claude_settings", "inventory: Claude Code settings"),
    (inventory, "desktop_sessions", "inventory: Claude Desktop sessions"),
    (inventory, "local_servers", "inventory: MCP servers"),
    (inventory, "company_signals", "inventory: company signals"),
    (inventory, "claude_code_versions", "inventory: Claude Code versions"),
    (inventory, "project_trust", "inventory: project trust"),
    (inventory, "protection_rows", "inventory: protection settings"),
    (inventory, "agent_app", "inventory: AI apps"),
]


def scan_writes_a_report(home: Path) -> bool:
    out = home.parent / "report.html"
    return cli.main(["--no-open", "--no-deep", "-o", str(out)]) == cli.EXIT_OK and (
        out.stat().st_size > 0
    )


@pytest.mark.parametrize(("module", "name"), SCAN_PARTS, ids=[name for _, name in SCAN_PARTS])
def test_any_part_of_the_scan_can_break_and_the_report_is_still_written(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str
):
    monkeypatch.setattr(module, name, broken)
    assert scan_writes_a_report(fake_home)


def test_the_catalog_can_break_and_the_report_is_still_written(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(cli.Catalog, "load", classmethod(broken))
    assert scan_writes_a_report(fake_home)


@pytest.mark.usefixtures("no_network")
@pytest.mark.parametrize(
    ("module", "name", "part"), COLLECTION_PARTS, ids=[name for _, name, _ in COLLECTION_PARTS]
)
def test_any_part_of_the_collection_can_break_and_only_that_part_is_missing(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str, part: str
):
    found = discover()
    monkeypatch.setattr(module, name, broken)
    upload = fake_home.parent / "upload"
    manifest = collect.collect_bundle(upload, found, fake_home)
    assert manifest["not_collected"] == [{"part": part, "reason": "RuntimeError"}]
    assert json.loads((upload / "manifest.json").read_text()) == manifest


def test_a_part_of_the_scan_that_hangs_is_left_behind(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(discovery_module, "PART_SECONDS", 1.0)
    monkeypatch.setattr(discovery_module, "find_login_files", hangs)
    started = time.monotonic()
    assert scan_writes_a_report(fake_home)
    assert time.monotonic() - started < 30


def test_a_skill_check_that_hangs_is_left_behind(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(skills, "SKILL_SECONDS", 1.0)
    monkeypatch.setattr(skillrules, "scan_skill", hangs)
    started = time.monotonic()
    report = build.build_report(discover(), Catalog([]))
    assert time.monotonic() - started < 30
    assert skills.TOO_LONG in {skill.error for skill in report.skills}
    assert report.servers


def test_a_part_of_the_collection_that_hangs_is_left_behind(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    found = discover()
    monkeypatch.setattr(collect, "STEP_SECONDS", 1.0)
    monkeypatch.setattr(collect, "_skill_packets", hangs)
    started = time.monotonic()
    manifest = collect.collect_bundle(fake_home.parent / "upload", found, fake_home)
    assert time.monotonic() - started < 30
    assert manifest["not_collected"] == [
        {"part": "skills", "reason": "did not finish within 1 seconds"}
    ]


def test_a_collection_that_never_finishes_sends_a_smaller_package(
    fake_home: Path, no_network, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(deep_check, "COLLECTION_SECONDS", 1.0)
    monkeypatch.setattr(deep_check, "collect_bundle", hangs)
    preparation = deep_check.prepare(discover())
    manifest = preparation.wait()
    assert manifest["not_collected"][0]["part"] == "the full package"
    assert (preparation.folder / "acts.json").is_file()
    preparation.discard()
