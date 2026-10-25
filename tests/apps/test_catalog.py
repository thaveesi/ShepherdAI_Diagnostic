import importlib.util
from pathlib import Path

from shepherd_scan._vendor.discovery.agents import DISCOVERERS
from shepherd_scan._vendor.discovery.well_known_clients import get_well_known_clients
from shepherd_scan.apps.catalog import load_apps
from shepherd_scan.names import AGENT_NAMES
from shepherd_scan.readers import register_readers

TOOL = Path(__file__).resolve().parents[2] / "tools" / "build_app_catalog.py"


def _tool():
    spec = importlib.util.spec_from_file_location("build_app_catalog", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shipped_app_list_loads_with_unique_ids():
    apps = load_apps()
    ids = [app.id for app in apps]
    assert len(apps) > 100
    assert len(ids) == len(set(ids))


def test_every_app_can_be_recognised_and_paths_are_in_the_home_folder():
    for app in load_apps():
        anchors = (
            app.mac_bundle_ids,
            app.mac_app_names,
            app.binaries,
            app.folders,
            app.editor_extensions,
            app.browser_extensions,
        )
        assert any(anchors), app.id
        assert all(folder.startswith("~/") for folder in app.folders), app.id
        assert all(path.startswith("~/") for path, _ in app.credential_files), app.id


def test_common_command_names_are_never_anchors():
    ambiguous = _tool().AMBIGUOUS_COMMANDS
    assert not [app.id for app in load_apps() if ambiguous & set(app.binaries)]


def test_every_reader_has_a_display_name_and_every_linked_reader_exists():
    register_readers()
    readers = set(DISCOVERERS) | {client.name for client in get_well_known_clients()}
    assert readers <= set(AGENT_NAMES)
    linked = {app.agent for app in load_apps() if app.agent}
    assert linked <= readers


def test_browser_and_computer_control_apps_say_what_they_do():
    for app in load_apps():
        if app.control is not None and not app.browser_extensions:
            assert app.can_do, app.id


def test_conversion_keeps_only_safe_anchors():
    tool = _tool()
    entry = tool.convert(
        {
            "id": "example",
            "name": "Example",
            "category": "ai_cli",
            "application_names": ["Example.app", "Example"],
            "binary_names": ["example", "agent", "example.exe"],
            "config_paths": ["~/.example", "~/.agents/skills", "$APPDATA/example", "/etc/example"],
            "extension_ids": ["example.example-vscode", "example"],
        }
    )
    assert entry["mac_app_names"] == ["Example.app"]
    assert entry["binaries"] == ["example"]
    assert entry["folders"] == ["~/.example"]
    assert entry["editor_extensions"] == ["example.example-vscode"]
    assert tool.has_anchor(entry)
    assert not tool.has_anchor(
        {**entry, "mac_app_names": [], "binaries": [], "folders": [], "editor_extensions": []}
    )
