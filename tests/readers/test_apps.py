import json
from pathlib import Path

import pytest

from shepherd_scan._vendor.discovery.agents import DISCOVERERS
from shepherd_scan._vendor.discovery.models import CouldNotParseMCPConfig, RemoteServer, StdioServer
from shepherd_scan.readers import register_readers
from shepherd_scan.readers.apps import (
    DEVIN_HOME,
    EDITOR_DATA_ROOT,
    GOOSE_HOME,
    READERS,
    ZED_HOME,
    AntigravityCliDiscoverer,
    AugmentDiscoverer,
    ClineDiscoverer,
    ContinueDiscoverer,
    DevinDiscoverer,
    FactoryDiscoverer,
    GooseDiscoverer,
    GrokBuildDiscoverer,
    HermesAgentDiscoverer,
    JunieDiscoverer,
    KiloCodeDiscoverer,
    KimiCodeDiscoverer,
    LMStudioDiscoverer,
    OpenHandsDiscoverer,
    PiDiscoverer,
    QwenCodeDiscoverer,
    RaycastDiscoverer,
    RooCodeDiscoverer,
    WarpDiscoverer,
    ZedDiscoverer,
    ZeptoClawDiscoverer,
    ZooCodeDiscoverer,
)

STANDARD = {
    "mcpServers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
        "docs": {"url": "https://docs.example.invalid/mcp", "type": "streamableHttp"},
    }
}
SKILL = "---\nname: notes\ndescription: Write notes.\n---\nWrite notes.\n"


def _write(home: Path, raw: str, text: str) -> Path:
    path = home / raw.removeprefix("~/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _skill(home: Path, raw_dir: str) -> None:
    _write(home, f"{raw_dir}/notes/SKILL.md", SKILL)


def _servers(discoverer) -> dict[str, StdioServer | RemoteServer]:
    found: dict[str, StdioServer | RemoteServer] = {}
    for entries in discoverer.discover_mcp_servers().values():
        assert isinstance(entries, list), entries
        found.update(dict(entries))
    return found


def _skill_names(discoverer) -> set[str]:
    return {skill.name for entries in discoverer.discover_skills().values() for skill in entries}


STANDARD_JSON_CASES = [
    (DevinDiscoverer, f"{DEVIN_HOME}/mcp_config.json", f"{DEVIN_HOME}/skills"),
    (ClineDiscoverer, "~/.cline/data/settings/cline_mcp_settings.json", "~/.cline/skills"),
    (LMStudioDiscoverer, "~/.lmstudio/mcp.json", None),
    (FactoryDiscoverer, "~/.factory/mcp.json", "~/.factory/skills"),
    (AugmentDiscoverer, "~/.augment/settings.json", "~/.augment/skills"),
    (JunieDiscoverer, "~/.junie/mcp/mcp.json", "~/.junie/skills"),
    (WarpDiscoverer, "~/.warp/.mcp.json", "~/.warp/skills"),
    (QwenCodeDiscoverer, "~/.qwen/settings.json", "~/.qwen/skills"),
    (OpenHandsDiscoverer, "~/.openhands/mcp.json", "~/.openhands/skills/installed"),
    (PiDiscoverer, "~/.pi/agent/mcp.json", "~/.pi/agent/skills"),
    (KimiCodeDiscoverer, "~/.kimi-code/mcp.json", "~/.kimi-code/skills"),
    (KimiCodeDiscoverer, "~/.kimi/mcp.json", None),
    (ZeptoClawDiscoverer, "~/.mcp/servers.json", "~/.zeptoclaw/skills"),
]


@pytest.mark.parametrize(("reader", "mcp_file", "skills_dir"), STANDARD_JSON_CASES)
def test_reader_finds_servers_and_skills(tmp_path: Path, reader, mcp_file, skills_dir):
    _write(tmp_path, mcp_file, json.dumps({"theme": "dark", **STANDARD}))
    if skills_dir:
        _skill(tmp_path, skills_dir)
    discoverer = reader(tmp_path)
    assert discoverer.client_exists() is not None
    servers = _servers(discoverer)
    assert isinstance(servers["github"], StdioServer)
    assert isinstance(servers["docs"], RemoteServer)
    assert servers["docs"].type == "http"
    if skills_dir:
        assert _skill_names(discoverer) == {"notes"}


def test_reader_is_absent_when_nothing_is_installed(tmp_path: Path):
    for reader in READERS:
        assert reader(tmp_path).client_exists() is None, reader.name


def test_unusable_entry_does_not_hide_its_neighbours(tmp_path: Path):
    servers = {"mcpServers": {"ok": {"command": "tool"}, "broken": {"args": ["no command or url"]}}}
    _write(tmp_path, "~/.factory/mcp.json", json.dumps(servers))
    assert set(_servers(FactoryDiscoverer(tmp_path))) == {"ok"}


def test_settings_file_without_servers_is_not_an_error(tmp_path: Path):
    _write(tmp_path, "~/.qwen/settings.json", json.dumps({"theme": "dark"}))
    assert QwenCodeDiscoverer(tmp_path).discover_mcp_servers() == {}


def test_malformed_file_is_reported_as_unreadable(tmp_path: Path):
    path = _write(tmp_path, "~/.lmstudio/mcp.json", "{ not json")
    result = LMStudioDiscoverer(tmp_path).discover_mcp_servers()
    assert isinstance(result[path.resolve().as_posix()], CouldNotParseMCPConfig)


def test_unreadable_folder_does_not_stop_discovery(tmp_path: Path):
    _write(tmp_path, "~/.factory/mcp.json", json.dumps(STANDARD))
    skills = tmp_path / ".factory" / "skills"
    _skill(tmp_path, "~/.factory/skills")
    skills.chmod(0)
    try:
        discoverer = FactoryDiscoverer(tmp_path)
        assert set(_servers(discoverer)) == {"github", "docs"}
        assert _skill_names(discoverer) == set()
    finally:
        skills.chmod(0o755)


def test_goose_extensions_become_servers(tmp_path: Path):
    _write(
        tmp_path,
        f"{GOOSE_HOME}/config.yaml",
        "GOOSE_MODE: approve\n"
        "extensions:\n"
        "  github:\n    type: stdio\n    cmd: npx\n    args: [-y, server-github]\n"
        "    envs: {LOG_LEVEL: 3}\n    env_keys: [GITHUB_TOKEN]\n"
        "  linear:\n    type: streamable_http\n    uri: https://mcp.linear.invalid/mcp\n"
        "  developer:\n    type: builtin\n",
    )
    servers = _servers(GooseDiscoverer(tmp_path))
    assert set(servers) == {"github", "linear"}
    github = servers["github"]
    assert isinstance(github, StdioServer)
    assert github.env == {"LOG_LEVEL": "3", "GITHUB_TOKEN": ""}
    assert servers["linear"].type == "http"


def test_malformed_yaml_is_reported_as_unreadable(tmp_path: Path):
    path = _write(tmp_path, f"{GOOSE_HOME}/config.yaml", "extensions: [unclosed\n")
    result = GooseDiscoverer(tmp_path).discover_mcp_servers()
    assert isinstance(result[path.resolve().as_posix()], CouldNotParseMCPConfig)


def test_continue_list_config_and_block_folder(tmp_path: Path):
    _write(
        tmp_path,
        "~/.continue/config.yaml",
        "name: my assistant\nmcpServers:\n"
        "  - name: sqlite\n    command: uvx\n    args: [mcp-server-sqlite]\n",
    )
    _write(
        tmp_path,
        "~/.continue/mcpServers/notion.yaml",
        "mcpServers:\n  - name: notion\n    url: https://mcp.notion.invalid/mcp\n",
    )
    _write(
        tmp_path,
        "~/.continue/mcpServers/copied.json",
        json.dumps({"mcpServers": {"fetch": {"command": "uvx"}}}),
    )
    assert set(_servers(ContinueDiscoverer(tmp_path))) == {"sqlite", "notion", "fetch"}


def test_zed_context_servers_both_shapes(tmp_path: Path):
    _write(
        tmp_path,
        f"{ZED_HOME}/settings.json",
        "// Zed settings allow comments\n"
        + json.dumps(
            {
                "context_servers": {
                    "flat": {"command": "npx", "args": ["server-a"], "env": {}},
                    "nested": {
                        "command": {"path": "uvx", "args": ["server-b"], "env": {"TOKEN": "x"}}
                    },
                    "remote": {"url": "https://mcp.example.invalid/mcp"},
                }
            }
        ),
    )
    servers = _servers(ZedDiscoverer(tmp_path))
    assert set(servers) == {"flat", "nested", "remote"}
    nested = servers["nested"]
    assert isinstance(nested, StdioServer)
    assert nested.command == "uvx"


def test_hermes_yaml_servers(tmp_path: Path):
    _write(
        tmp_path,
        "~/.hermes/config.yaml",
        "mcp_servers:\n  files:\n    command: npx\n    args: [server-files]\n",
    )
    assert set(_servers(HermesAgentDiscoverer(tmp_path))) == {"files"}


def test_cline_legacy_editor_storage(tmp_path: Path):
    storage = f"{EDITOR_DATA_ROOT}/Cursor/User/globalStorage/saoudrizwan.claude-dev"
    legacy = f"{storage}/settings/cline_mcp_settings.json"
    _write(tmp_path, legacy, json.dumps(STANDARD))
    assert set(_servers(ClineDiscoverer(tmp_path))) == {"github", "docs"}


def test_roo_code_editor_storage(tmp_path: Path):
    storage = f"{EDITOR_DATA_ROOT}/Code/User/globalStorage/rooveterinaryinc.roo-cline"
    path = f"{storage}/settings/mcp_settings.json"
    _write(tmp_path, path, json.dumps(STANDARD))
    discoverer = RooCodeDiscoverer(tmp_path)
    assert discoverer.client_exists() is not None
    assert set(_servers(discoverer)) == {"github", "docs"}


def test_raycast_reads_skills_only(tmp_path: Path):
    _skill(tmp_path, "~/.config/raycast/skills")
    discoverer = RaycastDiscoverer(tmp_path)
    assert discoverer.discover_mcp_servers() == {}
    assert _skill_names(discoverer) == {"notes"}


def test_antigravity_cli_reads_shared_file_only_without_the_ide(tmp_path: Path):
    _write(tmp_path, "~/.gemini/config/mcp_config.json", json.dumps(STANDARD))
    cli = AntigravityCliDiscoverer(tmp_path)
    assert set(_servers(cli)) == {"github", "docs"}
    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    assert AntigravityCliDiscoverer(tmp_path).discover_mcp_servers() == {}


def test_readers_are_registered_once():
    register_readers()
    register_readers()
    for reader in READERS:
        assert DISCOVERERS[reader.name] is reader


def test_kilo_code_current_and_earlier_settings(tmp_path: Path):
    _write(
        tmp_path,
        "~/.config/kilo/kilo.jsonc",
        "// Kilo 7 settings\n"
        + json.dumps(
            {
                "mcp": {
                    "files": {"type": "local", "command": ["npx", "-y", "server-files"]},
                    "docs": {"type": "remote", "url": "https://docs.example.invalid/mcp"},
                    "broken": {"type": "local", "command": []},
                }
            }
        ),
    )
    storage = f"{EDITOR_DATA_ROOT}/Code/User/globalStorage/kilocode.kilo-code"
    _write(tmp_path, f"{storage}/settings/mcp_settings.json", json.dumps(STANDARD))
    _skill(tmp_path, "~/.kilo/skills")
    discoverer = KiloCodeDiscoverer(tmp_path)
    servers = _servers(discoverer)
    assert set(servers) == {"files", "docs", "github"}
    files = servers["files"]
    assert isinstance(files, StdioServer)
    assert (files.command, files.args) == ("npx", ["-y", "server-files"])
    assert servers["docs"].type == "http"
    assert _skill_names(discoverer) == {"notes"}


def test_zoo_code_editor_storage(tmp_path: Path):
    storage = f"{EDITOR_DATA_ROOT}/Cursor/User/globalStorage/zoocodeorganization.zoo-code"
    _write(tmp_path, f"{storage}/settings/mcp_settings.json", json.dumps(STANDARD))
    discoverer = ZooCodeDiscoverer(tmp_path)
    assert discoverer.client_exists() is not None
    assert set(_servers(discoverer)) == {"github", "docs"}


def test_zeptoclaw_server_list_in_its_config(tmp_path: Path):
    _write(
        tmp_path,
        "~/.zeptoclaw/config.json",
        json.dumps(
            {
                "mcp": {
                    "servers": [
                        {"name": "files", "command": "npx", "args": ["server-files"]},
                        {"name": "web", "url": "https://mcp.example.invalid/mcp"},
                        "not an entry",
                    ]
                }
            }
        ),
    )
    assert set(_servers(ZeptoClawDiscoverer(tmp_path))) == {"files", "web"}


def test_grok_build_toml_servers(tmp_path: Path):
    _write(
        tmp_path,
        "~/.grok/config.toml",
        'model = "grok"\n[mcp_servers.files]\ncommand = "npx"\nargs = ["server-files"]\n'
        '[mcp_servers.web]\nurl = "https://mcp.example.invalid/mcp"\n',
    )
    _skill(tmp_path, "~/.grok/skills")
    discoverer = GrokBuildDiscoverer(tmp_path)
    assert set(_servers(discoverer)) == {"files", "web"}
    assert _skill_names(discoverer) == {"notes"}


def test_malformed_toml_is_reported_as_unreadable(tmp_path: Path):
    path = _write(tmp_path, "~/.grok/config.toml", "[mcp_servers.files\n")
    result = GrokBuildDiscoverer(tmp_path).discover_mcp_servers()
    assert isinstance(result[path.resolve().as_posix()], CouldNotParseMCPConfig)
