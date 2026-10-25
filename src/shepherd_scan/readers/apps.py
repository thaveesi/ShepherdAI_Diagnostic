"""Readers for agent apps beyond the built-in discovery list.

Each class declares where its app keeps its files; reading itself is shared (see ``layout``).
Locations come from each app's documentation and source code as of October 2026.
"""

from pathlib import Path
from typing import ClassVar

from shepherd_scan._vendor.discovery.agents.base import McpConfigsResult, _canonicalize_keys
from shepherd_scan._vendor.discovery.agents.vscode.antigravity import AntigravityDiscoverer
from shepherd_scan.readers.layout import LayoutDiscoverer, platform_paths

# Where VS Code-family editors keep per-extension storage, by platform.
EDITOR_DATA_ROOT: str = platform_paths(
    ("~/Library/Application Support",), ("~/AppData/Roaming",), ("~/.config",)
)[0]
EDITORS = ("Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium")


def editor_storage(extension_id: str, relative: str = "") -> tuple[str, ...]:
    """An extension's storage path inside every VS Code-family editor."""
    suffix = f"/{relative}" if relative else ""
    return tuple(
        f"{EDITOR_DATA_ROOT}/{editor}/User/globalStorage/{extension_id}{suffix}"
        for editor in EDITORS
    )


DEVIN_HOME: str = platform_paths(
    ("~/.config/devin",), ("~/AppData/Roaming/devin",), ("~/.config/devin",)
)[0]
ZED_HOME: str = platform_paths(("~/.config/zed",), ("~/AppData/Roaming/Zed",), ("~/.config/zed",))[
    0
]
GOOSE_HOME: str = platform_paths(
    ("~/.config/goose",), ("~/AppData/Roaming/Block/goose/config",), ("~/.config/goose",)
)[0]


class AntigravityCliDiscoverer(LayoutDiscoverer):
    """Antigravity CLI (``agy``), formerly Gemini CLI.

    It shares ``~/.gemini/config/mcp_config.json`` with the Antigravity IDE, which the IDE
    reader already lists, so that file is read here only when the IDE is not installed.
    """

    name = "antigravity cli"
    install_paths = ("~/.gemini/antigravity-cli", "~/.gemini/config")
    install_binaries = ("agy",)
    mcp_files = (("~/.gemini/config/mcp_config.json", "mcp-json"),)
    skills_dirs = ("~/.gemini/antigravity-cli/skills", "~/.gemini/config/skills")

    def discover_mcp_servers(self) -> McpConfigsResult:
        """Shared servers, unless the IDE reader already lists them."""
        ide = AntigravityDiscoverer(self.home_directory, self.target_folders)
        if ide.client_exists() is not None:
            return {}
        return super().discover_mcp_servers()


class DevinDiscoverer(LayoutDiscoverer):
    """Devin CLI and Devin Local inside Devin Desktop (formerly Windsurf)."""

    name = "devin"
    install_paths = (DEVIN_HOME, "~/.devin")
    install_binaries = ("devin",)
    mcp_files = (
        (f"{DEVIN_HOME}/mcp_config.json", "mcp-json"),
        (f"{DEVIN_HOME}/config.json", "settings-json"),
    )
    skills_dirs = (f"{DEVIN_HOME}/skills",)


class ClineDiscoverer(LayoutDiscoverer):
    """Cline: version 4 files under ``~/.cline``, earlier versions inside the editor's storage."""

    name = "cline"
    install_paths = ("~/.cline", *editor_storage("saoudrizwan.claude-dev"))
    install_binaries = ("cline",)
    mcp_files = (
        ("~/.cline/data/settings/cline_mcp_settings.json", "mcp-json"),
        ("~/Documents/Cline/MCP/cline_mcp_settings.json", "mcp-json"),
        *(
            (path, "mcp-json")
            for path in editor_storage("saoudrizwan.claude-dev", "settings/cline_mcp_settings.json")
        ),
    )
    skills_dirs = ("~/.cline/skills",)


class RooCodeDiscoverer(LayoutDiscoverer):
    """Roo Code (discontinued in May 2026 but still installed on many machines)."""

    name = "roo code"
    install_paths = editor_storage("rooveterinaryinc.roo-cline")
    mcp_files = tuple(
        (path, "mcp-json")
        for path in editor_storage("rooveterinaryinc.roo-cline", "settings/mcp_settings.json")
    )
    skills_dirs = ("~/.roo/skills",)


class ZedDiscoverer(LayoutDiscoverer):
    """Zed editor: MCP servers are ``context_servers`` in its settings file."""

    name = "zed"
    install_paths = (
        ZED_HOME,
        *platform_paths(("~/Library/Application Support/Zed",), (), ("~/.local/share/zed",)),
    )
    install_binaries = ("zed", "zeditor")
    mcp_files = ((f"{ZED_HOME}/settings.json", "zed-json"),)
    skills_dirs = ("~/.agents/skills",)


class GooseDiscoverer(LayoutDiscoverer):
    """The goose agent: MCP servers are ``extensions`` in its YAML config."""

    name = "goose"
    install_paths = (GOOSE_HOME,)
    mcp_files = ((f"{GOOSE_HOME}/config.yaml", "goose-yaml"),)
    skills_dirs = (f"{GOOSE_HOME}/skills", "~/.agents/skills")


class LMStudioDiscoverer(LayoutDiscoverer):
    """LM Studio, which can attach MCP servers to local models."""

    name = "lm studio"
    install_paths = ("~/.lmstudio", "~/.cache/lm-studio")
    mcp_files = (("~/.lmstudio/mcp.json", "mcp-json"),)


class FactoryDiscoverer(LayoutDiscoverer):
    """Factory's Droid CLI and desktop app."""

    name = "factory"
    install_paths = ("~/.factory",)
    install_binaries = ("droid",)
    mcp_files = (("~/.factory/mcp.json", "mcp-json"),)
    skills_dirs = ("~/.factory/skills",)


class AugmentDiscoverer(LayoutDiscoverer):
    """Augment's Auggie CLI: MCP servers live inside its settings file."""

    name = "augment"
    install_paths = ("~/.augment",)
    install_binaries = ("auggie",)
    mcp_files = (("~/.augment/settings.json", "settings-json"),)
    skills_dirs = ("~/.augment/skills",)


class ContinueDiscoverer(LayoutDiscoverer):
    """Continue (no longer developed, still installed): YAML config plus a block folder."""

    name = "continue"
    install_paths = ("~/.continue",)
    mcp_files = (
        ("~/.continue/config.yaml", "continue-yaml"),
        ("~/.continue/config.json", "settings-json"),
    )
    skills_dirs = ("~/.continue/skills",)
    block_folder: ClassVar[str] = "~/.continue/mcpServers"

    def discover_mcp_servers(self) -> McpConfigsResult:
        """The main config plus one server file per block in the ``mcpServers`` folder."""
        result = dict(super().discover_mcp_servers())
        folder = self._expand(self.block_folder)
        for path in self._block_files(folder):
            file_format = "continue-yaml" if path.suffix in (".yaml", ".yml") else "mcp-json"
            parsed = self.parse_servers_file(path, file_format)
            if parsed:
                result[path.as_posix()] = parsed
        return _canonicalize_keys(result)

    @staticmethod
    def _block_files(folder: Path) -> list[Path]:
        try:
            return sorted(p for p in folder.iterdir() if p.suffix in (".yaml", ".yml", ".json"))
        except OSError:
            return []


class JunieDiscoverer(LayoutDiscoverer):
    """JetBrains Junie (plugin and CLI)."""

    name = "junie"
    install_paths = ("~/.junie",)
    install_binaries = ("junie",)
    mcp_files = (("~/.junie/mcp/mcp.json", "mcp-json"),)
    skills_dirs = ("~/.junie/skills",)


class WarpDiscoverer(LayoutDiscoverer):
    """Warp terminal: servers set in its files (servers added inside the app are not in files)."""

    name = "warp"
    install_paths = ("~/.warp", *platform_paths((), (), ("~/.config/warp-terminal",)))
    mcp_files = (("~/.warp/.mcp.json", "mcp-json"),)
    skills_dirs = ("~/.warp/skills",)


class QwenCodeDiscoverer(LayoutDiscoverer):
    """Qwen Code: MCP servers live inside its settings file."""

    name = "qwen code"
    install_paths = ("~/.qwen",)
    install_binaries = ("qwen",)
    mcp_files = (("~/.qwen/settings.json", "settings-json"),)
    skills_dirs = ("~/.qwen/skills",)


class OpenHandsDiscoverer(LayoutDiscoverer):
    """OpenHands CLI."""

    name = "openhands"
    install_paths = ("~/.openhands",)
    install_binaries = ("openhands",)
    mcp_files = (("~/.openhands/mcp.json", "mcp-json"),)
    skills_dirs = ("~/.openhands/skills/installed",)


class HermesAgentDiscoverer(LayoutDiscoverer):
    """Hermes Agent: MCP servers live in its YAML config."""

    name = "hermes agent"
    install_paths = ("~/.hermes", *platform_paths((), ("~/AppData/Local/hermes",), ()))
    mcp_files = (("~/.hermes/config.yaml", "generic-yaml"),)
    skills_dirs = ("~/.hermes/skills",)


KILO_CONFIG_FILES = ("kilo.jsonc", "kilo.json", "opencode.jsonc", "opencode.json", "config.json")


class KiloCodeDiscoverer(LayoutDiscoverer):
    """Kilo Code: settings in ``~/.config/kilo`` since version 7, the editor's storage before."""

    name = "kilo code"
    install_paths = (
        "~/.config/kilo",
        "~/.kilo",
        "~/.kilocode",
        *editor_storage("kilocode.kilo-code"),
    )
    mcp_files = (
        *((f"~/.config/kilo/{file_name}", "opencode-json") for file_name in KILO_CONFIG_FILES),
        *(
            (path, "mcp-json")
            for path in editor_storage("kilocode.kilo-code", "settings/mcp_settings.json")
        ),
    )
    skills_dirs = (
        "~/.kilo/skills",
        "~/.kilocode/skills",
        *editor_storage("kilocode.kilo-code", "skills"),
    )


class ZooCodeDiscoverer(LayoutDiscoverer):
    """Zoo Code, the community continuation of Roo Code."""

    name = "zoo code"
    install_paths = editor_storage("zoocodeorganization.zoo-code")
    mcp_files = tuple(
        (path, "mcp-json")
        for path in editor_storage("zoocodeorganization.zoo-code", "settings/mcp_settings.json")
    )


class PiDiscoverer(LayoutDiscoverer):
    """The Pi coding agent."""

    name = "pi"
    install_paths = ("~/.pi/agent",)
    mcp_files = (("~/.pi/agent/mcp.json", "mcp-json"),)
    skills_dirs = ("~/.pi/agent/skills",)


class ZeptoClawDiscoverer(LayoutDiscoverer):
    """ZeptoClaw: MCP servers in its config, plus the shared files it also reads."""

    name = "zeptoclaw"
    install_paths = ("~/.zeptoclaw",)
    install_binaries = ("zeptoclaw",)
    mcp_files = (
        ("~/.zeptoclaw/config.json", "zeptoclaw-json"),
        ("~/.zeptoclaw/workspace/.mcp.json", "mcp-json"),
        ("~/.mcp/servers.json", "mcp-json"),
    )
    skills_dirs = ("~/.zeptoclaw/skills",)


class KimiCodeDiscoverer(LayoutDiscoverer):
    """Kimi Code CLI (``~/.kimi-code``) and the earlier kimi-cli (``~/.kimi``)."""

    name = "kimi code"
    install_paths = ("~/.kimi-code", "~/.kimi")
    install_binaries = ("kimi",)
    mcp_files = (("~/.kimi-code/mcp.json", "mcp-json"), ("~/.kimi/mcp.json", "mcp-json"))
    skills_dirs = ("~/.kimi-code/skills",)


class GrokBuildDiscoverer(LayoutDiscoverer):
    """Grok Build CLI: MCP servers are ``[mcp_servers.<name>]`` tables in its TOML config."""

    name = "grok build"
    install_paths = ("~/.grok/config.toml",)
    mcp_files = (("~/.grok/config.toml", "toml-mcp"),)
    skills_dirs = ("~/.grok/skills",)


class RaycastDiscoverer(LayoutDiscoverer):
    """Raycast: its skills folder is readable; its MCP servers are in an encrypted database."""

    name = "raycast"
    install_paths = ("~/.config/raycast",)
    skills_dirs = ("~/.config/raycast/skills",)


READERS: tuple[type[LayoutDiscoverer], ...] = (
    AntigravityCliDiscoverer,
    DevinDiscoverer,
    ClineDiscoverer,
    RooCodeDiscoverer,
    ZedDiscoverer,
    GooseDiscoverer,
    LMStudioDiscoverer,
    FactoryDiscoverer,
    AugmentDiscoverer,
    ContinueDiscoverer,
    JunieDiscoverer,
    WarpDiscoverer,
    QwenCodeDiscoverer,
    OpenHandsDiscoverer,
    HermesAgentDiscoverer,
    KiloCodeDiscoverer,
    ZooCodeDiscoverer,
    PiDiscoverer,
    ZeptoClawDiscoverer,
    KimiCodeDiscoverer,
    GrokBuildDiscoverer,
    RaycastDiscoverer,
)
