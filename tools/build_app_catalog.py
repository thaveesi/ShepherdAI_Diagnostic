"""Build ``src/shepherd_scan/data/apps.json``: the list of AI agent apps the scan recognises.

Not shipped. The base list is an open-source signature file of 89 AI products (Apache-2.0; see
THIRD_PARTY_NOTICES.txt), converted to our own format. Only detection anchors are taken:
app names, commands, settings folders in the home folder and editor extension ids. Anchors
that would match unrelated programs are dropped. Our own research adds the apps released or
renamed in 2026, and what each app keeps outside this computer.

Usage:
    python tools/build_app_catalog.py <path to ai_signatures.json>
"""

import json
import sys
from pathlib import Path
from typing import Any

OUTPUT = Path(__file__).resolve().parents[1] / "src" / "shepherd_scan" / "data" / "apps.json"

# Signatures that describe software packages inside projects, not apps on a computer.
EXCLUDED = {"ai-sdks", "smelt"}
# Command names that unrelated, common programs also use (e.g. the goose database tool, the
# AWS Copilot CLI); a match on these alone would report an AI app that is not there.
AMBIGUOUS_COMMANDS = {
    "agent", "amp", "aoe", "cn", "copilot", "goose", "hermes", "jan", "lemonade", "lms",
    "omni", "opcode", "pdx", "pieces", "q", "vibe", "void", "wsh",
}  # fmt: skip
# Folders several apps share, which do not show that any one of them is installed.
SHARED_FOLDER_PREFIXES = ("~/.agents", "~/.config/agents", "~/.config/AGENTS.md")
CATEGORY_KIND = {
    "supported_connector": "coding",
    "ai_cli": "coding",
    "editor_extension": "coding",
    "desktop_app": "assistant",
    "mcp_server": "coding",
    "plugin": "browser",
}
LOCAL_MODEL_APPS = {
    "ollama", "lemonade", "lmstudio", "jan", "localai", "vllm", "llamacpp", "open-webui",
    "gpt4all", "anythingllm", "lobechat", "koboldcpp", "msty", "boltai", "backyard-ai", "pinokio",
}  # fmt: skip
CODING_APPS = {
    "zed", "warp", "trae", "pieces", "void", "melty", "bloop", "sculptor", "cmux", "opcode",
    "chat2db", "wave-terminal",
}  # fmt: skip
RUNS_COMMANDS = {
    "claudecode", "claude-desktop", "codex", "openclaw", "zeptoclaw", "hermes", "cursor", "devin",
    "copilot", "antigravity", "openhands", "aider", "goose", "opencode", "amp", "omnigent",
    "continue", "cline", "amazonq", "qwen-code", "ra-aid", "zed", "warp", "trae", "void", "kiro",
    "auggie", "plandex", "swe-agent", "mistral-vibe", "crush", "gptscript", "docker-agent",
    "melty", "sculptor", "cmux", "opcode", "agent-deck", "agent-of-empires",
}  # fmt: skip

COMPUTER_CONTROL = (
    "Operates apps on this computer by looking at the screen and using the mouse and keyboard."
)
# Changes to converted entries: new names, the discovery reader that reads them, anchors
# confirmed by our research, and what each app keeps outside this computer.
OVERRIDES: dict[str, dict[str, Any]] = {
    "claudecode": {
        "id": "claude-code", "agent": "claude code", "mac_app_names": [], "folders": ["~/.claude"],
        "credential_files": [["~/.claude/.credentials.json", "Claude sign-in"]],
    },
    "claude-desktop": {
        "agent": "claude desktop", "mac_bundle_ids": ["com.anthropic.claudefordesktop"],
        "folders": ["~/Library/Application Support/Claude"], "control": "computer",
        "can_do": "Chats and Cowork tasks use the connectors on your Claude account and folders you share; computer use can operate apps on this computer.",  # noqa: E501
        "kept_elsewhere": "Connectors added on claude.ai are kept in your Claude account; only the ones this app has recorded on this computer are listed.",  # noqa: E501
    },
    "codex": {
        "agent": "codex", "folders": ["~/.codex"],
        "credential_files": [["~/.codex/auth.json", "ChatGPT or OpenAI sign-in"]],
    },
    "chatgpt-desktop": {
        "id": "chatgpt-classic", "name": "ChatGPT Classic", "mac_bundle_ids": ["com.openai.chat"],
        "mac_app_names": [], "folders": ["~/Library/Application Support/com.openai.chat"],
        "can_do": "'Work with Apps' reads from and edits content in other apps on this computer.",
        "kept_elsewhere": "Its connectors and custom instructions are kept in your ChatGPT account.",  # noqa: E501
    },
    "openclaw": {"agent": "openclaw", "kind": "assistant"},
    "zeptoclaw": {"kind": "assistant", "agent": "zeptoclaw", "folders": ["~/.zeptoclaw"]},
    "hermes": {"id": "hermes-agent", "agent": "hermes agent", "folders": ["~/.hermes"]},
    "cursor": {
        "agent": "cursor", "mac_bundle_ids": ["com.todesktop.230313mzl4w4u92"],
        "editor_extensions": [], "folders": ["~/.cursor"],
    },
    "devin": {"agent": "devin", "folders": ["~/.config/devin", "~/.devin"]},
    "copilot": {
        "id": "github-copilot", "agent": "github copilot", "folders": ["~/.copilot"],
        "credential_files": [["~/.copilot/config.json", "GitHub sign-in for Copilot CLI"]],
    },
    "antigravity": {
        "id": "antigravity-cli", "name": "Antigravity CLI", "agent": "antigravity cli",
        "folders": ["~/.gemini/antigravity-cli", "~/.gemini/config"],
    },
    "openhands": {"agent": "openhands", "folders": ["~/.openhands"]},
    "goose": {
        "agent": "goose", "folders": ["~/.config/goose"], "mac_bundle_ids": ["com.electron.goose"],
        "credential_files": [["~/.config/goose/secrets.yaml", "API keys goose saved in a file"]],
    },
    "opencode": {
        "agent": "opencode", "folders": ["~/.config/opencode", "~/.opencode", "~/.opencode.json"],
        "credential_files": [["~/.local/share/opencode/auth.json", "sign-ins to AI providers"]],
    },
    "amp": {"agent": "amp", "folders": ["~/.config/amp"]},
    "continue": {"agent": "continue", "folders": ["~/.continue"]},
    "cline": {
        "name": "Cline", "agent": "cline", "folders": ["~/.cline"],
        "mac_bundle_ids": ["bot.cline.app"],
        "editor_extensions": ["saoudrizwan.claude-dev"],
        "credential_files": [["~/.cline/data/secrets.json", "API keys Cline saved in a file"]],
    },
    "amazonq": {"agent": "amazon_q", "folders": ["~/.aws/amazonq"]},
    "qwen-code": {"agent": "qwen code", "folders": ["~/.qwen"]},
    "lmstudio": {
        "agent": "lm studio", "mac_bundle_ids": ["ai.elementlabs.lmstudio"],
        "folders": ["~/.lmstudio", "~/.cache/lm-studio", "~/Library/Application Support/LM Studio"],
    },
    "auggie": {"id": "augment", "name": "Augment (Auggie)", "agent": "augment", "folders": ["~/.augment"]},  # noqa: E501
    "kiro": {"agent": "kiro", "folders": ["~/.kiro"], "mac_bundle_ids": ["dev.kiro.desktop"]},
    "zed": {"agent": "zed", "folders": ["~/.config/zed"], "mac_bundle_ids": ["dev.zed.Zed"]},
    "warp": {
        "agent": "warp", "folders": ["~/.warp"], "mac_bundle_ids": ["dev.warp.Warp-Stable"],
        "kept_elsewhere": "MCP servers added inside Warp are kept in its app database and your Warp account; only servers set in its files are listed.",  # noqa: E501
    },
    "raycast": {
        "agent": "raycast", "folders": ["~/.config/raycast"],
        "mac_bundle_ids": ["com.raycast.macos"],
        "can_do": "Runs AI chats, commands and MCP tools from the launcher, including actions in connected apps.",  # noqa: E501
        "kept_elsewhere": "Its MCP servers and tool permission choices are kept in an encrypted app database.",  # noqa: E501
    },
    "notion": {
        "mac_bundle_ids": ["notion.id"],
        "can_do": "Notion AI agents create and edit pages and databases in your workspace and use connected apps.",  # noqa: E501
        "kept_elsewhere": "Its agents and connections are kept in your Notion workspace.",
    },
    "monday-desktop": {
        "can_do": "monday.com AI agents act on boards and items in your account.",
        "kept_elsewhere": "Its agents are kept in your monday.com account.",
    },
    "perplexity-comet": {
        "kind": "browser", "control": "browser", "mac_bundle_ids": ["ai.perplexity.comet"],
        "can_do": "AI browser: its assistant can act on any site you are signed in to in Comet.",
        "kept_elsewhere": "Its assistant settings are kept in your Perplexity account.",
    },
    "dia-browser": {
        "kind": "browser", "control": "browser", "mac_bundle_ids": ["company.thebrowser.dia"],
        "can_do": "AI browser: its assistant can read and act on pages you are signed in to in Dia.",  # noqa: E501
    },
    "browseros": {
        "kind": "browser", "control": "browser",
        "can_do": "AI browser with a built-in agent that acts on sites you are signed in to in it.",
    },
    "uipath-assistant": {
        "kind": "computer", "control": "computer",
        "can_do": "Starts automations that operate apps on this computer.",
    },
    "ui-tars-desktop": {"kind": "computer", "control": "computer", "can_do": COMPUTER_CONTROL},
    "agent-macos": {"kind": "computer", "control": "computer", "can_do": COMPUTER_CONTROL},
    "fazm": {"kind": "computer", "control": "computer", "can_do": COMPUTER_CONTROL},
    "cyclop-one": {"kind": "computer", "control": "computer", "can_do": COMPUTER_CONTROL},
    "zia-search": {"browser_extensions": ["jebapbhanimlfnddnammimbopafiddkd"], "folders": []},
}  # fmt: skip

ADDITIONS: list[dict[str, Any]] = [
    {
        "id": "chatgpt", "name": "ChatGPT", "kind": "assistant", "agent": "codex",
        "mac_bundle_ids": ["com.openai.codex"], "runs_commands": True, "control": "computer",
        "can_do": "Chat, Work and Codex in one app: runs commands and edits files, uses connected apps, and with Computer Use can operate other apps.",  # noqa: E501
        "kept_elsewhere": "Apps, connectors and plugins added on the web are kept in your ChatGPT account.",  # noqa: E501
    },
    {
        "id": "grok-bot", "name": "Grok Bot", "kind": "assistant",
        "mac_bundle_ids": ["com.anysphere.sand"], "mac_app_names": ["Grok Bot.app"],
        "folders": ["~/.grokbot", "~/Library/Application Support/com.anysphere.sand"],
        "runs_commands": True, "control": "computer",
        "can_do": "Always-on bots on a cloud computer with a browser, terminal and files; they sign in to web apps such as inboxes and CRMs, run scheduled routines, and through a helper on this computer can run commands and read files here.",  # noqa: E501
        "kept_elsewhere": "Its bots, connectors and skills live on its cloud computer and in your account.",  # noqa: E501
        "credential_files": [["~/.grokbot/local-exec-daemon-credential.json", "credential of Grok Bot's local command helper"]],  # noqa: E501
    },
    {
        "id": "muse", "name": "Muse (Meta)", "kind": "assistant",
        "mac_bundle_ids": ["com.meta.endo"], "control": "computer",
        "folders": ["~/Library/Application Support/com.meta.endo"],
        "can_do": "Reads and updates files and acts in Messages, Notes, Reminders, Mail and Calendar through Full Disk Access and Automation; computer use can operate any app. Connectors include Gmail, calendar, Notion, GitHub and Box.",  # noqa: E501
        "kept_elsewhere": "The agent and its connectors run in Meta's cloud.",
    },
    {
        "id": "microsoft-copilot", "name": "Microsoft Copilot", "kind": "assistant",
        "mac_bundle_ids": ["com.microsoft.m365copilot"], "control": "browser",
        "can_do": "Sends mail, schedules meetings and posts in Teams with your Microsoft account; Cowork can drive your Edge browser.",  # noqa: E501
        "kept_elsewhere": "Its connections and plugins are kept in your Microsoft account.",
    },
    {
        "id": "slack", "name": "Slack (Slackbot)", "kind": "assistant",
        "mac_bundle_ids": ["com.tinyspeck.slackmacgap"],
        "can_do": "Slackbot acts in connected apps (such as Google, Atlassian, Box, Notion and Salesforce) through MCP, and runs skills that can be shared and scheduled.",  # noqa: E501
        "kept_elsewhere": "Slackbot's connections and skills are kept in your Slack workspace.",
    },
    {
        "id": "gemini-app", "name": "Gemini (desktop app)", "kind": "assistant",
        "mac_bundle_ids": ["com.google.GeminiMacOS"],
        "can_do": "The Spark agent edits files in folders you grant and acts in connected Google apps.",  # noqa: E501
        "kept_elsewhere": "Its connected apps are kept in your Google account.",
    },
    {
        "id": "perplexity", "name": "Perplexity", "kind": "assistant",
        "mac_bundle_ids": ["ai.perplexity.macv3"], "control": "computer",
        "can_do": "Works with local files and apps, uses the computer and drives the Comet browser; supports custom MCP connectors.",  # noqa: E501
        "kept_elsewhere": "Its connectors, skills and instructions are kept in your Perplexity account.",  # noqa: E501
    },
    {
        "id": "grammarly", "name": "Grammarly (Superhuman Go)", "kind": "assistant",
        "mac_bundle_ids": ["com.grammarly.ProjectLlama"],
        "can_do": "Reads text you type in any app; its Superhuman Go agents draft and send email, with connectors such as Gmail, Outlook, Slack and Jira.",  # noqa: E501
        "kept_elsewhere": "Its connectors are kept in your Superhuman account.",
    },
    {
        "id": "granola", "name": "Granola", "kind": "assistant",
        "mac_bundle_ids": ["com.granola.app"],
        "can_do": "Captures meeting audio on this computer and syncs notes to connected tools such as your CRM.",  # noqa: E501
        "kept_elsewhere": "Notes and integrations are kept in your Granola account.",
    },
    {
        "id": "glean", "name": "Glean", "kind": "assistant", "mac_bundle_ids": ["com.glean.desktop"],  # noqa: E501
        "can_do": "Searches and acts across your work apps; Glean Tau works on local files, apps and code.",  # noqa: E501
        "kept_elsewhere": "Its connections are kept in your company's Glean account.",
    },
    {
        "id": "manus", "name": "Manus", "kind": "assistant",
        "mac_bundle_ids": ["im.manus.desktop", "ai.manus.agents"], "runs_commands": True,
        "control": "computer",
        "can_do": "'My Computer' runs commands on this computer with per-command approval; connectors include Gmail, Slack and GitHub.",  # noqa: E501
        "kept_elsewhere": "Its connectors and agents are kept in your Manus account.",
    },
    {
        "id": "simular", "name": "Simular", "kind": "computer", "mac_app_names": ["Simular.app"],
        "control": "computer", "can_do": COMPUTER_CONTROL,
    },
    {
        "id": "zoom", "name": "Zoom (AI Companion)", "kind": "assistant",
        "mac_bundle_ids": ["us.zoom.xos"],
        "can_do": "AI Companion runs custom agents and can update your CRM from meeting follow-ups.",  # noqa: E501
        "kept_elsewhere": "Its agents and workflows are kept in your Zoom account.",
    },
    {
        "id": "devin-desktop", "name": "Devin Desktop", "kind": "coding", "agent": "devin",
        "mac_bundle_ids": ["com.exafunction.windsurf"], "runs_commands": True,
    },
    {
        "id": "windsurf", "name": "Windsurf (now Devin Desktop)", "kind": "coding",
        "agent": "windsurf", "folders": ["~/.codeium/windsurf"], "runs_commands": True,
    },
    {
        "id": "antigravity", "name": "Antigravity", "kind": "coding", "agent": "antigravity",
        "mac_bundle_ids": ["com.google.antigravity", "com.google.antigravity-ide"],
        "folders": [
            "~/.antigravity", "~/.antigravity-ide", "~/.gemini/antigravity",
            "~/.gemini/antigravity-ide",
        ],
        "runs_commands": True,
    },
    {
        "id": "gemini-cli", "name": "Gemini CLI (now Antigravity CLI)", "kind": "coding",
        "agent": "gemini cli", "binaries": ["gemini"], "folders": ["~/.gemini/settings.json"],
        "runs_commands": True,
        "credential_files": [
            ["~/.gemini/oauth_creds.json", "Google sign-in"],
            ["~/.gemini/mcp-oauth-tokens.json", "sign-ins to MCP servers"],
        ],
    },
    {
        "id": "vscode", "name": "VS Code", "kind": "coding", "agent": "vscode",
        "mac_bundle_ids": ["com.microsoft.VSCode", "com.microsoft.VSCodeInsiders"],
        "binaries": ["code"], "runs_commands": True,
    },
    {
        "id": "github-copilot-app", "name": "GitHub Copilot app", "kind": "coding",
        "agent": "github copilot", "mac_bundle_ids": ["com.github.githubapp"],
        "folders": ["~/Library/Application Support/com.github.githubapp"],
        "runs_commands": True,
    },
    {
        "id": "roo-code", "name": "Roo Code", "kind": "coding", "agent": "roo code",
        "editor_extensions": ["rooveterinaryinc.roo-cline"], "runs_commands": True,
    },
    {
        "id": "factory", "name": "Factory (Droid)", "kind": "coding", "agent": "factory",
        "binaries": ["droid"], "folders": ["~/.factory"], "mac_bundle_ids": ["ai.factory.desktop"],
        "runs_commands": True,
    },
    {
        "id": "junie", "name": "JetBrains Junie", "kind": "coding", "agent": "junie",
        "binaries": ["junie"], "folders": ["~/.junie"], "runs_commands": True,
    },
    {
        "id": "kilo-code", "name": "Kilo Code", "kind": "coding", "agent": "kilo code",
        "editor_extensions": ["kilocode.kilo-code"],
        "folders": ["~/.config/kilo", "~/.kilo", "~/.kilocode"], "runs_commands": True,
    },
    {
        "id": "zoo-code", "name": "Zoo Code", "kind": "coding", "agent": "zoo code",
        "editor_extensions": ["zoocodeorganization.zoo-code"], "runs_commands": True,
    },
    {
        "id": "pi", "name": "Pi", "kind": "coding", "agent": "pi", "folders": ["~/.pi/agent"],
        "runs_commands": True,
        "credential_files": [["~/.pi/agent/auth.json", "sign-ins to AI providers"]],
    },
    {
        "id": "kimi-code", "name": "Kimi Code", "kind": "coding", "agent": "kimi code",
        "binaries": ["kimi"], "folders": ["~/.kimi-code", "~/.kimi"], "runs_commands": True,
        "credential_files": [["~/.kimi-code/credentials", "Kimi sign-in"]],
    },
    {
        "id": "grok-build", "name": "Grok Build", "kind": "coding", "agent": "grok build",
        "folders": ["~/.grok/config.toml"], "runs_commands": True,
    },
    {
        "id": "claude-in-chrome", "name": "Claude in Chrome", "kind": "browser",
        "browser_extensions": ["fcoeoabgfenejglbffodgkkbkcdhcgfn"], "control": "browser",
        "can_do": "Acts in your signed-in browser: navigates, fills in forms and clicks, and can run on its own or on a schedule.",  # noqa: E501
    },
    {
        "id": "chatgpt-extension", "name": "ChatGPT browser extension", "kind": "browser",
        "browser_extensions": ["hehggadaopoacecdllhhajmbjkdcmajg"], "control": "browser",
        "can_do": "Lets the ChatGPT app control your browser.",
    },
    {
        "id": "genspark", "name": "Genspark", "kind": "browser",
        "browser_extensions": ["hmdkfngkncmbgiehonfebecighedjiak"], "control": "browser",
        "can_do": "Browser agent with a built-in MCP store that acts on sites in your browser.",
    },
    {
        "id": "opera-neon", "name": "Opera Neon", "kind": "browser",
        "mac_bundle_ids": ["com.operasoftware.OperaNeon", "com.operasoftware.OperaNeonDeveloper"],
        "control": "browser",
        "can_do": "AI browser that acts on sites you are signed in to in it, and lets outside agents use it.",  # noqa: E501
    },
]  # fmt: skip

FIELDS = (
    "id", "name", "kind", "agent", "mac_bundle_ids", "mac_app_names", "binaries", "folders",
    "editor_extensions", "browser_extensions", "runs_commands", "control", "can_do",
    "kept_elsewhere", "credential_files",
)  # fmt: skip
LIST_FIELDS = (
    "mac_bundle_ids", "mac_app_names", "binaries", "folders", "editor_extensions",
    "browser_extensions", "credential_files",
)  # fmt: skip


def convert(signature: dict[str, Any]) -> dict[str, Any]:
    """One signature in our format, before overrides."""
    source_id = signature["id"]
    kind = CATEGORY_KIND.get(signature.get("category", ""), "coding")
    if source_id in LOCAL_MODEL_APPS:
        kind = "local models"
    elif source_id in CODING_APPS:
        kind = "coding"
    return {
        "id": source_id,
        "name": signature["name"],
        "kind": kind,
        "agent": None,
        "mac_bundle_ids": [],
        "mac_app_names": [
            name for name in signature.get("application_names") or [] if name.endswith(".app")
        ],
        "binaries": [
            name
            for name in signature.get("binary_names") or []
            if name not in AMBIGUOUS_COMMANDS and "." not in name
        ],
        "folders": [
            path
            for path in signature.get("config_paths") or []
            if path.startswith("~/") and not path.startswith(SHARED_FOLDER_PREFIXES)
        ],
        "editor_extensions": [
            ext for ext in signature.get("extension_ids") or [] if "." in ext and ext.islower()
        ],
        "browser_extensions": [],
        "runs_commands": source_id in RUNS_COMMANDS,
        "control": None,
        "can_do": None,
        "kept_elsewhere": None,
        "credential_files": [],
    }


def has_anchor(entry: dict[str, Any]) -> bool:
    """Whether the entry can be recognised on a computer at all."""
    anchors = ("mac_bundle_ids", "mac_app_names", "binaries", "folders", "editor_extensions")
    return any(entry[key] for key in (*anchors, "browser_extensions"))


def build(signatures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Converted, corrected and extended entries, sorted by name."""
    entries: list[dict[str, Any]] = []
    for signature in signatures:
        if signature["id"] in EXCLUDED:
            continue
        entry = convert(signature)
        entry.update(OVERRIDES.get(signature["id"], {}))
        entries.append(entry)
    for addition in ADDITIONS:
        entry: dict[str, Any] = dict.fromkeys(FIELDS)
        entry.update({key: [] for key in LIST_FIELDS})
        entry.update({"runs_commands": False, **addition})
        entries.append(entry)
    ids = [entry["id"] for entry in entries]
    duplicates = {entry_id for entry_id in ids if ids.count(entry_id) > 1}
    if duplicates:
        raise SystemExit(f"duplicate app ids: {sorted(duplicates)}")
    kept = [{key: entry[key] for key in FIELDS} for entry in entries if has_anchor(entry)]
    dropped = sorted(entry["name"] for entry in entries if not has_anchor(entry))
    print(f"{len(kept)} apps; dropped without any anchor: {', '.join(dropped)}")
    return sorted(kept, key=lambda entry: entry["name"].lower())


def main() -> None:
    """Read the signature file named on the command line and write the app list."""
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    signatures = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["signatures"]
    catalog = {"version": 1, "apps": build(signatures)}
    OUTPUT.write_text(json.dumps(catalog, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
