"""Display names for the agent apps that discovery reports by identifier."""

AGENT_NAMES: dict[str, str] = {
    "amazon_q": "Amazon Q Developer",
    "amp": "Amp",
    "antigravity": "Antigravity",
    "antigravity cli": "Antigravity CLI",
    "augment": "Augment (Auggie)",
    "claude code": "Claude Code",
    "claude desktop": "Claude Desktop",
    "cline": "Cline",
    "codex": "Codex / ChatGPT app",
    "continue": "Continue",
    "cursor": "Cursor",
    "devin": "Devin",
    "factory": "Factory (Droid)",
    "gemini cli": "Gemini CLI (now Antigravity CLI)",
    "github copilot": "GitHub Copilot",
    "goose": "goose",
    "grok build": "Grok Build",
    "hermes agent": "Hermes Agent",
    "junie": "JetBrains Junie",
    "kilo code": "Kilo Code",
    "kimi code": "Kimi Code",
    "kiro": "Kiro",
    "lm studio": "LM Studio",
    "openclaw": "OpenClaw",
    "opencode": "OpenCode",
    "openhands": "OpenHands",
    "pi": "Pi",
    "qwen code": "Qwen Code",
    "raycast": "Raycast",
    "roo code": "Roo Code",
    "vscode": "VS Code",
    "warp": "Warp",
    "windsurf": "Windsurf (now Devin Desktop)",
    "zed": "Zed",
    "zeptoclaw": "ZeptoClaw",
    "zoo code": "Zoo Code",
}


def agent_name(client: str | None) -> str:
    """Display name for an agent app identifier."""
    if not client:
        return "Unknown agent"
    return AGENT_NAMES.get(client.lower(), client)
