"""Turn what was found into parts 2 to 4 of the reach section, and per-app notes.

Part 1 (acts without asking) comes from ``acts``. This module adds saved logins and keys
(part 2), browser and whole-computer control (part 3) and someone else's access (part 4),
plus the notes for "Could not be checked" about what apps keep outside this computer.
"""

from collections import defaultdict
from pathlib import Path

from shepherd_scan._vendor.discovery.utils import get_relative_path
from shepherd_scan.apps.installed import FoundApp
from shepherd_scan.checks.plaintext import CredentialSetting
from shepherd_scan.names import agent_name
from shepherd_scan.reach.logins import LoginFile
from shepherd_scan.report.model import ReachFinding, SecretFinding
from shepherd_scan.settings_files import exists

COMPUTER_CONTROL = "Can operate apps on this computer"
BROWSER_CONTROL = "Acts on sites you are signed in to"
# Permission choices some apps keep where an offline scan cannot read them, by app list id.
UNREADABLE_PERMISSIONS: dict[str, str] = {
    "vscode": "'Always allow' choices for Copilot tools are kept in the editor's app database.",
    "lmstudio": "Per-tool 'Always allow' choices are not kept in a readable file.",
    "roo-code": "Its auto-approve switches are kept in the editor's app database.",
    "continue": "The editor's 'Automatic' tool permissions are kept inside the editor.",
    "junie": "Brave mode in the IDE plugin is not kept in a readable file.",
    "cursor": "The run mode chosen in the app is not kept in a readable file.",
}
GROK_BOT_NOTE = (
    "Newer versions keep the choice to run commands on this computer per registered computer, "
    "not in a readable file."
)


def login_findings(files: list[LoginFile]) -> list[ReachFinding]:
    """Part 2: saved logins and keys any agent able to run commands could use."""
    return [
        ReachFinding(part="logins", app=file.app or "", what=file.what, where=file.where)
        for file in files
    ]


def control_findings(apps: list[FoundApp]) -> list[ReachFinding]:
    """Part 3: browser agents and apps that can control the whole computer."""
    findings: list[ReachFinding] = []
    for found in apps:
        entry = found.entry
        if entry.control is None:
            continue
        if found.extensions:
            findings.extend(
                ReachFinding(
                    part="control",
                    app=entry.name,
                    what="; ".join(install.access) or entry.can_do or BROWSER_CONTROL,
                    where=install.where,
                )
                for install in found.extensions
            )
            continue
        fallback = COMPUTER_CONTROL if entry.control == "computer" else BROWSER_CONTROL
        findings.append(
            ReachFinding(
                part="control",
                app=entry.name,
                what=entry.can_do or fallback,
                where=found.sightings[0].describe(),
                basis="published",
            )
        )
    return findings


def shared_findings(credentials: list[CredentialSetting], home: Path) -> list[ReachFinding]:
    """Part 4: settings that use a shared bot, app or service account, or someone's key."""
    findings: list[ReachFinding] = []
    for (path, server, setting), group in _by_place(credentials).items():
        apps = ", ".join(sorted({agent_name(item.client) for item in group}))
        first = group[0]
        owner = server or apps
        where = f"{get_relative_path(path)} → {setting}"
        if first.shared:
            what = (
                f"{owner} uses a {first.kind}: whoever asks the agent acts with that account's "
                "access, not their own"
            )
            findings.append(ReachFinding(part="shared", app=apps, what=what, where=where))
        elif first.written and in_project_repository(Path(path), home):
            what = (
                f"{owner} uses a key written into a project file that everyone with the "
                "repository has, so the agent can act with whoever's key it is"
            )
            findings.append(ReachFinding(part="shared", app=apps, what=what, where=where))
    return findings


def plaintext_findings(credentials: list[CredentialSetting]) -> list[SecretFinding]:
    """Exposed keys: credentials written in plain text in agent settings, one per place."""
    findings: list[SecretFinding] = []
    for (path, server, setting), group in _by_place(credentials).items():
        if not group[0].written:
            continue
        apps = ", ".join(sorted({agent_name(item.client) for item in group}))
        findings.append(
            SecretFinding(
                kind=group[0].kind or "Key in plain text",
                where=f"{server} ({apps})" if server else apps,
                location=f"{get_relative_path(path)} → {setting}",
            )
        )
    return findings


def command_agents(apps: list[FoundApp], discovered: set[str]) -> list[str]:
    """Names of the agents on this computer that can run commands."""
    names = {
        agent_name(found.entry.agent) if found.entry.agent else found.entry.name
        for found in apps
        if found.entry.runs_commands
    }
    names.update(agent_name(client) for client in discovered if client in COMMAND_CLIENTS)
    return sorted(names, key=str.lower)


def elsewhere_notes(apps: list[FoundApp], *, grok_setting_found: bool) -> list[str]:
    """Per-app notes on connections and permission choices this scan cannot read."""
    notes: list[str] = []
    for found in apps:
        entry = found.entry
        name = agent_name(entry.agent) if entry.agent else entry.name
        if entry.kept_elsewhere:
            notes.append(f"{name}: {entry.kept_elsewhere}")
        if entry.id in UNREADABLE_PERMISSIONS:
            notes.append(f"{name}: {UNREADABLE_PERMISSIONS[entry.id]}")
        if entry.id == "grok-bot" and not grok_setting_found:
            notes.append(f"{name}: {GROK_BOT_NOTE}")
    return list(dict.fromkeys(notes))


# Discovery identifiers of agents that can run commands, for agents found without an app entry.
COMMAND_CLIENTS = frozenset({
    "claude code", "claude desktop", "codex", "cursor", "vscode", "windsurf", "kiro", "antigravity",
    "antigravity cli", "gemini cli", "github copilot", "amazon_q", "openclaw", "opencode", "amp",
    "devin", "cline", "roo code", "zoo code", "kilo code", "zed", "goose", "factory", "augment",
    "continue", "junie", "warp", "qwen code", "openhands", "hermes agent", "pi", "zeptoclaw",
    "kimi code", "grok build",
})  # fmt: skip


def in_project_repository(config: Path, home: Path) -> bool:
    """Whether a project's settings file sits inside a repository below the home folder.

    Settings in the home folder itself are left out: a home folder kept as a repository is a
    personal backup, not a project others work in.
    """
    try:
        relative = config.resolve().relative_to(home.resolve())
    except (OSError, ValueError):
        return False
    if len(relative.parts) < 2 or relative.parts[0].startswith("."):
        return False
    folder = home / relative.parts[0]
    for part in relative.parts[1:]:
        if exists(folder / ".git"):
            return True
        folder /= part
    return False


def _by_place(
    credentials: list[CredentialSetting],
) -> dict[tuple[str, str, str], list[CredentialSetting]]:
    """Credentials grouped by settings file, server and setting, keeping first-seen order."""
    groups: dict[tuple[str, str, str], list[CredentialSetting]] = defaultdict(list)
    for credential in credentials:
        groups[(credential.config_path, credential.server, credential.setting)].append(credential)
    return groups
