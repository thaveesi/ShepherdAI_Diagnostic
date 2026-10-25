# Modified from Apache-2.0 licensed code; see THIRD_PARTY_NOTICES.txt.
"""Per-agent discoverers.

Public API: the ``AgentDiscoverer`` abstract base, the concrete discoverers, the
``DISCOVERERS`` registry (agent name -> discoverer class), and
``find_discoverers`` (construct + filter to installed agents for one home).
"""

import logging
from pathlib import Path

from shepherd_scan._vendor.discovery.agents.base import AgentDiscoverer, DiscoveryScope
from shepherd_scan._vendor.discovery.agents.claude_code import ClaudeCodeDiscoverer
from shepherd_scan._vendor.discovery.agents.claude_desktop import ClaudeDesktopDiscoverer
from shepherd_scan._vendor.discovery.agents.codex import CodexDiscoverer
from shepherd_scan._vendor.discovery.agents.github_copilot import GitHubCopilotDiscoverer
from shepherd_scan._vendor.discovery.agents.opencode import OpenCodeDiscoverer
from shepherd_scan._vendor.discovery.agents.vscode import (
    AntigravityDiscoverer,
    CursorDiscoverer,
    KiroDiscoverer,
    VSCodeDiscoverer,
    VSCodeFamilyDiscoverer,
    WindsurfDiscoverer,
)

logger = logging.getLogger(__name__)

DISCOVERERS: dict[str, type[AgentDiscoverer]] = {
    ClaudeCodeDiscoverer.name: ClaudeCodeDiscoverer,
    ClaudeDesktopDiscoverer.name: ClaudeDesktopDiscoverer,
    VSCodeDiscoverer.name: VSCodeDiscoverer,
    CursorDiscoverer.name: CursorDiscoverer,
    WindsurfDiscoverer.name: WindsurfDiscoverer,
    KiroDiscoverer.name: KiroDiscoverer,
    AntigravityDiscoverer.name: AntigravityDiscoverer,
    CodexDiscoverer.name: CodexDiscoverer,
    GitHubCopilotDiscoverer.name: GitHubCopilotDiscoverer,
    OpenCodeDiscoverer.name: OpenCodeDiscoverer,
}


def find_discoverers(home_directory: Path | None, target_folders: list[Path] | None = None) -> list[AgentDiscoverer]:
    """Construct one instance per registered discoverer with the given home and
    explicit request targets, then return only those whose ``client_exists()``
    confirms the agent is installed. Each returned instance is home-bound; the
    caller just runs ``d.discover()`` on each.

    A discoverer whose ``client_exists()`` raises is skipped (and logged) so a
    single buggy subclass cannot abort discovery for the whole machine.
    """
    found: list[AgentDiscoverer] = []
    for cls in DISCOVERERS.values():
        discoverer = cls(home_directory, target_folders)
        try:
            exists = discoverer.client_exists() is not None
        except Exception:
            logger.exception("Discoverer %s.client_exists() raised; skipping", cls.__name__)
            continue
        if exists:
            found.append(discoverer)
    return found


__all__ = [
    "DISCOVERERS",
    "AgentDiscoverer",
    "AntigravityDiscoverer",
    "ClaudeCodeDiscoverer",
    "ClaudeDesktopDiscoverer",
    "CodexDiscoverer",
    "CursorDiscoverer",
    "DiscoveryScope",
    "GitHubCopilotDiscoverer",
    "KiroDiscoverer",
    "OpenCodeDiscoverer",
    "VSCodeDiscoverer",
    "VSCodeFamilyDiscoverer",
    "WindsurfDiscoverer",
    "find_discoverers",
]
