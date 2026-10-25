# Modified from Apache-2.0 licensed code; see THIRD_PARTY_NOTICES.txt.
"""VSCode-family discoverers (VSCode, Cursor, Windsurf, Kiro, Antigravity)."""

from shepherd_scan._vendor.discovery.agents.vscode.antigravity import AntigravityDiscoverer
from shepherd_scan._vendor.discovery.agents.vscode.base import VSCodeFamilyDiscoverer
from shepherd_scan._vendor.discovery.agents.vscode.cursor import CursorDiscoverer
from shepherd_scan._vendor.discovery.agents.vscode.kiro import KiroDiscoverer
from shepherd_scan._vendor.discovery.agents.vscode.vscode import VSCodeDiscoverer
from shepherd_scan._vendor.discovery.agents.vscode.windsurf import WindsurfDiscoverer

__all__ = [
    "AntigravityDiscoverer",
    "CursorDiscoverer",
    "KiroDiscoverer",
    "VSCodeDiscoverer",
    "VSCodeFamilyDiscoverer",
    "WindsurfDiscoverer",
]
