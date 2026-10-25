"""Find known AI browser extensions and read what each may do from its own manifest.

Only the extension ids on the app list are looked up, in every profile of the Chromium-family
browsers. The manifest is the extension's own description of the access it asks for; the
browser's history, cookies and saved passwords are never opened.
"""

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shepherd_scan.settings_files import exists, home_path, load_settings

logger = logging.getLogger(__name__)

# Chromium-family browsers: (user data folder, browser name), by platform.
MAC_BROWSERS = (
    ("~/Library/Application Support/Google/Chrome", "Chrome"),
    ("~/Library/Application Support/Google/Chrome Beta", "Chrome Beta"),
    ("~/Library/Application Support/Google/Chrome Canary", "Chrome Canary"),
    ("~/Library/Application Support/Microsoft Edge", "Edge"),
    ("~/Library/Application Support/BraveSoftware/Brave-Browser", "Brave"),
    ("~/Library/Application Support/Arc/User Data", "Arc"),
    ("~/Library/Application Support/Chromium", "Chromium"),
    ("~/Library/Application Support/Vivaldi", "Vivaldi"),
    ("~/Library/Application Support/com.operasoftware.Opera", "Opera"),
    ("~/Library/Application Support/Comet", "Comet"),
    ("~/Library/Application Support/Dia/User Data", "Dia"),
)
LINUX_BROWSERS = (
    ("~/.config/google-chrome", "Chrome"),
    ("~/.config/microsoft-edge", "Edge"),
    ("~/.config/BraveSoftware/Brave-Browser", "Brave"),
    ("~/.config/chromium", "Chromium"),
    ("~/.config/vivaldi", "Vivaldi"),
)
WINDOWS_BROWSERS = (
    ("~/AppData/Local/Google/Chrome/User Data", "Chrome"),
    ("~/AppData/Local/Microsoft/Edge/User Data", "Edge"),
    ("~/AppData/Local/BraveSoftware/Brave-Browser/User Data", "Brave"),
)
MAX_PROFILES = 50
ALL_SITES = frozenset({"<all_urls>", "*://*/*", "http://*/*", "https://*/*"})
SITES_SHOWN = 3


@dataclass(frozen=True)
class ExtensionInstall:
    """A known extension installed in one browser profile."""

    extension_id: str
    browser: str
    profile: str
    access: tuple[str, ...]

    @property
    def where(self) -> str:
        """The browser and profile, for a reader."""
        return f"{self.browser} ({self.profile})"


def browser_folders() -> tuple[tuple[str, str], ...]:
    """The Chromium-family user data folders for this platform."""
    if sys.platform == "darwin":
        return MAC_BROWSERS
    if sys.platform == "win32":
        return WINDOWS_BROWSERS
    return LINUX_BROWSERS


def find_extensions(home: Path, wanted: set[str]) -> dict[str, list[ExtensionInstall]]:
    """Where each wanted extension id is installed, keyed by id."""
    found: dict[str, list[ExtensionInstall]] = {}
    for raw, browser in browser_folders():
        for profile in _profiles(home_path(home, raw)):
            for extension_id in sorted(wanted):
                folder = profile / "Extensions" / extension_id
                if not exists(folder):
                    continue
                install = ExtensionInstall(
                    extension_id=extension_id,
                    browser=browser,
                    profile=_profile_label(profile),
                    access=tuple(site_access(_manifest(folder))),
                )
                found.setdefault(extension_id, []).append(install)
    return found


def site_access(manifest: dict[str, Any]) -> list[str]:
    """What an extension's manifest lets it do, in plain words."""
    permissions = _strings(manifest.get("permissions"))
    patterns = {item for item in permissions if "://" in item or item == "<all_urls>"}
    patterns.update(_strings(manifest.get("host_permissions")))
    scripts = manifest.get("content_scripts")
    for script in scripts if isinstance(scripts, list) else []:
        if isinstance(script, dict):
            patterns.update(_strings(script.get("matches")))
    access: list[str] = []
    if patterns & ALL_SITES:
        access.append("Can read and change data on all websites")
    elif patterns:
        shown = ", ".join(sorted(patterns)[:SITES_SHOWN])
        more = f" and {len(patterns) - SITES_SHOWN} more" if len(patterns) > SITES_SHOWN else ""
        access.append(f"Can read and change data on {shown}{more}")
    if "debugger" in permissions:
        access.append("Can take full control of browser tabs")
    if "cookies" in permissions:
        access.append("Can read and change cookies, including sign-ins, on the sites it can reach")
    if "nativeMessaging" in permissions:
        access.append("Can exchange messages with an app installed on this computer")
    return access


def _profiles(root: Path) -> list[Path]:
    """Profile folders under a browser's user data folder (the folder itself for Opera)."""
    if not exists(root):
        return []
    try:
        children = sorted(child for child in root.iterdir() if child.is_dir())
    except OSError:
        logger.warning("Could not list browser profiles in %s", root.as_posix())
        return []
    profiles = [root] if exists(root / "Extensions") else []
    profiles.extend(child for child in children if exists(child / "Extensions"))
    return profiles[:MAX_PROFILES]


def _profile_label(profile: Path) -> str:
    return "Default profile" if profile.name == "Default" else profile.name


def _manifest(extension_folder: Path) -> dict[str, Any]:
    """The manifest of the most recently installed version of an extension."""
    try:
        versions = [child for child in extension_folder.iterdir() if child.is_dir()]
        latest = max(versions, key=lambda child: child.stat().st_mtime, default=None)
    except OSError:
        logger.warning("Could not read extension folder %s", extension_folder.as_posix())
        return {}
    if latest is None:
        return {}
    return load_settings(latest / "manifest.json") or {}


def _strings(value: Any) -> set[str]:
    """The text items of a manifest list; anything else counts as empty."""
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str)}
