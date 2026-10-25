"""Find which apps on the app list are installed, and how each was recognised.

An app counts as found when any of its anchors is present: an app bundle in the Applications
folders (macOS), its command on this user's PATH, its settings folder or file in the home
folder, an editor extension, or a browser extension. Only names and existence are checked;
apart from app bundle descriptions and extension manifests, no file is opened.
"""

import logging
import plistlib
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from shepherd_scan._vendor.discovery.utils import get_relative_path, is_special_file
from shepherd_scan.apps.browsers import ExtensionInstall, find_extensions
from shepherd_scan.apps.catalog import AppEntry
from shepherd_scan.settings_files import exists, home_path

logger = logging.getLogger(__name__)

# Applications folders outside the home folder; the home folder's own is added at scan time.
SYSTEM_APP_FOLDERS: tuple[Path, ...] = (Path("/Applications"),)
MAX_APP_BUNDLES = 3000
EDITOR_EXTENSION_FOLDERS = (
    ("~/.vscode/extensions", "VS Code"),
    ("~/.vscode-insiders/extensions", "VS Code Insiders"),
    ("~/.cursor/extensions", "Cursor"),
    ("~/.windsurf/extensions", "Windsurf"),
    ("~/.devin/extensions", "Devin Desktop"),
    ("~/.vscode-oss/extensions", "VSCodium"),
    ("~/.kiro/extensions", "Kiro"),
    ("~/.antigravity/extensions", "Antigravity"),
    ("~/.trae/extensions", "TRAE"),
)


@dataclass(frozen=True)
class Sighting:
    """One piece of evidence that an app is installed."""

    how: str
    where: str

    def describe(self) -> str:
        """The evidence in a few words, for a reader."""
        return f"{self.how}: {self.where}"


@dataclass(frozen=True)
class AppBundle:
    """A macOS app bundle and the identifier it declares."""

    path: Path
    bundle_id: str


@dataclass
class FoundApp:
    """An app from the app list found on this computer."""

    entry: AppEntry
    sightings: list[Sighting] = field(default_factory=list)
    extensions: list[ExtensionInstall] = field(default_factory=list)


def find_installed_apps(home: Path, entries: tuple[AppEntry, ...]) -> list[FoundApp]:
    """Every app on the list with at least one anchor present on this computer.

    Args:
        home: The home folder being scanned (the current user's).
        entries: The app list.

    Returns:
        The apps found, in list order.
    """
    bundles = mac_app_bundles(home)
    editor_folders = _editor_extension_names(home)
    wanted = {extension for entry in entries for extension in entry.browser_extensions}
    extensions = find_extensions(home, wanted)
    found: list[FoundApp] = []
    for entry in entries:
        installs = [
            install for ext in entry.browser_extensions for install in extensions.get(ext, [])
        ]
        sightings = [
            *_bundle_sightings(entry, bundles),
            *_command_sightings(entry),
            *_folder_sightings(entry, home),
            *_editor_sightings(entry, editor_folders),
            *(Sighting("browser extension", install.where) for install in installs),
        ]
        if sightings:
            found.append(FoundApp(entry=entry, sightings=sightings, extensions=installs))
    return found


def mac_app_bundles(home: Path) -> list[AppBundle]:
    """App bundles in the Applications folders, one level of subfolders deep (macOS only)."""
    if sys.platform != "darwin":
        return []
    bundles: list[AppBundle] = []
    for folder in (*SYSTEM_APP_FOLDERS, home / "Applications"):
        for candidate in _app_candidates(folder):
            bundles.append(AppBundle(path=candidate, bundle_id=_bundle_id(candidate)))
            if len(bundles) >= MAX_APP_BUNDLES:
                return bundles
    return bundles


def _app_candidates(folder: Path) -> list[Path]:
    """``*.app`` folders directly inside ``folder`` and inside its plain subfolders."""
    candidates: list[Path] = []
    for child in _children(folder):
        if child.suffix == ".app":
            candidates.append(child)
        else:
            candidates.extend(grand for grand in _children(child) if grand.suffix == ".app")
    return candidates


def _children(folder: Path) -> list[Path]:
    try:
        return sorted(folder.iterdir()) if folder.is_dir() else []
    except OSError:
        logger.warning("Could not list %s", folder.as_posix())
        return []


def _bundle_id(app: Path) -> str:
    """The bundle identifier declared in an app's Info.plist, or empty if it has none.

    Some bundles, such as game launcher shortcuts, carry a malformed Info.plist; they are
    matched by name only.
    """
    info_plist = app / "Contents" / "Info.plist"
    if is_special_file(info_plist):
        return ""
    try:
        with info_plist.open("rb") as handle:
            info = plistlib.load(handle)
    except Exception as error:  # a malformed plist can fail inside the parser in many ways
        logger.debug("No readable Info.plist in %s: %s", app.as_posix(), error)
        return ""
    identifier = info.get("CFBundleIdentifier") if isinstance(info, dict) else None
    return identifier if isinstance(identifier, str) else ""


def _bundle_sightings(entry: AppEntry, bundles: list[AppBundle]) -> list[Sighting]:
    """Apps matched by bundle id; by folder name only for entries without a known bundle id."""
    if entry.mac_bundle_ids:
        wanted = {identifier.lower() for identifier in entry.mac_bundle_ids}
        matches = [bundle for bundle in bundles if bundle.bundle_id.lower() in wanted]
    else:
        names = set(entry.mac_app_names)
        matches = [bundle for bundle in bundles if bundle.path.name in names]
    return [Sighting("app", bundle.path.as_posix()) for bundle in matches]


def _command_sightings(entry: AppEntry) -> list[Sighting]:
    sightings: list[Sighting] = []
    for command in entry.binaries:
        location = shutil.which(command)
        if location:
            sightings.append(Sighting("command", get_relative_path(location)))
    return sightings


def _folder_sightings(entry: AppEntry, home: Path) -> list[Sighting]:
    return [Sighting("settings", raw) for raw in entry.folders if exists(home_path(home, raw))]


def _editor_extension_names(home: Path) -> list[tuple[str, str]]:
    """``(editor, extension folder name)`` for every installed editor extension."""
    names: list[tuple[str, str]] = []
    for raw, editor in EDITOR_EXTENSION_FOLDERS:
        names.extend((editor, child.name.lower()) for child in _children(home_path(home, raw)))
    return names


def _editor_sightings(entry: AppEntry, installed: list[tuple[str, str]]) -> list[Sighting]:
    sightings: list[Sighting] = []
    for extension in entry.editor_extensions:
        prefix = extension.lower()
        editors = sorted(
            {
                editor
                for editor, name in installed
                if name == prefix or name.startswith(f"{prefix}-")
            }
        )
        sightings.extend(Sighting(f"{editor} extension", extension) for editor in editors)
    return sightings
