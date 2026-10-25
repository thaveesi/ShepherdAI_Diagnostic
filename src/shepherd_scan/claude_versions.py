"""Which Claude Code versions are installed, per surface (read B of gate A).

Only folder names, link targets and the ``version`` field of an npm package manifest are read.
Several documented behaviours start at a version (for example the built-in auto start from
2.1.228 or 2.1.284), so the deep review needs the version each surface runs.
"""

import json
import re
import sys
from pathlib import Path

VERSION = re.compile(r"\d+\.\d+\.\d+")
NPM_PREFIXES = (
    "/usr/local/lib/node_modules",
    "/opt/homebrew/lib/node_modules",
    "~/.npm-global/lib/node_modules",
    "~/.local/lib/node_modules",
)
CASKROOMS = ("/opt/homebrew/Caskroom/claude-code", "/usr/local/Caskroom/claude-code")
EXTENSION_FOLDERS = ("~/.vscode/extensions", "~/.cursor/extensions")
EXTENSION_PREFIX = "anthropic.claude-code-"
# The documented thresholds of the built-in start mode (Claude Code docs, permission-modes).
AUTO_FOR_SOME = (2, 1, 228)
AUTO_FOR_ALL = (2, 1, 284)


def claude_code_versions(home: Path) -> dict[str, list[str]]:
    """Versions found per surface: terminal (and the one ``claude`` runs), Desktop, Cowork, IDE."""
    found = {
        "terminal": _terminal(home),
        "terminal_active": _active(home),
        "desktop": _folder_versions(_desktop_dir(home) / "claude-code"),
        "cowork": _folder_versions(_desktop_dir(home) / "claude-code-vm"),
        "ide": _extension_versions(home),
    }
    return {surface: versions for surface, versions in found.items() if versions}


def active_terminal_version(home: Path) -> str:
    """The version the ``claude`` command runs, or "" when it can't be told."""
    active = _active(home)
    return active[0] if active else ""


def start_mode_warning(version: str) -> str:
    """The scan's warning when no permission mode is set, worded for the installed version.

    Empty when that version starts in Manual mode. Conditional when the start depends on the
    plan (2.1.228 to 2.1.283, where the documentation and the changelog also disagree about
    2.1.283) or when the version is unknown.
    """
    parsed = _parse(version)
    if parsed is not None and parsed < AUTO_FOR_SOME:
        return ""
    if parsed is not None and parsed >= AUTO_FOR_ALL:
        return (
            f"No permission mode is set, so Claude Code {version} starts in auto mode: an "
            "automatic check approves actions instead of asking you"
        )
    if parsed is not None:
        return (
            f"No permission mode is set, so Claude Code {version} may start in auto mode on Pro, "
            "Max and Team plans: an automatic check would approve actions instead of asking you"
        )
    return (
        "No permission mode is set; depending on its version and plan, Claude Code may start "
        "in auto mode, where an automatic check approves actions instead of asking you"
    )


def _parse(version: str) -> tuple[int, ...] | None:
    match = VERSION.fullmatch(version or "")
    return tuple(int(part) for part in version.split(".")) if match else None


def _sorted(versions: set[str]) -> list[str]:
    return sorted(versions, key=lambda v: _parse(v) or (0,))


def _terminal(home: Path) -> list[str]:
    found = set(_folder_versions(home / ".local" / "share" / "claude" / "versions"))
    for prefix in NPM_PREFIXES:
        manifest = _expand(prefix, home) / "@anthropic-ai" / "claude-code" / "package.json"
        version = _manifest_version(manifest)
        if version:
            found.add(version)
    for cask in CASKROOMS:
        found.update(_folder_versions(Path(cask)))
    return _sorted(found)


def _active(home: Path) -> list[str]:
    """The version behind ``~/.local/bin/claude``, from its link target's folder name."""
    link = home / ".local" / "bin" / "claude"
    try:
        target = link.resolve() if link.is_symlink() else None
    except OSError:
        return []
    names = [part for part in (target.parts if target else ()) if VERSION.fullmatch(part)]
    return names[-1:]


def _desktop_dir(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude"
    if sys.platform == "win32":
        return home / "AppData" / "Roaming" / "Claude"
    return home / ".config" / "Claude"


def _folder_versions(folder: Path) -> list[str]:
    try:
        names = [entry.name for entry in folder.iterdir()] if folder.is_dir() else []
    except OSError:
        return []
    return _sorted({name for name in names if VERSION.fullmatch(name)})


def _extension_versions(home: Path) -> list[str]:
    found = set()
    for folder in EXTENSION_FOLDERS:
        for name in _folder_names(_expand(folder, home)):
            if name.startswith(EXTENSION_PREFIX):
                version = name[len(EXTENSION_PREFIX) :].split("-", 1)[0]
                if VERSION.fullmatch(version):
                    found.add(version)
    return _sorted(found)


def _folder_names(folder: Path) -> list[str]:
    try:
        return [entry.name for entry in folder.iterdir()] if folder.is_dir() else []
    except OSError:
        return []


def _expand(raw: str, home: Path) -> Path:
    return home / raw[2:] if raw.startswith("~/") else Path(raw)


def _manifest_version(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError, RecursionError):
        return ""
    version = data.get("version") if isinstance(data, dict) else None
    return version if isinstance(version, str) and VERSION.fullmatch(version) else ""
