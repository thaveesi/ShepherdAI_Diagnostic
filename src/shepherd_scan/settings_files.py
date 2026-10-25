"""Read agent settings files safely: size cap, unreadable files and malformed content handled.

A missing file is not a problem and returns None quietly. A file that exists but cannot be read
or parsed also returns None, and a warning naming it is logged so the report can list it under
"Could not be checked". Callers look up the few keys they need and keep no values.
"""

import logging
import plistlib
import tomllib
from pathlib import Path
from typing import Any

import pyjson5
import yaml

logger = logging.getLogger(__name__)

MAX_SETTINGS_BYTES = 5 * 1024 * 1024
# A YAML tag such as ``!!timestamp`` on text that is not a date fails inside the parser.
PARSE_ERRORS = (
    pyjson5.Json5Exception,
    ValueError,
    yaml.YAMLError,
    RecursionError,
    AttributeError,
    TypeError,
)


def home_path(home: Path, raw: str) -> Path:
    """A ``~/``-relative location under ``home``; other paths are returned unchanged."""
    if raw == "~":
        return home
    if raw.startswith("~/"):
        return home / raw[2:]
    return Path(raw)


def exists(path: Path) -> bool:
    """Whether a file or folder exists, treating an unreadable parent as absent."""
    try:
        return path.exists()
    except OSError:
        return False


def _read_bytes(path: Path) -> bytes | None:
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_SETTINGS_BYTES:
            logger.warning("Skipped %s: larger than %d bytes", path.as_posix(), MAX_SETTINGS_BYTES)
            return None
        return path.read_bytes()
    except PermissionError:
        logger.warning("Permission denied reading %s", path.as_posix())
    except OSError:
        logger.warning("Could not read %s", path.as_posix())
    return None


def read_text(path: Path) -> str | None:
    """The file's text, or None if it is missing, unreadable or larger than the cap."""
    raw = _read_bytes(path)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning("Could not read %s", path.as_posix())
        return None


def _load_plist(path: Path) -> dict[str, Any] | None:
    """A property list, XML or binary, such as a macOS managed-preferences profile."""
    raw = _read_bytes(path)
    if raw is None:
        return None
    try:
        data = plistlib.loads(raw)
    except Exception:  # a malformed plist can fail inside the parser in many ways
        logger.warning("Could not parse %s", path.as_posix())
        return None
    return data if isinstance(data, dict) else None


def load_settings(path: Path) -> dict[str, Any] | None:
    """Parse a settings file by its extension: TOML, YAML, a property list, or JSON.

    JSON may carry comments.

    Returns:
        The top-level mapping, an empty mapping for an empty file, or None when the file is
        missing, unreadable, malformed or not a mapping.
    """
    if path.suffix.lower() == ".plist":
        return _load_plist(path)
    text = read_text(path)
    if text is None:
        return None
    if not text.strip():
        return {}
    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            data: Any = tomllib.loads(text)
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        else:
            data = pyjson5.loads(text)
    except PARSE_ERRORS:
        logger.warning("Could not parse %s", path.as_posix())
        return None
    return data if isinstance(data, dict) else None


def lookup(data: Any, dotted: str) -> Any:
    """A nested value by dotted key, accepting either nested maps or a literal dotted key.

    Editors such as VS Code store ``"chat.tools.global.autoApprove"`` as one flat key, while
    other apps nest the same path; both spellings, and mixes of them, are found.
    """
    if not isinstance(data, dict):
        return None
    parts = dotted.split(".")
    for cut in range(len(parts), 0, -1):
        key = ".".join(parts[:cut])
        if key in data:
            rest = ".".join(parts[cut:])
            return lookup(data[key], rest) if rest else data[key]
    return None
