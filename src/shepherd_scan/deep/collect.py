"""Build the deep check's upload: what the review needs from this computer, blanked.

The upload is a folder in the layout the review reads: the inventory and the scan's settings
findings, one blanked packet per skill, per plugin with code outside its skills and per MCP
server package cached by npx or bun, the connector tool list, copies of the dependency lockfiles,
and the usage totals measured here. Each server package is also copied whole (blanked, without
its dependencies) under packages/, since a packet holds only a size-limited selection. The review
happens after the upload, never on this computer.
"""

import json
import logging
import re
import shutil
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shepherd_scan import __version__ as scanner_version
from shepherd_scan._vendor.discovery.redact import redact_text
from shepherd_scan._vendor.discovery.utils import get_relative_path, is_special_file
from shepherd_scan.carry_on import attempt
from shepherd_scan.deep.inventory import Inventory, LocalServer, build_inventory, plugin_of
from shepherd_scan.deep.skills import skills_on_this_computer, static_scan, write_packet
from shepherd_scan.deep.tools import tools_on_this_computer, write_tool_packet
from shepherd_scan.discovery import Discovery
from shepherd_scan.report.model import SecretFinding

FORMAT = 1
TEXT_SUFFIXES = frozenset(
    {".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".json",
     ".toml", ".yaml", ".yml", ".ps1", ".rb", ".go", ".rs", ".cfg", ".ini", ""}
)  # fmt: skip
SKIP_PARTS = frozenset(
    {"node_modules", ".git", "__pycache__", ".venv", "venv", ".in_use", "test", "tests",
     "__tests__", "skills"}
)  # fmt: skip
SKIP_NAMES = frozenset({"package-lock.json", "uv.lock", "yarn.lock", "pnpm-lock.yaml"})
CODE_SUFFIXES = (".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb", ".go")
LOCKFILE_NAMES = frozenset(
    {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
     "uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "Cargo.lock", "go.sum",
     "Gemfile.lock", "composer.lock"}
)  # fmt: skip
LOCKFILE_SKIP_PARTS = frozenset({"node_modules", ".git", "__pycache__", ".venv", "venv"})
logger = logging.getLogger(__name__)
# Each part of the collection gets this long; on a large computer the slowest took a minute.
STEP_SECONDS = 600.0
NOT_ALPHANUMERIC = re.compile(r"[^A-Za-z0-9]")
FILE_LIMIT = 200_000
PACKET_LIMIT = 300_000
SCAN_COPY_LIMIT = 20_000_000
LOCKFILE_LIMIT = 5_000_000
USAGE_ENGINE = "ccusage-codeburn"
USAGE_LABEL = "ccusage + CodeBurn"
# A registry package name, so it can only match its own folder in the launchers' caches.
NPM_NAME = re.compile(r"(?:@[\w~-][\w.~-]*/)?[\w~-][\w.~-]*")


def collect_bundle(
    out: Path, discovery: Discovery, home: Path, keys: Sequence[SecretFinding] = ()
) -> dict[str, Any]:
    """Write everything the review needs under ``out``, except the usage totals.

    The usage totals are added by ``add_usage`` once the person has agreed to the deep check.

    Args:
        out: A new folder for the upload.
        discovery: What the scan found on this computer.
        home: The person's home folder.
        keys: The exposed keys the scan lists, by type and place (``keys.json``).

    Returns:
        The manifest.
    """
    out.mkdir(parents=True)
    failures: list[dict[str, str]] = []

    def step(part: str, run: Callable[[], Any], default: Any) -> Any:
        return attempt(part, run, default, failures, seconds=STEP_SECONDS)

    inventory = step("the inventory", lambda: build_inventory(discovery, home, failures),
                     Inventory(apps=[]))  # fmt: skip
    step("the inventory file", lambda: save_inventory(out, discovery, inventory), None)
    step("exposed keys",
         lambda: write_json(out / "keys.json", [k.model_dump() for k in keys]), None)  # fmt: skip
    skills = step("skills", lambda: _skill_packets(discovery, out / "skills"),
                  {"ids": {}, "skipped": []})  # fmt: skip
    plugins = step("plugin code", lambda: _plugin_packets(skills, out / "skills", home), {})
    servers = step(
        "server packages", lambda: _server_packets(inventory.servers, out / "skills", home), {}
    )
    tools = step("connector tools", lambda: _tool_packet(discovery, out / "tools"), [])
    roots = plugins | {key: info["lock_root"] for key, info in servers.items() if info["lock_root"]}
    lockfiles = step("lockfiles", lambda: copy_lockfiles(out, roots), {})
    manifest = {
        "format": FORMAT,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "scanner_version": scanner_version,
        "skills": len(skills["ids"]),
        "plugins": len(plugins),
        "servers": len(servers),
        "tools": len(tools),
        "skills_not_readable": skills["skipped"],
        "keys": len(keys),
        "lockfiles": lockfiles,
        "engines": {},
        "not_collected": failures,
    }
    write_json(out / "manifest.json", manifest)
    strip_home(out, home)
    return manifest


def _tool_packet(discovery: Discovery, folder: Path) -> list[Any]:
    """Write the connector tools found on this computer; return them."""
    tools = tools_on_this_computer(discovery)
    if tools:
        write_tool_packet(tools, folder)
    return tools


def fallback_bundle(
    out: Path, discovery: Discovery, home: Path, keys: Sequence[SecretFinding], reason: str
) -> dict[str, Any]:
    """The smallest package worth sending when the full collection failed or ran out of time.

    It holds what the scan already found (exposed keys by type and place, settings that act
    without asking) and says why the rest is missing, so the review can still report.
    """
    out.mkdir(parents=True)
    write_json(out / "inventory.json", Inventory(apps=[]).to_json())
    write_json(out / "acts.json", [act.model_dump() for act in discovery.acts])
    write_json(out / "keys.json", [key.model_dump() for key in keys])
    manifest = {
        "format": FORMAT,
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "scanner_version": scanner_version,
        "skills": 0, "plugins": 0, "servers": 0, "tools": 0,
        "skills_not_readable": [],
        "keys": len(keys),
        "lockfiles": {},
        "engines": {},
        "not_collected": [{"part": "the full package", "reason": reason}],
    }  # fmt: skip
    write_json(out / "manifest.json", manifest)
    strip_home(out, home)
    return manifest


def add_usage(out: Path, usage: dict[str, Any], home: Path | None = None) -> dict[str, Any]:
    """Add the usage meters' answer ({"ok", "note", "data"}) to a collected upload.

    Returns:
        The updated manifest.
    """
    write_json(out / "engines" / f"{USAGE_ENGINE}.json", usage)
    strip_home(out / "engines", home or Path.home())
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    note = ("" if usage.get("ok") else "FAILED: ") + str(usage.get("note") or "")
    manifest["engines"] = {**(manifest.get("engines") or {}), USAGE_LABEL: note}
    write_json(out / "manifest.json", manifest)
    return manifest


def save_inventory(out: Path, discovery: Discovery, inventory: Inventory) -> None:
    """Write the inventory and the scan's settings findings, so a report can be rebuilt."""
    write_json(out / "inventory.json", inventory.to_json())
    write_json(out / "acts.json", [act.model_dump() for act in discovery.acts])


def copy_lockfiles(out: Path, roots: dict[str, Path]) -> dict[str, str]:
    """Copy each packet's dependency lockfiles; return upload path -> original location."""
    copied: dict[str, str] = {}
    for packet_id, root in sorted(roots.items()):
        for path in sorted(root.rglob("*")) if root.is_dir() else []:
            relative = path.relative_to(root)
            if path.name not in LOCKFILE_NAMES or LOCKFILE_SKIP_PARTS & set(relative.parts[:-1]):
                continue
            target = out / "lockfiles" / packet_id / relative
            try:
                if not path.is_file() or path.is_symlink() or path.stat().st_size > LOCKFILE_LIMIT:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
            except OSError:
                target.unlink(missing_ok=True)
                continue
            copied[target.relative_to(out).as_posix()] = get_relative_path(str(path))
    return copied


def _skill_packets(discovery: Discovery, skills_dir: Path) -> dict[str, Any]:
    sources, skipped = skills_on_this_computer(discovery)
    sources.sort(key=lambda source: (source.name.lower(), source.digest))
    ids: dict[str, list[str]] = {}
    for number, source in enumerate(sources, start=1):
        skill_id = f"skill-{number:03d}"
        try:
            write_packet(source, skill_id, skills_dir, folder_name=source.folder.name)
        except Exception as error:  # one skill must not stop the package; it is listed
            shutil.rmtree(skills_dir / skill_id, ignore_errors=True)
            where = get_relative_path(str(source.folder))
            skipped.append(f"{source.name}: {where} ({type(error).__name__})")
            continue
        update_packet(skills_dir / skill_id, {"kind": "skill"})
        ids[skill_id] = source.install_locations
    return {"ids": ids, "skipped": skipped}


def _plugin_packets(skills: dict[str, Any], skills_dir: Path, home: Path) -> dict[str, Path]:
    """One packet per plugin whose own folder holds code outside its skills: id -> root.

    Claude Code keeps earlier versions of a plugin in its cache after an update, so one plugin
    can have several folders; the newest cached version is packaged, as for server packages.
    """
    newest = _newest_plugins(skills)
    for skill_id, locations in skills["ids"].items():
        plugin = next((p for p in map(plugin_of, locations) if p is not None), None)
        if plugin is not None:
            update_packet(skills_dir / skill_id, {"plugin_packet": _plugin_packet_id(plugin)})
    written: dict[str, Path] = {}
    for packet_id, plugin in sorted(newest.items()):
        root = plugin["root"]
        folder = Path(root.replace("~", str(home), 1))
        files, skipped = _text_files(folder)
        if not any(name.lower().endswith(CODE_SUFFIXES) for name in files):
            continue
        meta = _packet_meta(packet_id, "plugin", root)
        meta["name"] = plugin["plugin"]
        meta["skipped_files"] = skipped
        target = skills_dir / packet_id
        if _written(target, _write_code_packet, target, files, meta):
            written[packet_id] = folder
    return written


def _written(target: Path, write: Callable[..., None], *args: Any) -> bool:
    """Write one packet into ``target``; if that fails, remove what it left and log it."""
    try:
        write(*args)
    except Exception as error:  # one add-on must not stop the package
        shutil.rmtree(target, ignore_errors=True)
        logger.warning("Could not package %s (%s)", target.name, type(error).__name__)
        return False
    return True


def _newest_plugins(skills: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Each plugin's newest cached version among the skills' install locations, by packet id."""
    newest: dict[str, dict[str, str]] = {}
    for locations in skills["ids"].values():
        for plugin in filter(None, map(plugin_of, locations)):
            kept = newest.get(_plugin_packet_id(plugin))
            if kept is None or _version_key(plugin["version"]) > _version_key(kept["version"]):
                newest[_plugin_packet_id(plugin)] = plugin
    return newest


def _plugin_packet_id(plugin: dict[str, str]) -> str:
    return f"plugin-{plugin['marketplace']}-{plugin['plugin']}"


def _server_packets(
    servers: list[LocalServer], skills_dir: Path, home: Path
) -> dict[str, dict[str, Any]]:
    """Packets for MCP server packages cached by npx or bun, newest cached version each."""
    written: dict[str, dict[str, Any]] = {}
    npx_cache = home / ".npm" / "_npx"
    for package in sorted({s.package for s in servers if s.launcher in ("npx", "bunx")}):
        versions = _cached_versions(package, home)
        if not versions:
            continue
        newest = max(versions, key=lambda item: _version_key(item[0]))
        packet_id = "server-" + re.sub(r"[^a-z0-9]+", "-", package.lower()).strip("-")
        if packet_id in written:
            continue
        meta = _packet_meta(packet_id, "server", get_relative_path(str(newest[1])))
        meta["name"] = package
        meta["versions_seen"] = sorted(v for v, _ in versions)
        meta["agents"] = sorted({s.agent for s in servers if s.package == package})
        files, meta["skipped_files"] = _text_files(newest[1])
        packet, copy = skills_dir / packet_id, skills_dir.parent / "packages" / packet_id
        if not _written(packet, _write_code_packet, packet, files, meta):
            continue
        if not _written(copy, _write_scan_copy, copy, newest[1]):
            shutil.rmtree(packet, ignore_errors=True)
            continue
        lock_root = next((p for p in newest[1].parents if p.parent == npx_cache), None)
        written[packet_id] = {"package": package, "folder": newest[1], "lock_root": lock_root}
    return written


def _cached_versions(package: str, home: Path) -> list[tuple[str, Path]]:
    if not NPM_NAME.fullmatch(package):
        return []
    found = []
    for manifest in sorted((home / ".npm" / "_npx").glob(f"*/node_modules/{package}/package.json")):
        found.append((_package_version(manifest), manifest.parent))
    for folder in sorted((home / ".bun" / "install" / "cache").glob(f"{package}@*")):
        found.append((folder.name.split("@")[1], folder))
    return [(version, folder) for version, folder in found if version]


def _package_version(manifest: Path) -> str:
    if is_special_file(manifest):
        return ""
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ""
    return str(data.get("version") or "") if isinstance(data, dict) else ""


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version)[:4])


def _copyable(path: Path, relative: Path) -> bool:
    """A text file worth copying: not a dependency, test, lockfile, source map or type stub."""
    try:
        if not path.is_file() or path.is_symlink() or SKIP_PARTS & set(relative.parts[:-1]):
            return False
    except OSError:
        return False
    if path.name in SKIP_NAMES or path.suffix.lower() not in TEXT_SUFFIXES:
        return False
    return not path.name.endswith((".map", ".d.ts"))


def _text_files(root: Path) -> tuple[dict[str, str], int]:
    """Blanked text of the files under root, and how many were left out by the size limit.

    Dependencies, tests, lockfiles and minified files are skipped.
    """
    files: dict[str, str] = {}
    used = 0
    skipped = 0
    for path in sorted(root.rglob("*")) if root.is_dir() else []:
        relative = path.relative_to(root)
        if not _copyable(path, relative) or path.name.endswith(".min.js"):
            continue
        try:
            too_big = path.stat().st_size > FILE_LIMIT
            text = "" if too_big else path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            too_big, text = True, ""
        if too_big:
            skipped += 1
            continue
        if used + len(text) > PACKET_LIMIT:
            skipped += 1
            continue
        files[relative.as_posix()] = redact_text(text) or ""
        used += len(text)
    return files, skipped


def _write_scan_copy(target: Path, root: Path) -> None:
    """Every text file of a server package, blanked, for the review.

    A packet holds a size-limited selection; this copy is the whole package, as it is on this
    computer (dependencies and tests left out, as for packets).
    """
    used = 0
    for path in sorted(root.rglob("*")) if root.is_dir() else []:
        relative = path.relative_to(root)
        if not _copyable(path, relative):
            continue
        try:
            used += path.stat().st_size
            if used > SCAN_COPY_LIMIT:
                return
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        copy = target / relative
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_text(redact_text(text) or "", encoding="utf-8")


def _packet_meta(packet_id: str, kind: str, location: str) -> dict[str, Any]:
    return {
        "id": packet_id,
        "kind": kind,
        "name": packet_id.split("-", 1)[1],
        "folder_name": None,
        "install_locations": [location],
        "agents": [],
    }


def _write_code_packet(target: Path, files: dict[str, str], meta: dict[str, Any]) -> None:
    files_dir = target / "files"
    files_dir.mkdir(parents=True)
    for relative, text in files.items():
        destination = files_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    meta["files"] = [{"path": p, "characters": len(t)} for p, t in files.items()]
    meta["static_scan"] = static_scan(files_dir)
    write_json(target / "packet.json", meta)


def update_packet(folder: Path, changes: dict[str, Any]) -> None:
    """Merge changes into one packet's packet.json."""
    path = folder / "packet.json"
    packet = json.loads(path.read_text(encoding="utf-8"))
    packet.update(changes)
    write_json(path, packet)


def strip_home(folder: Path, home: Path) -> None:
    r"""Show the home folder as ``~`` in every text file under ``folder``.

    File paths carry the person's user name; the review needs only where a file sits under home.
    Claude Code names its project folders after their path with every other character made a
    dash (``-Users-<name>-Desktop-…``), so that form of the home folder is replaced too. The
    home folder is found in any letter case (macOS paths ignore case), with escaped slashes
    (``\/Users\/<name>``) and before a full stop; ``/Users/<name>.c`` is another person's.
    """
    names = {str(home), str(home.resolve())}
    names |= {json.dumps(name)[1:-1] for name in names}
    names |= {name.replace("/", "\\/") for name in names}
    alternatives = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    dashed = {NOT_ALPHANUMERIC.sub("-", str(path)) for path in (home, home.resolve())}
    dashed_alternatives = "|".join(
        re.escape(name) for name in sorted(dashed, key=len, reverse=True)
    )
    pattern = re.compile(
        f"(?:{alternatives})(?![\\w-]|\\.[\\w-])|(?:{dashed_alternatives})(?![A-Za-z0-9])",
        re.IGNORECASE,
    )
    for path in folder.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        stripped = pattern.sub("~", text)
        if stripped != text:
            try:
                path.write_text(stripped, encoding="utf-8")
            except OSError:  # a copy that still names the home folder is not sent
                path.unlink()


def write_json(path: Path, data: Any) -> None:
    """Write one JSON file of the upload, creating its folder."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
