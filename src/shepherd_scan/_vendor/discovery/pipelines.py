# Modified from Apache-2.0 licensed code; see THIRD_PARTY_NOTICES.txt.
import getpass
import logging
import os
from pathlib import Path

from pydantic import BaseModel, Field

from shepherd_scan._vendor.discovery.agents import DiscoveryScope, find_discoverers
from shepherd_scan._vendor.discovery.inspect import (
    get_mcp_config_per_client,
    inspect_client,
)
from shepherd_scan._vendor.discovery.models import (
    CandidateClient,
    ClientToInspect,
    DiscoveredSkill,
    InspectedPath,
    ScanError,
    TokenAndClientInfo,
)
from shepherd_scan._vendor.discovery.redact import redact_inspected_path
from shepherd_scan._vendor.discovery.utils import get_readable_home_directories
from shepherd_scan._vendor.discovery.well_known_clients import get_well_known_clients

logger = logging.getLogger(__name__)


class InspectArgs(BaseModel):
    timeout: int
    tokens: list[TokenAndClientInfo]
    paths: list[str]
    all_users: bool = False
    scan_skills: bool = False
    discovery_scope: DiscoveryScope = DiscoveryScope.ALL
    target_folders: list[str] = Field(default_factory=list)


async def discover_clients_to_inspect(
    inspect_args: InspectArgs,
) -> tuple[list[ClientToInspect], list[InspectedPath], list[str]]:
    """
    Discover the clients/configs that would be inspected, without actually
    starting any MCP servers.
    """
    home_dirs_with_users = get_readable_home_directories(all_users=inspect_args.all_users)
    all_usernames: list[str] = [username for _path, username in home_dirs_with_users]

    unresolved_paths: list[InspectedPath] = []
    clients_to_inspect: list[ClientToInspect] = []
    if inspect_args.paths:
        for path in inspect_args.paths:
            ctis = await client_to_inspect_from_path(path, True, home_dirs_with_users, inspect_args.scan_skills)
            if ctis:
                clients_to_inspect.extend(ctis)
            else:
                normalized_path = path.replace("\\", "/")
                unresolved_paths.append(
                    InspectedPath(
                        path=normalized_path,
                        client=normalized_path,
                        error=ScanError(
                            message="File or folder not found", is_failure=False, category="file_not_found"
                        ),
                    )
                )
    else:
        target_folders: list[Path] = []
        seen_target_folders: set[Path] = set()
        for raw_path in inspect_args.target_folders:
            target_path = Path(raw_path).expanduser()
            try:
                key = target_path.resolve()
            except (OSError, RuntimeError, ValueError):
                # A NUL byte in a folder name raises ValueError; fall back to the
                # literal path so one bad entry cannot abort the whole discovery.
                key = target_path
            if key in seen_target_folders:
                continue
            seen_target_folders.add(key)
            try:
                exists = key.exists()
            except (OSError, RuntimeError, ValueError):
                logger.warning("Skipping inaccessible target folder: %s", target_path)
                continue
            if not exists:
                logger.warning("Skipping non-existent target folder: %s", target_path)
                continue
            target_folders.append(target_path)

        # Phase A — legacy path. Runs for EVERY well-known client including Claude Code.
        for client in get_well_known_clients():
            try:
                ctis = await get_mcp_config_per_client(client, home_dirs_with_users, scope=inspect_args.discovery_scope)
            except Exception:
                where = client.client_exists_paths[0] if client.client_exists_paths else "~"
                logger.exception("Could not read the settings of %s under %s", client.name, where)
                continue
            if ctis:
                clients_to_inspect.extend(ctis)
            else:
                logger.info(f"Client {client.name} does not exist on this machine. {client.client_exists_paths}")

        # Phase B — ABC path. Runs sequentially after Phase A and merges into its output.
        for home_directory, username in home_dirs_with_users:
            for discoverer in find_discoverers(home_directory, target_folders=target_folders):
                try:
                    cti = discoverer.discover(inspect_args.discovery_scope)
                except Exception:
                    logger.exception("Discoverer %s.discover() raised; skipping", type(discoverer).__name__)
                    continue
                if cti is None:
                    continue
                cti.username = username
                existing = next(
                    (c for c in clients_to_inspect if c.name == cti.name and c.username == cti.username),
                    None,
                )
                if existing is None:
                    clients_to_inspect.append(cti)
                else:
                    # Dict union: legacy keys first (insertion order), ABC keys appended.
                    # ABC values win on key collision (e.g., both phases emit a server
                    # under ``~/.claude.json``). Distinct keys from each phase coexist
                    # — same-name servers under different keys are kept as separate
                    # registrations (e.g., the same ``github`` server configured in
                    # two projects must both reach the inspector).
                    existing.mcp_configs = {**existing.mcp_configs, **cti.mcp_configs}
                    existing.skills_dirs = {**existing.skills_dirs, **cti.skills_dirs}

    # Only report usernames where an agent was detected in their home directory.
    # When no usernames were associated with detected agents:
    #   - Discovery mode with all_users: fall back to all readable usernames.
    #   - Otherwise (explicit paths or single-user mode): fall back to the current OS user only,
    #     to avoid disclosing unrelated usernames on the machine.
    detected_usernames: list[str] = sorted({cti.username for cti in clients_to_inspect if cti.username is not None})
    if detected_usernames:
        scanned_usernames = detected_usernames
    elif not inspect_args.paths and inspect_args.all_users:
        scanned_usernames = all_usernames
    else:
        scanned_usernames = [getpass.getuser()]

    return clients_to_inspect, unresolved_paths, scanned_usernames


async def inspect_pipeline(
    inspect_args: InspectArgs,
    *,
    clients_to_inspect: list[ClientToInspect] | None = None,
    unresolved_paths: list[InspectedPath] | None = None,
    scanned_usernames: list[str] | None = None,
    stream_stderr: bool = False,
    declined_servers: set[tuple[str, str]] | None = None,
    do_stdio_handshake: bool = False,
    allow_network: bool = False,
) -> tuple[list[InspectedPath], list[str]]:
    """Inspect each discovered client and return ``InspectedPath`` results.

    Unresolved explicit paths (e.g. file-not-found) already have their error
    represented by an otherwise-empty ``InspectedPath`` and are included directly.
    Remote MCP servers are only contacted when ``allow_network`` is true; local
    servers are only started when ``do_stdio_handshake`` is true.
    """
    if clients_to_inspect is None:
        clients_to_inspect, unresolved_paths, scanned_usernames = await discover_clients_to_inspect(inspect_args)
    inspected_paths = list(unresolved_paths or [])
    for client_to_inspect in clients_to_inspect:
        inspected_paths.append(
            await inspect_client(
                client_to_inspect,
                inspect_args.timeout,
                inspect_args.tokens,
                inspect_args.scan_skills,
                stream_stderr=stream_stderr,
                declined_servers=declined_servers,
                do_stdio_handshake=do_stdio_handshake,
                allow_network=allow_network,
            )
        )
    # Redact before anything is printed, written or handed to a check.
    inspected_paths = [redact_inspected_path(path) for path in inspected_paths]

    return inspected_paths, scanned_usernames or []


async def client_to_inspect_from_path(
    path: str,
    use_path_as_client_name: bool = False,
    home_dirs: list[tuple[Path, str]] | None = None,
    scan_skills: bool = False,
) -> list[ClientToInspect]:
    if home_dirs is None:
        home_dirs = [(Path.home(), getpass.getuser())]
    if scan_skills and os.path.isdir(os.path.expanduser(path)):
        if os.path.exists(os.path.join(path, "SKILL.md")):
            # split last segment from all other dirs in the path (account for trailing slash)
            last_dir = os.path.basename(os.path.normpath(path))

            path_without_last_dir = os.path.dirname(path)
            return [
                ClientToInspect(
                    name=path if use_path_as_client_name else "not-available",
                    client_path=path_without_last_dir,
                    mcp_configs={},
                    skills_dirs={
                        path_without_last_dir: [DiscoveredSkill(name=last_dir, path=path)],
                    },
                )
            ]
        else:
            candidate_client = CandidateClient(
                name=path if use_path_as_client_name else "not-available",
                client_exists_paths=[path],
                mcp_config_paths=[],
                skills_dir_paths=[path],
            )
            return await get_mcp_config_per_client(
                candidate_client, home_dirs=home_dirs, create_file_not_found_error=True
            )
    elif scan_skills and os.path.basename(os.path.normpath(path)).lower() == "skill.md":
        skill_directory = os.path.basename(os.path.dirname(os.path.normpath(path)))
        parent_of_skill_directory = os.path.dirname(os.path.dirname(os.path.normpath(path)))

        return [
            ClientToInspect(
                name=path if use_path_as_client_name else "not-available",
                client_path=parent_of_skill_directory,
                mcp_configs={},
                skills_dirs={
                    parent_of_skill_directory: [DiscoveredSkill(name=skill_directory, path=os.path.dirname(path))],
                },
            )
        ]
    else:
        candidate_client = CandidateClient(
            name=path if use_path_as_client_name else "not-available",
            client_exists_paths=[path],
            mcp_config_paths=[path],
            skills_dir_paths=[],
        )
        return await get_mcp_config_per_client(candidate_client, home_dirs=home_dirs, create_file_not_found_error=True)
