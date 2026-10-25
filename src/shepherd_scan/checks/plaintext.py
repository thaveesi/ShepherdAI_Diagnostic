"""Find credentials written straight into agent settings, before collection blanks them.

Agent settings hand credentials to MCP servers in four places: environment variables, request
headers, command arguments and web addresses. Some apps also keep API keys for AI providers in
their settings files. Each value is looked at once, in memory, to answer two questions: is it
written in the file (rather than a reference to an environment variable or a secret store), and
is it a kind that acts as a bot, app or service account by design? Only the setting's name and
those answers are kept; values never leave this module.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from detect_secrets.settings import default_settings

from shepherd_scan._vendor.discovery.models import ClientToInspect, RemoteServer, StdioServer
from shepherd_scan.checks.secrets import format_kind
from shepherd_scan.checks.servers import CREDENTIAL_NAME
from shepherd_scan.settings_files import home_path, load_settings

# Credential-like names that hold something other than a secret: identifiers, places, options.
NOT_A_SECRET = re.compile(
    r"(^|[_-])(ID|URL|URI|ENDPOINT|HOST|PORT|PATH|FILE|DIR|TYPE|MODE|REGION|NAME|USER|USERNAME"
    r"|EMAIL|HEADER|EXPIRY|EXPIRES|TTL|TIMEOUT|ENABLED|DISABLED|SCOPE|SCOPES|VERSION|LIMIT|COUNT"
    r"|SIZE|LENGTH|BUDGET)$|^MAX[_-]|TOKENIZER",
    re.IGNORECASE,
)
# Values that point elsewhere instead of holding the credential.
REFERENCE = re.compile(
    r"\$\{|\{\{|^\$[A-Za-z_]|^%[A-Za-z_]\w*%$|^\{env:|^(env|op|keychain|vault|secret)[:{]",
    re.IGNORECASE,
)
# An environment variable's name given as the value: the app reads the credential from there.
VARIABLE_NAME = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")
AUTH_SCHEME = re.compile(r"^(bearer|basic|token|apikey|api-key)\s+", re.IGNORECASE)
PLACEHOLDER = re.compile(
    r"^<.*>$|your[_\- ]|^(insert|paste|enter|add|put)[_\- ]"
    r"|^(x+|\*+|\.+|changeme|replace[_\- ]?me|todo|none|null|undefined|placeholder|example"
    r"|test|dummy|secret|password|token|api[_-]?key)$",
    re.IGNORECASE,
)
PATH_LIKE = re.compile(r"^(/|~/|\./|\.\./|[A-Za-z]:\\)")
URL_LIKE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
HEADER_ARGUMENT = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+)$")
MIN_CREDENTIAL_LENGTH = 8

# Formats recognised from their start: (prefix, type, acts as a bot/app/service by design).
KNOWN_PREFIXES: tuple[tuple[str, str, bool], ...] = (
    ("xoxb-", "Slack bot token", True),
    ("xapp-", "Slack app token", True),
    ("xoxp-", "Slack user token", False),
    ("ghs_", "GitHub App installation token", True),
    ("ghu_", "GitHub App user token", False),
    ("ghp_", "GitHub personal access token", False),
    ("github_pat_", "GitHub fine-grained token", False),
    ("gho_", "GitHub sign-in token", False),
    ("glpat-", "GitLab access token", False),
    ("ntn_", "Notion integration token", True),
    ("shpat_", "Shopify app token", True),
    ("sk-ant-", "Anthropic API key", False),
    ("sk-or-", "OpenRouter API key", False),
    ("sk-proj-", "OpenAI API key", False),
    ("AIza", "Google API key", False),
    ("lin_api_", "Linear API key", False),
    ("hf_", "Hugging Face token", False),
    ("npm_", "npm token", False),
    ("pypi-", "PyPI token", False),
    ("tvly-", "Tavily API key", False),
    ("pplx-", "Perplexity API key", False),
    ("xai-", "xAI API key", False),
    ("gsk_", "Groq API key", False),
    ("figd_", "Figma token", False),
)
# Setting names that, by convention, carry a bot, service or company account's credential.
SHARED_NAMES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"BOT[_-]?TOKEN", re.IGNORECASE), "bot token"),
    (re.compile(r"SERVICE[_-]?ROLE", re.IGNORECASE), "service-role key"),
    (re.compile(r"SERVICE[_-]?ACCOUNT", re.IGNORECASE), "service account"),
    (re.compile(r"^GOOGLE_APPLICATION_CREDENTIALS$", re.IGNORECASE), "Google service account key"),
    (re.compile(r"^AZURE_CLIENT_(SECRET|CERTIFICATE_PATH)$", re.IGNORECASE), "Azure app identity"),
)


@dataclass(frozen=True)
class CredentialSetting:
    """A credential handed to a server or kept in an app's settings. Never holds the value.

    Attributes:
        client: Discovery identifier of the agent app whose settings hold it.
        server: The MCP server it is passed to; empty for keys an app keeps for itself.
        config_path: The settings file, as found on disk.
        setting: Where in the settings it sits, e.g. ``EXA_API_KEY`` or ``header Authorization``.
        written: True when the value is written in the file rather than referenced.
        kind: The credential's type when recognised, e.g. ``Slack bot token``.
        shared: True for kinds that act as a bot, app or service account by design.
    """

    client: str
    server: str
    config_path: str
    setting: str
    written: bool
    kind: str | None = None
    shared: bool = False


Facts = tuple[str, bool, str | None, bool]


def credential_settings(clients: list[ClientToInspect]) -> list[CredentialSetting]:
    """Credentials in every MCP server entry found by discovery, before values are blanked."""
    found: list[CredentialSetting] = []
    with default_settings():
        for client in clients:
            for config_path, servers in client.mcp_configs.items():
                if not isinstance(servers, list):
                    continue
                for server_name, server in servers:
                    found.extend(
                        CredentialSetting(client.name, server_name, config_path, *facts)
                        for facts in _server_facts(server)
                    )
    return found


# Settings files where apps keep API keys for AI providers: (app, file, part holding the keys).
PROVIDER_KEY_FILES: tuple[tuple[str, str, str | None], ...] = (
    ("raycast", "~/.config/raycast/ai/providers.yaml", None),
    ("continue", "~/.continue/config.yaml", "models"),
    ("continue", "~/.continue/config.json", "models"),
    ("junie", "~/.junie/config.json", "byok"),
    ("opencode", "~/.config/opencode/opencode.json", "provider"),
)
MAX_WALK_NODES = 5000


def provider_keys(home: Path) -> list[CredentialSetting]:
    """API keys for AI providers written into an app's own settings file."""
    found: list[CredentialSetting] = []
    with default_settings():
        for client, raw, part in PROVIDER_KEY_FILES:
            path = home_path(home, raw)
            data = load_settings(path)
            if data is None:
                continue
            count = _count_written_keys(data.get(part) if part else data)
            if count:
                label = f"{count} API key{'s' if count != 1 else ''} for AI providers"
                setting = f"{part}: {label}" if part else label
                found.append(CredentialSetting(client, "", path.as_posix(), setting, written=True))
    return found


def _server_facts(server: StdioServer | RemoteServer) -> list[Facts]:
    if isinstance(server, StdioServer):
        facts = [_facts(name, value, name) for name, value in (server.env or {}).items()]
        facts.extend(_argument_facts(server.args))
    else:
        facts = [_facts(name, value, f"header {name}") for name, value in server.headers.items()]
        facts.extend(_address_facts(server.url, "address"))
    return [fact for fact in facts if fact is not None]


def _argument_facts(args: list[str]) -> list[Facts | None]:
    facts: list[Facts | None] = []
    position = 0
    while position < len(args):
        argument = args[position]
        if argument.startswith("-"):
            flag_facts, consumed = _flag_facts(args, position)
            facts.extend(flag_facts)
            position += consumed
            continue
        facts.extend(_value_facts(argument, f"argument {position + 1}"))
        position += 1
    return facts


def _flag_facts(args: list[str], position: int) -> tuple[list[Facts | None], int]:
    """Facts for ``--flag=value`` or ``--flag value``, and how many arguments were used."""
    flag, has_value, value = args[position].partition("=")
    name = flag.lstrip("-")
    if has_value:
        header = HEADER_ARGUMENT.match(value)
        if header is not None:
            return [_facts(header.group(1), header.group(2), f"argument {flag}")], 1
        return [_facts(name, value, f"argument {flag}")], 1
    following = args[position + 1] if position + 1 < len(args) else None
    if following is not None and not following.startswith("-") and _credential_name(name):
        return [_facts(name, following, f"argument {flag}")], 2
    return [], 1


def _value_facts(argument: str, setting: str) -> list[Facts | None]:
    """Facts for a positional argument: an address, a header, ``NAME=value`` or a bare value."""
    if URL_LIKE.match(argument):
        return _address_facts(argument, setting)
    header = HEADER_ARGUMENT.match(argument)
    if header is not None:
        return [_facts(header.group(1), header.group(2), f"{setting} (header {header.group(1)})")]
    if "=" in argument:
        name, _, value = argument.partition("=")
        return [_facts(name, value, f"{setting} ({name})")]
    return [_facts("", argument, setting)]


def _address_facts(url: str, setting: str) -> list[Facts | None]:
    try:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        password = parts.password
    except ValueError:
        return []
    facts = [_facts(name, value, f"{setting} parameter {name}") for name, value in query]
    if password:
        facts.append(_facts("PASSWORD", password, f"{setting} password"))
    return facts


def _facts(name: str, value: Any, setting: str) -> Facts | None:
    """What a single value tells us, or None when it is not a credential worth reporting."""
    text = value.strip() if isinstance(value, str) else ""
    if not text:
        return None
    kind, shared = _recognise(name, text)
    if not (kind or (name and _credential_name(name))):
        return None
    written = _written_in_file(text)
    if not (written or shared):
        return None
    return setting, written, kind, shared


def _credential_name(name: str) -> bool:
    normalized = name.replace("-", "_")
    return bool(CREDENTIAL_NAME.search(normalized)) and not NOT_A_SECRET.search(normalized)


def _recognise(name: str, value: str) -> tuple[str | None, bool]:
    """The credential's type and whether it is shared by design, from its format or name."""
    bare = AUTH_SCHEME.sub("", value)
    for prefix, kind, shared in KNOWN_PREFIXES:
        if bare.startswith(prefix):
            return kind, shared
    for pattern, kind in SHARED_NAMES:
        if name and pattern.search(name):
            return kind, True
    return format_kind(bare), False


def _written_in_file(value: str) -> bool:
    """True when the value itself is a credential written into the file."""
    text = AUTH_SCHEME.sub("", value.strip())
    return not (
        len(text) < MIN_CREDENTIAL_LENGTH
        or text.isdigit()
        or any(character.isspace() for character in text)
        or REFERENCE.search(text)
        or VARIABLE_NAME.match(text)
        or PLACEHOLDER.search(text)
        or PATH_LIKE.match(text)
        or URL_LIKE.match(text)
    )


def _count_written_keys(data: Any) -> int:
    """Credentials written in a settings subtree, walked with a bound.

    A value counts when it sits under a credential-named key (``apiKey``, ``api_keys: {...}``)
    or has a recognisable credential format, and is written rather than referenced.
    """
    count = 0
    visited = 0
    stack: list[tuple[str, Any, bool]] = [("", data, False)]
    while stack and visited < MAX_WALK_NODES:
        key, node, inherited = stack.pop()
        visited += 1
        credential = inherited or _credential_name(key)
        if isinstance(node, dict):
            stack.extend((str(child_key), child, credential) for child_key, child in node.items())
        elif isinstance(node, list):
            stack.extend((key, child, credential) for child in node)
        elif (
            isinstance(node, str)
            and _written_in_file(node)
            and (credential or _recognise("", node)[0])
        ):
            count += 1
    return count
