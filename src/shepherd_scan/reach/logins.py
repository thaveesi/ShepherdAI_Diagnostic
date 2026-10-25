"""Part 2 of the reach section: saved logins and keys that agents able to run commands could use.

Only whether each known file exists is checked; none of them is opened. SSH private keys are
counted by file name (``id_*`` without ``.pub``, or any file with a matching ``.pub`` next to it).
"""

import logging
from dataclasses import dataclass
from pathlib import Path

from shepherd_scan.apps.catalog import AppEntry
from shepherd_scan.settings_files import exists, home_path

logger = logging.getLogger(__name__)

# Well-known places where command-line tools save logins: (path, what is kept there).
LOGIN_FILES: tuple[tuple[str, str], ...] = (
    ("~/.aws/credentials", "AWS access keys"),
    ("~/.aws/sso/cache", "AWS sign-in sessions"),
    ("~/.config/gcloud/application_default_credentials.json", "Google Cloud sign-in"),
    ("~/.config/gcloud/credentials.db", "Google Cloud sign-in"),
    ("~/.azure/msal_token_cache.json", "Azure sign-in"),
    ("~/.azure/msal_token_cache.bin", "Azure sign-in"),
    ("~/.kube/config", "Kubernetes cluster access"),
    ("~/.docker/config.json", "Docker settings, where registry logins are saved"),
    ("~/.npmrc", "npm settings, where registry tokens are saved"),
    ("~/.pypirc", "PyPI upload settings, where upload tokens are saved"),
    ("~/.git-credentials", "Saved Git passwords and tokens"),
    ("~/.config/gh/hosts.yml", "GitHub CLI sign-in"),
    ("~/.config/glab-cli/config.yml", "GitLab CLI sign-in"),
    ("~/.netrc", "Saved logins for websites and servers"),
    ("~/.terraform.d/credentials.tfrc.json", "Terraform Cloud token"),
    ("~/.vault-token", "Vault token"),
    ("~/.cargo/credentials.toml", "crates.io token"),
    ("~/.gem/credentials", "RubyGems token"),
    ("~/.config/stripe/config.toml", "Stripe CLI sign-in"),
)
NOT_KEYS = frozenset({"config", "known_hosts", "known_hosts.old", "authorized_keys"})


@dataclass(frozen=True)
class LoginFile:
    """A saved login or key found on this computer. Only its place is known."""

    what: str
    where: str
    app: str | None = None


def find_login_files(home: Path, apps: tuple[AppEntry, ...]) -> list[LoginFile]:
    """Saved logins and keys present in the home folder, in a fixed order.

    Args:
        home: The home folder being scanned.
        apps: The app list, for each app's own sign-in files.

    Returns:
        SSH keys first, then command-line tool logins, then AI apps' own sign-in files.
    """
    found = _ssh_keys(home)
    found.extend(LoginFile(what, raw) for raw, what in LOGIN_FILES if exists(home_path(home, raw)))
    for entry in apps:
        for raw, holds in entry.credential_files:
            if exists(home_path(home, raw)):
                found.append(LoginFile(f"{entry.name}: {holds}", raw, app=entry.name))
    return found


def _ssh_keys(home: Path) -> list[LoginFile]:
    folder = home_path(home, "~/.ssh")
    try:
        names = (
            {child.name for child in folder.iterdir() if child.is_file()}
            if exists(folder)
            else set()
        )
    except OSError:
        logger.warning("Could not list %s", folder.as_posix())
        return []
    keys = sorted(
        name
        for name in names - NOT_KEYS
        if not name.endswith(".pub") and (name.startswith("id_") or f"{name}.pub" in names)
    )
    if not keys:
        return []
    noun = "SSH private key" if len(keys) == 1 else "SSH private keys"
    return [LoginFile(f"{len(keys)} {noun} ({', '.join(keys)})", "~/.ssh")]
