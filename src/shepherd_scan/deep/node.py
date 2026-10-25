"""The pinned Node runtime and usage meters, fetched into the scanner's own folder on request.

Only used for the deep check, after the person agrees. Node comes from nodejs.org and must
match the checksum pinned here. The two usage meters are installed by npm from the lockfile
shipped with the scanner, so every package is checked against its pinned hash, and no install
scripts run. Everything lands in the runtime folder; nothing is installed system-wide.
"""

import hashlib
import os
import platform
import shutil
import subprocess
import tarfile
from pathlib import Path

import httpx

NODE_VERSION = "22.23.3"
NODE_BUILDS = {
    ("Darwin", "arm64"): ("darwin-arm64",
                          "23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53"),
    ("Darwin", "x86_64"): ("darwin-x64",
                           "8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8"),
    ("Linux", "aarch64"): ("linux-arm64",
                           "5ced2d48d1d7198739b7f86804de0171aefb6823b684b12341d3321afc3cb0b2"),
    ("Linux", "x86_64"): ("linux-x64",
                          "1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af"),
}  # fmt: skip
NODE_DIST = "https://nodejs.org/dist"
METERS = Path(__file__).parent / "meters"
METER_COMMANDS = ("ccusage", "codeburn")


class SetupError(Exception):
    """Node or the usage meters could not be set up."""


def node_bin(runtime: Path, client: httpx.Client | None = None) -> Path:
    """Node's bin folder in the runtime folder, downloaded and checked first when missing.

    Raises:
        SetupError: If this computer has no pinned Node build, the download fails or does not
            match its checksum, or the runtime folder cannot be written.
    """
    build = NODE_BUILDS.get((platform.system(), platform.machine()))
    if build is None:
        raise SetupError(f"no pinned Node build for {platform.system()} {platform.machine()}")
    name = f"node-v{NODE_VERSION}-{build[0]}"
    folder = runtime / name
    archive = runtime / f"{name}.tar.gz"
    try:
        if (folder / "bin" / "node").is_file():
            return folder / "bin"
        runtime.mkdir(parents=True, exist_ok=True)
        download(f"{NODE_DIST}/v{NODE_VERSION}/{name}.tar.gz", archive, build[1], client)
        with tarfile.open(archive) as tar:
            tar.extractall(runtime, filter="data")
        archive.unlink()
    except (OSError, tarfile.TarError) as error:
        raise SetupError(f"Node could not be set up ({type(error).__name__})") from error
    return folder / "bin"


def meters_bin(runtime: Path, node: Path) -> Path:
    """The usage meters' commands, installed from the shipped lockfile when missing.

    Raises:
        SetupError: If their folder cannot be written or npm cannot install them.
    """
    target = runtime / "meters"
    commands = target / "node_modules" / ".bin"
    env = dict(os.environ)
    env["PATH"] = f"{node}{os.pathsep}{env.get('PATH', '')}"
    env["npm_config_cache"] = str(runtime / "npm-cache")
    command = [str(node / "npm"), "ci", "--ignore-scripts", "--no-audit", "--no-fund",
               "--loglevel=error"]  # fmt: skip
    try:
        if all((commands / name).exists() for name in METER_COMMANDS):
            return commands
        target.mkdir(parents=True, exist_ok=True)
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(METERS / name, target / name)
        subprocess.run(  # noqa: S603 - the npm shipped with the pinned Node, no shell
            command, cwd=target, env=env, check=True, capture_output=True, timeout=600
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SetupError(f"the usage meters could not be installed ({type(error).__name__})") from (
            error
        )
    return commands


def download(url: str, target: Path, sha256: str, client: httpx.Client | None = None) -> None:
    """Fetch one file and keep it only if it matches the pinned checksum.

    Raises:
        SetupError: If the download fails or does not match.
    """
    digest = hashlib.sha256()
    try:
        http = client or httpx.Client(follow_redirects=True, timeout=120)
    except (ImportError, ValueError, OSError, httpx.InvalidURL) as error:
        raise SetupError(f"could not connect to download {url} ({type(error).__name__})") from (
            error
        )
    try:
        with http.stream("GET", url) as response, target.open("wb") as out:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                digest.update(chunk)
                out.write(chunk)
    except httpx.HTTPError as error:
        target.unlink(missing_ok=True)
        raise SetupError(f"could not download {url} ({type(error).__name__})") from error
    finally:
        if client is None:
            http.close()
    if digest.hexdigest() != sha256:
        target.unlink()
        raise SetupError(f"{url} did not match its pinned checksum, so it was not used")
