import json
from pathlib import Path

import pytest

from shepherd_scan._vendor.discovery.models.mcp import StdioServer
from shepherd_scan.deep.collect import _cached_versions
from shepherd_scan.deep.inventory import LocalServer, _local_server, package_spec

COMMIT = "0123456789abcdef0123456789abcdef01234567"


@pytest.mark.parametrize(
    ("launcher", "args", "expected"),
    [
        ("npx", ["-y", "@upstash/context7-mcp"], ("@upstash/context7-mcp", "")),
        ("npx", ["-y", "@briefhq/mcp-server@latest", "serve"], ("@briefhq/mcp-server", "latest")),
        ("npx", ["-y", "exa-mcp-server@3.1.9"], ("exa-mcp-server", "3.1.9")),
        ("npx", ["--registry", "https://registry.example", "-y", "pkg@1.0.0"], ("pkg", "1.0.0")),
        ("npx", ["--registry=https://registry.example", "pkg"], ("pkg", "")),
        ("npx", ["-y", "--package", "@acme/tools@2.0.0", "acme-mcp"], ("@acme/tools", "2.0.0")),
        ("npx", ["-p", "@acme/tools@^2.0.0", "acme-mcp"], ("@acme/tools", "^2.0.0")),
        ("npx", ["-y", "--", "pkg@next"], ("pkg", "next")),
        ("npx", ["-y", "github:acme/mcp#v1.2.0"], ("github:acme/mcp", "v1.2.0")),
        ("npx", ["acme/mcp"], ("github:acme/mcp", "")),
        ("npx", ["./local-server"], ("./local-server", "")),
        ("npx", [], ("", "")),
        ("bunx", ["-p", "pkg@1.0.0", "cmd"], ("pkg", "1.0.0")),
        ("pnpx", ["--package", "pkg@1.0.0", "cmd"], ("pkg", "1.0.0")),
        ("uvx", ["--from", "fetch-mcp==0.6.2", "fetch-mcp"], ("fetch-mcp", "0.6.2")),
        ("uvx", ["--python", "3.12", "mcp-server-fetch"], ("mcp-server-fetch", "")),
        ("uvx", ["-p", "3.12", "mcp-server-fetch@0.6.2"], ("mcp-server-fetch", "0.6.2")),
        ("uvx", ["mcp-server-time@latest"], ("mcp-server-time", "latest")),
        ("uvx", ["--from", "mcp-proxy>=0.3", "mcp-proxy"], ("mcp-proxy", ">=0.3")),
        ("uvx", ["--from", "acme-mcp[cli]===1.0", "acme"], ("acme-mcp", "1.0")),
        ("uvx", ["--from", "git+https://github.com/acme/mcp@v1.0", "acme"],
         ("git+https://github.com/acme/mcp", "v1.0")),
        ("uvx", ["--from", "/Users/someone/dev/acme", "acme"], ("/Users/someone/dev/acme", "")),
        ("pipx", ["run", "acme-mcp"], ("acme-mcp", "")),
        ("pipx", ["run", "--spec", "acme-mcp==1.2", "acme"], ("acme-mcp", "1.2")),
        ("pipx", ["run", "--python", "3.12", "acme-mcp"], ("acme-mcp", "")),
    ],
)  # fmt: skip
def test_the_package_is_read_past_the_launchers_own_options(launcher, args, expected):
    assert package_spec(launcher, args) == expected


@pytest.mark.parametrize(
    "spec",
    [
        f"acme @ git+https://deploy:s3cret-value@github.com/acme/mcp@{COMMIT}",
        f"acme@git+https://deploy:s3cret-value@github.com/acme/mcp@{COMMIT}#egg=acme",
        f"git+https://deploy:s3cret-value@github.com/acme/mcp@{COMMIT}?token=s3cret-value",
    ],
)
def test_a_source_keeps_its_ref_but_never_a_login_or_query(spec):
    package, version = package_spec("uvx", ["--from", spec, "acme"])
    assert (package, version) == ("git+https://github.com/acme/mcp", COMMIT)


def server(launcher: str, package: str, version: str) -> LocalServer:
    return LocalServer("Cursor", "acme", launcher, package, version, "~/.cursor/mcp.json")


@pytest.mark.parametrize(
    ("launcher", "package", "version", "pinned"),
    [
        ("npx", "exa-mcp-server", "3.1.9", True),
        ("npx", "exa-mcp-server", "3.2.0-beta.1", True),
        ("npx", "exa-mcp-server", "latest", False),
        ("npx", "exa-mcp-server", "next", False),
        ("npx", "exa-mcp-server", "^1.2.0", False),
        ("npx", "exa-mcp-server", "~1.2.0", False),
        ("npx", "exa-mcp-server", "1.2", False),
        ("npx", "exa-mcp-server", "", False),
        ("uvx", "mcp-server-fetch", "0.6.2", True),
        ("uvx", "mcp-server-fetch", ">=0.6", False),
        ("uvx", "mcp-server-fetch", "1.*", False),
        ("uvx", "mcp-server-fetch", "latest", False),
        ("npx", "github:acme/mcp", "v1.2.0", False),
        ("npx", "github:acme/mcp", COMMIT, True),
        ("uvx", "git+https://github.com/acme/mcp", "main", False),
        ("uvx", "git+https://github.com/acme/mcp", COMMIT, True),
        ("path", "~/bin/server", "", False),
    ],
)  # fmt: skip
def test_only_an_exact_version_or_commit_counts_as_pinned(launcher, package, version, pinned):
    assert server(launcher, package, version).pinned is pinned


def test_a_launcher_pointed_at_a_folder_runs_code_from_that_folder(tmp_path: Path):
    folder = tmp_path / "acme"
    folder.mkdir()
    config = StdioServer(command="uvx", args=["--from", str(folder), "acme"])
    local = _local_server("Cursor", "acme", config, "~/.cursor/mcp.json")
    assert (local.launcher, local.present, local.pinned) == ("path", True, False)
    relative = StdioServer(command="npx", args=["file:../acme"])
    assert _local_server("Cursor", "acme", relative, "~").present is None


def test_the_package_cache_is_searched_only_for_registry_names(tmp_path: Path):
    outside = tmp_path / ".npm" / "_npx" / "outside"
    outside.mkdir(parents=True)
    (outside / "package.json").write_text(json.dumps({"version": "9.9.9"}))
    (tmp_path / ".npm" / "_npx" / "abc123" / "node_modules").mkdir(parents=True)
    assert _cached_versions("../../outside", tmp_path) == []
