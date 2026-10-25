import pytest

from shepherd_scan._vendor.discovery.models import RemoteServer, StdioServer
from shepherd_scan.catalog import Catalog, CatalogError

CATALOG = {
    "version": 1,
    "labels_from": "test",
    "servers": [
        {
            "name": "GitHub",
            "match": {
                "urls": ["api.githubcopilot.com/mcp"],
                "packages": ["@modelcontextprotocol/server-github", "github-mcp-server"],
                "connector_names": ["GitHub"],
            },
            "tools": {
                "merge_pull_request": {"description": "Merge a pull request", "packs": ["CHANGE"]},
                "get_issue": {"description": "Read an issue", "packs": []},
            },
        },
        {"name": "Gmail", "match": {"connector_names": ["Gmail"]}, "tools": {}},
    ],
}


@pytest.fixture
def catalog() -> Catalog:
    return Catalog.from_json(CATALOG)


def test_shipped_catalog_loads():
    shipped = Catalog.load()
    assert isinstance(shipped.entries, list)


@pytest.mark.parametrize(
    "server",
    [
        StdioServer(command="npx", args=["-y", "@modelcontextprotocol/server-github"]),
        StdioServer(command="npx", args=["-y", "@modelcontextprotocol/server-github@2025.4.8"]),
        StdioServer(
            command="docker", args=["run", "-i", "ghcr.io/github/github-mcp-server:latest"]
        ),
        StdioServer(command="/usr/local/bin/github-mcp-server", args=["stdio"]),
        RemoteServer(url="https://api.githubcopilot.com/mcp/", type="http"),
    ],
)
def test_known_servers_match(catalog: Catalog, server):
    entry = catalog.match_server(server)
    assert entry is not None
    assert entry.name == "GitHub"


@pytest.mark.parametrize(
    "server",
    [
        StdioServer(command="npx", args=["-y", "@modelcontextprotocol/server-github-extra"]),
        StdioServer(command="uvx", args=["mcp-server-git"]),
        RemoteServer(url="https://example.invalid/mcp", type="http"),
    ],
)
def test_unknown_servers_do_not_match(catalog: Catalog, server):
    assert catalog.match_server(server) is None


def test_connector_matches_by_name_case_insensitively(catalog: Catalog):
    entry = catalog.match_connector("  gmail ")
    assert entry is not None
    assert entry.name == "Gmail"
    assert catalog.match_connector("Outlook") is None


def test_packs_for_known_and_unknown_tools(catalog: Catalog):
    assert catalog.packs_for("GitHub", "merge_pull_request") == ["CHANGE"]
    assert catalog.packs_for("GitHub", "get_issue") == []
    assert catalog.packs_for("GitHub", "not_a_tool") == []
    assert catalog.packs_for(None, "merge_pull_request") == []


def test_tool_records_have_running_server_shape(catalog: Catalog):
    records = catalog.entries[0].tool_records()
    assert {"name": "merge_pull_request", "description": "Merge a pull request"} in records


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "version 1"),
        ({"version": 2, "servers": []}, "version 1"),
        ({"version": 1, "servers": {}}, "must be a list"),
        ({"version": 1, "servers": [{"match": {}}]}, "needs a 'name'"),
        ({"version": 1, "servers": [{"name": "X", "match": []}]}, "'match' must be an object"),
        ({"version": 1, "servers": [{"name": "X", "tools": []}]}, "'tools' must be an object"),
        (
            {"version": 1, "servers": [{"name": "X", "tools": {"t": {"packs": ["MONEY"]}}}]},
            "unknown packs",
        ),
        ({"version": 1, "servers": [{"name": "X", "match": {"urls": "a"}}]}, "lists of strings"),
    ],
)
def test_malformed_catalog_fails_with_clear_message(data, message):
    with pytest.raises(CatalogError, match=message):
        Catalog.from_json(data)
