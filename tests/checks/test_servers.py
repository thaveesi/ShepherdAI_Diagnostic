import pytest
from mcp.types import Implementation, InitializeResult, Tool

from shepherd_scan._vendor.discovery.models import (
    InspectedServer,
    RemoteServer,
    ScanError,
    ServerSignature,
    StdioServer,
)
from shepherd_scan.catalog import Catalog
from shepherd_scan.checks.servers import (
    connector_result,
    credential_settings,
    describe_launch,
    server_result,
)

CATALOG = Catalog.from_json(
    {
        "version": 1,
        "servers": [
            {
                "name": "Files",
                "match": {"packages": ["mcp-server-files"], "connector_names": ["Drive"]},
                "tools": {"delete_file": {"description": "Delete a file", "packs": ["CHANGE"]}},
            }
        ],
    }
)


@pytest.mark.parametrize(
    ("name", "is_credential"),
    [
        ("GITHUB_PERSONAL_ACCESS_TOKEN", True),
        ("SLACK_BOT_TOKEN", True),
        ("OPENAI_API_KEY", True),
        ("OPENAI_KEY", True),
        ("DB_PASSWORD", True),
        ("GITLAB_PAT", True),
        ("Authorization", True),
        ("X-API-Key", True),
        ("Cookie", True),
        ("GIT_AUTHOR_NAME", False),
        ("DEBUG", False),
        ("LOG_LEVEL", False),
        ("KEYBOARD_LAYOUT", False),
    ],
)
def test_credential_setting_names(name: str, is_credential: bool):
    server = StdioServer(command="x", env={name: "**REDACTED**"})
    assert (credential_settings(server) == [name]) is is_credential


def test_remote_headers_are_checked_for_credentials():
    server = RemoteServer(url="https://e.invalid", headers={"Authorization": "x", "Accept": "y"})
    assert credential_settings(server) == ["Authorization"]


def test_launch_is_truncated():
    server = StdioServer(command="tool", args=["x" * 300])
    text = describe_launch(server)
    assert len(text) == 160
    assert text.endswith("…")


def test_remote_server_is_listed_without_tools():
    inspected = InspectedServer(name="crm", server=RemoteServer(url="https://crm.invalid/mcp"))
    result = server_result(inspected, "Claude Code", CATALOG)
    assert result.kind == "remote"
    assert result.tools == []
    assert result.tools_source == "none"


def test_started_server_lists_its_own_tools():
    signature = ServerSignature(
        metadata=InitializeResult(
            protocolVersion="2024-11-05",
            capabilities={},
            serverInfo=Implementation(name="files", version="1"),
        ),
        tools=[Tool(name="delete_file", description="Delete a file\nmore", inputSchema={})],
    )
    inspected = InspectedServer(
        name="files",
        server=StdioServer(command="uvx", args=["mcp-server-files"]),
        signature=signature,
    )
    result = server_result(inspected, "Cursor", CATALOG)
    assert result.tools_source == "started"
    assert result.catalog_name == "Files"
    assert [(t.name, t.description, t.packs) for t in result.tools] == [
        ("delete_file", "Delete a file", ["CHANGE"])
    ]


def test_known_server_not_started_uses_catalog_tools():
    inspected = InspectedServer(
        name="files", server=StdioServer(command="uvx", args=["mcp-server-files"])
    )
    result = server_result(inspected, "Cursor", CATALOG)
    assert result.tools_source == "catalog"
    assert [tool.name for tool in result.tools] == ["delete_file"]


def test_declined_server_error_is_not_shown():
    inspected = InspectedServer(
        name="x",
        server=StdioServer(command="x"),
        error=ScanError(message="Skipped", category="user_declined"),
    )
    assert server_result(inspected, "Cursor", CATALOG).error is None


def test_connector_result_with_recorded_tools():
    tools = [{"name": "upload", "description": "Upload a file"}, {"description": "no name"}]
    result = connector_result("Drive", "Claude Desktop", tools, CATALOG)
    assert result.kind == "account connector"
    assert result.catalog_name == "Files"
    assert [tool.name for tool in result.tools] == ["upload"]
    assert result.tools_source == "session record"


def test_launch_shows_blanked_values_plainly():
    remote = RemoteServer(url="https://crm.invalid/mcp?api_key=%2A%2AREDACTED%2A%2A")
    local = StdioServer(command="db", args=["--password", "**REDACTED_SECRET_KEYWORDDETECTOR**"])
    assert describe_launch(remote) == "https://crm.invalid/mcp?api_key=[hidden]"
    assert describe_launch(local) == "db --password [hidden]"
