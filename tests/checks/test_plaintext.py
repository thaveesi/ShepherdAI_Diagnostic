import json
from pathlib import Path

import pytest

from shepherd_scan._vendor.discovery.models import (
    ClientToInspect,
    CouldNotParseMCPConfig,
    RemoteServer,
    StdioServer,
)
from shepherd_scan.checks.plaintext import credential_settings, provider_keys
from tests.conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN

LITERAL = "f3c9a1e2-7b4d-4c8e-9a6f-2d1b5e8c7a90"  # made-up value in an API key's shape
SLACK_BOT = "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"  # made-up value


def _client(mcp_configs) -> ClientToInspect:
    return ClientToInspect(name="cursor", client_path="/x", mcp_configs=mcp_configs, skills_dirs={})


def _settings(server):
    return credential_settings([_client({"/home/u/.cursor/mcp.json": [("srv", server)]})])


def _stdio(**fields) -> StdioServer:
    return StdioServer(command=fields.pop("command", "npx"), **fields)


def _summary(found) -> list[tuple[str, bool, str | None, bool]]:
    return [(item.setting, item.written, item.kind, item.shared) for item in found]


def test_literal_key_in_environment_is_written_in_plain_text():
    found = _settings(_stdio(env={"EXA_API_KEY": LITERAL, "DEBUG": "1"}))
    assert _summary(found) == [("EXA_API_KEY", True, None, False)]


def test_recognised_formats_are_named():
    found = _settings(_stdio(env={"GITHUB_TOKEN": FAKE_GITHUB_TOKEN, "AWS_KEY": FAKE_AWS_KEY}))
    assert _summary(found) == [
        ("GITHUB_TOKEN", True, "GitHub personal access token", False),
        ("AWS_KEY", True, "AWS Access Key", False),
    ]


@pytest.mark.parametrize(
    "value",
    [
        "${EXA_API_KEY}",
        "$EXA_API_KEY",
        "${env:EXA_API_KEY}",
        "{env:EXA_API_KEY}",
        "${input:exa-key}",
        "op://vault/exa/credential",
        "EXA_API_KEY",
        "%EXA_API_KEY%",
        "",
        "   ",
        "your-api-key-here",
        "<your key>",
        "changeme",
        "xxxxxxxxxxxx",
        "short",
        "1234567890123",
        "/Users/someone/.secrets/exa",
        "https://example.invalid/key",
        "two words here",
    ],
)
def test_references_placeholders_and_non_keys_are_not_reported(value):
    assert _settings(_stdio(env={"EXA_API_KEY": value})) == []


@pytest.mark.parametrize(
    "name", ["GOOGLE_CLIENT_ID", "TOKEN_URL", "MAX_TOKENS", "AUTH_TYPE", "API_KEY_HEADER"]
)
def test_settings_that_hold_no_secret_are_ignored(name):
    assert _settings(_stdio(env={name: "some-long-value-1234"})) == []


def test_headers_with_literal_and_referenced_tokens():
    server = RemoteServer(
        url="https://mcp.example.invalid/mcp",
        headers={"Authorization": f"Bearer {LITERAL}", "X-Api-Key": "Bearer ${TOKEN}"},
    )
    assert _summary(_settings(server)) == [("header Authorization", True, None, False)]


def test_keys_in_web_address_parameters_and_passwords():
    url = f"https://user:{LITERAL}@mcp.example.invalid/mcp?api_key={LITERAL}&x=1"
    server = RemoteServer(url=url)
    assert _summary(_settings(server)) == [
        ("address parameter api_key", True, None, False),
        ("address password", True, None, False),
    ]


def test_keys_in_command_arguments():
    args = [
        "-y",
        "some-server",
        f"--api-key={LITERAL}",
        "--token",
        LITERAL,
        "--header",
        f"Authorization: Bearer {LITERAL}",
        "-e",
        f"GITHUB_TOKEN={FAKE_GITHUB_TOKEN}",
        FAKE_GITHUB_TOKEN,
        f"https://mcp.example.invalid/sse?key={LITERAL}",
        "--port",
        "8080",
    ]
    assert [item.setting for item in _settings(_stdio(args=args))] == [
        "argument --api-key",
        "argument --token",
        "argument 7 (header Authorization)",
        "argument 9 (GITHUB_TOKEN)",
        "argument 10",
        "argument 11 parameter key",
    ]


def test_flag_value_is_not_read_twice():
    found = _settings(_stdio(args=["--token", FAKE_GITHUB_TOKEN]))
    assert [item.setting for item in found] == ["argument --token"]


def test_shared_accounts_are_recognised_by_format_and_by_name():
    found = _settings(
        _stdio(
            env={
                "SLACK_TOKEN": SLACK_BOT,
                "DISCORD_BOT_TOKEN": "${DISCORD_BOT_TOKEN}",
                "GOOGLE_APPLICATION_CREDENTIALS": "/Users/u/keys/service.json",
                "SUPABASE_SERVICE_ROLE_KEY": LITERAL,
            }
        )
    )
    assert _summary(found) == [
        ("SLACK_TOKEN", True, "Slack bot token", True),
        ("DISCORD_BOT_TOKEN", False, "bot token", True),
        ("GOOGLE_APPLICATION_CREDENTIALS", False, "Google service account key", True),
        ("SUPABASE_SERVICE_ROLE_KEY", True, "service-role key", True),
    ]


def test_values_are_never_kept():
    server = _stdio(env={"EXA_API_KEY": LITERAL}, args=[f"--api-key={FAKE_GITHUB_TOKEN}"])
    text = repr(_settings(server))
    assert LITERAL not in text
    assert FAKE_GITHUB_TOKEN not in text


def test_unreadable_server_files_are_skipped():
    broken = CouldNotParseMCPConfig(message="could not parse", is_failure=True)
    assert credential_settings([_client({"/x/mcp.json": broken})]) == []


def _write(home: Path, raw: str, text: str) -> None:
    path = home / raw.removeprefix("~/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_provider_keys_in_app_settings(tmp_path: Path):
    _write(
        tmp_path,
        "~/.config/raycast/ai/providers.yaml",
        f"providers:\n  - id: one\n    api_keys:\n      openai: {LITERAL}\n      groq: ${{GROQ}}\n",
    )
    _write(
        tmp_path,
        "~/.continue/config.yaml",
        f"models:\n  - name: a\n    apiKey: {LITERAL}\n  - name: b\n    apiKey: ${{KEY}}\n"
        f"mcpServers:\n  - name: s\n    env:\n      TOKEN: {LITERAL}\n",
    )
    _write(tmp_path, "~/.junie/config.json", json.dumps({"byok": {"openai": {"apiKey": LITERAL}}}))
    found = provider_keys(tmp_path)
    assert [(item.client, item.setting, item.written) for item in found] == [
        ("raycast", "1 API key for AI providers", True),
        ("continue", "models: 1 API key for AI providers", True),
        ("junie", "byok: 1 API key for AI providers", True),
    ]
    assert LITERAL not in repr(found)


def test_provider_files_without_keys_or_unreadable_are_skipped(tmp_path: Path):
    _write(tmp_path, "~/.continue/config.yaml", "models:\n  - name: a\n    model: gpt-5\n")
    _write(tmp_path, "~/.junie/config.json", "{ not json")
    assert provider_keys(tmp_path) == []
