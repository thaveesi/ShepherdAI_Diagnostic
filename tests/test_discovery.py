import logging
from pathlib import Path

import pytest

from shepherd_scan._vendor.discovery.agents import claude_desktop
from shepherd_scan.discovery import WARNING_LOGGER, discover


@pytest.fixture
def locked_skill(fake_home: Path, monkeypatch):
    monkeypatch.setattr(claude_desktop.sys, "platform", "darwin")
    locked = fake_home / ".claude" / "skills" / "locked"
    locked.mkdir()
    (locked / "SKILL.md").write_text("---\nname: locked\ndescription: x\n---\n")
    locked.chmod(0)
    yield locked
    locked.chmod(0o755)


@pytest.fixture
def quiet_logging(monkeypatch):
    """The command's normal logging: only critical messages reach the terminal."""
    root = logging.getLogger()
    monkeypatch.setattr(root, "level", logging.CRITICAL)


def test_warnings_are_collected_in_quiet_mode_without_printing(
    locked_skill, quiet_logging, no_network, capsys
):
    found = discover()
    assert any("locked" in warning for warning in found.warnings)
    captured = capsys.readouterr()
    assert "locked" not in captured.err + captured.out


def test_logger_settings_are_restored_after_discovery(locked_skill, quiet_logging, no_network):
    discovery_logger = logging.getLogger(WARNING_LOGGER)
    before = (discovery_logger.level, discovery_logger.propagate, list(discovery_logger.handlers))
    discover()
    after = (discovery_logger.level, discovery_logger.propagate, list(discovery_logger.handlers))
    assert before == after


def test_remote_servers_are_never_contacted(fake_home: Path, no_network):
    found = discover()
    assert no_network == []
    remote = [
        server
        for path in found.paths
        for server in path.servers
        if getattr(server.server, "url", None)
    ]
    assert remote
    assert all(server.signature is None and server.error is None for server in remote)
