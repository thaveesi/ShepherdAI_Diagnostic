from pathlib import Path

from shepherd_scan.apps.catalog import load_apps
from shepherd_scan.reach.logins import find_login_files


def _touch(home: Path, raw: str) -> Path:
    path = home / raw.removeprefix("~/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not read", encoding="utf-8")
    return path


def test_ssh_keys_counted_by_name(tmp_path: Path):
    for name in ("id_ed25519", "id_ed25519.pub", "deploy", "deploy.pub", "config", "known_hosts"):
        _touch(tmp_path, f"~/.ssh/{name}")
    (tmp_path / ".ssh" / "authorized_keys").write_text("x", encoding="utf-8")
    [ssh] = find_login_files(tmp_path, ())
    assert (ssh.what, ssh.where) == ("2 SSH private keys (deploy, id_ed25519)", "~/.ssh")


def test_login_files_and_app_sign_ins_are_found_by_existence_only(tmp_path: Path):
    _touch(tmp_path, "~/.docker/config.json").chmod(0)
    _touch(tmp_path, "~/.aws/credentials")
    _touch(tmp_path, "~/.codex/auth.json").chmod(0)
    (tmp_path / ".aws" / "sso" / "cache").mkdir(parents=True)
    try:
        found = find_login_files(tmp_path, load_apps())
    finally:
        (tmp_path / ".docker" / "config.json").chmod(0o600)
        (tmp_path / ".codex" / "auth.json").chmod(0o600)
    assert [(item.what, item.where, item.app) for item in found] == [
        ("AWS access keys", "~/.aws/credentials", None),
        ("AWS sign-in sessions", "~/.aws/sso/cache", None),
        ("Docker settings, where registry logins are saved", "~/.docker/config.json", None),
        ("Codex: ChatGPT or OpenAI sign-in", "~/.codex/auth.json", "Codex"),
    ]


def test_nothing_saved_means_nothing_reported(tmp_path: Path):
    (tmp_path / ".ssh").mkdir()
    assert find_login_files(tmp_path, load_apps()) == []
