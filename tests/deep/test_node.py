import hashlib
from pathlib import Path

import httpx
import pytest

from shepherd_scan.deep import node
from shepherd_scan.deep.node import SetupError, download, node_bin


def serving(body: bytes) -> httpx.Client:
    return httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    )


def test_a_download_is_kept_only_when_it_matches_its_pinned_checksum(tmp_path: Path):
    target = tmp_path / "node.tar.gz"
    download("https://nodejs.example/node.tar.gz", target,
             hashlib.sha256(b"good").hexdigest(), serving(b"good"))  # fmt: skip
    assert target.read_bytes() == b"good"
    with pytest.raises(SetupError, match="did not match its pinned checksum"):
        download("https://nodejs.example/node.tar.gz", target,
                 hashlib.sha256(b"good").hexdigest(), serving(b"tampered"))  # fmt: skip
    assert not target.exists()


def test_a_failed_download_leaves_nothing_behind(tmp_path: Path):
    failing = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(404)))
    target = tmp_path / "node.tar.gz"
    with pytest.raises(SetupError, match="could not download"):
        download("https://nodejs.example/node.tar.gz", target, "0" * 64, failing)
    assert not target.exists()


def test_a_computer_without_a_pinned_node_build_is_told_so(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(node.platform, "system", lambda: "Plan9")
    with pytest.raises(SetupError, match="no pinned Node build"):
        node_bin(tmp_path)


def test_node_already_in_the_runtime_folder_is_not_downloaded_again(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(node.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(node.platform, "machine", lambda: "arm64")
    existing = tmp_path / f"node-v{node.NODE_VERSION}-darwin-arm64" / "bin"
    existing.mkdir(parents=True)
    (existing / "node").write_text("")
    refusing = httpx.Client(transport=httpx.MockTransport(lambda request: pytest.fail("fetched")))
    assert node_bin(tmp_path, refusing) == existing


def test_a_runtime_folder_that_cannot_be_written_is_a_setup_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(node.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(node.platform, "machine", lambda: "arm64")
    blocked = tmp_path / "a-file"
    blocked.write_text("")
    refusing = httpx.Client(transport=httpx.MockTransport(lambda request: pytest.fail("fetched")))
    with pytest.raises(SetupError, match="Node could not be set up"):
        node_bin(blocked / "runtime", refusing)
    with pytest.raises(SetupError, match="could not be installed"):
        node.meters_bin(blocked / "runtime", tmp_path)


def test_a_node_archive_that_cannot_be_unpacked_is_a_setup_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(node.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(node.platform, "machine", lambda: "arm64")
    body = b"not an archive"
    monkeypatch.setitem(
        node.NODE_BUILDS, ("Darwin", "arm64"), ("darwin-arm64", hashlib.sha256(body).hexdigest())
    )
    with pytest.raises(SetupError, match="Node could not be set up"):
        node_bin(tmp_path, serving(body))


@pytest.mark.parametrize(
    ("variable", "value"),
    [("ALL_PROXY", "socks4://127.0.0.1:1080"), ("ALL_PROXY", "socks5://127.0.0.1:7890"),
     ("NO_PROXY", "localhost,fd00::/8")],
)  # fmt: skip
def test_a_proxy_the_download_cannot_use_is_a_setup_error(
    tmp_path: Path, monkeypatch, variable: str, value: str
):
    monkeypatch.setenv(variable, value)
    with pytest.raises(SetupError, match="could not connect"):
        download("https://nodejs.example/node.tar.gz", tmp_path / "node.tar.gz", "0" * 64)


def test_a_runtime_folder_inside_a_folder_the_terminal_may_not_open_is_a_setup_error(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(node.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(node.platform, "machine", lambda: "arm64")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        with pytest.raises(SetupError, match="Node could not be set up"):
            node_bin(locked / "runtime", serving(b""))
        with pytest.raises(SetupError, match="could not be installed"):
            node.meters_bin(locked / "runtime", tmp_path)
    finally:
        locked.chmod(0o755)
