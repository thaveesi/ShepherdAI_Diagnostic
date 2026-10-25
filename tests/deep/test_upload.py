import io
import json
import re
import tarfile
from pathlib import Path
from urllib.parse import unquote

import httpx
import pytest

from shepherd_scan.deep import upload
from shepherd_scan.deep.upload import REFERENCE, UploadError, new_reference, pack, send

TOKEN = "made-up-sign-in-token"  # noqa: S105 - a made-up value


def test_the_archive_holds_every_file_by_its_path_in_the_upload(tmp_path: Path):
    (tmp_path / "skills" / "skill-001").mkdir(parents=True)
    (tmp_path / "skills" / "skill-001" / "packet.json").write_text("{}")
    (tmp_path / "manifest.json").write_text('{"format": 1}')
    with tarfile.open(fileobj=io.BytesIO(pack(tmp_path)), mode="r:gz") as tar:
        assert tar.getnames() == ["manifest.json", "skills/skill-001/packet.json"]
        member = tar.extractfile("manifest.json")
        assert member is not None and member.read() == b'{"format": 1}'


def test_the_archive_does_not_name_the_mac_account(tmp_path: Path):
    (tmp_path / "manifest.json").write_text("{}")
    with tarfile.open(fileobj=io.BytesIO(pack(tmp_path)), mode="r:gz") as tar:
        assert [(member.uname, member.gname) for member in tar.getmembers()] == [("", "")]


def drop_box(*upload_statuses: int, seen: list[httpx.Request], sign_in: int = 200) -> httpx.Client:
    """Firebase as the scanner sees it: an anonymous sign-in, then the upload."""
    statuses = iter(upload_statuses)

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "identitytoolkit.googleapis.com":
            body = {"localId": "sender-1", "idToken": TOKEN} if sign_in == 200 else {}
            return httpx.Response(sign_in, json=body)
        return httpx.Response(next(statuses), json={"name": "uploads/sender-1/x.tar.gz"})

    return httpx.Client(transport=httpx.MockTransport(answer))


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upload.time, "sleep", lambda seconds: None)


def test_the_scanner_signs_in_anonymously_and_adds_its_package(no_network):
    seen: list[httpx.Request] = []
    reference = "20261018-0123456789ab"
    assert (
        send(b"archive", "key-1", "box.firebasestorage.app", reference, drop_box(200, seen=seen))
        == reference
    )
    sign_in, sent = seen
    assert str(sign_in.url) == "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=key-1"
    assert json.loads(sign_in.content) == {"returnSecureToken": True}
    assert sent.url.path == "/v0/b/box.firebasestorage.app/o"
    assert unquote(sent.url.params["name"]) == f"uploads/sender-1/{reference}.tar.gz"
    assert sent.url.params["uploadType"] == "media"
    assert "%2F" in str(sent.url)
    assert sent.headers["Authorization"] == f"Firebase {TOKEN}"
    assert sent.headers["Content-Type"] == "application/gzip"
    assert sent.content == b"archive"


def test_server_errors_are_retried_and_a_refusal_is_not(no_network):
    seen: list[httpx.Request] = []
    send(b"a", "key", "box", "20261018-0123456789ab", drop_box(503, 200, seen=seen))
    assert len(seen) == 3
    refused: list[httpx.Request] = []
    with pytest.raises(UploadError, match="refused the package \\(403\\)") as error:
        send(b"a", "key", "box", "20261018-0123456789ab", drop_box(403, seen=refused))
    assert len(refused) == 2
    assert TOKEN not in str(error.value)


def test_a_refused_sign_in_stops_before_anything_is_sent(no_network):
    seen: list[httpx.Request] = []
    with pytest.raises(UploadError, match="could not sign in \\(400\\)"):
        send(b"a", "bad-key", "box", "20261018-0123456789ab", drop_box(seen=seen, sign_in=400))
    assert len(seen) == 1


def test_an_unreachable_drop_box_is_reported_after_three_tries(no_network):
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    failing = httpx.Client(transport=httpx.MockTransport(unreachable))
    with pytest.raises(UploadError, match="could not reach Shepherd"):
        send(b"a", "key", "box", "20261018-0123456789ab", failing)


def test_a_package_over_the_limit_is_refused_before_any_request(monkeypatch, no_network):
    monkeypatch.setattr(upload, "MAX_BYTES", 10)
    seen: list[httpx.Request] = []
    with pytest.raises(UploadError, match="larger than"):
        send(b"x" * 11, "key", "box", "20261018-0123456789ab", drop_box(200, seen=seen))
    assert seen == []


def test_references_have_the_date_and_twelve_random_digits():
    first, second = new_reference(), new_reference()
    assert REFERENCE.match(first) and REFERENCE.match(second) and first != second
    assert re.fullmatch(r"\d{8}", first[:8])


def test_a_proxy_the_upload_cannot_use_is_an_upload_problem(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ALL_PROXY", "socks4://127.0.0.1:1080")
    with pytest.raises(UploadError, match="could not be set up"):
        send(b"x", "key", "bucket", "ref")


def test_a_missing_certificate_file_is_an_upload_problem(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "gone.pem"))
    with pytest.raises(UploadError, match="could not be set up"):
        send(b"x", "key", "bucket", "ref")


def test_a_socks_proxy_setting_gives_a_clear_upload_message(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:7890")
    with pytest.raises(UploadError) as raised:
        send(b"x", "key", "bucket", "ref")
    assert "run the scanner again in a terminal without that setting" in str(raised.value)
    assert "pip install" not in str(raised.value)


def test_a_sign_in_answer_that_is_not_an_object_is_an_upload_problem():
    listing = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[1, 2]))
    )
    with pytest.raises(UploadError, match="could not read the sign-in answer"):
        send(b"x", "key", "bucket", "ref", listing)


def test_an_answer_that_cannot_be_decoded_is_tried_again_then_reported(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(upload.time, "sleep", lambda seconds: None)

    def garbled(request: httpx.Request) -> httpx.Response:
        raise httpx.DecodingError("bad gzip", request=request)

    with pytest.raises(UploadError, match="could not reach Shepherd"):
        send(b"x", "key", "bucket", "ref", httpx.Client(transport=httpx.MockTransport(garbled)))


def test_a_no_proxy_list_with_ipv6_ranges_gives_a_clear_upload_message(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("NO_PROXY", "localhost,fd00::/8")
    with pytest.raises(UploadError, match="could not be set up"):
        send(b"x", "key", "bucket", "ref")
