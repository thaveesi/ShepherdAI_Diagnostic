import json
import shutil
from pathlib import Path

import pytest
from rich.console import Console

from shepherd_scan import cli
from shepherd_scan.deep import destination
from shepherd_scan.deep import run as deep_check
from shepherd_scan.deep.run import configured
from shepherd_scan.deep.upload import UploadError
from shepherd_scan.discovery import discover


@pytest.fixture
def not_set_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """A copy of the scanner whose drop box values are still empty."""
    monkeypatch.setattr(destination, "API_KEY", "")
    monkeypatch.setattr(destination, "BUCKET", "")


@pytest.mark.usefixtures("not_set_up")
def test_the_deep_check_is_offered_only_once_the_drop_box_is_set_up(monkeypatch):
    assert configured({}) is None
    monkeypatch.setattr(destination, "API_KEY", "example-key")
    assert configured({}) is None
    monkeypatch.setattr(destination, "BUCKET", "example.firebasestorage.app")
    check = configured({"SHEPHERD_RUNTIME": "/rt"})
    assert check is not None
    assert (check.api_key, check.bucket) == ("example-key", "example.firebasestorage.app")
    assert check.runtime == Path("/rt")


@pytest.fixture
def recorded_runs(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    runs: list[Path] = []
    monkeypatch.setattr(
        deep_check, "run", lambda console, preparation, check, folder: runs.append(folder)
    )
    return runs


@pytest.fixture
def set_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """A copy of the scanner with the deep check set up."""
    monkeypatch.setattr(destination, "API_KEY", "example-key")
    monkeypatch.setattr(destination, "BUCKET", "example.firebasestorage.app")


@pytest.fixture
def preparations(monkeypatch: pytest.MonkeyPatch) -> list[deep_check.Preparation]:
    """Every package preparation started, still real."""
    started: list[deep_check.Preparation] = []
    real = deep_check.prepare

    def recording(discovery, keys=()):
        started.append(real(discovery, keys))
        return started[-1]

    monkeypatch.setattr(deep_check, "prepare", recording)
    return started


def set_up_drop_box(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(destination, "API_KEY", "example-key")
    monkeypatch.setattr(destination, "BUCKET", "example.firebasestorage.app")


def interactive(monkeypatch: pytest.MonkeyPatch, answer: str) -> None:
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_args: answer)


def scan(tmp_path: Path, *flags: str) -> int:
    return cli.main(["--no-open", "--output", str(tmp_path / "report.html"), *flags])


def test_with_deep_the_check_runs_after_the_report(fake_home, recorded_runs, monkeypatch, tmp_path):
    set_up_drop_box(monkeypatch)
    assert scan(tmp_path, "--deep") == cli.EXIT_OK
    assert (tmp_path / "report.html").is_file()
    assert recorded_runs == [tmp_path / "report-deep-check"]


def test_without_an_answer_nothing_is_sent(fake_home, recorded_runs, monkeypatch, tmp_path):
    set_up_drop_box(monkeypatch)
    assert scan(tmp_path) == cli.EXIT_OK
    assert scan(tmp_path, "--deep", "--no-deep") == cli.EXIT_OK
    assert recorded_runs == []


@pytest.mark.parametrize("stop", [EOFError, KeyboardInterrupt])
def test_closing_the_question_means_no(stop, monkeypatch):
    def closed(*_args):
        raise stop

    monkeypatch.setattr("builtins.input", closed)
    console = Console(force_terminal=False, width=200)
    assert not deep_check.wanted(console, interactive=True, assume_yes=False)


@pytest.mark.usefixtures("not_set_up")
def test_asking_for_the_deep_check_when_it_is_not_set_up_is_an_error(fake_home, tmp_path, capsys):
    assert scan(tmp_path, "--deep") == cli.EXIT_ERROR
    assert "not set up" in capsys.readouterr().out


def test_the_question_shows_its_answers(capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_args: "n")
    console = Console(force_terminal=False, width=200)
    assert not deep_check.wanted(console, interactive=True, assume_yes=False)
    assert "[y/N]" in capsys.readouterr().out


@pytest.mark.parametrize(
    "case",
    [
        ((), False, False),
        (("--deep",), False, True),
        ((), True, True),
        (("--no-deep",), True, False),
    ],
    ids=["no terminal", "--deep", "terminal", "--no-deep"],
)
@pytest.mark.usefixtures("fake_home", "set_up", "recorded_runs")
def test_the_package_is_prepared_only_when_the_question_will_be_asked(
    preparations, monkeypatch, tmp_path, case
):
    flags, terminal, prepared = case
    if terminal:
        interactive(monkeypatch, "n")
    scan(tmp_path, *flags)
    assert bool(preparations) is prepared
    assert all(not p.folder.parent.exists() for p in preparations)


@pytest.mark.usefixtures("fake_home", "set_up")
def test_saying_no_deletes_the_prepared_package(preparations, monkeypatch, tmp_path):
    interactive(monkeypatch, "n")
    assert scan(tmp_path) == cli.EXIT_OK
    [preparation] = preparations
    assert not preparation.folder.parent.exists()
    assert not (tmp_path / "report-deep-check").exists()


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Archives handed to the upload, which answers with a fixed reference."""
    archives: list[bytes] = []
    monkeypatch.setattr(
        deep_check, "send", lambda archive, *_args: archives.append(archive) or "r-1"
    )
    usage = {"ok": True, "note": "measured", "data": {}}
    monkeypatch.setattr(deep_check, "_measure_usage", lambda console, runtime: usage)
    return archives


@pytest.mark.usefixtures("fake_home", "set_up")
def test_yes_adds_usage_keeps_a_copy_beside_the_report_and_sends_once(
    preparations, sent, tmp_path, capsys
):
    assert scan(tmp_path, "--deep") == cli.EXIT_OK
    copy = tmp_path / "report-deep-check"
    manifest = json.loads((copy / "manifest.json").read_text())
    assert manifest["engines"] == {"ccusage + CodeBurn": "measured"}
    assert (copy / "engines" / "ccusage-codeburn.json").is_file()
    assert len(sent) == 1
    assert not preparations[0].folder.parent.exists()
    out = capsys.readouterr().out
    assert "Sent. Your reference is" in out and "r-1" in out


@pytest.mark.usefixtures("fake_home", "set_up")
def test_a_copy_that_cannot_be_kept_beside_the_report_is_sent_all_the_same(
    sent, monkeypatch, tmp_path, capsys
):
    def refuse(source: Path, destination: Path) -> None:
        Path(destination).mkdir()
        raise shutil.Error("copystat: Operation not permitted")

    monkeypatch.setattr(deep_check.shutil, "move", refuse)
    assert scan(tmp_path, "--deep") == cli.EXIT_OK
    assert len(sent) == 1 and "could not be kept" in capsys.readouterr().out
    assert not (tmp_path / "report-deep-check").exists()


@pytest.mark.usefixtures("fake_home", "set_up")
def test_a_failed_background_collection_is_collected_again(sent, monkeypatch, tmp_path):
    real = deep_check.collect_bundle
    calls: list[int] = []

    def first_fails(*args):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("disk busy")
        return real(*args)

    monkeypatch.setattr(deep_check, "collect_bundle", first_fails)
    assert scan(tmp_path, "--deep") == cli.EXIT_OK
    assert len(calls) == 2 and len(sent) == 1


@pytest.mark.usefixtures("fake_home", "set_up")
def test_a_collection_that_fails_twice_still_sends_what_the_scan_found(
    sent, monkeypatch, tmp_path, capsys
):
    def always_fails(*_args):
        raise OSError("disk full")

    monkeypatch.setattr(deep_check, "collect_bundle", always_fails)
    assert scan(tmp_path, "--deep") == cli.EXIT_OK
    assert len(sent) == 1 and "Traceback" not in capsys.readouterr().out
    copy = tmp_path / "report-deep-check"
    manifest = json.loads((copy / "manifest.json").read_text())
    assert manifest["not_collected"] == [{"part": "the full package", "reason": "OSError"}]
    for name in ("inventory.json", "acts.json", "keys.json"):
        assert (copy / name).is_file()


@pytest.mark.usefixtures("fake_home")
def test_the_background_collection_prints_nothing(capsys):
    preparation = deep_check.prepare(discover())
    preparation.wait()
    preparation.discard()
    assert capsys.readouterr().out == ""
    assert not preparation.folder.parent.exists()


def test_before_asking_it_says_the_scan_sent_nothing_and_what_the_deep_check_sends(
    capsys, monkeypatch
):
    monkeypatch.setattr("builtins.input", lambda *_args: "n")
    console = Console(force_terminal=False, width=200)
    deep_check.wanted(console, interactive=True, assume_yes=False)
    shown = " ".join(capsys.readouterr().out.split())  # bullets wrap within their column
    for fact in ("stayed on this computer and sent nothing", "Conversations are excluded",
                 "Detected passwords and API keys are redacted",
                 "Credential findings include only type and location",
                 "Access is limited to us.",
                 "We delete our copies of submitted information"):  # fmt: skip
        assert fact in shown
    assert shown.index("sent nothing") < shown.index("[y/N]")


@pytest.mark.usefixtures("fake_home", "set_up")
def test_a_failed_send_names_the_kept_copy_only_when_there_is_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    def refused(*_args: object) -> str:
        raise UploadError("Shepherd refused the package (403)")

    usage = {"ok": True, "note": "measured", "data": {}}
    monkeypatch.setattr(deep_check, "send", refused)
    monkeypatch.setattr(deep_check, "_measure_usage", lambda console, runtime: usage)
    monkeypatch.setenv("COLUMNS", "1000")
    assert scan(tmp_path, "--deep") == cli.EXIT_ERROR
    kept = tmp_path / "report-deep-check"
    assert f"What would have been sent is in {kept}." in capsys.readouterr().out

    def refuse(source: Path, destination: Path) -> None:
        raise shutil.Error("copystat: Operation not permitted")

    monkeypatch.setattr(deep_check.shutil, "move", refuse)
    assert scan(tmp_path, "--deep") == cli.EXIT_ERROR
    assert "What would have been sent" not in capsys.readouterr().out


@pytest.mark.usefixtures("fake_home", "set_up")
def test_no_room_for_the_package_means_the_deep_check_is_not_offered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    def no_room(*_args: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(deep_check, "prepare", no_room)
    assert scan(tmp_path, "--deep") == cli.EXIT_OK
    assert "cannot be offered" in capsys.readouterr().out


@pytest.mark.usefixtures("fake_home", "set_up")
def test_a_report_folder_named_like_terminal_markup_is_named_as_written_after_sending(
    sent, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setenv("COLUMNS", "1000")
    folder = tmp_path / "a[" / "b]"
    folder.mkdir(parents=True)
    assert scan(folder, "--deep") == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "A copy of what is sent is in" in out
    assert f"{folder / 'report-deep-check'}." in out
