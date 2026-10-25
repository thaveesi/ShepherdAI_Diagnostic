"""The deep check: after the scan, and only if the person agrees, send a blanked copy for review.

While the person reads the report, the package is collected in the background into a private
temporary folder, so saying yes only adds the usage totals and sends. Saying no deletes it: nothing
leaves the computer and nothing is kept.

The package goes to Shepherd's drop box (``destination.py``); until that is set up, the deep
check is not offered. A copy of everything sent is kept next to the report.
"""

import atexit
import logging
import shutil
import tempfile
import threading
from collections.abc import Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from shepherd_scan.carry_on import attempt
from shepherd_scan.deep import destination
from shepherd_scan.deep.collect import add_usage, collect_bundle, fallback_bundle
from shepherd_scan.deep.node import SetupError, meters_bin, node_bin
from shepherd_scan.deep.upload import UploadError, new_reference, pack, send
from shepherd_scan.deep.usage import measure
from shepherd_scan.discovery import Discovery
from shepherd_scan.report.model import SecretFinding
from shepherd_scan.report.terminal import PINK, say

logger = logging.getLogger(__name__)
# The whole collection normally takes under a minute; past this, what is ready is sent.
COLLECTION_SECONDS = 1800.0
DISCARD_SECONDS = 10.0

EXPLANATION = (
    "The scan you just ran stayed on this computer and sent nothing.",
    "The deep check is optional. If you say yes:",
    "We’ll receive a copy of your agent settings, add-on files, "  # noqa: RUF001 - owner's wording
    "connector tool lists, session settings, AI app list and usage totals for review. "
    "Conversations are excluded.",
    "Detected passwords and API keys are redacted, along with usernames in file paths and email "
    "addresses in settings. Credential findings include only type and location.",
    "Access is limited to us. We delete our copies of submitted information after your report "
    "and any requested corrections are complete.",
)
QUESTION = "Run the deep check? [y/N] "


@dataclass(frozen=True)
class DeepCheck:
    """Where the deep check sends to, and where it keeps its tools."""

    api_key: str
    bucket: str
    runtime: Path


def configured(environ: Mapping[str, str]) -> DeepCheck | None:
    """The drop box this copy of the scanner sends to, or None while none is set up."""
    if not destination.API_KEY or not destination.BUCKET:
        return None
    runtime = environ.get("SHEPHERD_RUNTIME") or str(Path.home() / ".cache" / "shepherd-scan")
    return DeepCheck(api_key=destination.API_KEY, bucket=destination.BUCKET, runtime=Path(runtime))


class PreparationError(Exception):
    """The package could not be collected."""


class Preparation:
    """The deep-check package, collected in a background thread into a private temporary folder.

    The thread writes nothing to the terminal; its error, if any, is raised by ``wait``.
    """

    def __init__(
        self, discovery: Discovery, home: Path, keys: Sequence[SecretFinding] = ()
    ) -> None:
        """Start collecting what ``discovery`` found under ``home``, and the keys it found."""
        self._parent = Path(tempfile.mkdtemp(prefix="shepherd-deep-"))
        self.folder = self._parent / "package"
        self._discovery = discovery
        self._home = home
        self._keys = tuple(keys)
        self._manifest: dict[str, Any] | None = None
        self._error: Exception | None = None
        self._thread = threading.Thread(target=self._collect, name="deep-check", daemon=True)
        atexit.register(self.discard)
        self._thread.start()

    @property
    def done(self) -> bool:
        """Whether the background collection has finished."""
        return not self._thread.is_alive()

    def wait(self) -> dict[str, Any]:
        """The package's manifest, collecting once more here if the background run failed.

        When the collection fails twice, or does not finish in time, a smaller package is
        made instead (what the scan found, and why the rest is missing), so something
        is always sent.

        Raises:
            PreparationError: If not even the smaller package can be written.
        """
        self._thread.join(COLLECTION_SECONDS)
        if self._thread.is_alive():
            return self._fallback(f"did not finish within {COLLECTION_SECONDS:.0f} seconds")
        if self._manifest is not None:
            return self._manifest
        logger.info("The background collection failed (%s); collecting again", self._error)
        shutil.rmtree(self.folder, ignore_errors=True)
        try:
            self._manifest = collect_bundle(self.folder, self._discovery, self._home, self._keys)
        except Exception as error:  # the smaller package is sent instead
            return self._fallback(type(error).__name__)
        return self._manifest

    def _fallback(self, reason: str) -> dict[str, Any]:
        logger.warning("Sending a smaller package: the collection %s", reason)
        self.folder = self._parent / "fallback"
        shutil.rmtree(self.folder, ignore_errors=True)
        try:
            self._manifest = fallback_bundle(
                self.folder, self._discovery, self._home, self._keys, reason
            )
        except Exception as error:
            raise PreparationError(f"{type(error).__name__}: {error}") from error
        return self._manifest

    def keep(self, destination: Path) -> bool:
        """Move the package to ``destination``, where the person can see what was sent.

        Returns:
            False if it could not be moved there, as on a disk that refuses some file names;
            the package is then only deleted.
        """
        existed = destination.exists()
        try:
            shutil.move(self.folder, destination)
        except OSError as error:
            logger.info("Could not keep a copy in %s: %s", destination, error)
            if not existed:
                shutil.rmtree(destination, ignore_errors=True)
            self.discard()
            return False
        self.discard()
        return True

    def discard(self) -> None:
        """Delete whatever is left of the temporary folder, without waiting on a stuck part."""
        self._thread.join(DISCARD_SECONDS)
        shutil.rmtree(self._parent, ignore_errors=True)
        atexit.unregister(self.discard)

    def _collect(self) -> None:
        try:
            self._manifest = collect_bundle(self.folder, self._discovery, self._home, self._keys)
        except Exception as error:
            self._error = error


def prepare(discovery: Discovery, keys: Sequence[SecretFinding] = ()) -> Preparation:
    """Start collecting the package for the deep check in the background.

    Args:
        discovery: What the scan found.
        keys: The exposed keys the report lists, by type and place; never their values.
    """
    return Preparation(discovery, Path.home(), keys)


def wanted(console: Console, *, interactive: bool, assume_yes: bool) -> bool:
    """Whether to run the deep check: always with --deep, otherwise only if the person says so."""
    if assume_yes:
        return True
    if not interactive:
        return False
    explain(console)
    try:
        answer = console.input(f"  [bold]{escape(QUESTION)}[/]")
    except (EOFError, KeyboardInterrupt):
        console.print()
        say(console, "No deep check: nothing was sent.")
        return False
    return answer.strip().lower() in {"y", "yes"}


def explain(console: Console) -> None:
    """What the scan did, and what the deep check would send, where, and who reviews it."""
    first, offer, *steps = EXPLANATION
    console.print()
    console.print(Rule(style="dim"))
    console.print()
    say(console, escape(first))
    say(console, f"[bold]{escape(offer)}[/]")
    console.print()
    bullets = Table(show_header=False, box=None, padding=(0, 1, 1, 0))
    bullets.add_column(style=PINK, no_wrap=True)
    bullets.add_column(max_width=72)
    for step in steps:
        bullets.add_row("•", escape(step))
    say(console, bullets)


def run(console: Console, preparation: Preparation, check: DeepCheck, folder: Path) -> str:
    """Measure usage, add it to the prepared package, keep it in ``folder``, send it.

    Returns:
        The reference the person can quote.

    Raises:
        PreparationError: If the package could not be collected.
        UploadError: If the upload cannot be delivered.
    """
    not_measured = {"ok": False, "note": "the usage meters stopped", "data": {}}
    usage = attempt("usage figures", lambda: _measure_usage(console, check.runtime), not_measured)
    finishing = nullcontext() if preparation.done else console.status("Finishing the collection…")
    with finishing:
        manifest = preparation.wait()
    manifest = attempt("usage figures", lambda: add_usage(preparation.folder, usage), manifest)
    archive = pack(preparation.folder)
    kept = preparation.keep(folder)
    console.print()
    say(console, f"Collected {manifest['skills']} skills, {manifest['plugins']} plugins, "
                 f"{manifest['servers']} server packages and {manifest['tools']} connector tools "
                 f"({len(archive) / 1e6:.1f} MB).")  # fmt: skip
    if kept:
        say(console, "A copy of what is sent is in")
        say(console, f"[bold]{escape(str(folder))}[/].")
    else:
        say(console, f"A copy could not be kept in {escape(str(folder))}; it is sent all the same.")
    with console.status("Sending…"):
        try:
            reference = send(archive, check.api_key, check.bucket, new_reference())
        except UploadError:
            raise
        except Exception as error:  # reported as an upload problem; the package is kept
            raise UploadError(f"the upload stopped ({type(error).__name__})") from error
    console.print()
    say(console, sent_card(reference))
    return reference


def sent_card(reference: str) -> Panel:
    """The closing message, the reference on its own line so it stands out and copies cleanly."""
    message = Group(
        Text("Sent. Your reference is", style="bold"),
        Text(""),
        Text(f"   {reference}   ", style=f"bold white on {PINK}"),
        Text(""),
        Text("Shepherd reviews the results and sends you the deep report."),
    )
    return Panel(message, box=ROUNDED, border_style=PINK, padding=(1, 3), expand=False)


def _measure_usage(console: Console, runtime: Path) -> dict[str, Any]:
    try:
        with console.status("Setting up the usage meters (first time only)…"):
            node = node_bin(runtime)
            meters = meters_bin(runtime, node)
    except SetupError as error:
        say(console, f"Usage could not be measured: {escape(str(error))}. "
                     "The deep check carries on without.")  # fmt: skip
        return {"ok": False, "note": str(error), "data": {}}
    with console.status("Measuring usage on this computer…"):
        return measure(meters, node, Path.home().name)
