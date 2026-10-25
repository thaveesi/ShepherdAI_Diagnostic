"""Command line entry point: check the AI agents on this computer and write the report."""

import argparse
import html
import logging
import os
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from shepherd_scan import __version__
from shepherd_scan._vendor.discovery.utils import ensure_unicode_console
from shepherd_scan.carry_on import attempt
from shepherd_scan.catalog import Catalog
from shepherd_scan.deep import run as deep_check
from shepherd_scan.deep.upload import UploadError
from shepherd_scan.discovery import discover, list_local_servers
from shepherd_scan.names import agent_name
from shepherd_scan.report.build import build_report
from shepherd_scan.report.html import render_html
from shepherd_scan.report.model import Report
from shepherd_scan.report.terminal import print_logo, print_summary, say

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="shepherd-scan",
        description=(
            "Check the AI agents on this computer: what they are connected to, the add-ons "
            "they load and keys left in their settings. Runs offline and sends nothing."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="where to save the report (default: shepherd-report-<date>.html in this folder)",
    )
    parser.add_argument(
        "--start-local-servers",
        action="store_true",
        help="also start the MCP servers installed on this computer to list their tools "
        "(asks first; online services are never contacted)",
    )
    parser.add_argument("--yes", action="store_true", help="do not ask before starting servers")
    parser.add_argument("--json", type=Path, metavar="PATH", help="also save the findings as JSON")
    parser.add_argument("--no-open", action="store_true", help="do not open the report when done")
    parser.add_argument(
        "--deep",
        action="store_true",
        help="after the scan, run the deep check without asking (sends a blanked copy for review)",
    )
    parser.add_argument("--no-deep", action="store_true", help="do not offer the deep check")
    parser.add_argument("--verbose", action="store_true", help="show detailed progress messages")
    parser.add_argument("--version", action="version", version=f"shepherd-scan {__version__}")
    return parser.parse_args(argv)


def _configure_logging(verbose: bool) -> None:
    """Keep the terminal clean; anything that could not be read is listed in the report."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.CRITICAL,
        format="%(levelname)s %(name)s: %(message)s",
    )


def _confirm_server_start(console: Console, *, assume_yes: bool) -> bool:
    servers = list_local_servers()
    if not servers:
        say(console, "No local MCP servers are installed, so there is nothing to start.")
        return False
    say(console, f"{len(servers)} local MCP server(s) would be started on this computer:")
    for server in servers:
        say(
            console,
            f"  • {escape(server.name)} ({escape(agent_name(server.agent))}): "
            f"{escape(server.command)}",
        )
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        say(console, "Not starting them: run in a terminal to answer, or pass --yes.")
        return False
    try:
        answer = (
            console.input("  " + escape("Start them to list their tools? [y/N] ")).strip().lower()
        )
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _default_output() -> Path:
    name = f"shepherd-report-{datetime.now():%Y-%m-%d-%H%M}.html"
    try:
        return Path.cwd() / name
    except OSError:  # the folder the scan was started from is gone
        return Path.home() / name


class ReportSaveError(Exception):
    """The report could not be written to disk."""


def _write_report(report: Report, requested: Path | None) -> Path:
    """Save the report, falling back to the home folder if this folder is not writable.

    Raises:
        ReportSaveError: If the report cannot be written anywhere.
    """
    page = _render(report)
    target = requested or _default_output()
    try:
        target.write_text(page, encoding="utf-8")
    except OSError as error:
        if requested is not None:
            raise ReportSaveError(f"{target}: {error.strerror or error}") from error
        target = Path.home() / target.name
        try:
            target.write_text(page, encoding="utf-8")
        except OSError as fallback_error:
            raise ReportSaveError(f"{target}: {fallback_error.strerror or fallback_error}") from (
                fallback_error
            )
    return target.resolve()


def _render(report: Report) -> str:
    """The report page; a short page with what was found if the full one cannot be drawn."""
    try:
        return render_html(report).encode("utf-8", "replace").decode("utf-8")
    except Exception as error:  # the report must still be written
        logging.getLogger(__name__).warning("Could not draw the full report: %s", error)
        counts = [("AI agents and apps", report.agents), ("Servers and connectors", report.servers),
                  ("Skills", report.skills), ("Exposed keys", report.secrets),
                  ("Ways agents can go further than you meant", report.reach)]  # fmt: skip
        rows = "".join(f"<tr><td>{html.escape(name)}</td><td>{len(items)}</td></tr>"
                       for name, items in counts)  # fmt: skip
        problems = "".join(f"<li>{html.escape(problem)}</li>" for problem in report.problems)
        return (
            '<!doctype html><meta charset="utf-8"><title>Shepherd scan</title>'
            f"<h1>Shepherd scan {html.escape(report.tool_version)}</h1>"
            f"<p>The full report could not be drawn ({type(error).__name__}); "
            f"this is what was found.</p><table>{rows}</table><ul>{problems}</ul>"
        )


def _open_in_browser(path: Path) -> None:
    try:
        webbrowser.open(path.as_uri())
    except (webbrowser.Error, OSError):
        logging.getLogger(__name__).info("Could not open a browser for %s", path)


def _run(args: argparse.Namespace, console: Console) -> int:
    started = time.monotonic()
    start_servers = args.start_local_servers and _confirm_server_start(console, assume_yes=args.yes)
    with console.status("Looking for AI agents, their tools and add-ons…"):
        discovery = discover(start_local_servers=start_servers)
        catalog = attempt("the server catalog", Catalog.load, Catalog([]))
        report = build_report(discovery, catalog, local_servers_started=start_servers)
    output = _write_report(report, args.output)
    try:
        preparation = deep_check.prepare(discovery, report.secrets) if _will_ask(args) else None
    except Exception as error:  # without a package the deep check is not offered
        say(console, f"The deep check cannot be offered: {escape(str(error))}.")
        preparation = None
    try:
        if args.json is not None:
            try:
                args.json.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            except Exception as error:  # the report itself is already saved
                say(console, f"Could not save the JSON copy: {escape(str(error))}.")
        seconds = time.monotonic() - started
        if not attempt("the summary", lambda: print_summary(console, report, output, seconds)
                       or True, False):  # fmt: skip
            say(console, f"Report saved: {escape(str(output))}")
        if not args.no_open and sys.stdout.isatty():
            _open_in_browser(output)
        return _deep_check(args, console, preparation, output)
    finally:
        if preparation is not None:
            preparation.discard()


def _will_ask(args: argparse.Namespace) -> bool:
    """Whether the deep check will be offered (or run with --deep), so its package is needed."""
    if deep_check.configured(os.environ) is None or args.no_deep:
        return False
    return args.deep or sys.stdin.isatty()


def _deep_check(
    args: argparse.Namespace,
    console: Console,
    preparation: deep_check.Preparation | None,
    report_path: Path,
) -> int:
    """Offer the deep check once the report is done; run it if the person agrees."""
    check = deep_check.configured(os.environ)
    if check is None or args.no_deep or preparation is None:
        if args.deep and check is None:
            say(console, "The deep check is not set up in this copy of the scanner.")
            return EXIT_ERROR
        return EXIT_OK
    if not deep_check.wanted(console, interactive=sys.stdin.isatty(), assume_yes=args.deep):
        return EXIT_OK
    folder = _free_folder(report_path.with_name(f"{report_path.stem}-deep-check"))
    return _send_deep_check(console, preparation, check, folder)


def _send_deep_check(
    console: Console,
    preparation: deep_check.Preparation,
    check: deep_check.DeepCheck,
    folder: Path,
) -> int:
    """Run the agreed deep check and turn its problems into a message and an exit code."""
    try:
        deep_check.run(console, preparation, check, folder)
    except KeyboardInterrupt:
        say(console, "The deep check was stopped before it finished. The report is saved.")
        return EXIT_INTERRUPTED
    except deep_check.PreparationError as error:
        say(
            console,
            f"[red]The deep check could not be prepared:[/] {escape(str(error))}. "
            "The report is saved.",
        )
        return EXIT_ERROR
    except UploadError as error:
        kept = f" What would have been sent is in {escape(str(folder))}." if folder.exists() else ""
        say(console, f"[red]The deep check could not be sent:[/] {escape(str(error))}.{kept}")
        return EXIT_ERROR
    except Exception as error:  # the last net: say what happened; the report is saved
        kept = f" What was collected is in {escape(str(folder))}." if folder.exists() else ""
        say(
            console,
            f"[red]The deep check stopped:[/] {type(error).__name__}: {escape(str(error))}. "
            f"The report is saved.{kept}",
        )
        return EXIT_ERROR
    return EXIT_OK


def _free_folder(wanted: Path) -> Path:
    """The wanted folder name, numbered if a folder of that name already exists."""
    candidate, number = wanted, 2
    while candidate.exists():
        candidate, number = wanted.with_name(f"{wanted.name}-{number}"), number + 1
    return candidate


def main(argv: list[str] | None = None) -> int:
    """Run the scan and return the process exit code.

    Args:
        argv: Command line arguments; defaults to the process arguments.

    Returns:
        0 when the report was written, 1 on an error, 130 when interrupted.
    """
    args = _parse_args(argv)
    ensure_unicode_console()
    # Settings files can hold numbers longer than Python's default 4,300-digit limit.
    sys.set_int_max_str_digits(0)
    _configure_logging(args.verbose)
    console = Console(highlight=False)
    print_logo(console)
    say(
        console,
        f"[bold]Shepherd scan[/] [dim]{__version__}[/]: checking this computer's AI agents.",
    )
    if deep_check.configured(os.environ) is None:
        say(console, "[dim]Runs offline: nothing is sent anywhere.[/]")
    else:
        say(
            console,
            "[dim]Runs offline: nothing is sent unless you choose the deep check at the end.[/]",
        )
    try:
        return _run(args, console)
    except KeyboardInterrupt:
        say(console, "Stopped before finishing; no report was written.")
        return EXIT_INTERRUPTED
    except ReportSaveError as error:
        say(
            console,
            f"[red]Could not save the report[/] ({error}). Try --output with another folder.",
        )
        return EXIT_ERROR
    except Exception as error:
        if args.verbose:
            raise
        say(
            console,
            f"[red]The scan stopped because of an unexpected error:[/] {type(error).__name__}: "
            f"{escape(str(error))}. Run again with --verbose for details.",
        )
        return EXIT_ERROR
