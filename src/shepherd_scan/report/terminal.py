"""What the scan prints in the terminal: its logo, the closing summary and a shared margin."""

from importlib.resources import files
from pathlib import Path

from rich.console import Console, RenderableType
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from shepherd_scan.report.model import Report

NAMES_SHOWN = 6
INDENT = 2
PINK = "#ff3b5c"
# The logo is 72 columns wide; on a narrower terminal it would wrap into a broken shape.
LOGO_MIN_WIDTH = 76


def say(console: Console, text: RenderableType) -> None:
    """Print one block of output with the left margin every line of the scan's output shares."""
    console.print(Padding(text, (0, 0, 0, INDENT)))


def print_logo(console: Console) -> None:
    """The Shepherd logo in block characters, on a terminal wide enough to show it whole."""
    if not console.is_terminal or console.width < LOGO_MIN_WIDTH:
        return
    try:
        art = files("shepherd_scan.report").joinpath("logo.txt").read_text(encoding="utf-8")
    except OSError:  # the scan runs the same without its logo
        return
    console.print()
    for line in art.splitlines():
        console.print(Text(" " * INDENT + line, style=PINK))
    console.print()


def _names(names: list[str]) -> str:
    shown = ", ".join(names[:NAMES_SHOWN])
    extra = len(names) - NAMES_SHOWN
    return f"{shown} and {extra} more" if extra > 0 else shown


def print_summary(console: Console, report: Report, output: Path, seconds: float) -> None:
    """Print what was found and where the full report was saved.

    Args:
        console: Where to print.
        report: The finished report.
        output: Path of the saved HTML report.
        seconds: How long the scan took.
    """
    with_credentials = sum(1 for server in report.servers if server.credentials)
    flagged = report.flagged_skills
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="bold", no_wrap=True)
    table.add_column(justify="right", no_wrap=True)
    table.add_column(style="dim", max_width=44)
    table.add_row("AI agent apps", str(len(report.agents)), _names([a.name for a in report.agents]))
    table.add_row(
        "Servers and connectors",
        str(len(report.servers)),
        f"{with_credentials} hold credentials in their settings" if with_credentials else "",
    )
    table.add_row("Add-ons (skills)", str(len(report.skills)), "")
    table.add_row(
        "Flagged for a closer look",
        _count(len(flagged)),
        "automated, unconfirmed" if flagged else "",
    )
    table.add_row("Exposed keys", _count(len(report.secrets)), "")
    table.add_row(
        "Can go further than you meant",
        _count(len(report.reach)),
        "acting without asking, saved logins, wide control, shared accounts"
        if report.reach
        else "",
    )
    console.print()
    say(
        console,
        f"[bold green]Scan finished[/] in {seconds:.1f}s. No network connections were made.",
    )
    console.print()
    say(console, table)
    if report.problems:
        console.print()
        say(
            console,
            f"[dim]{len(report.problems)} location(s) could not be read; see the report.[/]",
        )
    console.print()
    say(console, "Report saved:")
    say(console, f"[bold underline]{escape(str(output))}[/]")


def _count(value: int) -> str:
    return f"[red]{value}[/]" if value else str(value)
