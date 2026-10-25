from io import StringIO

from rich.console import Console

from shepherd_scan.deep.run import sent_card
from shepherd_scan.report.terminal import print_logo


def printed(console: Console) -> str:
    file = console.file
    assert isinstance(file, StringIO)
    return file.getvalue()


def test_the_logo_shows_on_a_terminal_wide_enough_for_it():
    console = Console(file=StringIO(), force_terminal=True, width=80)
    print_logo(console)
    assert "█" in printed(console)


def test_no_logo_when_the_output_is_not_a_terminal_or_too_narrow():
    for console in (Console(file=StringIO(), force_terminal=False, width=120),
                    Console(file=StringIO(), force_terminal=True, width=60)):  # fmt: skip
        print_logo(console)
        assert printed(console) == ""


def test_the_closing_card_puts_the_reference_on_its_own_line():
    console = Console(file=StringIO(), width=80)
    console.print(sent_card("20261024-3f9a1c7e2b40"))
    lines = printed(console).splitlines()
    assert any("Sent. Your reference is" in line for line in lines)
    [line] = [line for line in lines if "20261024-3f9a1c7e2b40" in line]
    assert line.strip("│ ") == "20261024-3f9a1c7e2b40"
