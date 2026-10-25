"""The shipped code must not name the projects it was adapted from; only the notices file does."""

import re
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "shepherd_scan"
BRANDS = re.compile(
    r"snyk|invariant|cisco|defenseclaw|sentry|mcp-scan|mcp_scan|agent[ -_]?scan", re.IGNORECASE
)


def test_no_brand_names_in_shipped_files():
    offenders = []
    for path in PACKAGE.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if BRANDS.search(line):
                offenders.append(f"{path.relative_to(PACKAGE)}:{line_number}: {line.strip()}")
    assert offenders == []


def test_every_adapted_file_carries_the_modification_notice():
    notice = "# Modified from Apache-2.0 licensed code; see THIRD_PARTY_NOTICES.txt."
    missing = [
        str(path.relative_to(PACKAGE))
        for path in (PACKAGE / "_vendor").rglob("*.py")
        if path.name != "__init__.py" or path.parent != PACKAGE / "_vendor"
        if not path.read_text(encoding="utf-8").startswith(notice)
    ]
    assert missing == []
