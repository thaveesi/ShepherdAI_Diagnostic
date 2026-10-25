"""Blank secrets and personal data in a setting's text before anything is written or sent."""

import re

from shepherd_scan._vendor.discovery.redact import redact_text
from shepherd_scan.checks.secrets import hide_blanked_values

# Personal data in settings rules and hooks, such as ``git config user.email ...``. The address
# git uses for SSH remotes (git@github.com) is not a person's.
PERSONAL_DATA = (
    (re.compile(r"(user\.name\s+)(?:'[^']*'|\"[^\"]*\"|\S+)"), r"\1<name>"),
    (re.compile(r"\b(?!git@)[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "<email>"),
)


def clean(text: str) -> str:
    """Blank any secret value, email address or git user name in a setting before it is sent."""
    text = text.encode("utf-8", "replace").decode("utf-8")  # half an escaped emoji (\ud83d)
    text = hide_blanked_values(redact_text(text) or "")
    for pattern, replacement in PERSONAL_DATA:
        text = pattern.sub(replacement, text)
    return text
