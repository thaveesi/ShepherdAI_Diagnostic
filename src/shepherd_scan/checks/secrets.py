"""Credentials in skills, found from the blanking done at collection, and credential formats.

Skill files are blanked as they are read, leaving a marker such as
``**REDACTED_SECRET_AWSKEYDETECTOR**`` in place of each value. This module turns those markers
into report entries and names credential formats for the settings check. It never stores a
secret's value.
"""

import functools
import re

from detect_secrets.core.scan import scan_line
from detect_secrets.settings import default_settings, get_plugins

from shepherd_scan._vendor.discovery.models import InspectedSkill
from shepherd_scan.report.model import SecretFinding

MARKER = re.compile(r"\*\*REDACTED_SECRET_([A-Z0-9_]+)\*\*")
# Any blanked value, including the URL-encoded form used inside web addresses.
BLANKED_VALUE = re.compile(
    r"\*\*REDACTED(?:_SECRET_[A-Z0-9_]+)?\*\*|%2A%2AREDACTED(?:_SECRET_[A-Z0-9_]+)?%2A%2A"
)
HIDDEN = "[hidden]"
# Detectors that recognise a credential by its own format, such as an AWS key or a GitHub token.
# Blanking at collection also uses generic detectors (long random strings, "password = ..."
# keywords, user:pass URLs). Those protect values from being shown, but in documentation they
# mostly match hashes, test vectors and teaching examples, so they are not reported as findings.
REPORTED_DETECTORS = frozenset(
    {
        "ARTIFACTORYDETECTOR",
        "AWSKEYDETECTOR",
        "AZURESTORAGEKEYDETECTOR",
        "CLOUDANTDETECTOR",
        "DISCORDBOTTOKENDETECTOR",
        "GITHUBTOKENDETECTOR",
        "GITLABTOKENDETECTOR",
        "IBMCLOUDIAMDETECTOR",
        "IBMCOSHMACDETECTOR",
        "MAILCHIMPDETECTOR",
        "NPMDETECTOR",
        "OPENAIDETECTOR",
        "PRIVATEKEYDETECTOR",
        "PYPITOKENDETECTOR",
        "SENDGRIDDETECTOR",
        "SLACKDETECTOR",
        "SOFTLAYERDETECTOR",
        "SQUAREOAUTHDETECTOR",
        "STRIPEDETECTOR",
        "TELEGRAMBOTTOKENDETECTOR",
        "TWILIOKEYDETECTOR",
    }
)


@functools.cache
def _detector_names() -> dict[str, str]:
    with default_settings():
        plugins = list(get_plugins())
    return {type(plugin).__name__.upper(): str(plugin.secret_type) for plugin in plugins}


def secret_kind(marker_name: str) -> str:
    """Plain-language name for the detector that produced a marker."""
    return _detector_names().get(marker_name, "Credential")


@functools.cache
def _reported_types() -> frozenset[str]:
    names = _detector_names()
    return frozenset(names[detector] for detector in REPORTED_DETECTORS if detector in names)


def format_kind(value: str) -> str | None:
    """The credential type when a format-specific detector recognises the value.

    Runs in memory on one value and keeps nothing; call it inside ``default_settings()``.
    """
    reported = _reported_types()
    value = value.encode("utf-8", "replace").decode("utf-8")  # half an escaped emoji
    for secret in scan_line(value):
        if secret.type in reported:
            return secret.type
    return None


def secrets_in_skill(skill: InspectedSkill) -> list[SecretFinding]:
    """Secrets found in a skill's files, by file and line."""
    findings: list[SecretFinding] = []
    for skill_file in skill.files:
        for line_number, line in enumerate(skill_file.content.splitlines(), start=1):
            for marker_name in MARKER.findall(line):
                if marker_name not in REPORTED_DETECTORS:
                    continue
                findings.append(
                    SecretFinding(
                        kind=secret_kind(marker_name),
                        where=skill.name,
                        location=f"{skill_file.path}:{line_number}",
                    )
                )
    return findings


def merge_secret_findings(*groups: list[SecretFinding]) -> list[SecretFinding]:
    """Combine findings from several detectors, keeping one entry per place."""
    merged: dict[tuple[str, str], SecretFinding] = {}
    for group in groups:
        for finding in group:
            merged.setdefault((finding.where, finding.location), finding)
    return sorted(merged.values(), key=lambda f: (f.where.lower(), f.location))


def hide_blanked_values(text: str) -> str:
    """Show every blanked value as ``[hidden]`` so the report reads plainly."""
    return BLANKED_VALUE.sub(HIDDEN, text)
