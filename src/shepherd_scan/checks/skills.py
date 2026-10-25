"""Run the skill rules on one skill and translate the results into report terms."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shepherd_scan._vendor import skillrules
from shepherd_scan._vendor.discovery.redact import redact_text
from shepherd_scan.carry_on import attempt
from shepherd_scan.checks.secrets import hide_blanked_values
from shepherd_scan.report.model import SecretFinding, Severity, SkillFlag

logger = logging.getLogger(__name__)

# Rule categories, worded for someone who does not read security reports every day.
CATEGORY_WORDING: dict[str, str] = {
    "Prompt Injection": "Hidden or manipulative instructions",
    "Pre-prompt Injection": "Runs a command as soon as the skill loads",
    "Obfuscation": "Hidden characters or encoded text",
    "Malicious Code": "Risky code in bundled scripts",
    "Supply Chain": "Installs or runs packages automatically",
    "Excessive Permissions": "Unrestricted tool access",
    "Hook Exploitation": "Runs commands automatically through hooks",
    "Symlink Exfiltration": "Links to files outside the skill",
    "Test File RCE": "Test files that run code when tests run",
    "Image Injection": "Text hidden inside images",
}
# Malformed-metadata findings are not security issues; secrets get their own section.
CREDENTIAL_CATEGORY = "Secret Exposure"
# Credential rules that recognise a key by its format. The rules' generic patterns
# ("password = '...'", "api_key = '...'") mostly match teaching examples and are not reported.
FORMAT_SPECIFIC_CREDENTIAL_RULES = frozenset(
    {
        "AWS Access Key ID",
        "AWS Secret Access Key",
        "GitHub Personal Access Token",
        "GitHub Server Token",
        "GitHub OAuth Token",
        "GitHub Fine-Grained PAT",
        "OpenAI API Key",
        "Anthropic API Key",
        "Stripe Live Key",
        "Slack Token",
        "Private Key",
    }
)
IGNORED_CATEGORIES = frozenset({"Validation", CREDENTIAL_CATEGORY})
EVIDENCE_LIMIT = 160
# The rules read a skill's main file in full; anything larger is reported as unchecked.
MAX_SKILL_MD_BYTES = 1_000_000
# Checking one skill takes well under a second; a check still running after this is left behind.
SKILL_SECONDS = 60.0
TOO_LONG = "The automated check took too long on this skill."


@dataclass
class SkillCheck:
    """Flags, secrets and any error from checking one skill."""

    flags: list[SkillFlag] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    error: str | None = None


def check_skill(skill_name: str, installation_path: str) -> SkillCheck:
    """Run the skill rules on a skill directory or single-file skill.

    Args:
        skill_name: Display name of the skill, used to say where a secret was found.
        installation_path: Path of the skill directory or file on this computer.

    Returns:
        The flags and secrets found, or an error saying why the skill was not checked.
    """
    return attempt(
        f"the skill {skill_name}",
        lambda: _check(skill_name, installation_path),
        SkillCheck(error=TOO_LONG),
        seconds=SKILL_SECONDS,
    )


def _check(skill_name: str, installation_path: str) -> SkillCheck:
    path = Path(installation_path).expanduser()
    try:
        findings = _run_rules(path)
    except _NotCheckedError as reason:
        return SkillCheck(error=str(reason))
    except Exception:
        logger.exception("Skill rules failed on %s", installation_path)
        return SkillCheck(error="The automated check could not read this skill.")
    return _translate(skill_name, findings)


class _NotCheckedError(Exception):
    """A skill the rules deliberately did not check, with the reason."""


def _run_rules(path: Path) -> list[dict[str, Any]]:
    if path.is_file():
        return _check_single_file(path)
    if not path.is_dir():
        raise _NotCheckedError("The skill's folder no longer exists.")
    main_file = next((p for p in path.iterdir() if p.name.lower() == "skill.md"), None)
    if main_file is not None and main_file.stat().st_size > MAX_SKILL_MD_BYTES:
        raise _NotCheckedError("The skill's main file is too large to check automatically.")
    result = skillrules.scan_skill(path)
    if "error" in result:
        raise _NotCheckedError("The skill has no readable SKILL.md file.")
    return list(result.get("findings", []))


def _check_single_file(path: Path) -> list[dict[str, Any]]:
    if path.stat().st_size > MAX_SKILL_MD_BYTES:
        raise _NotCheckedError("The skill file is too large to check automatically.")
    content = path.read_text(encoding="utf-8", errors="replace")
    findings = skillrules.check_prompt_injection(content, path.name)
    findings += skillrules.check_obfuscation(content, path.name)
    findings += skillrules.check_secrets(content, path.name)
    return findings


def _translate(skill_name: str, findings: list[dict[str, Any]]) -> SkillCheck:
    check = SkillCheck()
    for finding in findings:
        category = str(finding.get("category", ""))
        location = str(finding.get("location", ""))
        if category == CREDENTIAL_CATEGORY:
            kind = str(finding.get("description", ""))
            if kind in FORMAT_SPECIFIC_CREDENTIAL_RULES:
                check.secrets.append(SecretFinding(kind=kind, where=skill_name, location=location))
            continue
        if category in IGNORED_CATEGORIES:
            continue
        check.flags.append(
            SkillFlag(
                category=CATEGORY_WORDING.get(category, category or "Other"),
                severity=_severity(finding.get("severity")),
                location=location,
                detail=str(finding.get("description", "")),
                evidence=_safe_evidence(finding.get("evidence")),
            )
        )
    check.flags.sort(key=lambda flag: (flag.severity.rank, flag.location))
    return check


def _severity(value: object) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.MEDIUM


def _safe_evidence(value: object) -> str | None:
    """Trim a matched line and blank any credential in it before it reaches the report."""
    if not isinstance(value, str) or not value.strip():
        return None
    redacted = hide_blanked_values(redact_text(value.strip()) or "")
    if len(redacted) > EVIDENCE_LIMIT:
        return redacted[: EVIDENCE_LIMIT - 1] + "…"
    return redacted
