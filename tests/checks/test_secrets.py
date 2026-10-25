from detect_secrets.settings import default_settings

from shepherd_scan._vendor.discovery.models import InspectedSkill, SkillFile
from shepherd_scan._vendor.discovery.skill_client import collect_skill_files
from shepherd_scan.checks.secrets import (
    format_kind,
    merge_secret_findings,
    secret_kind,
    secrets_in_skill,
)
from shepherd_scan.report.model import SecretFinding
from tests.conftest import FAKE_AWS_KEY, FAKE_GITHUB_TOKEN


def test_marker_names_become_plain_kinds():
    assert secret_kind("AWSKEYDETECTOR") == "AWS Access Key"
    assert secret_kind("SLACKDETECTOR") == "Slack Token"
    assert secret_kind("NOTAREALDETECTOR") == "Credential"


def test_secrets_in_skill_report_file_and_line():
    skill = InspectedSkill(
        name="deploy",
        installation_path="skills/deploy",
        files=[
            SkillFile(path="SKILL.md", content="intro\nkey = **REDACTED_SECRET_AWSKEYDETECTOR**\n"),
            SkillFile(path="scripts/a.py", content="host = **REDACTED_SECRET_IPPUBLICDETECTOR**"),
            SkillFile(
                path="docs.md",
                content="secret = **REDACTED_SECRET_KEYWORDDETECTOR**\n"
                "digest **REDACTED_SECRET_HEXHIGHENTROPYSTRING**\n"
                "id **REDACTED_SECRET_BASE64HIGHENTROPYSTRING**\n"
                "url **REDACTED_SECRET_BASICAUTHDETECTOR**\n"
                "jwt **REDACTED_SECRET_JWTTOKENDETECTOR**",
            ),
        ],
    )
    findings = secrets_in_skill(skill)
    assert findings == [SecretFinding(kind="AWS Access Key", where="deploy", location="SKILL.md:2")]


def test_format_kind_names_only_format_specific_detectors():
    with default_settings():
        assert format_kind(FAKE_AWS_KEY) == "AWS Access Key"
        assert format_kind(FAKE_GITHUB_TOKEN) == "GitHub Token"
        assert format_kind("3f9a2c71-5b8e-4d6f-9a1c-2e7b8d4f6a90") is None
        assert format_kind("hello world") is None


def test_merge_keeps_one_entry_per_place():
    first = SecretFinding(kind="AWS Access Key", where="s", location="SKILL.md:2")
    duplicate = SecretFinding(kind="AWS Access Key ID", where="s", location="SKILL.md:2")
    other = SecretFinding(kind="Slack Token", where="a", location="x:1")
    merged = merge_secret_findings([first], [duplicate, other])
    assert merged == [other, first]


def test_teaching_examples_and_hashes_are_not_reported_but_real_formats_are(tmp_path):
    """The false alarms seen on a real machine, run through real collection and blanking."""
    folder = tmp_path / "insecure-examples"
    folder.mkdir()
    (folder / "SKILL.md").write_text(
        "---\nname: insecure-examples\ndescription: Shows insecure defaults.\n---\n"
        "const secret = process.env.SECRET || 'default-secret-value';\n"
        "const DB_PASSWORD = process.env.DB_PASSWORD || 'admin123';\n"
        "FROM ghcr.io/astral-sh/uv@sha256:"
        "2381d6aa60c326b71fd40023f921a0a3b8f91b14d5db6b90402e65a635053709 AS uv\n"
        "| Java | `aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3QgcGFjayBpZA==` |\n"
        "Connect with https://admin:hunter2pass@db.example.invalid/app\n"
        "  password: 'securePassword123'\n",
        encoding="utf-8",
    )
    (folder / "deploy.sh").write_text('export AWS_KEY="AKIA2E0A8F3B244C9986"\n', encoding="utf-8")
    skill = InspectedSkill(
        name="insecure-examples",
        installation_path=str(folder),
        files=collect_skill_files(str(folder)),
    )
    findings = secrets_in_skill(skill)
    assert [(f.kind, f.location) for f in findings] == [("AWS Access Key", "deploy.sh:1")]
