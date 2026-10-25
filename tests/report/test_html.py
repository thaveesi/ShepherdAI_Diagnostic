import re
from datetime import UTC, datetime
from typing import Any

from shepherd_scan.report.html import MAX_REACH_ROWS, group_tools, render_html
from shepherd_scan.report.model import (
    AgentResult,
    ReachFinding,
    ReachPart,
    Report,
    ServerResult,
    Severity,
    SkillFlag,
    SkillResult,
    ToolInfo,
)

SCRIPT = "<script>alert(1)</script>"


def _report(**fields) -> Report:
    return Report(generated_at=datetime(2026, 10, 14, tzinfo=UTC), tool_version="0.1.0", **fields)


def test_untrusted_text_is_escaped():
    report = _report(
        skills=[
            SkillResult(
                name=SCRIPT,
                path="~/.claude/skills/x",
                agents=["Claude Code"],
                flags=[
                    SkillFlag(
                        category="Hidden or manipulative instructions",
                        severity=Severity.HIGH,
                        location="SKILL.md:1",
                        detail=SCRIPT,
                        evidence=SCRIPT,
                    )
                ],
            )
        ],
        servers=[
            ServerResult(
                name=SCRIPT,
                agent="Cursor",
                kind="local",
                tools=[ToolInfo(name=SCRIPT, description=SCRIPT)],
            )
        ],
    )
    html = render_html(report)
    assert SCRIPT not in html
    assert "&lt;script&gt;" in html


def test_page_loads_nothing_from_the_network():
    html = render_html(_report())
    assert "default-src 'none'" in html
    assert not re.search(r"""(src|href)\s*=\s*["']?https?:""", html, re.IGNORECASE)
    assert "<script" not in html.lower()


def test_empty_report_renders_every_section():
    html = render_html(_report())
    for section in ("flagged", "keys", "reach", "servers", "agents", "limits"):
        assert f'id="{section}"' in html
    assert "No add-on matched the automated rules." in html
    assert html.count("Nothing found.") == 4


def test_every_section_is_collapsible_and_starts_open():
    html = render_html(_report(problems=["could not read ~/.x/settings.json"]))
    assert html.count('<details class="block" open>') == 7
    assert html.count('<details class="part" open>') == 4


def test_summary_cards_keep_their_order_with_the_new_card_last():
    html = render_html(_report())
    labels = re.findall(r'<div class="l">([^<]+)</div>', html)
    assert labels == [
        "AI agent apps",
        "Connected servers and connectors",
        "Add-ons (skills)",
        "Add-ons flagged for a closer look",
        "Exposed keys",
        "Ways agents can go further than you meant",
    ]


def _finding(part: ReachPart, number: int = 0, **fields: Any) -> ReachFinding:
    values: dict[str, Any] = {
        "app": "Claude Code",
        "what": f"finding {number}",
        "where": f"~/place-{number}",
    }
    values.update(fields)
    return ReachFinding(part=part, **values)


def test_reach_parts_list_findings_with_their_basis():
    report = _report(
        reach=[
            _finding("acts", 1, basis="default"),
            _finding("logins", 2, app=""),
            _finding("control", 3, basis="published"),
            _finding("shared", 4),
        ],
        command_agents=["Claude Code", "Cursor"],
    )
    html = render_html(report)
    for number in range(1, 5):
        assert f"finding {number}" in html
    assert "app default" in html
    assert "published features" in html
    assert "Agents on this computer that can run commands: Claude Code, Cursor." in html
    assert "Acts without asking (1)" in html


def test_long_reach_parts_fold_after_a_limit():
    findings = [_finding("acts", number) for number in range(MAX_REACH_ROWS + 3)]
    html = render_html(_report(reach=findings))
    assert "<summary>3 more</summary>" in html
    assert f"finding {MAX_REACH_ROWS + 2}" in html


def test_apps_without_readable_settings_are_described_not_hidden():
    app = AgentResult(
        name="Slack (Slackbot)",
        path="",
        servers=0,
        skills=0,
        found_by=["app: /Applications/Slack.app"],
        seen_inside=False,
        note="Kept in your Slack workspace.",
        can_do="Acts in connected apps.",
    )
    html = render_html(_report(agents=[app]))
    assert "Can't see inside: Kept in your Slack workspace." in html
    assert "Found: app: /Applications/Slack.app" in html
    assert "Acts in connected apps." in html


def test_untrusted_text_in_new_sections_is_escaped():
    app = AgentResult(
        name=SCRIPT,
        path="",
        servers=0,
        skills=0,
        found_by=[SCRIPT],
        seen_inside=False,
        note=SCRIPT,
        site_access=[SCRIPT],
    )
    report = _report(
        agents=[app],
        reach=[_finding("acts", 1, app=SCRIPT, what=SCRIPT, where=SCRIPT)],
        kept_elsewhere=[SCRIPT],
    )
    assert SCRIPT not in render_html(report)


def test_label_note_shown_only_without_labels():
    unlabelled = _report(servers=[ServerResult(name="s", agent="a", kind="local")])
    labelled = _report(
        servers=[
            ServerResult(
                name="s",
                agent="a",
                kind="local",
                tools=[ToolInfo(name="t", description="", packs=["CHANGE"])],
            )
        ]
    )
    assert "not included in this offline scan" in render_html(unlabelled)
    assert "not included in this offline scan" not in render_html(labelled)


def test_group_tools_orders_consequences_and_puts_unlabelled_last():
    tools = [
        ToolInfo(name="pay", description="", packs=["FINANCIAL"]),
        ToolInfo(name="read", description=""),
        ToolInfo(name="edit", description="", packs=["CHANGE", "DATA"]),
    ]
    groups = [(pack, [t.name for t in members]) for pack, members in group_tools(tools)]
    assert groups == [
        ("CHANGE", ["edit"]),
        ("DATA", ["edit"]),
        ("FINANCIAL", ["pay"]),
        ("UNLABELLED", ["read"]),
    ]
