"""Usage totals measured on this computer, for the deep check's cost section.

Two pinned usage meters read the agents' local usage records here, which hold the
conversations. Only what the report uses leaves this computer: each month's token totals and
costs by model, and the waste findings' texts, cleaned first (session references become "one
session", quoted message text is dropped, the home folder's name is hidden). The meters' other
output, such as the files reworked most often, is never kept.
"""

import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SESSION_REF = re.compile(r"\S+/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
QUOTED = re.compile('"[^"]*"|\u201c[^\u201d]*\u201d|\u2018[^\u2019]*\u2019')
TOOL_NAME = re.compile(r"\bCodeBurn\b", re.IGNORECASE)
HOME_PATH = re.compile(r"-Users-[^-/\s]+-|/Users/[^/\s]+/|-home-[^-/\s]+-|/home/[^/\s]+/")
MONTH_FIELDS = ("period", "inputTokens", "outputTokens", "cacheCreationTokens", "cacheReadTokens",
                "totalCost")  # fmt: skip
FINDING_FIELDS = ("id", "title", "explanation", "estimatedSavingsUSD", "tokensSaved")
TIMEOUT_SECONDS = 900


def measure(meters: Path, node: Path, user: str) -> dict[str, Any]:
    """Monthly totals and the last 30 days' waste findings, as {"ok", "note", "data"}.

    Args:
        meters: The folder holding the pinned meters' commands.
        node: The folder holding the node command they run with.
        user: The home folder's name, hidden wherever it appears.
    """
    data: dict[str, Any] = {"measured_on": datetime.now(UTC).date().isoformat()}
    notes = []
    commands = {
        "monthly": [str(meters / "ccusage"), "monthly", "--json", "--offline"],
        "optimize": [str(meters / "codeburn"), "optimize", "-p", "30days", "--json"],
    }
    for key, command in commands.items():
        try:
            answer = _run_json(command, node)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            notes.append(f"{key} did not run ({type(error).__name__})")
            continue
        data[key] = monthly_totals(answer) if key == "monthly" else clean_optimize(answer, user)
    ok = "monthly" in data or "optimize" in data
    return {"ok": ok, "note": "; ".join(notes) or "measured", "data": data}


def monthly_totals(answer: Any) -> dict[str, Any]:
    """Each month's token totals and its cost by model; nothing else."""
    months = answer.get("monthly") if isinstance(answer, dict) else None
    kept = []
    for month in months if isinstance(months, list) else []:
        if not isinstance(month, dict):
            continue
        breakdowns = month.get("modelBreakdowns")
        models = [
            {"modelName": m.get("modelName"), "cost": m.get("cost")}
            for m in (breakdowns if isinstance(breakdowns, list) else [])
            if isinstance(m, dict)
        ]
        metadata = month.get("metadata") if isinstance(month.get("metadata"), dict) else {}
        agents = metadata.get("agents") if isinstance(metadata.get("agents"), list) else []
        kept.append({key: month.get(key) for key in MONTH_FIELDS}
                    | {"modelBreakdowns": models, "metadata": {"agents": agents}})  # fmt: skip
    return {"monthly": kept}


def clean_optimize(answer: Any, user: str = "") -> dict[str, Any]:
    """The waste findings only, with their texts cleaned."""
    findings = answer.get("findings") if isinstance(answer, dict) else None
    kept = []
    for item in findings if isinstance(findings, list) else []:
        if not isinstance(item, dict):
            continue
        entry = {key: item.get(key) for key in FINDING_FIELDS}
        for key in ("title", "explanation"):
            if isinstance(entry[key], str):
                entry[key] = tidy(entry[key], user)
        fix = item.get("fix") if isinstance(item.get("fix"), dict) else {}
        entry["fix"] = {key: tidy(str(fix.get(key) or ""), user) for key in ("label", "text")}
        kept.append(entry)
    return {"findings": kept}


def tidy(text: str, user: str = "") -> str:
    """One line: no session references, quoted message text or tool name; home shown as ~."""
    if user:
        # Claude names project folders after their path with every other character made a dash.
        dashed = re.sub(r"[^A-Za-z0-9]", "-", user)
        for form in (f"-Users-{dashed}-", f"/Users/{user}/", f"-home-{dashed}-", f"/home/{user}/"):
            text = text.replace(form, "~/")
    text = SESSION_REF.sub("one session", text)
    text = QUOTED.sub("(text not shown)", text)
    text = TOOL_NAME.sub("this check", text)
    return " ".join(HOME_PATH.sub("~/", text).split())


def _run_json(command: list[str], node: Path) -> Any:
    env = dict(os.environ)
    env["PATH"] = f"{node}{os.pathsep}{env.get('PATH', '')}"
    env["CODEBURN_CURSOR_SYNC"] = "0"
    completed = subprocess.run(  # noqa: S603 - pinned meters installed by this tool, no shell
        command, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False, env=env
    )
    return json.loads(completed.stdout)
