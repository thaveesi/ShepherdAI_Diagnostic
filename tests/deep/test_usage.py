from shepherd_scan.deep.usage import clean_optimize, monthly_totals, tidy

MONTH = {
    "period": "2026-09", "inputTokens": 10, "outputTokens": 5, "cacheCreationTokens": 1,
    "cacheReadTokens": 2, "totalCost": 1.5, "totalTokens": 18, "modelsUsed": ["m"],
    "modelBreakdowns": [{"modelName": "m", "cost": 1.5, "inputTokens": 10}],
    "metadata": {"agents": ["claude"], "projects": ["~/secret-project"]},
}  # fmt: skip


def test_only_the_month_totals_and_costs_by_model_are_kept():
    [kept] = monthly_totals({"monthly": [MONTH], "totals": {"totalCost": 9}})["monthly"]
    assert kept["period"] == "2026-09" and kept["totalCost"] == 1.5
    assert kept["modelBreakdowns"] == [{"modelName": "m", "cost": 1.5}]
    assert kept["metadata"] == {"agents": ["claude"]}
    assert "modelsUsed" not in kept and "totalTokens" not in kept


def test_only_the_waste_findings_are_kept_and_their_text_is_cleaned():
    answer = {
        "findings": [{
            "id": "paste", "title": "Same block pasted", "tokensSaved": 9000,
            "explanation": 'You pasted "my plan" in '
                           "-Users-jo-work/2b7afd02-d860-4802-81b2-acac65d5004c",
            "fix": {"label": "Move it", "text": "Put it in /Users/jo/CLAUDE.md"},
            "trend": "up", "basis": "x",
        }],
        "topReworkedFiles": [{"path": "/Users/jo/work/secret.py", "edits": 4}],
        "coachingNotes": ["Your client Acme..."],
    }  # fmt: skip
    cleaned = clean_optimize(answer, "jo")
    assert list(cleaned) == ["findings"]
    [finding] = cleaned["findings"]
    assert "my plan" not in finding["explanation"] and "2b7afd02" not in finding["explanation"]
    assert finding["fix"] == {"label": "Move it", "text": "Put it in ~/CLAUDE.md"}
    assert "trend" not in finding


def test_tidy_hides_quotes_of_every_kind_and_the_home_folder():
    text = (
        'Pasted \u201ca\u201d and \u2018b\u2019 and "c" in /Users/jo-x/work, '
        "/home/jo-x/w and -Users-jo-x-proj"
    )
    cleaned = tidy(text, "jo-x")
    assert cleaned.count("(text not shown)") == 3
    assert "jo-x" not in cleaned


def test_month_details_of_an_unexpected_shape_are_left_out():
    months = [MONTH | {"metadata": ["claude"]}, MONTH | {"modelBreakdowns": 3},
              MONTH | {"metadata": {"agents": "claude"}}]  # fmt: skip
    kept = monthly_totals({"monthly": months})["monthly"]
    assert [month["metadata"]["agents"] for month in kept] == [[], ["claude"], []]
    assert kept[1]["modelBreakdowns"] == []
