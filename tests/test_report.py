"""Tests du rendu (report.py) : comptes, JSON structuré, console."""

import json

from cis_tool import report
from cis_tool.models import Result, Rule, Status


def _res(status, cat="ssh", cis="5.1.20"):
    rule = Rule(id="x", cis_id=cis, title="T", level=1, category=cat,
                type="file_directive", params={})
    return Result(rule, status, actual="no", expected="no")


def test_summarize_counts():
    results = [_res(Status.COMPLIANT), _res(Status.NON_COMPLIANT), _res(Status.ERROR)]
    assert report.summarize(results) == {
        "total": 3, "compliant": 1, "non_compliant": 1, "error": 1,
    }


def test_json_is_valid_and_structured():
    data = json.loads(report.render_json([_res(Status.COMPLIANT)]))
    assert data["summary"]["total"] == 1
    assert data["benchmark"].startswith("CIS Ubuntu")
    entry = data["results"][0]
    assert entry["cis_id"] == "5.1.20"
    assert entry["status"] == "compliant"


def test_console_groups_and_summarizes():
    out = report.render_console(
        [_res(Status.NON_COMPLIANT, cat="ssh"), _res(Status.COMPLIANT, cat="network")],
        color=False,
    )
    assert "=== ssh" in out
    assert "=== network" in out
    assert "FAIL" in out and "PASS" in out
    assert "Résumé" in out


def test_console_no_color_has_no_ansi():
    out = report.render_console([_res(Status.COMPLIANT)], color=False)
    assert "\033[" not in out