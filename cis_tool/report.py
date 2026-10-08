"""Rendu des résultats d'audit : console (lisible) et JSON (exploitable).

Séparé du moteur et de la CLI : les fonctions prennent une liste de Result et
renvoient une chaîne. Aucune logique d'audit ici, uniquement de la présentation
— ce qui rend le rendu testable sans toucher au système.
"""

from __future__ import annotations

import json
import platform
from collections import Counter
from datetime import datetime, timezone

from .models import Result, Status

BENCHMARK = "CIS Ubuntu Linux 22.04 LTS v3.0.0"

_LABEL = {
    Status.COMPLIANT: "PASS",
    Status.NON_COMPLIANT: "FAIL",
    Status.ERROR: "ERR ",
}
_COLOR = {
    Status.COMPLIANT: "32",      # vert
    Status.NON_COMPLIANT: "31",  # rouge
    Status.ERROR: "33",          # jaune
}


def summarize(results: list[Result]) -> dict:
    """Comptes par statut."""
    c = Counter(r.status for r in results)
    return {
        "total": len(results),
        "compliant": c[Status.COMPLIANT],
        "non_compliant": c[Status.NON_COMPLIANT],
        "error": c[Status.ERROR],
    }


# --- rendu console -----------------------------------------------------------
def render_console(results: list[Result], color: bool = True) -> str:
    lines: list[str] = []
    for category, items in _group_by_category(results).items():
        ok = sum(1 for r in items if r.status is Status.COMPLIANT)
        lines.append(f"=== {category}  ({ok}/{len(items)} conformes) ===")
        for r in items:
            lines.append(_format_line(r, color))
        lines.append("")
    s = summarize(results)
    lines.append(f"Résumé : {s['total']} règles — {s['compliant']} conformes, "
                 f"{s['non_compliant']} non conformes, {s['error']} erreurs")
    return "\n".join(lines)


def _group_by_category(results: list[Result]) -> dict[str, list[Result]]:
    groups: dict[str, list[Result]] = {}
    for r in results:
        groups.setdefault(r.rule.category, []).append(r)
    return groups


def _format_line(r: Result, color: bool) -> str:
    label = _LABEL[r.status]
    if color:
        label = f"\033[{_COLOR[r.status]}m{label}\033[0m"
    if r.actual is not None:
        extra = f"  (relevé : {r.actual})"
    elif r.detail:
        extra = f"  ({r.detail})"
    else:
        extra = ""
    return f"[{label}] {r.rule.cis_id:<8} {r.rule.title}{extra}"


# --- rendu JSON --------------------------------------------------------------
def build_report(results: list[Result]) -> dict:
    """Dictionnaire structuré, prêt à sérialiser (JSON) ou à consommer."""
    return {
        "tool": "cis_tool",
        "benchmark": BENCHMARK,
        "host": platform.node(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(results),
        "results": [
            {
                "id": r.rule.id,
                "cis_id": r.rule.cis_id,
                "title": r.rule.title,
                "category": r.rule.category,
                "level": r.rule.level,
                "status": r.status.value,
                "actual": r.actual,
                "expected": r.expected,
                "detail": r.detail,
            }
            for r in results
        ],
    }


def render_json(results: list[Result]) -> str:
    return json.dumps(build_report(results), indent=2, ensure_ascii=False)