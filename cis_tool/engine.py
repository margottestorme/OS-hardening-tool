"""Moteur : charge les règles, les filtre, les audite via les handlers.

Il ne connaît aucune règle ni aucun handler concret : il importe le package
handlers (qui les enregistre via @register), demande les Rule au loader, puis
délègue chaque audit au handler correspondant au `type:` de la règle.
"""

from __future__ import annotations

from pathlib import Path

from . import handlers  # noqa: F401  → importe = peuple le registre des handlers
from .base import HandlerError, get_handler
from .models import Result, Rule, Status
from .rules_loader import load_rules


def run_audit(
    rules_path: str | Path,
    level: int | None = None,
    categories: list[str] | None = None,
) -> list[Result]:
    """Charge, filtre et audite les règles. Renvoie la liste des Result."""
    rules = _filter(load_rules(rules_path), level, categories)

    results: list[Result] = []
    for rule in rules:
        try:
            handler = get_handler(rule.type)
            results.append(handler.check(rule))
        except HandlerError as exc:
            # type inconnu, params manquants… : erreur d'audit, pas non-conformité
            results.append(Result(rule, Status.ERROR, detail=str(exc)))
    return results


def _filter(
    rules: list[Rule],
    level: int | None,
    categories: list[str] | None,
) -> list[Rule]:
    out = rules
    if level is not None:
        # En CIS, le Level 2 étend le Level 1. Donc --level N inclut tout ce qui
        # est <= N : --level 1 = seulement L1 ; --level 2 = L1 + L2.
        out = [r for r in out if r.level <= level]
    if categories:
        wanted = set(categories)
        out = [r for r in out if r.category in wanted]
    return out