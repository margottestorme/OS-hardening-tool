"""Moteur : audit, et remédiation avec sauvegarde préalable.

Il ne connaît aucune règle ni aucun handler concret : il importe le package
handlers (qui les enregistre via @register), demande les Rule au loader, puis
délègue chaque audit/remédiation au handler correspondant au `type:` de la règle.
"""

from __future__ import annotations

from pathlib import Path

from . import handlers  # noqa: F401  → importe = peuple le registre des handlers
from .backup import BackupSession
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
            results.append(Result(rule, Status.ERROR, detail=str(exc)))
    return results


def remediate(
    before: list[Result],
    rules_path: str | Path,
    backups_root: str | Path,
    level: int | None = None,
    categories: list[str] | None = None,
) -> tuple[list[Result], str, list[tuple[str, Exception]]]:
    """Sauvegarde puis remédie chaque règle non conforme, et re-audite.

    Ordre impératif par règle : sauvegarder ses fichiers cibles AVANT de la
    modifier. Renvoie (résultats après, horodatage de sauvegarde, erreurs).
    """
    session = BackupSession(backups_root)
    errors: list[tuple[str, Exception]] = []

    for r in before:
        if r.status is not Status.NON_COMPLIANT:
            continue  # on ne remédie ni le conforme ni l'erreur d'audit
        try:
            handler = get_handler(r.rule.type)
            session.save(r.rule.cis_id, handler.target_files(r.rule))  # backup d'abord
            handler.apply(r.rule)                                      # puis remédiation
        except Exception as exc:  # noqa: BLE001 — on collecte, on n'interrompt pas tout
            errors.append((r.rule.cis_id, exc))

    session.write_manifest()
    after = run_audit(rules_path, level=level, categories=categories)  # re-vérification
    return after, session.timestamp, errors


def _filter(
    rules: list[Rule],
    level: int | None,
    categories: list[str] | None,
) -> list[Rule]:
    out = rules
    if level is not None:
        # En CIS, le Level 2 étend le Level 1 : --level N inclut tout ce qui est <= N.
        out = [r for r in out if r.level <= level]
    if categories:
        wanted = set(categories)
        out = [r for r in out if r.category in wanted]
    return out