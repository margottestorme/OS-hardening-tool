"""Chargement et validation des règles YAML → objets Rule.

Responsabilités :
  - lire un fichier .yaml (ou tout un dossier de règles) ;
  - fusionner le bloc `defaults` dans les params de chaque règle ;
  - valider la structure (champs requis, level ∈ {1,2}, ids uniques) AVANT de
    produire des Rule, pour échouer proprement plutôt qu'en plein audit.

Ce module ne connaît pas les handlers : il valide la FORME, pas le fond. Vérifier
qu'un `type:` a bien un handler associé se fait au dispatch, côté moteur
(get_handler), seule source de vérité des types connus.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import Rule

REQUIRED_FIELDS = ("id", "cis_id", "title", "level", "category", "type")
VALID_LEVELS = (1, 2)


class RuleValidationError(Exception):
    """Une règle YAML est mal formée (champ manquant, level invalide, id dupliqué)."""


def load_rules(path: str | Path) -> list[Rule]:
    """Charge toutes les règles depuis un fichier .yaml ou un dossier de .yaml."""
    path = Path(path)
    if path.is_dir():
        files = sorted(path.glob("*.yaml"))
    elif path.is_file():
        files = [path]
    else:
        raise RuleValidationError(f"Chemin de règles introuvable : {path}")

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for f in files:
        rules.extend(_load_file(f, seen_ids))
    return rules


def _load_file(path: Path, seen_ids: set[str]) -> list[Rule]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    defaults = data.get("defaults", {}) or {}
    raw_rules = data.get("rules", []) or []

    rules = []
    for raw in raw_rules:
        rule = _build_rule(raw, defaults, path)
        if rule.id in seen_ids:
            raise RuleValidationError(f"[{path.name}] id de règle en double : '{rule.id}'")
        seen_ids.add(rule.id)
        rules.append(rule)
    return rules


def _build_rule(raw: dict, defaults: dict, source: Path) -> Rule:
    where = f"[{source.name}]"

    # 1. champs requis
    missing = [field for field in REQUIRED_FIELDS if field not in raw]
    if missing:
        rid = raw.get("id", "<sans id>")
        raise RuleValidationError(
            f"{where} règle '{rid}' : champ(s) manquant(s) : {', '.join(missing)}"
        )

    # 2. level valide
    level = raw["level"]
    if level not in VALID_LEVELS:
        raise RuleValidationError(
            f"{where} règle '{raw['id']}' : level {level!r} invalide (attendu 1 ou 2)"
        )

    # 3. fusion defaults → params (les params de la règle priment sur les defaults)
    params = {**defaults, **(raw.get("params") or {})}

    return Rule(
        id=raw["id"],
        cis_id=str(raw["cis_id"]),
        title=raw["title"],
        level=level,
        category=raw["category"],
        type=raw["type"],
        params=params,
        profile=raw.get("profile", "server"),
        remediation=raw.get("remediation", {}) or {},
    )