"""Structures de données partagées par tout le moteur.

Ce module ne contient QUE des données : aucune logique d'audit ni de
remédiation. C'est le vocabulaire commun entre le loader, le moteur, les
handlers et le rapport. Tout le reste manipule des `Rule` et des `Result`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Status(str, Enum):
    """Résultat de l'audit d'une règle.

    On distingue explicitement NON_COMPLIANT (le système n'est pas dans l'état
    voulu — cas normal, remédiable) de ERROR (l'audit lui-même n'a pas pu
    aboutir : fichier absent, commande en échec). Ne pas confondre les deux :
    une erreur d'audit n'est pas une non-conformité, et le rapport doit les
    afficher différemment.
    """

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    ERROR = "error"


@dataclass(frozen=True)
class Rule:
    """Une règle CIS chargée depuis le YAML (defaults déjà fusionnés).

    Le moteur ne connaît pas le détail des règles : il ne voit que cette
    structure générique. `type` indique quel handler saura la traiter, et
    `params` porte tout ce dont ce handler a besoin (clé, valeur attendue,
    chemin de fichier…). Immuable une fois chargée.
    """

    id: str
    cis_id: str
    title: str
    level: int
    category: str
    type: str
    params: dict
    profile: str = "server"
    remediation: dict = field(default_factory=dict)


@dataclass
class Result:
    """Le verdict d'un `check()` sur une règle.

    Porte une référence vers la règle auditée, le statut, et de quoi produire
    un rapport lisible (valeur relevée, valeur attendue, message éventuel).
    """

    rule: Rule
    status: Status
    actual: str | None = None      # valeur relevée sur le système
    expected: str | None = None    # valeur attendue (pour le rapport)
    detail: str | None = None      # message libre (raison d'une erreur, etc.)

    @property
    def compliant(self) -> bool:
        return self.status is Status.COMPLIANT