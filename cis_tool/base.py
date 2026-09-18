"""Contrat que tout handler doit respecter — le cœur de l'architecture.

Le moteur ne parle qu'à cette interface : il ne sait rien du détail SSH,
sysctl ou permissions. Conséquence directe : ajouter une catégorie de
contrôle = écrire un nouveau Handler et l'enregistrer, SANS toucher au moteur.
C'est l'argument central à défendre en soutenance.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import Rule, Result


class HandlerError(Exception):
    """Erreur liée aux handlers (type inconnu, params invalides, etc.)."""


class Handler(ABC):
    """Interface commune à tous les handlers.

    Chaque sous-classe :
      - déclare l'attribut de classe `type` (le `type:` du YAML qu'elle gère) ;
      - implémente `check()` — audit, en lecture seule ;
      - implémente `apply()` — remédiation, idempotente.
    """

    #: le `type:` YAML pris en charge (ex. "file_directive"). À définir en sous-classe.
    type: str

    @abstractmethod
    def check(self, rule: Rule) -> Result:
        """Audite `rule` sur le système et renvoie un Result. Ne modifie RIEN."""
        ...

    @abstractmethod
    def apply(self, rule: Rule) -> list[str]:
        """Applique la remédiation ; renvoie la liste des fichiers modifiés.

        Contrats importants (utilisés aux jalons 5–6) :
          - idempotent : relancer sur un système déjà conforme ne change rien ;
          - n'est appelé par le moteur qu'après un check non conforme ;
          - le moteur sauvegarde d'abord `target_files()`, puis appelle apply().
        """
        ...

    def target_files(self, rule: Rule) -> list[str]:
        """Fichiers que la remédiation modifiera — sert au backup/rollback.

        Défaut raisonnable : le champ `file` ou `path` des params. Les handlers
        dont la cible se calcule autrement (ex. sysctl → persist_file) le
        surchargent.
        """
        target = rule.params.get("file") or rule.params.get("path")
        return [target] if target else []


# --- Registre des handlers ---------------------------------------------------
# Permet au moteur de retrouver le bon handler à partir du `type:` d'une règle,
# sans jamais connaître les classes concrètes (couplage faible). Un handler
# s'enregistre lui-même via le décorateur @register.

_REGISTRY: dict[str, type[Handler]] = {}


def register(handler_cls: type[Handler]) -> type[Handler]:
    """Décorateur de classe : enregistre un handler sous son `type`."""
    handler_type = getattr(handler_cls, "type", None)
    if not handler_type:
        raise HandlerError(
            f"{handler_cls.__name__} doit définir un attribut de classe `type`"
        )
    _REGISTRY[handler_type] = handler_cls
    return handler_cls


def get_handler(type_name: str) -> Handler:
    """Retourne une instance du handler gérant `type_name`."""
    try:
        return _REGISTRY[type_name]()
    except KeyError:
        connus = ", ".join(sorted(_REGISTRY)) or "(aucun enregistré)"
        raise HandlerError(
            f"Aucun handler pour le type '{type_name}'. Types connus : {connus}"
        )