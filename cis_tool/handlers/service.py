"""Handler `service` : un service/paquet indésirable (CIS section 2.x).

Deux cas distincts, choisis par le champ `state` :
  - state: absent   → le PAQUET ne doit pas être installé   (audit via dpkg-query) ;
  - state: disabled → le SERVICE doit être désactivé/masqué  (audit via systemctl).

Premier handler à s'appuyer sur des commandes système plutôt que sur des
fichiers. Audit sans privilège : `dpkg-query` et `systemctl is-enabled` sont
interrogeables par tout utilisateur. Remédiation (jalon 5) : purge du paquet
ou mask du service.
"""

from __future__ import annotations

import subprocess

from ..base import Handler, HandlerError, register
from ..models import Rule, Result, Status

@register
class ServiceHandler(Handler):
    type = "service"

    # --- audit (lecture seule) ----------------------------------------------
    def check(self, rule: Rule) -> Result:
        state = rule.params.get("state", "absent")
        if state == "absent":
            return self._check_package_absent(rule)
        if state == "disabled":
            return self._check_service_disabled(rule)
        return Result(rule, Status.ERROR, detail=f"state inconnu : {state!r}")

    # --- remédiation — jalon 5, non appelée par un audit --------------------
    def apply(self, rule: Rule) -> list[str]:
        state = rule.params.get("state", "absent")
        if state == "absent":
            subprocess.run(["apt-get", "purge", "-y", rule.params["package"]],
                           capture_output=True, text=True)
        elif state == "disabled":
            subprocess.run(["systemctl", "--now", "mask", rule.params["unit"]],
                           capture_output=True, text=True)
        # action système, pas d'édition de fichier → rien à sauvegarder par copie.
        # (le rollback d'un service relève d'une logique dédiée : réinstaller /
        #  unmask, à traiter à part au jalon 5.)
        return []

    # --- cas 'absent' : le paquet ne doit pas être installé -----------------
    def _check_package_absent(self, rule: Rule) -> Result:
        package = rule.params["package"]
        rc, out = self._run(["dpkg-query", "-W", "-f=${Status}", package])
        # dpkg-query renvoie != 0 si le paquet est inconnu → jamais installé.
        # Sinon le 3e champ du statut vaut "installed" si réellement installé.
        installed = rc == 0 and out.split()[-1:] == ["installed"]
        actual = "installé" if installed else "non installé"
        status = Status.NON_COMPLIANT if installed else Status.COMPLIANT
        return Result(rule, status, actual=actual, expected="non installé")

    # --- cas 'disabled' : le service doit être désactivé/masqué -------------
    def _check_service_disabled(self, rule: Rule) -> Result:
        unit = rule.params["unit"]
        _, out = self._run(["systemctl", "is-enabled", unit])
        # stdout vide = unité inexistante (systemctl écrit l'erreur sur stderr) :
        # on la traite comme "not-found", donc conforme.
        state = out.strip() or "not-found"
        # Non conforme UNIQUEMENT si le service est activé ; tout le reste
        # (disabled, masked, not-found, static…) est acceptable.
        status = Status.NON_COMPLIANT if state == "enabled" else Status.COMPLIANT
        return Result(rule, status, actual=state, expected="disabled/masked")

    # --- exécution de commande ----------------------------------------------
    @staticmethod
    def _run(cmd: list[str]) -> tuple[int, str]:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError as exc:
            # commande absente = problème d'infra, pas une non-conformité.
            # Le moteur transforme ce HandlerError en Result ERROR.
            raise HandlerError(f"commande introuvable : {cmd[0]}") from exc
        return proc.returncode, proc.stdout