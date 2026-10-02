"""Handler `kmod` : un module noyau qui ne doit pas être disponible (CIS 1.1.1.x).

« Non disponible » = DEUX conditions cumulées :
  1. le module n'est pas chargé (absent de /proc/modules) ;
  2. son chargement est bloqué (une directive `install <mod> /bin/false`
     ou `/bin/true` dans un fichier de /etc/modprobe.d/, /usr/lib/modprobe.d/…).

Un module non chargé mais dont le chargement reste possible n'est PAS conforme :
il suffirait de monter un système de fichiers concerné pour le charger.

Audit sans privilège (lecture de /proc/modules et des modprobe.d).
Remédiation (jalon 5) : écrit /etc/modprobe.d/<mod>.conf (install + blacklist)
et décharge le module s'il est chargé.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ..base import Handler, register
from ..models import Rule, Result, Status

MODPROBE_DIRS = (
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
)


@register
class KmodHandler(Handler):
    type = "kmod"

    # --- audit (lecture seule) ----------------------------------------------
    def check(self, rule: Rule) -> Result:
        module = rule.params["module"]

        loaded = self._is_loaded(module)
        blocked = self._is_load_blocked(module)

        problems = []
        if loaded:
            problems.append("module chargé")
        if not blocked:
            problems.append("chargement non bloqué")

        actual = ("chargé" if loaded else "non chargé") + \
                 (", bloqué" if blocked else ", non bloqué")
        expected = "non chargé, chargement bloqué"
        if problems:
            return Result(rule, Status.NON_COMPLIANT, actual=actual,
                          expected=expected, detail="; ".join(problems))
        return Result(rule, Status.COMPLIANT, actual=actual, expected=expected)

    # --- remédiation — jalon 5, non appelée par un audit --------------------
    def apply(self, rule: Rule) -> list[str]:
        module = rule.params["module"]
        conf = Path(f"/etc/modprobe.d/{module}.conf")
        conf.write_text(
            f"install {module} /bin/false\nblacklist {module}\n",
            encoding="utf-8",
        )
        if self._is_loaded(module):  # décharge à chaud (best effort, root requis)
            subprocess.run(["modprobe", "-r", module], capture_output=True, text=True)
        return [str(conf)]

    def target_files(self, rule: Rule) -> list[str]:
        return [f"/etc/modprobe.d/{rule.params['module']}.conf"]

    # --- internes -----------------------------------------------------------
    @staticmethod
    def _is_loaded(module: str) -> bool:
        proc = Path("/proc/modules")
        if not proc.exists():
            return False
        # /proc/modules nomme les modules avec des underscores (usb_storage)
        target = module.replace("-", "_")
        for line in proc.read_text().splitlines():
            if line and line.split()[0] == target:
                return True
        return False

    @staticmethod
    def _is_load_blocked(module: str) -> bool:
        # accepte le module écrit avec '-' ou '_' (usb-storage / usb_storage)
        canonical = module.replace("-", "_")
        name = re.escape(canonical).replace("_", "[-_]")
        pattern = re.compile(rf"^\s*install\s+{name}\s+/bin/(true|false)\b")
        for d in MODPROBE_DIRS:
            path = Path(d)
            if not path.is_dir():
                continue
            for conf in path.glob("*.conf"):
                try:
                    for line in conf.read_text(encoding="utf-8").splitlines():
                        if pattern.match(line):
                            return True
                except OSError:
                    continue
        return False