"""Handler `file_perms` : owner / group / mode d'un fichier sensible.

Troisième mécanisme d'audit de l'outil, très différent des deux premiers :
ici on ne lit pas un contenu, on interroge les métadonnées via `stat`.

  - Audit       = stat du fichier (autorisé sans privilège pour /etc/*).
                  Le mode est comparé « au plus permissif » : conforme si le
                  mode réel n'a AUCUN bit de permission au-delà de mode_max
                  (un mode plus strict que l'attendu reste conforme).
  - Remédiation = chmod / chown (jalon 5).
"""

from __future__ import annotations

import grp
import os
import pwd
from pathlib import Path

from ..base import Handler, register
from ..models import Rule, Result, Status


@register
class FilePermsHandler(Handler):
    type = "file_perms"

    # --- audit (lecture seule) ----------------------------------------------
    def check(self, rule: Rule) -> Result:
        p = rule.params
        path = Path(p["path"])
        exp_owner = p.get("owner")
        exp_group = p.get("group")
        mode_max = int(str(p["mode_max"]), 8) if "mode_max" in p else None

        if not path.exists():
            return Result(rule, Status.ERROR, detail=f"fichier absent : {path}")

        st = path.stat()
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
        mode = st.st_mode & 0o777

        problems = []
        if exp_owner is not None and owner != exp_owner:
            problems.append(f"owner={owner} (attendu {exp_owner})")
        if exp_group is not None and group != exp_group:
            problems.append(f"group={group} (attendu {exp_group})")
        # mode conforme si aucun bit au-delà de mode_max (⇒ plus strict = OK)
        if mode_max is not None and (mode & ~mode_max):
            problems.append(f"mode={mode:04o} plus permissif que {mode_max:04o}")

        actual = f"{mode:04o} {owner}:{group}"
        expected = self._describe_expected(exp_owner, exp_group, mode_max)
        if problems:
            return Result(rule, Status.NON_COMPLIANT, actual=actual,
                          expected=expected, detail="; ".join(problems))
        return Result(rule, Status.COMPLIANT, actual=actual, expected=expected)

    # --- remédiation — jalon 5, non appelée par un audit --------------------
    def apply(self, rule: Rule) -> list[str]:
        p = rule.params
        path = Path(p["path"])
        if "mode_max" in p:
            path.chmod(int(str(p["mode_max"]), 8))
        if p.get("owner") or p.get("group"):
            uid = pwd.getpwnam(p["owner"]).pw_uid if p.get("owner") else -1
            gid = grp.getgrnam(p["group"]).gr_gid if p.get("group") else -1
            os.chown(path, uid, gid)
        return [str(path)]

    # --- interne ------------------------------------------------------------
    @staticmethod
    def _describe_expected(owner, group, mode_max) -> str:
        parts = []
        if mode_max is not None:
            parts.append(f"mode<={mode_max:04o}")
        if owner:
            parts.append(f"owner={owner}")
        if group:
            parts.append(f"group={group}")
        return ", ".join(parts)