"""Handler `sysctl` : un paramètre noyau (clé sysctl) = valeur attendue.

Le cas d'école du déclaratif : une clé, une valeur. On lit et on écrit
directement sous /proc/sys plutôt que d'appeler le binaire `sysctl` — pas de
dépendance à un exécutable ni au PATH, et c'est cohérent avec l'approche
« on manipule des fichiers » du reste de l'outil.

  - Audit        = lecture de /proc/sys/<clé> (autorisée sans privilège).
  - Remédiation  = écriture /proc/sys/<clé> (à chaud) + ligne dans un fichier
                   /etc/sysctl.d/ (persistance au reboot). Idempotente.
"""

from __future__ import annotations

from pathlib import Path

from ..base import Handler, register
from ..models import Rule, Result, Status

DEFAULT_PERSIST = "/etc/sysctl.d/60-cis-hardening.conf"


@register
class SysctlHandler(Handler):
    type = "sysctl"

    # --- audit (lecture seule) ----------------------------------------------
    def check(self, rule: Rule) -> Result:
        key = rule.params["key"]
        expected = str(rule.params["expected"])

        actual = self._read(key)
        if actual is None:
            # clé absente = feature/module non présent : on ne peut pas auditer
            return Result(rule, Status.ERROR, expected=expected,
                          detail=f"clé sysctl introuvable : {key}")

        ok = self._normalize(actual) == self._normalize(expected)
        status = Status.COMPLIANT if ok else Status.NON_COMPLIANT
        return Result(rule, status, actual=actual, expected=expected)

    # --- remédiation (idempotente) — jalon 5, non appelée par un audit -------
    def apply(self, rule: Rule) -> list[str]:
        key = rule.params["key"]
        expected = str(rule.params["expected"])
        persist = Path(rule.params.get("persist_file", DEFAULT_PERSIST))

        self._upsert_persist(persist, key, expected)      # persistance
        self._proc_path(key).write_text(expected + "\n")  # application à chaud
        return [str(persist)]

    def target_files(self, rule: Rule) -> list[str]:
        return [rule.params.get("persist_file", DEFAULT_PERSIST)]

    # --- internes -----------------------------------------------------------
    @staticmethod
    def _proc_path(key: str) -> Path:
        # net.ipv4.ip_forward  ->  /proc/sys/net/ipv4/ip_forward
        return Path("/proc/sys") / key.replace(".", "/")

    def _read(self, key: str) -> str | None:
        path = self._proc_path(key)
        if not path.exists():
            return None
        try:
            return path.read_text().strip()
        except OSError:
            return None

    @staticmethod
    def _normalize(value: str) -> str:
        # /proc peut séparer plusieurs valeurs par des tabulations ; on
        # normalise les blancs multiples pour une comparaison stable.
        return " ".join(value.split())

    def _upsert_persist(self, persist: Path, key: str, expected: str) -> None:
        desired = f"{key} = {expected}"
        lines = persist.read_text(encoding="utf-8").splitlines() if persist.exists() else []
        out: list[str] = []
        replaced = False
        for line in lines:
            stripped = line.strip()
            is_key = (
                bool(stripped)
                and not stripped.startswith("#")
                and stripped.split("=", 1)[0].strip() == key
            )
            if is_key:
                if not replaced:
                    out.append(desired)   # remplace la 1re occurrence
                    replaced = True
                # occurrences suivantes supprimées → jamais d'empilement
            else:
                out.append(line)
        if not replaced:
            out.append(desired)
        persist.write_text("\n".join(out) + "\n", encoding="utf-8")