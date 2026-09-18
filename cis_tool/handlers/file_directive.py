"""Handler `file_directive` : une directive `clé valeur` dans un fichier de conf.

Couvre SSH (sshd_config), sudo, login.defs, PAM… tout ce qui se règle par une
ligne `Directive Valeur`. Audit en lecture seule ; remédiation idempotente
(remplace la directive existante, ne l'empile jamais).
"""

from __future__ import annotations

from pathlib import Path

from ..base import Handler, register
from ..models import Rule, Result, Status


@register
class FileDirectiveHandler(Handler):
    type = "file_directive"

    # --- audit (lecture seule) ----------------------------------------------
    def check(self, rule: Rule) -> Result:
        p = rule.params
        path = Path(p["file"])
        directive = p["directive"]
        expected = p["expected"]
        operator = p.get("operator", "eq")

        if not path.exists():
            return Result(rule, Status.ERROR, expected=str(expected),
                          detail=f"fichier absent : {path}")

        actual = self._read_directive(path, directive)

        # Directive absente = non conforme : le CIS exige une valeur explicite,
        # on ne suppose pas que le défaut compilé de sshd fait l'affaire.
        if actual is None:
            return Result(rule, Status.NON_COMPLIANT, actual=None, expected=str(expected),
                          detail="directive non définie (aucune valeur explicite)")

        ok, detail = self._compare(actual, expected, operator)
        status = Status.COMPLIANT if ok else Status.NON_COMPLIANT
        return Result(rule, status, actual=actual, expected=str(expected), detail=detail)

    # --- remédiation (idempotente) — utilisée au jalon 5, pas par un audit ---
    def apply(self, rule: Rule) -> list[str]:
        p = rule.params
        path = Path(p["file"])
        directive = p["directive"]
        expected = p["expected"]
        sep = p.get("separator", " ")
        desired = f"{directive}{sep}{expected}"

        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        out: list[str] = []
        replaced = False
        for line in lines:
            if self._is_directive_line(line, directive):
                if not replaced:
                    out.append(desired)     # remplace la 1re occurrence
                    replaced = True
                # occurrences suivantes : supprimées (jamais empilées → idempotent)
            else:
                out.append(line)
        if not replaced:
            out.append(desired)             # absente → on l'ajoute

        path.write_text("\n".join(out) + "\n", encoding="utf-8")
        return [str(path)]

    # --- internes -----------------------------------------------------------
    @staticmethod
    def _is_directive_line(line: str, directive: str) -> bool:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return False
        token = stripped.split(None, 1)[0]
        return token.lower() == directive.lower()

    def _read_directive(self, path: Path, directive: str) -> str | None:
        # sshd_config et consorts : la 1re occurrence non commentée fait foi.
        for line in path.read_text(encoding="utf-8").splitlines():
            if self._is_directive_line(line, directive):
                parts = line.strip().split(None, 1)
                return parts[1].strip() if len(parts) > 1 else ""
        return None

    @staticmethod
    def _compare(actual: str, expected, operator: str) -> tuple[bool, str | None]:
        if operator == "eq":
            return actual.strip().lower() == str(expected).strip().lower(), None
        if operator in ("le", "ge"):
            try:
                a, e = int(actual), int(expected)
            except ValueError:
                return False, f"valeur non numérique : {actual!r}"
            return (a <= e, None) if operator == "le" else (a >= e, None)
        return False, f"opérateur inconnu : {operator!r}"