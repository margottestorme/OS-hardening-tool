"""CLI minimale — jalon 2 (audit seul).

Étoffée aux jalons suivants : --apply, --rollback, --report json/html.
Codes de sortie : 0 = tout conforme, 1 = au moins une non-conformité, 2 = erreur.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import run_audit
from .models import Status

# rules/ubuntu-22.04/ à la racine du dépôt (cis_tool/ est un cran en dessous)
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "ubuntu-22.04"

SYMBOLS = {
    Status.COMPLIANT: "PASS",
    Status.NON_COMPLIANT: "FAIL",
    Status.ERROR: "ERR ",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis_tool", description="Audit CIS — Ubuntu 22.04 LTS (v3.0.0)"
    )
    parser.add_argument("--level", type=int, choices=(1, 2),
                        help="niveau CIS maximal à auditer (1 = L1 seul, 2 = L1+L2)")
    parser.add_argument("--category", action="append", metavar="CAT",
                        help="catégorie à auditer (répétable, ex. --category ssh)")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES,
                        help="fichier .yaml ou dossier de règles")
    args = parser.parse_args(argv)

    results = run_audit(args.rules, level=args.level, categories=args.category)

    n_fail = n_err = 0
    for r in results:
        if r.status is Status.NON_COMPLIANT:
            n_fail += 1
        elif r.status is Status.ERROR:
            n_err += 1
        actual = "" if r.actual is None else f"  (relevé : {r.actual})"
        print(f"[{SYMBOLS[r.status]}] {r.rule.cis_id:<8} {r.rule.title}{actual}")

    total = len(results)
    n_ok = total - n_fail - n_err
    print(f"\n{total} règles — {n_ok} conformes, {n_fail} non conformes, {n_err} erreurs")

    if n_err:
        return 2
    if n_fail:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())