"""CLI — jalons 2 à 4 (audit + rapport).

Étoffée au jalon 5 : --apply, --rollback.
Codes de sortie : 0 = tout conforme, 1 = au moins une non-conformité, 2 = erreur.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import run_audit
from .report import render_console, render_json, summarize

# rules/ubuntu-22.04/ à la racine du dépôt (cis_tool/ est un cran en dessous)
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "ubuntu-22.04"


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
    parser.add_argument("--report", choices=("console", "json"), default="console",
                        help="format de sortie (défaut : console)")
    parser.add_argument("--output", type=Path, metavar="FICHIER",
                        help="écrire le rapport dans un fichier au lieu de la sortie standard")
    args = parser.parse_args(argv)

    results = run_audit(args.rules, level=args.level, categories=args.category)

    if args.report == "json":
        text = render_json(results)
    else:
        # couleurs seulement en sortie console interactive (pas vers un fichier/pipe)
        use_color = args.output is None and sys.stdout.isatty()
        text = render_console(results, color=use_color)

    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"Rapport écrit dans {args.output}")
    else:
        print(text)

    s = summarize(results)
    if s["error"]:
        return 2
    if s["non_compliant"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())