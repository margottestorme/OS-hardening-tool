"""CLI — audit, rapport, remédiation, rollback.

Codes de sortie : 0 = tout conforme, 1 = au moins une non-conformité, 2 = erreur.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .backup import rollback
from .engine import remediate, run_audit
from .models import Status
from .report import render_console, render_json, summarize

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = REPO_ROOT / "rules" / "ubuntu-22.04"
BACKUPS_DIR = REPO_ROOT / "backups"

_YES = {"o", "oui", "y", "yes"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cis_tool", description="Audit et durcissement CIS — Ubuntu 22.04 LTS (v3.0.0)"
    )
    parser.add_argument("--level", type=int, choices=(1, 2),
                        help="niveau CIS maximal (1 = L1 seul, 2 = L1+L2)")
    parser.add_argument("--category", action="append", metavar="CAT",
                        help="catégorie à traiter (répétable, ex. --category ssh)")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES,
                        help="fichier .yaml ou dossier de règles")
    parser.add_argument("--report", choices=("console", "json"), default="console",
                        help="format du rapport d'audit (défaut : console)")
    parser.add_argument("--output", type=Path, metavar="FICHIER",
                        help="écrire le rapport dans un fichier")
    parser.add_argument("--apply", action="store_true",
                        help="corriger les non-conformités (MODIFIE le système)")
    parser.add_argument("--yes", action="store_true",
                        help="ne pas demander de confirmation avec --apply")
    parser.add_argument("--rollback", metavar="HORODATAGE",
                        help="restaurer une sauvegarde puis quitter")
    args = parser.parse_args(argv)

    if args.rollback:
        return _do_rollback(args.rollback)
    if args.apply:
        return _do_apply(args)
    return _do_audit(args)


def _do_audit(args) -> int:
    results = run_audit(args.rules, level=args.level, categories=args.category)
    if args.report == "json":
        text = render_json(results)
    else:
        use_color = args.output is None and sys.stdout.isatty()
        text = render_console(results, color=use_color)

    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"Rapport écrit dans {args.output}")
    else:
        print(text)

    s = summarize(results)
    return 2 if s["error"] else (1 if s["non_compliant"] else 0)


def _do_apply(args) -> int:
    before = run_audit(args.rules, level=args.level, categories=args.category)
    to_fix = [r for r in before if r.status is Status.NON_COMPLIANT]

    if not to_fix:
        print("Rien à remédier : aucune non-conformité détectée.")
        return 0

    print(f"{len(to_fix)} non-conformité(s) seront corrigées :")
    for r in to_fix:
        print(f"  - {r.rule.cis_id:<8} {r.rule.title}")

    if not args.yes:
        reply = input("\nAppliquer la remédiation ? [o/N] ").strip().lower()
        if reply not in _YES:
            print("Annulé — rien n'a été modifié.")
            return 0

    after, ts, errors = remediate(before, args.rules, BACKUPS_DIR,
                                  level=args.level, categories=args.category)
    sb, sa = summarize(before), summarize(after)

    print("\nRemédiation appliquée.")
    print(f"  avant : {sb['non_compliant']} non conformes")
    print(f"  après : {sa['non_compliant']} non conformes")

    if errors:
        print(f"\n{len(errors)} remédiation(s) en échec :")
        for cis_id, exc in errors:
            print(f"  - {cis_id} : {exc}")
        if any(isinstance(e, PermissionError) for _, e in errors):
            print("Astuce : la remédiation modifie /etc — relance avec sudo.")

    print(f"\nSauvegarde : {ts}")
    print(f"Rollback   : python3 -m cis_tool --rollback {ts}")
    return 0 if sa["non_compliant"] == 0 else 1


def _do_rollback(timestamp: str) -> int:
    try:
        restored = rollback(BACKUPS_DIR, timestamp)
    except FileNotFoundError as exc:
        print(f"Erreur : {exc}")
        return 2
    print(f"{len(restored)} fichier(s) restauré(s) depuis la sauvegarde {timestamp}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())