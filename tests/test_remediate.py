"""Test d'intégration : cycle complet audit → remédiation → re-check → rollback.

Utilise le vrai handler file_directive sur un fichier temporaire — aucun accès
au système réel, aucun privilège requis.
"""

from cis_tool.backup import rollback
from cis_tool.engine import remediate, run_audit
from cis_tool.report import summarize


def _write_rules(rules_dir, target):
    rules_dir.mkdir()
    (rules_dir / "ssh.yaml").write_text(
        "rules:\n"
        "  - id: r\n"
        '    cis_id: "5.1.20"\n'
        "    title: T\n"
        "    level: 1\n"
        "    category: ssh\n"
        "    type: file_directive\n"
        "    params:\n"
        f"      file: {target}\n"
        "      directive: PermitRootLogin\n"
        '      expected: "no"\n',
        encoding="utf-8",
    )


def test_apply_fixes_then_rollback_restores(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("Port 22\n", encoding="utf-8")
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir, target)
    backups = tmp_path / "backups"

    # 1. audit : non conforme (directive absente)
    before = run_audit(rules_dir)
    assert summarize(before)["non_compliant"] == 1

    # 2. remédiation : sauvegarde + apply + re-check
    after, ts, errors = remediate(before, rules_dir, backups)
    assert errors == []
    assert summarize(after)["non_compliant"] == 0
    assert "PermitRootLogin no" in target.read_text(encoding="utf-8")

    # 3. rollback : le fichier revient à son état d'origine
    rollback(backups, ts)
    restored = target.read_text(encoding="utf-8")
    assert restored == "Port 22\n"
    assert "PermitRootLogin" not in restored