"""Tests de la sauvegarde/rollback (backup.py), sur des fichiers temporaires."""

import json
from pathlib import Path

from cis_tool.backup import BackupSession, rollback


def test_backup_and_rollback_restores_content_and_mode(tmp_path):
    target = tmp_path / "etc" / "conf"
    target.parent.mkdir()
    target.write_text("original\n", encoding="utf-8")
    target.chmod(0o640)
    backups = tmp_path / "backups"

    sess = BackupSession(backups)
    sess.save("1.1", [str(target)])
    sess.write_manifest()

    # simulation d'une remédiation
    target.write_text("modifié\n", encoding="utf-8")
    target.chmod(0o600)

    rollback(backups, sess.timestamp)
    assert target.read_text(encoding="utf-8") == "original\n"
    assert (target.stat().st_mode & 0o777) == 0o640


def test_rollback_deletes_file_created_by_remediation(tmp_path):
    target = tmp_path / "etc" / "new.conf"      # n'existe pas avant
    target.parent.mkdir()
    backups = tmp_path / "backups"

    sess = BackupSession(backups)
    sess.save("3.3", [str(target)])             # existed_before = False
    sess.write_manifest()

    target.write_text("créé par apply\n", encoding="utf-8")
    rollback(backups, sess.timestamp)
    assert not target.exists()


def test_file_backed_up_once_captures_true_original(tmp_path):
    # deux règles écrivant dans le même fichier (cas sysctl partagé)
    target = tmp_path / "shared.conf"
    target.write_text("v0\n", encoding="utf-8")
    backups = tmp_path / "backups"

    sess = BackupSession(backups)
    sess.save("3.3.1", [str(target)])           # capture v0
    target.write_text("v1\n", encoding="utf-8")  # 1re remédiation
    sess.save("3.3.2", [str(target)])           # ne doit PAS recapturer v1
    sess.write_manifest()

    target.write_text("v2\n", encoding="utf-8")  # 2e remédiation
    rollback(backups, sess.timestamp)
    assert target.read_text(encoding="utf-8") == "v0\n"   # bien l'original, pas v1


def test_manifest_records_existence(tmp_path):
    target = tmp_path / "c"
    target.write_text("x", encoding="utf-8")
    backups = tmp_path / "backups"

    sess = BackupSession(backups)
    sess.save("1.1", [str(target)])
    mpath = sess.write_manifest()

    data = json.loads(Path(mpath).read_text(encoding="utf-8"))
    assert data["files"][0]["path"] == str(target)
    assert data["files"][0]["existed_before"] is True