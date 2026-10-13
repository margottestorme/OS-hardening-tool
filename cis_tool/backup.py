"""Sauvegarde par fichier + manifeste, et rollback.

Avant toute remédiation, les fichiers qui vont être modifiés sont copiés dans
backups/<horodatage>/ (arborescence d'origine préservée) et décrits dans un
manifest.json. Le rollback relit ce manifeste pour :
  - restaurer le contenu ET les métadonnées (mode/owner) des fichiers qui
    existaient déjà avant la remédiation ;
  - supprimer les fichiers que la remédiation avait créés de toutes pièces
    (ex. /etc/modprobe.d/cramfs.conf).

Un même fichier n'est sauvegardé qu'UNE fois par session (dédup par chemin) :
c'est indispensable quand plusieurs règles écrivent dans le même fichier
(ex. toutes les règles sysctl partagent /etc/sysctl.d/60-cis-hardening.conf).
Sans ça, la 2e sauvegarde capturerait un fichier déjà modifié.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path


class BackupSession:
    """Une session de sauvegarde horodatée + son manifeste."""

    def __init__(self, backups_root: str | Path):
        self.dir = Path(backups_root) / datetime.now().strftime("%Y%m%d-%H%M%S")
        self._files: dict[str, dict] = {}

    @property
    def timestamp(self) -> str:
        return self.dir.name

    def save(self, cis_id: str, files: list[str]) -> None:
        """Sauvegarde les fichiers d'une règle, AVANT que celle-ci ne les modifie."""
        for f in files:
            path = Path(f)
            key = str(path)
            if key in self._files:            # état d'origine déjà capturé
                self._files[key]["rules"].append(cis_id)
                continue
            existed = path.exists()
            record = {"path": key, "existed_before": existed, "rules": [cis_id]}
            if existed:
                dest = self.dir / path.relative_to(path.anchor)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, dest)       # contenu + mode + horodatages
                st = path.stat()
                record.update(mode=st.st_mode & 0o777, uid=st.st_uid, gid=st.st_gid)
            self._files[key] = record

    def write_manifest(self) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        manifest = {"timestamp": self.timestamp, "files": list(self._files.values())}
        path = self.dir / "manifest.json"
        path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        return path


def rollback(backups_root: str | Path, timestamp: str) -> list[str]:
    """Restaure l'état d'avant la remédiation d'une session donnée.

    Renvoie la liste des chemins restaurés ou supprimés.
    """
    session = Path(backups_root) / timestamp
    manifest_path = session / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifeste introuvable : {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    touched: list[str] = []
    for rec in manifest["files"]:
        path = Path(rec["path"])
        if rec["existed_before"]:
            backup_file = session / path.relative_to(path.anchor)
            shutil.copy2(backup_file, path)       # restaure contenu + mode
            os.chmod(path, rec["mode"])           # restauration explicite (ceinture + bretelles)
            os.chown(path, rec["uid"], rec["gid"])  # copy2 ne restaure PAS l'owner
        elif path.exists():
            path.unlink()                          # créé par la remédiation → on le retire
        touched.append(str(path))
    return touched