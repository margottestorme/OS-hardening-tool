# OS-hardening-tool . Ubuntu 22.04 LTS

Outil en ligne de commande qui **audite** une machine Ubuntu contre le benchmark CIS,
puis **remédie** les écarts sur demande, à partir de règles déclaratives.

---

## 1. Benchmark retenu

- **Référentiel** : CIS Ubuntu Linux 22.04 LTS Benchmark **v3.0.0**
- **Profil** : **Level 1**, **Server** (le Level 2 est traité en bonus)
- **Cible** : VM Ubuntu 22.04 LTS, sans interface graphique

### Note de version

| Domaine | Section v3.0.0 |
|---|---|
| SSH | **5.1.x** |
| sudo / élévation de privilèges | **5.2.x** |
| PAM (verrouillage, qualité mot de passe) | **5.3.x** |
| Vieillissement des mots de passe (shadow suite) | **5.4.1.x** |
| Pare-feu | **section 4** — Host Based Firewall (sortie de la section réseau) |
| Logging / audit | **section 6** |

> Le PDF officiel `CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v3.0.0.pdf` fait foi pour
> tout libellé, niveau et valeur attendue.

---

## 2. Périmètre

### 2.1 Cœur obligatoire (Level 1 Server)

Principe : couvrir un **large spectre de catégories** pour démontrer que le moteur est
générique, en ne retenant dans chacune que des règles **automatisables et remédiables
à chaud** (audit → valeur attendue → remédiation).

| Catégorie | Section CIS v3.0.0 | Handler | Jalon |
|---|---|---|---|
| Modules noyau filesystem (cramfs, udf, usb-storage…) | 1.1.1.x | `kmod` | 3 |
| Services serveur / clients (avahi, cups, telnet, rsh…) | 2.1.x / 2.2.x | `service` | 3 |
| Paramètres réseau (sysctl : forwarding, redirects, rp_filter…) | 3.3.x | `sysctl` | 3 |
| SSH (~22 règles dans `sshd_config`) | 5.1.x | `file_directive` | 2 |
| sudo / élévation (use_pty, log file, timestamp_timeout…) | 5.2.x | `file_directive` | 2 |
| PAM — faillock & pwquality (minlen, complexité, verrouillage) | 5.3.3.x | `file_directive` | 2 |
| Vieillissement des mots de passe (`login.defs`) | 5.4.1.x | `file_directive` | 2 |
| Permissions fichiers sensibles (`/etc/passwd`, `/etc/shadow`…) | 7.1.x | `file_perms` | 3 |

### 2.2 Exclusions volontaires

| Exclu | Section | Raison |
|---|---|---|
| Partitions séparées (`/home`, `/var`, `/var/log`…) | 1.1.2.3 – 1.1.2.7 | Non remédiables à chaud (repartitionnement à l'installation) ; auditables seulement, mauvais candidats pour `--apply` |
| GDM / GNOME | 1.7.x | VM serveur sans interface graphique → hors sujet |
| AIDE (intégrité fichiers) | 6.3.x | Lourd et lent à l'exécution, casse le rythme d'une démo |
| Mot de passe bootloader | 1.4.x | Risqué à démontrer, faible valeur |
| Règles marquées **« Manual »** | — | Non auto-auditables proprement ; au mieux affichées en « info à vérifier » |

### 2.3 Bonus (variable d'ajustement)

`ufw (4.1.x)` → `logging/audit (6.x)` → quelques règles **Level 2** → rapport **HTML** →
**multi-OS** → comparaison **Lynis / OpenSCAP**.

---

## 3. Architecture

### 3.1 Principe directeur

Le **moteur ne connaît aucune règle CIS en dur**. Il sait :
charger des règles déclaratives (YAML) → exécuter un audit → comparer à une valeur
attendue → produire un statut → et, sur `--apply`, remédier puis re-vérifier.

**Ajouter un contrôle CIS = ajouter une entrée YAML, jamais toucher au code.**

### 3.2 Handlers typés

Chaque règle déclare un `type` ; le moteur dispatche vers le handler correspondant.
Cinq handlers suffisent à couvrir tout le périmètre Level 1 :

| Handler | Rôle | Audit | Remédiation |
|---|---|---|---|
| `kmod` | module noyau non disponible | lecture `modprobe` | fichier dans `/etc/modprobe.d/` |
| `service` | service/paquet absent ou masqué | état `systemd` / `dpkg` | `disable` / `mask` / `purge` |
| `sysctl` | clé sysctl = valeur | `sysctl -n <clé>` | écriture `/etc/sysctl.d/` + `sysctl -w` |
| `file_directive` | directive `clé valeur` dans un fichier de conf | lecture + parse | remplace la directive (ou l'ajoute si absente) |
| `file_perms` | owner/group/mode d'un fichier | `stat` | `chmod` / `chown` |

**Interface commune** à tous les handlers :
`check(params) -> (conforme, valeur_actuelle)` et `apply(params) -> fichiers_modifiés`.
Le moteur ne parle qu'à cette interface : il ne sait rien du détail SSH ou sysctl.

### 3.3 Schéma de règle YAML (le contrat)

```yaml
- id: ssh_permit_root_login        # clé interne stable
  cis_id: "5.1.20"                 # référence CIS citable dans le rapport
  title: "Ensure sshd PermitRootLogin is disabled"
  level: 1                         # alimente --level
  profile: server
  category: ssh
  type: file_directive             # sélectionne le handler
  params:
    directive: PermitRootLogin
    operator: eq                   # eq | le | ge  (défaut : eq)
    expected: "no"
  remediation:
    reload: "systemctl reload ssh" # hook post-remédiation
```

### 3.4 Flux d'exécution

**Audit (mode par défaut, lecture seule)**
`cli` → `rules_loader` (charge + valide le YAML) → `engine` (filtre level/catégorie)
→ `handler.check()` (audit + comparaison) → `report` (console / JSON).

**Remédiation (`--apply`, uniquement sur les règles non conformes)**
`backup` (copie du fichier + ligne dans `manifest.json`) → `handler.apply()`
→ `re-check` (confirme que la règle est désormais conforme) → `report`.

**Rollback**
`--rollback <horodatage>` relit le manifeste et restaure les fichiers d'origine.

### 3.5 Décisions clés

- **Backup par fichier + manifeste** (et non snapshot VM global) → rollback ciblé et
  démontrable : on peut ouvrir le dossier `backups/` et montrer le fichier d'origine.
- **Idempotence** : le handler `file_directive` **remplace** la directive existante,
  jamais un `append` aveugle (sinon la directive s'empile et l'idempotence est cassée).
  Relancer 2× doit converger sans rien recasser.
- **Codes de sortie** : `0` = tout conforme, `1` = au moins une non-conformité,
  `2` = erreur d'exécution → l'audit devient intégrable dans une CI.
- **Validation au chargement** : `rules_loader` vérifie champs requis, `type` connu,
  `level ∈ {1,2}` → pas de plantage en démo, et rigueur visible.
- **Détection d'OS** (bonus) : lecture de `/etc/os-release`. L'arborescence
  `rules/ubuntu-22.04/` est prévue dès maintenant pour rendre le multi-OS trivial.

---

## 4. Arborescence du dépôt

```
OS-hardening/
├── cis_tool/
│   ├── cli.py            # argparse/click : --level, --category, --apply, --rollback
│   ├── engine.py         # orchestration : charge, filtre, dispatch, collecte
│   ├── rules_loader.py   # parse + VALIDE le YAML contre le schéma
│   ├── models.py         # dataclasses Rule, Result
│   ├── handlers/
│   │   ├── base.py       # interface Handler (check / apply)
│   │   ├── file_directive.py
│   │   ├── sysctl.py
│   │   ├── kmod.py
│   │   ├── service.py
│   │   └── file_perms.py
│   ├── backup.py         # sauvegarde par fichier + manifeste + rollback
│   └── report.py         # console / JSON (HTML en bonus)
├── rules/
│   └── ubuntu-22.04/
│       ├── ssh.yaml
│       ├── filesystem.yaml
│       ├── network.yaml
│       └── ...
├── backups/              # <horodatage>/<chemin_original> + manifest.json
├── reports/
├── tests/
├── README.md
└── requirements.txt
```

---

## 5. Stack technique

- **Python 3.10+**
- **PyYAML** — chargement des règles
- **rich** (optionnel) — rendu console lisible
- **argparse** ou **click** — CLI
- **jinja2** — rapport HTML (bonus, plus tard)

Exécution attendue : en **root** sur la VM cible (certains audits et toutes les
remédiations nécessitent les privilèges).

---

## 6. À défendre en soutenance

- **Choix du périmètre** : pourquoi ces catégories, pourquoi ces exclusions (§2.2).
- **Séparation moteur / règles déclaratives** : extensibilité sans écrire de code.
- **Backup/rollback traçable** par manifeste, plutôt que snapshot VM.
- **Idempotence prouvée** en relançant l'outil deux fois de suite.
- **Intégrabilité CI** via les codes de sortie.
