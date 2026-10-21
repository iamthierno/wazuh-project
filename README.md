# Wazuh — déploiement de A à Z

Projet clé en main pour déployer une plateforme de supervision de sécurité
**Wazuh 4.14.9** (SIEM / XDR), puis y raccorder les machines et les équipements
réseau :

- **Serveur** : installation **native Linux** ou **Docker**, au choix, avec un seul script (`deploy.sh`).
- **Agents** : découverte du réseau et installation **à distance** sur Linux, Windows et macOS. Une seule commande installe, enrôle et vérifie l'agent (`agents/install-agent.sh`).
- **Équipements réseau** : réception syslog prête, guides FortiGate, Palo Alto, Cisco ASA/IOS et autres, plus des règles de détection complémentaires.

```
                     ┌─────────────── Serveur Wazuh (all-in-one) ───────────────┐
  Agents ──1514/1515─►  Manager ──► Indexer (9200) ──► Dashboard (443)          │◄── Navigateur
  Linux/Win/Mac      │     ▲                                                     │
                     └─────┼─────────────────────────────────────────────────────┘
       FortiGate · Palo Alto · Cisco ──syslog 514/udp
```

---

## 1. Démarrage rapide

```bash
git clone <ce-dépôt> wazuh-project && cd wazuh-project
nano config.env              # (optionnel) IP, ports, syslog, version…
sudo ./deploy.sh             # menu : 1) natif  2) Docker
```

| Option du menu | Équivalent non interactif |
|---|---|
| 1) Installation native Linux | `sudo ./deploy.sh --native` |
| 2) Installation Docker (vérifie et installe Docker si besoin) | `sudo ./deploy.sh --docker` |
| 3) Vérifier l'état | `sudo ./deploy.sh --status` |
| 4) Reconfigurer (syslog, groupes, règles) | `sudo ./deploy.sh --reconfigure` |
| 6) Sauvegarder | `sudo ./deploy.sh --backup` |
| 7) Désinstaller | `sudo ./deploy.sh --uninstall` |

Options globales : `-y` (sans confirmation), `-v` / `-vv` (verbeux / debug),
`--ignore-checks` (ignore les contrôles bloquants).

En fin d'installation, le script affiche **l'URL du dashboard, l'utilisateur
`admin` et son mot de passe**. Tous les secrets sont conservés dans
`/etc/wazuh-deploy/state.env` (root, `chmod 600`).

Prérequis : [docs/prerequis.md](docs/prerequis.md). Le minimum est de 4 vCPU,
8 Go de RAM et 50 Go de disque, sous Ubuntu 20.04–24.04, Debian 11–13 ou
RHEL/Rocky/Alma 8–10.

### Ce que fait `deploy.sh`

| Étape | Natif | Docker |
|---|---|---|
| Contrôles (OS, CPU/RAM/disque, ports, Internet, NTP) | ✔ | ✔ |
| Docker + Compose v2 : vérification, installation depuis le dépôt officiel | — | ✔ |
| `vm.max_map_count=262144` (persistant) | (assistant officiel) | ✔ |
| Installation indexer + manager + dashboard | assistant officiel `wazuh-install.sh -a` | `docker compose` (images 4.14.9) |
| Certificats TLS | assistant officiel | générateur officiel, OpenSSL en secours |
| Mots de passe forts et uniques (admin, API, dashboard) | générés par l'assistant | générés, hachés en bcrypt, comptes de démo supprimés |
| Réception syslog des équipements (`514/udp`, IP autorisées) | ✔ | ✔ |
| Enrôlement des agents protégé par mot de passe | ✔ | ✔ |
| Groupes `linux` / `windows` / `macos` avec configuration centralisée | ✔ | ✔ |
| Règles complémentaires FortiGate / Palo Alto / Cisco | ✔ | ✔ |
| Pare-feu local (ufw / firewalld) | ✔ | — |
| Dépôt Wazuh verrouillé (pas de mise à jour accidentelle) | ✔ | — (version d'image figée) |

---

## 2. Déployer les agents à distance

Le script se lance **depuis le serveur Wazuh**, en natif comme en Docker. Il
découvre les machines, détecte leur OS, se connecte (SSH ou WinRM), vérifie les
prérequis, installe l'agent, l'enrôle dans le bon groupe, puis **attend qu'il
soit « Active » sur le manager**. Il n'y a aucune autre configuration à faire.

```bash
cd agents
sudo ./install-agent.sh 192.168.1.0/24 -d                     # qui est sur le réseau ?
sudo ./install-agent.sh 192.168.1.0/24 -l -u admin -p -n 10   # tous les Linux, 10 en parallèle
sudo ./install-agent.sh 192.168.1.10-50 -w -u 'CORP\admin' -p # tous les Windows de la plage
sudo ./install-agent.sh 192.168.1.30 -m -u admin -p -dry      # simulation sur un Mac
sudo ./install-agent.sh 192.168.1.0/24 -s                     # statut de tous les agents
sudo ./install-agent.sh 192.168.1.10 -rf -u admin -p          # désinstallation complète
```

| Option | Rôle |
|---|---|
| `<ip>`, `<ip/24>`, `<ip1-ip10>`, `<ip1 - ip10>`, `-f fichier` | cibles |
| `-l` `-w` `-m` | filtres Linux / Windows / macOS (combinables : `-lw`) |
| `-d` | découverte seule |
| `-c` | vérifier si l'agent est installé |
| `-s` | statut (service et manager) ; sans identifiants, vue du manager uniquement |
| `--log` | dernières lignes du journal de l'agent (`--lines N`) |
| `-U` / `--update` | mise à jour vers la version du manager |
| `-r` / `-rf` / `--purge` | désinstaller / désinstaller et purger (supprime aussi l'agent du manager) |
| `-u` / `-p` / `-k` / `--creds` | utilisateur / mot de passe (demandé s'il est omis) / clé SSH / fichier d'identifiants |
| `-n N` | installations en parallèle |
| `-dry` | simulation |
| `-g` `-M` `-x` `--force` `--offline` `-y` `-v` `-vv` `-q` `-o rapport.csv` | voir `--help` |

Guide complet : [docs/agents.md](docs/agents.md), qui détaille les prérequis
Windows et macOS, le fonctionnement et les cas d'erreur. Pour Windows, exécutez
une fois [`agents/active-winRm.ps1`](agents/active-winRm.ps1) sur chaque poste,
ou déployez-le par GPO.

---

## 3. Intégrer les équipements réseau

Le serveur écoute déjà en syslog. Il reste à configurer chaque équipement :
[network-devices/README.md](network-devices/README.md).

- [FortiGate](network-devices/fortigate.md)
- [Palo Alto](network-devices/paloalto.md)
- [Cisco ASA](network-devices/cisco-asa.md)
- [Cisco IOS / IOS-XE](network-devices/cisco-ios.md)
- [Autres équipements](network-devices/autres.md) (pfSense, Sophos, Juniper, SonicWall, Check Point, F5…)

Pour vérifier le décodage et les alertes : `sudo ./scripts/test-device-logs.sh`.

---

## 4. Exploitation

| Script | Rôle |
|---|---|
| `scripts/healthcheck.sh [-v]` | état complet : services, ports, indexer, API, agents, syslog, disque, certificats |
| `scripts/backup.sh [dossier]` | sauvegarde de la configuration (clés des agents, règles, groupes, certificats) ; rétention de 14 sauvegardes |
| `scripts/restore.sh <archive>` | restauration (même mode, même version) |
| `scripts/uninstall.sh [--keep-data]` | désinstallation, avec sauvegarde proposée au préalable |
| `scripts/test-device-logs.sh [équipement\|fichier] [--send]` | test des décodeurs et règles sur des logs |

Journaux d'exécution : `/var/log/wazuh-deploy/` (un fichier par exécution, sans
aucun mot de passe en clair).

Dépannage : [docs/troubleshooting.md](docs/troubleshooting.md).

---

## 5. Arborescence

```
wazuh-project/
├── deploy.sh                    # Point d'entrée : menu natif / Docker / état / sauvegarde / désinstallation
├── config.env                   # Tous les paramètres
├── lib/                         # common, precheck, native, docker, certs, server_config
├── docker/
│   ├── docker-compose.yml       # Stack single-node paramétrée (.env généré)
│   ├── generate-indexer-certs.yml
│   ├── config/                  # Configurations officielles 4.14.9 + modèles (mots de passe)
│   └── deployer/Dockerfile      # Outils de déploiement des agents (mode Docker)
├── manager/
│   ├── rules/                   # Règles complémentaires (équipements réseau)
│   ├── decoders/                # Décodeurs personnalisés
│   └── shared/{linux,windows,macos}/agent.conf   # Configuration centralisée par groupe
├── agents/
│   ├── install-agent.sh         # Découverte et déploiement à distance
│   ├── lib/                     # targets, discover, remote_ssh, remote_win, winrm_exec.py, manager_api, actions, payloads/
│   ├── active-winRm.ps1         # Prépare un poste Windows (WinRM)
│   ├── credentials.example      # Modèle de fichier d'identifiants
│   └── packages/                # Cache des paquets (--offline)
├── network-devices/             # Guides par constructeur + échantillons de logs
├── scripts/                     # healthcheck, backup, restore, uninstall, test-device-logs
├── tests/run-tests.sh           # Tests automatiques (shellcheck, cibles, payloads, règles)
└── docs/                        # prérequis, agents, dépannage
```

## Sécurité

- Les mots de passe ne sont jamais passés en argument aux machines distantes et ne sont jamais écrits dans les journaux, où ils sont masqués.
- `-p` sans valeur demande le mot de passe de façon masquée. La variable `WAZUH_DEPLOY_PASS` est aussi acceptée.
- Les scripts envoyés aux VMs sont créés en `umask 077` et supprimés après exécution.
- L'enrôlement des agents exige un mot de passe (`authd.pass`).
- Le fichier `--creds` est refusé s'il n'est pas en `chmod 600`.
- Les clés d'hôte SSH sont enregistrées dans `/etc/wazuh-deploy/known_hosts`, en mode *accept-new*.
- WinRM est configuré par `active-winRm.ps1` sans Basic ni trafic non chiffré, et le port peut être restreint à l'IP du serveur.
