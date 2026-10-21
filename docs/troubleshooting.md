# Dépannage

## Serveur

| Symptôme | Vérification / solution |
|---|---|
| Le dashboard ne s'ouvre pas | `sudo ./scripts/healthcheck.sh`. En Docker : `docker logs wazuh-dashboard`. En natif : `systemctl status wazuh-dashboard`. |
| L'indexer ne démarre pas (Docker) | `sysctl vm.max_map_count` doit valoir 262144 (le script le règle) et il faut assez de RAM (voir `INDEXER_JAVA_HEAP`). |
| « Wazuh API unreachable » dans le dashboard | `docker logs wazuh-manager` ou `systemctl status wazuh-manager`, puis le mot de passe `API_PASSWORD` dans `state.env`. |
| Mot de passe admin oublié | `sudo grep INDEXER_ADMIN_PASSWORD /etc/wazuh-deploy/state.env` |
| Disque plein / indexer en lecture seule | Purger les anciens index (*Index Management*) et configurer une politique ISM de rétention. |
| Installation native interrompue | `/var/log/wazuh-install.log`, puis `./deploy.sh --uninstall` et relancer. |
| Réappliquer la configuration (syslog, groupes, règles) | `sudo ./deploy.sh --reconfigure` |

## Agents

| Message de `install-agent.sh` | Cause / solution |
|---|---|
| `authentification SSH refusée` | Mauvais utilisateur, mot de passe ou clé. Vérifiez aussi `PasswordAuthentication yes` dans `sshd_config` si vous utilisez un mot de passe. |
| `sudo refusé : mot de passe sudo requis` | Utilisateur avec clé sans `NOPASSWD` : ajoutez `-p`. |
| `l'utilisateur n'a pas les droits sudo` | Ajoutez-le au groupe `sudo` ou `wheel`. |
| `clé d'hôte SSH modifiée` | VM réinstallée : `ssh-keygen -R <ip> -f /etc/wazuh-deploy/known_hosts` |
| `Accès manager 1514/1515 ... KO` | La VM ne joint pas le serveur. Vérifiez le pare-feu (VM, réseau, serveur), la route et l'IP (`-M`). |
| `aucun port d'administration ouvert` | SSH ou WinRM fermé : `active-winRm.ps1` pour Windows, *Session à distance* pour macOS. |
| `WinRM … authentification refusée` | Compte local non administrateur intégré : `LocalAccountTokenFilterPolicy=1` (fait par `active-winRm.ps1`). Essayez `--win-auth ntlm`. |
| `connexion impossible` (WinRM) | Port 5985 filtré, ou profil réseau « Public » : relancez `active-winRm.ps1`. |
| `installé mais non actif sur le manager` | `install-agent.sh <ip> --log -u … -p` : cherchez `ERROR` (mot de passe d'enrôlement, port 1514, nom en double). |
| `déjà installé — ignoré` | Comportement normal ; `--force` pour réinstaller, `-U` pour mettre à jour. |
| `nom … déjà utilisé par une autre machine` | VMs clonées avec le même hostname : l'agent est nommé `<hostname>-<ip>`. Renommez la machine si possible. |
| Découverte : OS `unix (à confirmer)` | Linux ou macOS : confirmé automatiquement après connexion (`uname`). |
| Découverte : hôte absent | Ping et ports filtrés : `--no-ping`. Vérifiez que le port 22 ou 5985 est ouvert depuis le serveur. |

Journal détaillé de chaque exécution : `/var/log/wazuh-deploy/agents-<action>-<date>.log`.
Pour voir chaque commande exécutée : `-vv`.

### Côté agent (manuellement)

| | Linux | Windows | macOS |
|---|---|---|---|
| Journal | `/var/ossec/logs/ossec.log` | `C:\Program Files (x86)\ossec-agent\ossec.log` | `/Library/Ossec/logs/ossec.log` |
| Service | `systemctl status wazuh-agent` | `Get-Service WazuhSvc` | `/Library/Ossec/bin/wazuh-control status` |

## Équipements réseau

Voir [network-devices/README.md](../network-devices/README.md#vérifier-quun-équipement-remonte-bien).
Les deux causes les plus fréquentes :

1. L'IP source de l'équipement n'est pas dans `SYSLOG_ALLOWED_IPS`.
2. Un pare-feu bloque le port 514/udp vers le serveur.
