# Déploiement des agents : `agents/install-agent.sh`

## Principe : une commande, un agent opérationnel

```
install-agent.sh 192.168.1.0/24 -u admin -p
        │
        ├─ 1. Cibles       IP, sous-réseau, plage, fichier ; exclusions (-x) et serveur lui-même retirés
        ├─ 2. Découverte   nmap : hôtes actifs, ports 22/135/445/3389/5985/5986/548…, empreinte OS,
        │                  bannière SSH, TTL, vendeur MAC → linux / windows / macos
        ├─ 3. Connexion    SSH (Linux, macOS) ou WinRM (Windows), N hôtes en parallèle (-n)
        ├─ 4. Contrôles    droits root/admin · architecture · espace disque · la VM joint-elle le
        │                  manager sur 1514/1515 ? · accès à packages.wazuh.com · agent déjà présent ?
        ├─ 5. Installation paquet deb / rpm / pkg / msi à la version du manager, avec :
        │                  WAZUH_MANAGER, mot de passe d'enrôlement, groupe (linux|windows|macos), nom
        ├─ 6. Enrôlement   automatique au démarrage de l'agent (port 1515, mot de passe)
        ├─ 7. Vérification attente du statut « Active » sur le manager (API), groupe affiché
        └─ 8. Résumé       tableau + journal (+ CSV avec -o)
```

Dès que l'agent est actif, le manager lui pousse la configuration de son groupe
(`manager/shared/<groupe>/agent.conf`) : auditd et FIM pour Linux ; Sysmon,
PowerShell, Defender et RDP pour Windows ; persistance pour macOS.

## Préparer les machines

### Linux
- SSH ouvert depuis le serveur Wazuh.
- Un utilisateur `root`, ou un utilisateur `sudo` : son mot de passe sert aussi à `sudo`. Avec une clé SSH, il faut soit `NOPASSWD`, soit fournir aussi `-p`.

### Windows
Sur chaque poste, une fois, en administrateur :
```powershell
powershell -ExecutionPolicy Bypass -File .\active-winRm.ps1 -WazuhServer 192.168.1.5
```
En masse : GPO *Configuration ordinateur → Stratégies → Paramètres Windows →
Scripts → Démarrage*, ou une GPO WinRM native avec écouteur, pare-feu 5985 et
`LocalAccountTokenFilterPolicy`.

Comptes acceptés :

| Contexte | Exemple |
|---|---|
| domaine | `-u 'CORP\admin'` ou `-u admin@corp.local` |
| workgroup | administrateur local |

Pour l'authentification : `--win-auth ntlm|negotiate|kerberos`. Pour le
chiffrement HTTPS : `--win-https`, avec l'écouteur 5986 créé par `active-winRm.ps1 -Https`.

À défaut de WinRM, si **OpenSSH Server** est actif (port 22), le script
l'utilise automatiquement.

### macOS
*Réglages Système → Général → Partage → Session à distance* : activé pour un
compte administrateur.

## Identifiants

| Méthode | Exemple |
|---|---|
| Ligne de commande | `-u admin -p` (le mot de passe est demandé, masqué) |
| Variable d'environnement | `WAZUH_DEPLOY_PASS='…' ./install-agent.sh … -u admin -p` |
| Clé SSH | `-u admin -k ~/.ssh/id_ed25519` (sans `-u`, `root` est utilisé) |
| Fichier par OS | `--creds /root/wazuh-creds` (modèle : `agents/credentials.example`, `chmod 600` obligatoire) |

Ordre de priorité : la ligne de commande l'emporte sur le fichier `--creds`.

> ⚠️ `-p MonMotDePasse` fonctionne, mais le mot de passe reste visible dans
> l'historique du shell. Préférez `-p` seul.

## Exemples

```bash
# Inventaire du réseau, exporté en CSV
sudo ./install-agent.sh 192.168.1.0/24 -d -o /root/inventaire.csv

# Simulation complète (connexion + contrôles, aucune modification)
sudo ./install-agent.sh 192.168.1.0/24 -u admin -p -dry

# Linux + Windows, 10 en parallèle, sans confirmation, en excluant deux serveurs
sudo ./install-agent.sh 192.168.1.0/24 -lw -u admin -p -n 10 -y -x 192.168.1.1,192.168.1.254

# Liste de machines dans un fichier, groupe personnalisé
sudo ./install-agent.sh -f serveurs-prod.txt -l -k /root/.ssh/id_ed25519 -g prod-linux

# VMs sans Internet : le serveur pousse le paquet
sudo ./install-agent.sh 10.10.0.0/24 -l -u admin -p --offline

# Exploitation
sudo ./install-agent.sh 192.168.1.0/24 -s                # statut vu du manager (sans identifiants)
sudo ./install-agent.sh 192.168.1.20 -s -u admin -p      # statut service + manager
sudo ./install-agent.sh 192.168.1.20 --log --lines 100 -u admin -p
sudo ./install-agent.sh 192.168.1.0/24 -c -u admin -p    # quelles VMs ont l'agent ? quelle version ?
sudo ./install-agent.sh 192.168.1.0/24 -U -u admin -p    # mise à jour vers la version du manager
sudo ./install-agent.sh 192.168.1.20 -r -u admin -p      # désinstaller
sudo ./install-agent.sh 192.168.1.20 -rf -u admin -p     # désinstaller + purger les fichiers
```

> Un groupe personnalisé (`-g prod-linux`) est créé automatiquement sur le
> manager s'il n'existe pas. Pour lui donner une configuration centralisée,
> créez `manager/shared/prod-linux/agent.conf`, ajoutez `prod-linux` à
> `AGENT_GROUPS` dans `config.env`, puis lancez `sudo ./deploy.sh --reconfigure`.

## Statuts du résumé

| Statut | Signification |
|---|---|
| `OK` | action réussie (pour une installation : agent **Active** sur le manager) |
| `ECHEC` | erreur ; le détail indique la cause (authentification, sudo, port 1514 bloqué…) |
| `IGNORE` | volontairement non traité : déjà installé (`--force` pour forcer), hors filtre, aucun port d'administration, manager |
| `ABSENT` | agent non installé (`-c` / `-s`) |
| `ATTENTION` | agent présent mais service arrêté ou déconnecté du manager |
| `SIMULE` | mode `-dry` |

Le code retour vaut `0` si aucun hôte n'est en `ECHEC`, sinon `1` (utilisable
en automatisation).

## Mode Docker

Si le serveur tourne sous Docker et que les outils nécessaires (nmap, sshpass,
pypsrp) ne sont pas installés sur l'hôte, `install-agent.sh` se relance
automatiquement dans le conteneur `wazuh-deployer`, en réseau hôte. Il n'y a
rien à installer sur l'hôte et la commande reste identique.

Pour forcer l'exécution sur l'hôte : `NO_DEPLOYER=1 ./install-agent.sh …`.
