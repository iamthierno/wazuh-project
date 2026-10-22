# Laboratoire de test

Environnement complet pour éprouver la plateforme **avant la production** :
détections, catégorisation des équipements, réponse active, charge et
robustesse. Il tourne sur un serveur Wazuh déployé en Docker
(`sudo ./deploy.sh --docker`).

> ⚠️ Réservé aux tests : le labo reconfigure le manager avec son propre
> inventaire (`lab/inventory.csv`). Après `./lab/lab.sh down`, relancez
> `sudo ./deploy.sh --reconfigure` pour revenir à l'inventaire de production.

## Contenu

| Composant | Détail | Réalisme |
|---|---|---|
| 3 VMs Linux | Conteneurs Ubuntu 24.04 (`srv-web01`, `srv-web02`, `srv-db01`) avec SSH, rsyslog, iptables | Agent **réel** installé par `install-agent.sh` |
| 2 postes Windows | `WIN-SRV01` (Server 2022), `WIN11-PC01` (Windows 11) | Agent **simulé** : protocole agent réel (enrôlement, AES, keepalive), événements EventChannel réalistes |
| 1 Mac | `MAC-DIRECTION` (macOS 14) | Agent **simulé**, journaux SSH / sudo |
| 10 équipements | FortiGate ×2, Palo Alto, Cisco ASA, Cisco IOS, pfSense, Sophos XG, Juniper SRX, Cisco FTD, MikroTik | Syslog depuis une **IP source distincte** par équipement |
| 1 intrus | Équipement hors inventaire (172.18.0.250) | Doit être **rejeté** |

Windows et macOS ne peuvent pas s'exécuter en conteneur sur un hôte Linux, et
une VM exige la virtualisation matérielle (KVM). Le simulateur
(`agent-sim/wazuh_agent_sim.py`) s'appuie sur le simulateur officiel de
`wazuh-qa` : pour le manager, ce sont de vrais agents Windows et macOS, qui
passent par le même décodeur (`windows_eventchannel`) et les mêmes règles.

## Commandes

```bash
sudo ./lab/lab.sh up             # monte tout (≈ 3 min)
sudo ./lab/lab.sh attack         # rejoue les scénarios d'attaque (toutes sources)
sudo ./lab/lab.sh load 10000 30  # charge syslog : 10 000 EPS pendant 30 s + mesures
sudo ./lab/lab.sh status         # agents et VMs
sudo ./lab/lab.sh down           # supprime le labo (agents du labo uniquement)
```

Sans accès à Docker Hub, utilisez une image Ubuntu locale :
`LAB_BASE_IMAGE=mon-ubuntu:24.04 ./lab/lab.sh up`.

## Scénarios d'attaque (`attack`)

| Source | Action simulée | Détection attendue |
|---|---|---|
| srv-web01 | 10 mots de passe SSH faux | 5551 / 5763 (10) + **réponse active** : IP bloquée 600 s |
| srv-web02 | compte ajouté au groupe sudo, clé SSH root, cron, sudoers | 100200, 100210, 100211 (12), 100212 (10) |
| WIN-SRV01 | brute force RDP puis succès, compte créé, ajout aux Administrateurs, tâche planifiée, service, Kerberos RC4, IP malveillante, journal effacé | 60204, **100236 (13)**, 60154, 100230, 100262 (12), 100231-100234 (10) |
| MAC-DIRECTION | brute force SSH puis succès, sudo sur master.passwd | 5763, **100265 (13)**, 100202 |
| Équipements | brute force VPN/admin, balayages, IPS, modifications de configuration | 100100, 100111, 100113, 100121, 100124, 100125, 100132, 100142, 100151, 87702, 100102 (12) |

Résultats détaillés et mesures : [docs/tests-robustesse.md](../docs/tests-robustesse.md).
