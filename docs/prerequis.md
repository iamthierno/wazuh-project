# Prérequis

## Serveur Wazuh (all-in-one)

| Ressource | Minimum | Recommandé (≤ 100 agents) | 100–500 agents |
|---|---|---|---|
| vCPU | 4 | 8 | 8+ (envisager le multi-nœuds au-delà) |
| RAM | 8 Go | 16 Go | 32 Go |
| Disque | 50 Go | 200 Go SSD | selon rétention (≈ 0,5–2 Go/jour/100 agents) |

**OS supportés** : Ubuntu 20.04 / 22.04 / 24.04, Debian 11 / 12 / 13,
RHEL / Rocky / AlmaLinux / Oracle Linux 8 / 9 / 10, Amazon Linux 2023
(x86_64 ou aarch64).

Autres points à prévoir :

- Une IP fixe : c'est elle que les agents et les équipements utiliseront.
- Une horloge synchronisée (chrony / systemd-timesyncd), indispensable pour corréler les événements.
- Un accès Internet sortant pendant l'installation : `packages.wazuh.com` en natif, Docker Hub en Docker.

## Flux réseau à ouvrir

| Source | Destination | Port | Usage |
|---|---|---|---|
| Agents (VMs) | Serveur Wazuh | **1514/tcp** | événements des agents |
| Agents (VMs) | Serveur Wazuh | **1515/tcp** | enrôlement des agents |
| Équipements réseau | Serveur Wazuh | **514/udp** (ou tcp) | syslog |
| Postes d'administration | Serveur Wazuh | **443/tcp** | dashboard |
| Serveur Wazuh | VMs Linux / macOS | **22/tcp** | déploiement à distance (SSH) |
| Serveur Wazuh | VMs Windows | **5985/tcp** (ou 5986) | déploiement à distance (WinRM) |
| VMs | `packages.wazuh.com:443` | 443/tcp | téléchargement de l'agent (sinon `--offline` : le serveur pousse le paquet) |
| (interne) | Serveur Wazuh | 55000/tcp, 9200/tcp | API et indexer, à ne pas exposer hors du réseau d'administration |

## Machines cibles des agents

| OS | Prérequis |
|---|---|
| **Linux** (Debian/Ubuntu, RHEL/Rocky/Alma/CentOS, SUSE, Amazon Linux) | SSH actif, utilisateur `root` ou membre de `sudo`/`wheel`, `curl` ou `wget` |
| **Windows** 10/11, Server 2012 R2 → 2025 | WinRM activé (`agents/active-winRm.ps1`, une fois par poste ou par GPO), compte administrateur local ou du domaine. Ou OpenSSH Server activé. |
| **macOS** 11+ (Intel ou Apple Silicon) | *Réglages → Général → Partage → Session à distance* activé, compte administrateur |
