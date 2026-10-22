# Détection : ce que fait Wazuh nativement, ce que le projet ajoute

Wazuh embarque **déjà** des « modèles » de collecte et de détection : environ
4 500 règles et des centaines de décodeurs. Il n'y a rien à personnaliser
pour la majorité des sources. Le projet s'appuie sur ce socle natif. Il
**n'en modifie aucune règle** et n'ajoute que ce qui manquait, vérifié en
laboratoire ([tests-robustesse.md](tests-robustesse.md)).

## Couverture native utilisée telle quelle

| Source | Collecte | Exemples de détections natives |
|---|---|---|
| Linux | journaux système, auth, dpkg/yum ; FIM ; SCA (CIS) ; inventaire et vulnérabilités | brute force SSH (5763, 5712), PAM (5551), nouvel utilisateur (5902), échecs puis succès (40112) |
| Windows | Security, System, Application ; Sysmon, PowerShell, Defender (via `agent.conf` du groupe) | brute force (60204), groupe Administrateurs modifié (60154), Defender (62123), règles Sysmon et PowerShell |
| macOS | unified logs ; FIM ; SCA | sudo, sshd, connexions |
| FortiGate, Palo Alto, Cisco ASA/IOS/FTD, pfSense, Sophos, SonicWall, Check Point, F5… | syslog | échecs de connexion, menaces IPS, refus répétés (81605, 87702…) |

## Ajouts du projet (`manager/rules`, `manager/decoders`, `manager/lists`)

| Angle mort constaté nativement | Ajout | Règle(s) | Niveau |
|---|---|---|---|
| Aucune alerte quand un compte est ajouté au groupe `sudo`/`wheel`/`docker` | détection usermod/gpasswd | 100200 | 12 |
| Connexion SSH en root : niveau 3 | rehaussée | 100201 | 10 |
| Lecture de `/etc/shadow`, clés privées… via sudo | détection | 100202 | 10 |
| Clé SSH autorisée, sudoers, cron, unités systemd, `sshd_config`, `/etc/hosts` modifiés | FIM ciblé (+ chemins surveillés en temps réel) | 100210 à 100215 | 8 à 12 |
| Journal Windows effacé : niveau 5 | rehaussé | 100230 | 12 |
| Service / tâche planifiée Windows : niveau 4-5 | rehaussés | 100231, 100232 | 10 |
| Ajout aux groupes d'administration du domaine | détection | 100233 | 12 |
| Kerberoasting (ticket RC4) | détection | 100234 | 10 |
| Logon RDP réussi juste après un brute force (champ IP propre à Windows) | corrélation | 100236 | 13 |
| Succès juste après brute force pour les équipements ajoutés | corrélation transverse | 100265 | 13 |
| Accès d'administration réussi depuis une IP publique | liste `private-networks` | 100260 | 10 |
| IP malveillante connue (renseignement sur les menaces) | liste `blocklist-ip` à alimenter | 100261, 100262 | 12 |
| Modification de configuration hors heures ouvrées / le week-end | règles horaires | 100263, 100264 | 10 |
| Agent arrêté (sabotage) / déconnecté | rehaussées | 100270, 100271 | 9 / 7 |
| FortiGate : brute force VPN, configuration, IPS critique | | 100100-100102 | 5-12 |
| Palo Alto : auth, brute force, balayage, configuration (niveau 0 nativement) | | 100110-100113 | 5-10 |
| Cisco ASA / FTD : AAA rejeté (niveau 0-2 nativement), brute force, commandes | | 100120-100124 | 5-10 |
| Cisco IOS : une alerte par échec | agrégation | 100125 | 10 |
| Juniper SRX en mode `event` : non décodé | **décodeurs** + règles | 100130-100133 | 5-10 |
| MikroTik : aucun décodeur | **décodeurs** + règles | 100140-100144 | 3-10 |
| Sophos : échec d'authentification au niveau 0 | | 100150, 100151 | 5-10 |

> Compromis assumé : la nuit (20h-7h) et le week-end, une modification de
> configuration est remontée par 100263/100264 (niveau 10, groupes
> `config_changed`, `off_hours`) **à la place** de l'alerte du constructeur
> (niveau 5). Wazuh ne produit qu'une alerte par événement. Le journal
> d'origine reste consultable dans `full_log`, et l'équipement dans `device.*`.

## Réponse active (XDR)

Activée par défaut (`ACTIVE_RESPONSE=yes` dans `config.env`) :

| Déclencheur | Action | Durée |
|---|---|---|
| Brute force SSH/PAM, multiples échecs (5763, 5712, 5551, 40111) | `firewall-drop` sur l'agent Linux | 600 s (`AR_TIMEOUT`) |
| Brute force Windows (60204) | `netsh` (pare-feu Windows) sur l'agent | 600 s |

Ne sont jamais bloquées : les IP du serveur Wazuh (détectées automatiquement)
et `AR_WHITELIST` (réseaux d'administration).

## Autres réglages avancés (`config.env`)

| Paramètre | Effet |
|---|---|
| `SLACK_WEBHOOK_URL`, `ALERT_NOTIFY_LEVEL` | notification Slack des alertes ≥ niveau 10 |
| `VIRUSTOTAL_API_KEY` | analyse VirusTotal des fichiers modifiés (FIM) |
| `ALERTS_RETENTION_DAYS` | suppression automatique des alertes au-delà de N jours (ISM, 90 par défaut) |
| `ANALYSISD_QUEUE_SIZE` | absorbe les rafales (0 perte à 15 000 EPS) |
| `SYSLOG_RESTRICT_TO_INVENTORY` | seuls les équipements inventoriés peuvent envoyer du syslog |

> Les clés (Slack, VirusTotal) sont écrites dans `ossec.conf`. Ne les commitez
> pas : renseignez-les sur le serveur uniquement.

## Alimenter la liste d'IP malveillantes

Le fichier `manager/lists/blocklist-ip` contient une ligne `IP:description` par
adresse. Vous pouvez l'alimenter depuis votre flux de renseignement (MISP,
AbuseIPDB, export de pare-feu…), puis lancer `sudo ./deploy.sh --reconfigure`.
