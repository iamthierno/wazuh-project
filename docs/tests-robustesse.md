# Tests de robustesse — mesures et corrections

Campagne menée le 22/10/2026 sur le laboratoire [`lab/`](../lab/README.md).
La plateforme était Wazuh 4.14.9 en Docker sur 1 serveur de 4 vCPU et 16 Go de
RAM, avec 21 sources : 3 agents Linux réels, 3 agents Windows/macOS simulés,
11 équipements réseau.

## Synthèse

| Test | Résultat avant correction | Correction apportée | Résultat après correction |
|---|---|---|---|
| Charge syslog 10 000 EPS (20 s) | **25 408 événements perdus (13 %)** : file de décodage d'analysisd saturée | Files d'analysisd portées de 16 384 à 131 072 (`ANALYSISD_QUEUE_SIZE`) | **0 perte** à 10 000 et 15 000 EPS, RAM +70 Mo |
| Reconfiguration en mode Docker | **Ignorée** : le conteneur ne recopie `ossec.conf` qu'au premier démarrage | `deploy.sh` pousse aussi le fichier dans le conteneur | Appliquée immédiatement |
| Second bloc `<ruleset>` (listes CDB) | **Règles et décodeurs locaux désactivés** (`etc/rules`, `etc/decoders`) | Listes insérées dans le `<ruleset>` principal | Tous les fichiers locaux chargés |
| Règles `<if_group>` du fichier XDR | Non rattachées aux règles des équipements (ordre de chargement) | Fichier renommé `local_xdr_rules.xml` (chargé en dernier) | Corrélations actives sur toutes les sources |
| Réponse active : brute force depuis le serveur Wazuh | **Le serveur lui-même était bloqué** par ses agents (erreurs de mot de passe via `install-agent.sh`) | Toutes les IP du serveur ajoutées automatiquement à `white_list` | Serveur jamais bloqué ; attaquant externe bloqué 600 s |
| Healthcheck : contrôle des ports | **Toujours KO** sur un serveur réel (mauvaise colonne de `ss`) | Colonne corrigée | Ports correctement détectés |
| Healthcheck : indexer « yellow » | Faux avertissement (réplica d'un index système en mono-nœud) | Distinction index système / index de données | OK avec explication |
| Cisco IOS : brute force | 21 alertes de niveau 9 (une par échec) | Règle d'agrégation 100125 | 1 alerte de brute force de niveau 10 |
| Enrichissement `device.*` | Non appliqué : `date_index_name` du pipeline Wazuh contourne le `final_pipeline` | Processeur inséré dans le pipeline Filebeat avant la redirection | 100 % des alertes d'équipements enrichies |

## 1. Charge syslog

Mesure : `sudo ./lab/lab.sh load <EPS> 20`. L'envoi vient de 11 IP sources,
dont 1 non inventoriée qui est volontairement rejetée. Cet équipement
représente 13,3 % des messages : c'est l'écart constant entre « envoyés » et
« reçus ».

| Débit | Envoyés | Reçus par analysisd | Perdus analysisd | CPU manager | Avant/après |
|---|---|---|---|---|---|
| 500 EPS | 10 000 | 8 676 | 0 | < 1 % | avant |
| 2 000 EPS | 40 003 | 34 678 | 0 | < 1 % | avant |
| 5 000 EPS | 99 984 | 86 661 | 0 | 23 % | avant |
| 10 000 EPS | 200 205 | 169 633 | **25 408** | 23 % | avant |
| 10 000 EPS | 200 205 | 170 995 | **0** | 23 % | **après** |
| 15 000 EPS | 299 582 | 254 461 | **0** | 328 % (pic) | **après** |

À 15 000 EPS, environ 2 % des datagrammes UDP sont perdus avant analysisd
(tampon réseau du noyau). Au-delà de 10 000 EPS soutenus, il est recommandé :

- de passer les équipements en **syslog TCP** (`SYSLOG_PROTOCOL=tcp` ou `both`) ;
- ou d'augmenter `net.core.rmem_max` ;
- ou de répartir la charge sur un **cluster** de managers.

## 2. Entrées malformées

L'envoi depuis un équipement autorisé de 50 messages de chaque type a été
absorbé sans arrêt ni erreur critique :

- paquet vide ;
- 1,5 Ko d'octets aléatoires ;
- UTF-8 invalide ;
- ligne de 65 Ko ;
- chaînes de format (`%n%s`) ;
- tentatives d'injection XML/JSON (`"rule":{"level":15}`) ;
- octets nuls.

Tous les démons sont restés actifs, et aucune alerte de niveau 15 n'a été
fabriquée par injection.

## 3. Montée en charge des agents

| Test | Mesure |
|---|---|
| 50 agents simulés connectés simultanément (Windows 10 et macOS 15), chacun rejouant son scénario d'attaque | **50/50 actifs**, 0 événement perdu, RAM manager +18 Mo, CPU < 2 % au repos |
| Redémarrage du manager avec 6 agents connectés | **6/6 reconnectés en 35 s**, sans intervention |
| Enrôlement avec un mot de passe faux ou absent | **Refusé** (`Invalid password`) |
| Syslog d'un équipement hors inventaire | **Rejeté** (0 alerte) |

## 4. Matrice de détection (scénario `lab.sh attack`)

37 détections de niveau ≥ 8 sur les 21 sources. Les principales :

| Source | Détection | Règle | Niveau |
|---|---|---|---|
| WIN-SRV01 | Logon RDP réussi juste après un brute force | 100236 | 13 |
| MAC-DIRECTION | Connexion SSH réussie juste après un brute force | 100265 | 13 |
| FortiGate (×2) | Attaque IPS critique | 100102 | 12 |
| WIN-SRV01 | Journal de sécurité effacé / IP malveillante / groupe Administrateurs modifié | 100230 / 100262 / 60154 | 12 |
| srv-web02 | Compte ajouté au groupe sudo / clé SSH root / sudoers modifié | 100200 / 100210 / 100211 | 12 |
| Palo Alto | Menace critique | 64504 | 11 |
| Tous les équipements | Brute force (VPN, admin, AAA), balayage, configuration hors heures | 100100, 100111, 100113, 100121, 100124, 100132, 100142, 100151, 87702, 100263 | 10 |
| WIN-SRV01 | Brute force RDP, service installé, tâche planifiée, Kerberoasting | 60204, 100231, 100232, 100234 | 10 |
| srv-web01 | Brute force SSH, puis **IP bloquée par réponse active** | 5551 | 10 |

## 5. Limites connues

- **Windows et macOS** ont été testés avec des agents simulés (protocole réel)
  et non avec de vrais postes. Le chemin d'installation à distance
  (WinRM / `windows_agent.ps1`) reste à valider sur un vrai Windows.
- **Agent Linux du labo** : le paquet officiel n'était pas téléchargeable
  (`packages.wazuh.com` bloqué). Les binaires officiels de l'image Docker
  `wazuh/wazuh-agent:4.14.9` ont donc été reconditionnés.
- Le module **Vulnérabilités** a besoin d'un accès à `cti.wazuh.com` pour mettre
  à jour sa base.
- L'enrichissement `device.*` s'insère dans le pipeline Filebeat de Wazuh :
  après une **mise à jour de Wazuh**, relancez `sudo ./deploy.sh --reconfigure`.
