# Autres équipements

Principe identique pour tous : envoyer le syslog vers `IP_WAZUH:514/udp`
depuis une IP autorisée dans `SYSLOG_ALLOWED_IPS`, puis vérifier avec
`tcpdump` et `./scripts/test-device-logs.sh <fichier>`.

| Équipement | Où configurer | Décodeur Wazuh natif |
|---|---|---|
| **pfSense / OPNsense** | *Status → System Logs → Settings* → *Remote Logging* : `IP_WAZUH:514`, cocher *Everything* ou *Firewall Events* | `pfsense` |
| **Sophos Firewall (SFOS / XG)** | *System services → Log settings* → *Add* serveur syslog, format *Device standard*, cocher les catégories | `sophos_fw` |
| **Juniper SRX / Junos** | `set system syslog host IP_WAZUH any info` + `set security log mode event` | `junos` |
| **SonicWall** | *Log → Syslog* → *Add* serveur, format *Default* | `sonicwall` |
| **Check Point** | Log Exporter : `cp_log_export add name wazuh target-server IP_WAZUH target-port 514 protocol udp format syslog` | `checkpoint`, `checkpoint-smart1` |
| **F5 BIG-IP** | `tmsh modify sys syslog remote-servers add { wazuh { host IP_WAZUH remote-port 514 } }` | `f5_bigip` |
| **Huawei USG** | `info-center loghost IP_WAZUH` | `huawei-usg` |
| **Cisco FTD (FMC)** | *Devices → Platform Settings → Syslog* → Logging Destinations + Syslog Servers | `cisco-ftd` |
| **Imperva, Barracuda, NetScaler, Arbor, FireEye…** | Syslog distant dans la console | décodeurs dédiés |
| **Switches HP/Aruba, MikroTik, Ubiquiti…** | « Remote syslog server » | génériques (`syslog`) : alertes sur mots-clés (fail, error…) |

## Équipement non reconnu (décodeur `AUCUN`)

1. Récupérez quelques lignes de log brutes dans un fichier.
2. Testez : `sudo ./scripts/test-device-logs.sh mon-equipement.log`.
3. Si aucun décodeur ne correspond, ajoutez-en un dans `manager/decoders/`
   et des règles dans `manager/rules/` (IDs 100200+), puis
   `sudo ./deploy.sh --reconfigure` (validation automatique, retrait si invalide).

Documentation Wazuh : *Custom decoders* et *Custom rules* (documentation.wazuh.com).
