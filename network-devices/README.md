# Intégration des équipements réseau

Les équipements (pare-feu, routeurs, switches) n'accueillent pas d'agent : ils
envoient leurs journaux en **syslog** au serveur Wazuh, qui les décode et
génère des alertes.

```
FortiGate / Palo Alto / Cisco ──syslog UDP 514──► Manager Wazuh ──► Indexer ──► Dashboard
```

## Inventaire et catégorisation (tableau de bord organisé)

Déclarez vos équipements dans [`inventory.csv`](inventory.csv) :

```
ip,nom,type,constructeur,site
192.168.1.1,FGT-SIEGE,firewall,Fortinet,Siège
192.168.3.1,MT-AGENCE-NORD,router,MikroTik,Agence Nord
```

Puis lancez `sudo ./deploy.sh --reconfigure`. Cette commande :

1. N'autorise en syslog **que** ces IP (`SYSLOG_RESTRICT_TO_INVENTORY=yes`). Un équipement inconnu est rejeté, ce qui a été vérifié en labo.
2. Enrichit **chaque alerte** d'équipement avec les champs `device.name`, `device.type`, `device.category` (Pare-feu, Routeur, Switch…), `device.vendor`, `device.site` et `device.ip`. Un équipement absent de l'inventaire est classé d'après son décodeur.
3. Importe dans le dashboard le tableau de bord **« Équipements réseau (SOC) »**. Il présente les alertes par catégorie, par équipement, par constructeur et par site, l'évolution dans le temps, les échecs d'authentification par équipement et les principales règles déclenchées. Il ajoute aussi 4 recherches enregistrées (toutes les alertes, pare-feu, routeurs et switches, niveau ≥ 10), avec les colonnes `device.*` prêtes à l'emploi.

Dans Threat Hunting ou Discover, filtrez par exemple avec
`device.category:"Pare-feu" and device.site:"Siège"`.

## Côté serveur : déjà fait par `deploy.sh`

| Élément | Valeur | Où le modifier |
|---|---|---|
| Écoute syslog | `514/udp` (ou tcp/both) | `config.env` → `SYSLOG_PORT`, `SYSLOG_PROTOCOL` |
| Sources autorisées | `10.0.0.0/8 172.16.0.0/12 192.168.0.0/16` + 127.0.0.1 | `config.env` → `SYSLOG_ALLOWED_IPS` |
| Règles complémentaires | `manager/rules/local_network_devices.xml` (ID 100100-100199) | puis `./deploy.sh --reconfigure` |

> 🔒 Bonne pratique : remplacez les plages privées de `SYSLOG_ALLOWED_IPS` par
> les **IP exactes** de vos équipements, puis lancez `sudo ./deploy.sh --reconfigure`.
> Un équipement dont l'IP n'est pas autorisée est **ignoré silencieusement**.

## Côté équipement : un guide par constructeur

| Équipement | Guide | Décodeur Wazuh natif | Règles ajoutées par ce projet |
|---|---|---|---|
| Fortinet FortiGate | [fortigate.md](fortigate.md) | `fortigate-firewall-v5/v6` | brute force SSL VPN, changement de config (niv. 5), IPS critique (niv. 12) |
| Palo Alto (PAN-OS) | [paloalto.md](paloalto.md) | `paloalto` | échec d'auth (niv. 5), brute force (niv. 10), changement de config (niv. 5) |
| Cisco ASA / FTD | [cisco-asa.md](cisco-asa.md) | `cisco-asa` | échec AAA (niv. 5), brute force (niv. 10), commandes de config |
| Cisco IOS / IOS-XE | [cisco-ios.md](cisco-ios.md) | `cisco-ios` | brute force agrégé (10) : nativement une alerte de niveau 9 par échec |
| pfSense | [autres.md](autres.md) | `pf` (natif) | — (natif : blocages répétés 87702) |
| Sophos Firewall (XG/SFOS) | [autres.md](autres.md) | `sophos-fw` (natif) | échec d'auth (5, niveau 0 nativement), brute force (10) |
| Juniper SRX (mode `event`) | [autres.md](autres.md) | **`juniper-srx-*` (ajouté)** : le natif n'accepte que le format structured-data | refus, balayage (10), commit de configuration |
| Cisco FTD (LINA) | [cisco-asa.md](cisco-asa.md) | `cisco-ftd` (natif) | échec AAA (5, niveau 2 nativement), brute force (10) |
| MikroTik RouterOS | [autres.md](autres.md) | **`mikrotik` (ajouté)** : aucun décodeur natif | échecs, brute force (10), connexion, configuration |
| Autres (SonicWall, Check Point, F5, Huawei…) | [autres.md](autres.md) | selon le constructeur | — |

## Vérifier qu'un équipement remonte bien

1. **Les paquets arrivent-ils ?** (sur le serveur Wazuh)
   ```bash
   sudo tcpdump -ni any udp port 514 and host <IP_EQUIPEMENT>
   ```
2. **Le manager les accepte-t-il ?** L'IP doit être dans `SYSLOG_ALLOWED_IPS`.
3. **Sont-ils décodés et génèrent-ils des alertes ?**
   ```bash
   sudo ./scripts/test-device-logs.sh fortigate      # échantillons fournis
   sudo ./scripts/test-device-logs.sh /chemin/vers/mes-logs.log
   ```
4. **Dans le dashboard** : *Threat Hunting* → filtre `rule.groups: fortigate`
   (ou `paloalto`, `cisco-asa`, `cisco_ios`, `network_device`).

Les échantillons utilisés pour valider les règles sont dans [`samples/`](samples/).
