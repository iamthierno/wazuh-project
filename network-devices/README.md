# Intégration des équipements réseau

Les équipements (pare-feu, routeurs, switches) n'accueillent pas d'agent : ils
envoient leurs journaux en **syslog** au serveur Wazuh, qui les décode et
génère des alertes.

```
FortiGate / Palo Alto / Cisco ──syslog UDP 514──► Manager Wazuh ──► Indexer ──► Dashboard
```

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
| Cisco IOS / IOS-XE | [cisco-ios.md](cisco-ios.md) | `cisco-ios` | — (natif suffisant : login, config, interfaces) |
| Autres (pfSense, Sophos, Juniper, SonicWall, Check Point, F5, Huawei…) | [autres.md](autres.md) | selon le constructeur | — |

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
