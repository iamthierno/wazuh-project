# Cisco ASA (et FTD en mode LINA) → Wazuh

Remplacez `192.168.1.5` par l'IP du serveur Wazuh et `inside` par le nom de
l'interface qui le joint.

## 1. Configuration

```
configure terminal
logging enable
logging timestamp
logging device-id hostname
logging buffered informational
logging trap informational
logging host inside 192.168.1.5
! Port/protocole par défaut : UDP 514. Pour TCP : logging host inside 192.168.1.5 tcp/1470
! (et SYSLOG_PROTOCOL=tcp/both + port adapté côté Wazuh)
! Commandes administrateur tracées (111008/111010) :
logging message 111008 level informational
logging message 111010 level informational
end
write memory
```

> ⚠️ Ne pas utiliser `logging trap debugging` en production (volume énorme).

## 2. Test

```
show logging | include Trap|host
```
Provoquez un échec de connexion SSH sur l'ASA, puis sur le serveur Wazuh :
```bash
sudo tcpdump -ni any udp port 514 and host <IP_ASA>
sudo ./scripts/test-device-logs.sh cisco-asa
```
Dashboard → `rule.groups: cisco-asa`.

## 3. Ce qui est détecté

| Événement | Règle | Niveau |
|---|---|---|
| Connexion admin réussie (605005) | 64009 (natif) | 3 |
| **Authentification AAA rejetée (113015)** | **100120** | **5** |
| **Brute force** (8 échecs / 2 min) | **100121** | **10** |
| **Commande de configuration** (`write memory`, `configure`…) | **100122** | **5** |
| Messages ASA niveau 1 à 4 (alert → warning) | 64001-64004 (natif) | 6 à 3 |
