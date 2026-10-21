# Cisco IOS / IOS-XE (routeurs et switches Catalyst) → Wazuh

Remplacez `192.168.1.5` par l'IP du serveur Wazuh et `Vlan10` par l'interface
source (son IP doit être autorisée dans `SYSLOG_ALLOWED_IPS`).

## 1. Configuration

```
configure terminal
 service timestamps log datetime msec localtime show-timezone
 logging origin-id hostname
 logging source-interface Vlan10
 logging trap informational
 logging host 192.168.1.5
 ! Journaliser les connexions (réussies / échouées)
 login on-failure log
 login on-success log
 ! Journaliser chaque commande de configuration
 archive
  log config
   logging enable
   notify syslog contenttype plaintext
   hidekeys
 exit
end
write memory
```

Sur IOS-XE avec VRF de management : `logging host 192.168.1.5 vrf Mgmt-intf`.

## 2. Test

```
show logging | include Trap|Logging to
send log 6 "Test Wazuh"
```
Sur le serveur Wazuh :
```bash
sudo tcpdump -ni any udp port 514 and host <IP_SWITCH>
sudo ./scripts/test-device-logs.sh cisco-ios
```
Dashboard → `rule.groups: cisco_ios`.

## 3. Ce qui est détecté (règles natives)

| Événement | Règle | Niveau |
|---|---|---|
| Échec de connexion (SEC_LOGIN-4-LOGIN_FAILED) | 4724 | 9 |
| Connexion réussie | 4722 | 3 |
| Configuration modifiée (SYS-5-CONFIG_I) | 4721 | 3 |
| Interface up/down (LINK-3-UPDOWN) | 4713 | 4 |
