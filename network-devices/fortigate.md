# FortiGate (FortiOS 6.4 / 7.x) → Wazuh

Remplacez `192.168.1.5` par l'IP de votre serveur Wazuh (`MANAGER_IP`).

## 1. Configuration CLI

```
config log syslogd setting
    set status enable
    set server "192.168.1.5"
    set mode udp
    set port 514
    set facility local7
    set format default
    # Recommandé si plusieurs interfaces : IP source fixe (doit être autorisée côté Wazuh)
    # set source-ip 192.168.1.1
end

config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic enable
    set multicast-traffic disable
    set sniffer-traffic disable
    set anomaly enable
end

config log eventfilter
    set event enable
    set system enable
    set vpn enable
    set user enable
    set router enable
    set security-rating disable
end
```

Pour que le trafic soit journalisé, chaque règle de pare-feu doit avoir la
journalisation activée :

```
config firewall policy
    edit <ID>
        set logtraffic all        # ou "utm" pour ne garder que les événements de sécurité
    next
end
```

> 💡 **Volume** : `forward-traffic` + `logtraffic all` peut générer énormément
> de logs. Commencez par `set logtraffic utm` sur les règles à fort trafic.

## 2. Configuration GUI (alternative)

*Log & Report* → *Log Settings* → **Send logs to syslog** : activé,
IP `192.168.1.5`, puis *Apply*. Les options avancées (port, mode, facility)
restent en CLI.

## 3. Test

Depuis le FortiGate :
```
diagnose log test
```
Sur le serveur Wazuh :
```bash
sudo tcpdump -ni any udp port 514 and host <IP_FORTIGATE>
sudo ./scripts/test-device-logs.sh fortigate
```
Dashboard → *Threat Hunting* → `rule.groups: fortigate`.

## 4. Ce qui est détecté

| Événement | Règle | Niveau |
|---|---|---|
| Échec de connexion SSL VPN | 81614 (natif) | 4 |
| **Brute force SSL VPN** (8 échecs / 2 min, même IP) | **100100** | **10** |
| Échec de connexion administrateur | 81606 (natif) | 4 |
| Brute force admin | 81607 (natif) | 7 |
| **Modification de configuration** | **100101** | **5** |
| Attaque bloquée par l'IPS | 81629 (natif) | 6 |
| **Attaque IPS critique** | **100102** | **12** |
| Trafic refusé | 81618 (natif) | 1 |
