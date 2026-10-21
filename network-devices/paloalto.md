# Palo Alto Networks (PAN-OS 9.1 / 10.x / 11.x) → Wazuh

Remplacez `192.168.1.5` par l'IP de votre serveur Wazuh (`MANAGER_IP`).
Format attendu par Wazuh : **BSD** (syslog classique, champs CSV PAN-OS).

## 1. Profil syslog (GUI)

1. *Device* → *Server Profiles* → *Syslog* → **Add**
   - Name : `Wazuh`
   - Onglet *Servers* → Add : Name `wazuh`, Server `192.168.1.5`,
     Transport **UDP**, Port **514**, Format **BSD**, Facility `LOG_USER`
2. *Objects* → *Log Forwarding* → **Add** profil `Wazuh-LF`
   - Match list `traffic` : Log Type *traffic*, Filter *All Logs*, Syslog → `Wazuh`
   - Match list `threat` : Log Type *threat*, Filter *All Logs*, Syslog → `Wazuh`
   - (optionnel) `url`, `wildfire`, `auth`
3. *Policies* → *Security* : pour chaque règle → onglet *Actions* →
   **Log Forwarding** = `Wazuh-LF` (cocher *Log at Session End*)
4. *Device* → *Log Settings* : pour **System**, **Configuration**, **User-ID**,
   **GlobalProtect** → Add → Filter *All Logs* → Syslog `Wazuh`
5. **Commit**

## 2. Équivalent CLI (indicatif, syntaxe selon la version)

```
configure
set shared log-settings syslog Wazuh server wazuh server 192.168.1.5 transport UDP port 514 format BSD facility LOG_USER
set shared log-settings profiles Wazuh-LF match-list traffic log-type traffic filter "All Logs" send-syslog Wazuh
set shared log-settings profiles Wazuh-LF match-list threat log-type threat filter "All Logs" send-syslog Wazuh
set shared log-settings system match-list Wazuh-System filter "All Logs" send-syslog Wazuh
set shared log-settings config match-list Wazuh-Config filter "All Logs" send-syslog Wazuh
commit
```
Puis associez `Wazuh-LF` à vos règles de sécurité (GUI étape 3).

> Avec Panorama : créez les mêmes objets dans le *Device Group* / *Template*
> et poussez la configuration.

## 3. Test

```
test log-forwarding ...      # selon version ; sinon générez un échec de connexion admin
```
Sur le serveur Wazuh :
```bash
sudo tcpdump -ni any udp port 514 and host <IP_PALOALTO>
sudo ./scripts/test-device-logs.sh paloalto
```
Dashboard → `rule.groups: paloalto`.

## 4. Ce qui est détecté

| Événement | Règle | Niveau |
|---|---|---|
| THREAT critique / élevé | 64504 / 64503 (natif) | 11 / 5 |
| Session refusée (TRAFFIC deny/drop) | 64508 (natif) | 6 |
| **Échec d'authentification** (SYSTEM auth-fail) | **100110** | **5** |
| **Brute force** (8 échecs / 2 min) | **100111** | **10** |
| **Modification de configuration** (CONFIG) | **100112** | **5** |
