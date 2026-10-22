#!/usr/bin/env bash
# =============================================================================
#  lib/devices.sh — Inventaire et catégorisation des équipements réseau
#    - network-devices/inventory.csv : ip,nom,type,constructeur,site
#    - IP syslog autorisées = IP de l'inventaire (SYSLOG_RESTRICT_TO_INVENTORY)
#    - pipeline d'ingestion « wazuh-device-enrich » dans l'indexer : ajoute à
#      chaque alerte d'équipement les champs device.name / device.type /
#      device.vendor / device.site / device.category / device.ip
# =============================================================================

DEVICE_PIPELINE="wazuh-device-enrich"
INVENTORY_FILE="${INVENTORY_FILE:-${PROJECT_DIR}/network-devices/inventory.csv}"

# Lignes utiles de l'inventaire (sans commentaires ni en-tête)
inventory_rows() {
  [[ -r "$INVENTORY_FILE" ]] || return 0
  grep -vE '^[[:space:]]*(#|$)' "$INVENTORY_FILE" | grep -viE '^ip,' | tr -d '\r'
}

# IP de l'inventaire, séparées par des espaces
inventory_ips() { inventory_rows | cut -d, -f1 | tr -d ' ' | paste -sd' ' -; }

# Applique la restriction syslog aux IP de l'inventaire
devices_apply_allowed_ips() {
  local ips
  ips="$(inventory_ips)"
  if [[ "${SYSLOG_RESTRICT_TO_INVENTORY:-yes}" == "yes" && -n "$ips" ]]; then
    # shellcheck disable=SC2034  # lue par build_ossec_block
    SYSLOG_ALLOWED_IPS="$ips"
    log_info "Syslog limité aux $(wc -w <<<"$ips") équipement(s) de l'inventaire"
  fi
}

# Corps JSON du pipeline (inventaire + correspondances décodeur -> catégorie)
_device_pipeline_json() {
  local devices
  devices="$(inventory_rows | jq -R -s '
    split("\n") | map(select(length > 0) | split(",") | map(gsub("^\\s+|\\s+$"; "")))
    | map({key: .[0], value: {name: .[1], type: (.[2] // "autre"), vendor: (.[3] // ""), site: (.[4] // "")}})
    | from_entries')"
  [[ -n "$devices" ]] || devices='{}'
  jq -n --argjson devices "$devices" '{
    description: "Catégorisation des équipements réseau (wazuh-project)",
    processors: [{ script: {
      lang: "painless",
      ignore_failure: true,
      params: {
        devices: $devices,
        vendors: [
          ["fortigate", "firewall", "Fortinet"], ["paloalto", "firewall", "Palo Alto"],
          ["cisco-asa", "firewall", "Cisco"], ["cisco-ftd", "firewall", "Cisco"], ["pix", "firewall", "Cisco"],
          ["cisco-ios", "router", "Cisco"], ["pf", "firewall", "pfSense"], ["sophos", "firewall", "Sophos"],
          ["juniper", "firewall", "Juniper"], ["junos", "firewall", "Juniper"], ["mikrotik", "router", "MikroTik"],
          ["sonicwall", "firewall", "SonicWall"], ["checkpoint", "firewall", "Check Point"],
          ["huawei-usg", "firewall", "Huawei"], ["f5", "proxy", "F5"], ["netscaler", "proxy", "Citrix"]
        ],
        categories: {
          firewall: "Pare-feu", router: "Routeur", switch: "Switch", wifi: "Wi-Fi",
          vpn: "VPN", proxy: "Proxy / répartiteur", autre: "Autre équipement"
        }
      },
      source: "
        if (ctx.agent == null || ctx.agent.id != \"000\" || ctx.location == null) { return; }
        String loc = ctx.location;
        if (loc.length() < 3 || !Character.isDigit(loc.charAt(0)) || loc.indexOf(\" \") >= 0) { return; }
        Map d = new HashMap();
        Map inv = params.devices.get(loc);
        if (inv != null) { d.putAll(inv); }
        String dec = (ctx.decoder != null && ctx.decoder.name != null) ? ctx.decoder.name : \"\";
        if (!d.containsKey(\"vendor\") || d.get(\"vendor\") == \"\") {
          for (def v : params.vendors) {
            if (dec.startsWith(v[0])) { d.putIfAbsent(\"type\", v[1]); d.put(\"vendor\", v[2]); break; }
          }
        }
        if (!d.containsKey(\"type\")) { d.put(\"type\", \"autre\"); }
        if (!d.containsKey(\"name\") || d.get(\"name\") == \"\") {
          String n = null;
          if (ctx.data != null) {
            if (ctx.data.devname != null) { n = ctx.data.devname; }
            else if (ctx.data.device_name != null) { n = ctx.data.device_name; }
          }
          if (n == null && ctx.predecoder != null && ctx.predecoder.hostname != null) { n = ctx.predecoder.hostname; }
          d.put(\"name\", n != null ? n : loc);
        }
        d.putIfAbsent(\"site\", \"non renseigné\");
        if (d.get(\"site\") == \"\") { d.put(\"site\", \"non renseigné\"); }
        String cat = params.categories.get(d.get(\"type\"));
        d.put(\"category\", cat != null ? cat : \"Autre équipement\");
        d.put(\"ip\", loc);
        ctx.device = d;
      "
    }}]
  }'
}

# Installe pipeline + modèle d'index + réglage des index existants
devices_install_enrichment() {
  local url="https://127.0.0.1:9200" auth="admin:${INDEXER_ADMIN_PASSWORD}" body code
  if ! curl -sk -m 10 -o /dev/null -u "$auth" "$url"; then
    log_warn "Indexer injoignable : catégorisation des équipements non installée"
    return 1
  fi
  body="$(_device_pipeline_json)" || { log_warn "Inventaire illisible (${INVENTORY_FILE})"; return 1; }

  code="$(curl -sk -m 20 -o /dev/null -w '%{http_code}' -u "$auth" -X PUT "${url}/_ingest/pipeline/${DEVICE_PIPELINE}" \
          -H 'Content-Type: application/json' -d "$body")"
  [[ "$code" == 200 ]] || { log_error "Création du pipeline ${DEVICE_PIPELINE} refusée (HTTP ${code})"; return 1; }

  # Branchement dans le pipeline Filebeat de Wazuh, AVANT date_index_name :
  # ce processeur redirige l'alerte vers l'index du jour, ce qui empêcherait
  # un « final_pipeline » de s'exécuter. Idempotent ; à refaire après une
  # mise à jour de Wazuh (nouveau pipeline Filebeat) via --reconfigure.
  local fb fbody
  fb="$(curl -sk -m 20 -u "$auth" "${url}/_ingest/pipeline" | jq -r 'keys[] | select(test("wazuh-alerts-pipeline$"))' | head -1)"
  if [[ -z "$fb" ]]; then
    log_warn "Pipeline Filebeat Wazuh introuvable : enrichissement device.* inactif"
    return 1
  fi
  fbody="$(curl -sk -m 20 -u "$auth" "${url}/_ingest/pipeline/${fb}" | jq --arg p "$DEVICE_PIPELINE" '
    .[] | .processors |= (
      map(select((.pipeline.name // "") != $p))
      | (map(has("date_index_name")) | index(true)) as $i
      | if $i == null then . + [{pipeline: {name: $p, ignore_failure: true}}]
        else .[:$i] + [{pipeline: {name: $p, ignore_failure: true}}] + .[$i:] end)')"
  code="$(curl -sk -m 20 -o /dev/null -w '%{http_code}' -u "$auth" -X PUT "${url}/_ingest/pipeline/${fb}" \
          -H 'Content-Type: application/json' -d "$fbody")"
  [[ "$code" == 200 ]] || { log_error "Mise à jour du pipeline ${fb} refusée (HTTP ${code})"; return 1; }

  # Typage keyword des champs device.* (futurs index + index existants)
  local mapping='{"properties": {"device": {"properties": {
      "name": {"type": "keyword"}, "type": {"type": "keyword"}, "vendor": {"type": "keyword"},
      "site": {"type": "keyword"}, "category": {"type": "keyword"}, "ip": {"type": "keyword"}}}}}'
  curl -sk -m 20 -o /dev/null -u "$auth" -X PUT "${url}/_template/wazuh-device-enrich" \
    -H 'Content-Type: application/json' \
    -d "{\"order\": 1, \"index_patterns\": [\"wazuh-alerts-4.x-*\"], \"mappings\": ${mapping}}"
  curl -sk -m 20 -o /dev/null -u "$auth" -X PUT "${url}/wazuh-alerts-4.x-*/_mapping" \
    -H 'Content-Type: application/json' -d "$mapping"

  log_ok "Catégorisation des équipements active ($(inventory_rows | wc -l) équipement(s) inventorié(s))"
}

# Politique de rétention des alertes (ISM)
devices_install_retention() {
  local days="${ALERTS_RETENTION_DAYS:-0}" url="https://127.0.0.1:9200" auth="admin:${INDEXER_ADMIN_PASSWORD}" code
  [[ "$days" =~ ^[0-9]+$ && "$days" -gt 0 ]] || { log_verbose "Rétention illimitée (ALERTS_RETENTION_DAYS=0)"; return 0; }
  curl -sk -m 20 -o /dev/null -u "$auth" -X DELETE "${url}/_plugins/_ism/policies/wazuh-alerts-retention" || true
  code="$(curl -sk -m 20 -o /dev/null -w '%{http_code}' -u "$auth" -X PUT "${url}/_plugins/_ism/policies/wazuh-alerts-retention" \
    -H 'Content-Type: application/json' -d "{\"policy\": {
      \"description\": \"Suppression des alertes au-delà de ${days} jours (wazuh-project)\",
      \"default_state\": \"actif\",
      \"states\": [
        {\"name\": \"actif\", \"actions\": [], \"transitions\": [{\"state_name\": \"suppression\", \"conditions\": {\"min_index_age\": \"${days}d\"}}]},
        {\"name\": \"suppression\", \"actions\": [{\"delete\": {}}], \"transitions\": []}
      ],
      \"ism_template\": [{\"index_patterns\": [\"wazuh-alerts-*\", \"wazuh-archives-*\"], \"priority\": 100}]
    }}")"
  if [[ "$code" =~ ^20 ]]; then
    curl -sk -m 20 -o /dev/null -u "$auth" -X POST "${url}/_plugins/_ism/add/wazuh-alerts-*" \
      -H 'Content-Type: application/json' -d '{"policy_id": "wazuh-alerts-retention"}' || true
    log_ok "Rétention des alertes : ${days} jours (politique ISM wazuh-alerts-retention)"
  else
    log_warn "Politique de rétention non appliquée (HTTP ${code})"
  fi
}
