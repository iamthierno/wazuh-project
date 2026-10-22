#!/usr/bin/env bash
# =============================================================================
#  import-dashboards.sh — Importe le tableau de bord « Équipements réseau (SOC) »
#  et les recherches enregistrées par catégorie dans le dashboard Wazuh.
#  Rafraîchit d'abord la liste des champs de l'index pattern wazuh-alerts-*
#  (pour que les champs device.* soient utilisables). Idempotent.
#  Appelé par deploy.sh (installation et --reconfigure).
# =============================================================================
set -o pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"

require_root
load_config
load_state || die "Aucun déploiement trouvé (${STATE_FILE})."
DASH="https://127.0.0.1:${DASHBOARD_PORT}"
AUTH="admin:${INDEXER_ADMIN_PASSWORD}"
H=(-H 'osd-xsrf: true')

code="$(curl -sk -m 15 -o /dev/null -w '%{http_code}' -u "$AUTH" "${DASH}/api/status")"
[[ "$code" == 200 ]] || { log_warn "Dashboard non prêt (HTTP ${code}) : import reporté"; exit 1; }

# 1) Champs de l'index pattern (ajoute device.* sans toucher aux réglages Wazuh)
fields="$(curl -sk -m 60 -u "$AUTH" "${H[@]}" \
  "${DASH}/api/index_patterns/_fields_for_wildcard?pattern=wazuh-alerts-*&meta_fields=_source&meta_fields=_id&meta_fields=_type&meta_fields=_index&meta_fields=_score")"
if jq -e '.fields | length > 0' >/dev/null 2>&1 <<<"$fields"; then
  jq -c '{attributes: {fields: (.fields | tostring)}}' <<<"$fields" \
    | curl -sk -m 60 -o /dev/null -u "$AUTH" "${H[@]}" -H 'Content-Type: application/json' \
        -X PUT "${DASH}/api/saved_objects/index-pattern/wazuh-alerts-*" -d @- \
    && log_ok "Index pattern wazuh-alerts-* : $(jq '.fields | length' <<<"$fields") champs"
else
  log_warn "Lecture des champs de wazuh-alerts-* impossible"
fi

# 2) Recherches, visualisations et tableau de bord
tmp="$(mktemp --suffix=.ndjson)"; trap 'rm -f "$tmp"' EXIT
python3 "${PROJECT_DIR}/dashboards/build_network_dashboard.py" > "$tmp" || die "Génération des objets impossible"
res="$(curl -sk -m 60 -u "$AUTH" "${H[@]}" -X POST "${DASH}/api/saved_objects/_import?overwrite=true" -F "file=@${tmp}")"
if jq -e '.success == true' >/dev/null 2>&1 <<<"$res"; then
  log_ok "Tableau de bord « Équipements réseau (SOC) » importé ($(jq '.successCount' <<<"$res") objets)"
else
  log_warn "Import partiel : $(jq -c '.errors // .' <<<"$res" | cut -c1-300)"
  exit 1
fi
