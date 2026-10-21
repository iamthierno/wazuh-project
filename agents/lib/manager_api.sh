#!/usr/bin/env bash
# =============================================================================
#  agents/lib/manager_api.sh — Dialogue avec l'API REST du manager Wazuh
#  (statut, ID, suppression des agents). Fonctionne en natif comme en Docker
#  (API publiée sur 55000). Identifiants lus dans /etc/wazuh-deploy/state.env.
# =============================================================================

API_URL="${API_URL:-https://127.0.0.1:55000}"

api_available() { [[ -n "${API_USER:-}" && -n "${API_PASSWORD:-}" ]]; }

# Obtient (ou réutilise) un jeton JWT, partagé entre les workers via un fichier
api_token() {
  local tf="${RUN_DIR}/api.token" t age
  if [[ -s "$tf" ]]; then
    age=$(( $(date +%s) - $(stat -c %Y "$tf" 2>/dev/null || echo 0) ))
    if (( age < 600 )) && [[ "${1:-}" != "refresh" ]]; then cat "$tf"; return 0; fi
  fi
  api_available || return 2
  t="$(curl -sk -m 15 -u "${API_USER}:${API_PASSWORD}" -X POST \
        "${API_URL}/security/user/authenticate?raw=true" 2>/dev/null)"
  [[ "$t" =~ ^eyJ ]] || return 1
  ( umask 077; printf '%s' "$t" > "$tf" )
  printf '%s' "$t"
}

# api_call <MÉTHODE> <chemin> [arguments curl...]
api_call() {
  local method="$1" path="$2" tok out code; shift 2
  tok="$(api_token)" || return $?
  out="$(curl -sk -m 30 -w '\n%{http_code}' -X "$method" -H "Authorization: Bearer ${tok}" "$@" "${API_URL}${path}" 2>/dev/null)"
  code="${out##*$'\n'}"
  if [[ "$code" == "401" ]]; then
    tok="$(api_token refresh)" || return 1
    out="$(curl -sk -m 30 -w '\n%{http_code}' -X "$method" -H "Authorization: Bearer ${tok}" "$@" "${API_URL}${path}" 2>/dev/null)"
    code="${out##*$'\n'}"
  fi
  printf '%s' "${out%$'\n'*}"
  [[ "$code" =~ ^2 ]]
}

# Agent par nom -> "id|status|version|ip|lastKeepAlive|groupes" (vide si absent)
api_agent_by_name() {
  api_call GET "/agents" -G --data-urlencode "name=$1" \
    --data-urlencode "select=id,name,status,version,ip,registerIP,lastKeepAlive,group" 2>/dev/null \
  | jq -r '.data.affected_items[0] // empty
           | [.id, .status, (.version // "-" | sub("^Wazuh v";"")), .ip, (.lastKeepAlive // "-"), ((.group // []) | join(","))]
           | join("|")' 2>/dev/null
}

# Agent par ID -> même format
api_agent_by_id() {
  api_call GET "/agents" -G --data-urlencode "agents_list=$1" \
    --data-urlencode "select=id,name,status,version,ip,registerIP,lastKeepAlive,group" 2>/dev/null \
  | jq -r '.data.affected_items[0] // empty
           | [.id, .status, (.version // "-" | sub("^Wazuh v";"")), .ip, (.lastKeepAlive // "-"), ((.group // []) | join(","))]
           | join("|")' 2>/dev/null
}

# Agents enregistrés avec cette IP -> "id|nom|status|version" par ligne
api_agents_by_ip() {
  api_call GET "/agents" -G --data-urlencode "q=ip=$1,registerIP=$1" \
    --data-urlencode "select=id,name,status,version" 2>/dev/null \
  | jq -r '.data.affected_items[] | select(.id != "000")
           | [.id, .name, .status, (.version // "-" | sub("^Wazuh v";""))] | join("|")' 2>/dev/null
}

# Supprime un agent du manager : api_delete_agent <id>
api_delete_agent() {
  [[ -n "$1" && "$1" != "000" ]] || return 1
  api_call DELETE "/agents?agents_list=$1&status=all&older_than=0s" 2>/dev/null \
    | jq -e '.data.total_affected_items >= 1' >/dev/null 2>&1
}

# Attend que l'agent soit "active" : api_wait_active <nom> <timeout_s>
# -> affiche "id|status|version|ip|lastKeepAlive|groupes" du dernier état
api_wait_active() {
  local name="$1" timeout="${2:-120}" waited=0 info=""
  while (( waited <= timeout )); do
    info="$(api_agent_by_name "$name")"
    if [[ "$info" == *"|active|"* ]]; then printf '%s' "$info"; return 0; fi
    sleep 5; waited=$((waited + 5))
  done
  printf '%s' "$info"
  return 1
}

# Vérifie qu'un groupe existe, le crée sinon : api_ensure_group <groupe>
# Retour : 0 existe/créé, 1 création impossible
api_ensure_group() {
  local g="$1" n
  n="$(api_call GET "/groups" -G --data-urlencode "groups_list=${g}" 2>/dev/null | jq -r '.data.total_affected_items // 0' 2>/dev/null)"
  (( ${n:-0} >= 1 )) && return 0
  api_call POST "/groups" -H 'Content-Type: application/json' -d "{\"group_id\":\"${g}\"}" 2>/dev/null \
    | jq -e '.error == 0' >/dev/null 2>&1
}
