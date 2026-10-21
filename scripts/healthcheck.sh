#!/usr/bin/env bash
# =============================================================================
#  healthcheck.sh — État de la plateforme Wazuh (natif ou Docker)
#  Services, ports, indexer, API, dashboard, agents, syslog, disque, certificats
#  Code retour : 0 = tout est OK, 1 = au moins un point en erreur
# =============================================================================
set -o pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"

for a in "$@"; do
  case "$a" in -v) VERBOSITY=2 ;; -vv) VERBOSITY=3 ;; -h|--help) sed -n '3,6p' "$0"; exit 0 ;; esac
done

require_root
load_config
load_state || die "Aucun déploiement trouvé (${STATE_FILE}). Lancez d'abord ./deploy.sh"
MODE="$(deploy_mode)"
FAILS=0
ko() { FAILS=$((FAILS + 1)); }

banner
log_step "Plateforme Wazuh — mode ${MODE:-inconnu}, version ${WAZUH_VERSION}, IP ${MANAGER_IP}"

# --- Services
if [[ "$MODE" == docker ]]; then
  for c in wazuh-indexer wazuh-manager wazuh-dashboard; do
    st="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo absent)"
    up="$(docker inspect -f '{{.State.StartedAt}}' "$c" 2>/dev/null | cut -c1-19)"
    if [[ "$st" == running ]]; then check_line "Conteneur ${c}" OK "démarré ${up}"
    else check_line "Conteneur ${c}" KO "$st"; ko; fi
  done
else
  for s in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
    if systemctl is-active --quiet "$s"; then check_line "Service ${s}" OK
    else check_line "Service ${s}" KO "$(systemctl is-active "$s" 2>/dev/null)"; ko; fi
  done
fi

# --- Démons internes du manager
down="$(mgr_exec /var/ossec/bin/wazuh-control status 2>/dev/null | grep 'not running' \
        | grep -vE 'clusterd|maild|agentlessd|integratord|csyslogd|dbd' | awk '{print $1}' | tr '\n' ' ')"
if [[ -z "$down" ]]; then check_line "Démons du manager" OK
else check_line "Démons du manager" KO "arrêtés : ${down}"; ko; fi

# --- Ports
for p in "${DASHBOARD_PORT}/tcp" 1514/tcp 1515/tcp 55000/tcp 9200/tcp "${SYSLOG_PORT}/${SYSLOG_PROTOCOL/both/udp}"; do
  if port_in_use "${p%/*}" "${p#*/}"; then check_line "Port ${p} en écoute" OK
  else check_line "Port ${p} en écoute" KO; ko; fi
done

# --- Indexer
h="$(curl -sk -m 10 -u "admin:${INDEXER_ADMIN_PASSWORD}" https://127.0.0.1:9200/_cluster/health 2>/dev/null)"
st="$(jq -r '.status // empty' <<<"$h" 2>/dev/null)"
case "$st" in
  green)  check_line "Indexer (cluster)" OK "green" ;;
  yellow) check_line "Indexer (cluster)" WARN "yellow (normal en mono-nœud si des réplicas sont demandés)" ;;
  *)      check_line "Indexer (cluster)" KO "${st:-injoignable}"; ko ;;
esac
today="$(date -u +%Y.%m.%d)"
n="$(curl -sk -m 10 -u "admin:${INDEXER_ADMIN_PASSWORD}" "https://127.0.0.1:9200/wazuh-alerts-*-${today}/_count" 2>/dev/null | jq -r '.count // empty' 2>/dev/null)"
[[ -n "$n" ]] && check_line "Alertes indexées aujourd'hui" OK "${n}" || check_line "Alertes indexées aujourd'hui" WARN "aucune pour l'instant"

# --- API
RUN_DIR="$(mktemp -d)"; trap 'rm -rf "$RUN_DIR"' EXIT
# shellcheck source=agents/lib/manager_api.sh
. "${PROJECT_DIR}/agents/lib/manager_api.sh"
if api_token >/dev/null 2>&1; then
  check_line "API Wazuh (55000)" OK
  summary="$(api_call GET /agents/summary/status 2>/dev/null)"
  if [[ -n "$summary" ]]; then
    read -r act dis nev pend tot < <(jq -r '.data.connection | "\(.active) \(.disconnected) \(.never_connected) \(.pending) \(.total)"' <<<"$summary" 2>/dev/null)
    if (( ${dis:-0} + ${nev:-0} > 0 )); then
      check_line "Agents" WARN "${act} actif(s) / ${tot} — déconnectés : ${dis}, jamais connectés : ${nev}, en attente : ${pend}"
    else
      check_line "Agents" OK "${act} actif(s) / ${tot}"
    fi
    if (( VERBOSITY >= 2 )); then
      api_call GET "/agents?select=id,name,ip,status,version,group&limit=500" 2>/dev/null \
        | jq -r '.data.affected_items[] | select(.id!="000") | "    \(.id)  \(.name)  \(.ip)  \(.status)  \(.version // "-")  \((.group // []) | join(","))"'
    fi
  fi
else
  check_line "API Wazuh (55000)" KO "authentification impossible"; ko
fi

# --- Dashboard
code="$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "https://127.0.0.1:${DASHBOARD_PORT}/" 2>/dev/null)"
if [[ "$code" =~ ^(200|302|401)$ ]]; then check_line "Dashboard (${DASHBOARD_URL:-https://${MANAGER_IP}})" OK "HTTP ${code}"
else check_line "Dashboard" KO "HTTP ${code:-000}"; ko; fi

# --- Syslog / enrôlement
if mgr_exec grep -q '<connection>syslog</connection>' /var/ossec/etc/ossec.conf 2>/dev/null; then
  check_line "Réception syslog équipements" OK "${SYSLOG_PORT}/${SYSLOG_PROTOCOL}"
else check_line "Réception syslog équipements" WARN "non configurée (./deploy.sh --reconfigure)"; fi
if mgr_exec grep -q '<use_password>yes</use_password>' /var/ossec/etc/ossec.conf 2>/dev/null; then
  check_line "Enrôlement protégé par mot de passe" OK
else check_line "Enrôlement protégé par mot de passe" WARN "désactivé"; fi

# --- Disque
if [[ "$MODE" == docker ]]; then path="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
else path="/var/lib/wazuh-indexer"; fi
use="$(df -P "$path" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')"
if (( ${use:-0} < 80 )); then check_line "Disque (${path})" OK "${use}% utilisé"
elif (( use < 90 )); then check_line "Disque (${path})" WARN "${use}% utilisé"
else check_line "Disque (${path})" KO "${use}% utilisé — l'indexer passe en lecture seule à 95%"; ko; fi

# --- Certificat du dashboard
exp="$(echo | openssl s_client -connect "127.0.0.1:${DASHBOARD_PORT}" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
if [[ -n "$exp" ]]; then
  days=$(( ( $(date -d "$exp" +%s) - $(date +%s) ) / 86400 ))
  if (( days > 30 )); then check_line "Certificat dashboard" OK "expire dans ${days} j"
  else check_line "Certificat dashboard" WARN "expire dans ${days} j"; fi
fi

echo
if (( FAILS == 0 )); then log_ok "Plateforme opérationnelle."; else log_error "${FAILS} point(s) en erreur."; fi
(( FAILS == 0 ))
