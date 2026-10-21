#!/usr/bin/env bash
# =============================================================================
#  test-device-logs.sh — Teste les décodeurs/règles sur des logs d'équipements
#  Usage :
#    ./scripts/test-device-logs.sh                    tous les échantillons
#    ./scripts/test-device-logs.sh fortigate          un équipement
#    ./scripts/test-device-logs.sh mon-fichier.log    vos propres logs
#    ./scripts/test-device-logs.sh --send
#        envoie aussi les échantillons en syslog UDP au manager (test de bout
#        en bout, depuis 127.0.0.1 qui est toujours autorisé)
# =============================================================================
set -o pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"

require_root
load_config
load_state || true
SAMPLES="${PROJECT_DIR}/network-devices/samples"
SEND=0
files=()
while (( $# )); do
  case "$1" in
    --send) SEND=1 ;;
    -h|--help) sed -n '3,11p' "$0"; exit 0 ;;
    *) if [[ -f "$1" ]]; then files+=("$1")
       elif [[ -f "${SAMPLES}/$1.log" ]]; then files+=("${SAMPLES}/$1.log")
       else die "Fichier ou équipement inconnu : $1 (disponibles : $(find "$SAMPLES" -name '*.log' -printf '%f ' | sed 's/\.log//g'))"; fi ;;
  esac
  shift
done
(( ${#files[@]} )) || files=("${SAMPLES}"/*.log)

printf "${C_BOLD}%-14s  %-24s  %-7s  %-5s  %s${C_RESET}\n" "FICHIER" "DÉCODEUR" "RÈGLE" "NIV." "DESCRIPTION"
for f in "${files[@]}"; do
  # shellcheck disable=SC2094  # le fichier n'est que lu
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    out="$(printf '%s\n' "$line" | mgr_exec /var/ossec/bin/wazuh-logtest 2>&1)"   # résultats sur stderr
    dec="$(awk "/Phase 2/{p=1} p && /\tname:/{gsub(/.*name: |'/,\"\"); print; exit}" <<<"$out")"
    id="$(awk "/Phase 3/{p=1} p && /\tid:/{gsub(/.*id: |'/,\"\"); print; exit}" <<<"$out")"
    lvl="$(awk "/Phase 3/{p=1} p && /\tlevel:/{gsub(/.*level: |'/,\"\"); print; exit}" <<<"$out")"
    desc="$(awk "/Phase 3/{p=1} p && /\tdescription:/{sub(/.*description: '/,\"\"); sub(/'\$/,\"\"); print; exit}" <<<"$out")"
    color="$C_GREEN"; [[ -z "$id" ]] && color="$C_RED"
    (( ${lvl:-0} >= 10 )) && color="$C_YELLOW"
    printf "%-14s  %-24.24s  ${color}%-7s${C_RESET}  %-5s  %s\n" "$(basename "$f" .log)" "${dec:-AUCUN}" "${id:--}" "${lvl:--}" "${desc:-aucune règle}"
    if (( SEND )); then
      printf '%s' "$line" > "/dev/udp/127.0.0.1/${SYSLOG_PORT}" 2>/dev/null || true
    fi
  done < "$f"
done
if (( SEND )); then log_info "Échantillons envoyés en syslog UDP sur 127.0.0.1:${SYSLOG_PORT} (vérifiez le dashboard : Threat Hunting)."; fi
exit 0
