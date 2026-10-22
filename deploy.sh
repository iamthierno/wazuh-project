#!/usr/bin/env bash
# =============================================================================
#  deploy.sh — Point d'entrée unique du déploiement Wazuh
#
#  Usage :
#    sudo ./deploy.sh                 menu interactif
#    sudo ./deploy.sh --native        option 1 : installation native Linux
#    sudo ./deploy.sh --docker        option 2 : installation Docker
#    sudo ./deploy.sh --status        état de la plateforme (healthcheck)
#    sudo ./deploy.sh --reconfigure   ré-applique syslog, groupes, règles
#    sudo ./deploy.sh --backup        sauvegarde de la configuration
#    sudo ./deploy.sh --uninstall     désinstallation
#  Options : -y (sans confirmation)  -v / -vv (verbeux / debug)  -q (silencieux)
#            --ignore-checks (ignore les contrôles bloquants)
# =============================================================================
set -o pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"
# shellcheck source=lib/precheck.sh
. "${PROJECT_DIR}/lib/precheck.sh"
# shellcheck source=lib/devices.sh
. "${PROJECT_DIR}/lib/devices.sh"
# shellcheck source=lib/server_config.sh
. "${PROJECT_DIR}/lib/server_config.sh"
# shellcheck source=lib/native.sh
. "${PROJECT_DIR}/lib/native.sh"
# shellcheck source=lib/certs.sh
. "${PROJECT_DIR}/lib/certs.sh"
# shellcheck source=lib/docker.sh
. "${PROJECT_DIR}/lib/docker.sh"

usage() {
  sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'
}

reconfigure() {
  local mode
  mode="$(deploy_mode)"
  [[ -n "$mode" ]] || die "Aucune installation Wazuh détectée."
  log_step "Reconfiguration du manager (${mode})"
  [[ -n "${ENROLLMENT_PASSWORD:-}" ]] || state_set ENROLLMENT_PASSWORD "$(gen_password 24)"
  if [[ "$mode" == "docker" ]]; then
    apply_ossec_conf "${DOCKER_DIR}/config/wazuh_cluster/wazuh_manager.conf"
  else
    apply_ossec_conf /var/ossec/etc/ossec.conf
  fi
  configure_manager_runtime
  manager_restart
  wait_manager_api 300
}

menu() {
  local choice
  banner
  local mode; mode="$(deploy_mode)"
  [[ -n "$mode" ]] && log_info "Installation existante détectée : mode ${C_BOLD}${mode}${C_RESET}"
  cat <<EOF
  ${C_BOLD}1)${C_RESET} Installation native Linux   (indexer + manager + dashboard sur cet hôte)
  ${C_BOLD}2)${C_RESET} Installation Docker         (vérifie/installe Docker puis lance la stack)
  ${C_BOLD}3)${C_RESET} Vérifier l'état             (healthcheck)
  ${C_BOLD}4)${C_RESET} Reconfigurer le manager     (syslog, groupes, règles, enrôlement)
  ${C_BOLD}5)${C_RESET} Déployer des agents         (aide de install-agent.sh)
  ${C_BOLD}6)${C_RESET} Sauvegarder la configuration
  ${C_BOLD}7)${C_RESET} Désinstaller
  ${C_BOLD}0)${C_RESET} Quitter
EOF
  read -r -p "Votre choix : " choice </dev/tty
  case "$choice" in
    1) ACTION=native ;;
    2) ACTION=docker ;;
    3) ACTION=status ;;
    4) ACTION=reconfigure ;;
    5) ACTION=agents ;;
    6) ACTION=backup ;;
    7) ACTION=uninstall ;;
    *) exit 0 ;;
  esac
}

main() {
  ACTION=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --native|-1)    ACTION=native ;;
      --docker|-2)    ACTION=docker ;;
      --status|-s)    ACTION=status ;;
      --reconfigure)  ACTION=reconfigure ;;
      --backup)       ACTION=backup ;;
      --uninstall)    ACTION=uninstall ;;
      --ignore-checks) IGNORE_CHECKS=1 ;;
      -y|--yes)       ASSUME_YES=1 ;;
      -v)             VERBOSITY=2 ;;
      -vv)            VERBOSITY=3 ;;
      -q)             VERBOSITY=0 ;;
      -h|--help)      usage; exit 0 ;;
      *) usage; die "Option inconnue : $1" ;;
    esac
    shift
  done
  export ASSUME_YES VERBOSITY IGNORE_CHECKS

  require_root
  load_config
  # L'état d'une installation précédente complète la configuration
  load_state || true

  [[ -z "$ACTION" ]] && menu

  case "$ACTION" in
    native|docker|reconfigure) log_init "deploy-${ACTION}"; log_info "Journal : ${LOG_FILE}" ;;
  esac

  case "$ACTION" in
    native)      banner; native_install ;;
    docker)      banner; docker_install ;;
    reconfigure) reconfigure ;;
    status)      exec "${PROJECT_DIR}/scripts/healthcheck.sh" ;;
    agents)      exec "${PROJECT_DIR}/agents/install-agent.sh" --help ;;
    backup)      exec "${PROJECT_DIR}/scripts/backup.sh" ;;
    uninstall)   exec "${PROJECT_DIR}/scripts/uninstall.sh" ;;
  esac
}

main "$@"
