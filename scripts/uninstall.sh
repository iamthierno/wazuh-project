#!/usr/bin/env bash
# =============================================================================
#  uninstall.sh — Désinstallation du serveur Wazuh (natif ou Docker)
#  Usage : ./scripts/uninstall.sh [--keep-data] [-y]
#    --keep-data : Docker uniquement, conserve les volumes (alertes, clés)
#  Une sauvegarde de la configuration est proposée avant suppression.
#  Les agents installés sur les VMs ne sont pas touchés
#  (voir : ./agents/install-agent.sh <cibles> -rf).
# =============================================================================
set -o pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"

KEEP_DATA=0
for a in "$@"; do
  case "$a" in --keep-data) KEEP_DATA=1 ;; -y) ASSUME_YES=1 ;; -h|--help) sed -n '3,9p' "$0"; exit 0 ;; esac
done

require_root
load_config
load_state || true
MODE="$(deploy_mode)"
[[ -n "$MODE" ]] || die "Aucune installation Wazuh détectée."

log_warn "Vous allez DÉSINSTALLER Wazuh (${MODE}) de ce serveur."
confirm "Confirmer la désinstallation ?" n || exit 0
if confirm "Faire une sauvegarde de la configuration avant ?" o; then
  "${PROJECT_DIR}/scripts/backup.sh" || confirm "La sauvegarde a échoué. Continuer quand même ?" n || exit 1
fi

if [[ "$MODE" == docker ]]; then
  log_step "Arrêt et suppression de la stack Docker"
  if (( KEEP_DATA )); then
    docker compose --project-directory "$DOCKER_DIR" -f "${DOCKER_DIR}/docker-compose.yml" down
    log_ok "Conteneurs supprimés (volumes conservés)"
  else
    docker compose --project-directory "$DOCKER_DIR" -f "${DOCKER_DIR}/docker-compose.yml" down -v
    rm -rf "$DOCKER_DIR"
    log_ok "Conteneurs, volumes et ${DOCKER_DIR} supprimés"
  fi
  docker image rm wazuh-deployer:latest >/dev/null 2>&1 || true
else
  log_step "Désinstallation native (assistant officiel)"
  inst="${DEPLOY_STATE_DIR}/native/wazuh-install.sh"
  if [[ ! -f "$inst" ]]; then
    curl -fsSL -o "$inst" "https://packages.wazuh.com/${WAZUH_MINOR}/wazuh-install.sh" || die "wazuh-install.sh introuvable"
  fi
  bash "$inst" -u || log_warn "L'assistant a signalé des erreurs"
  rm -f /etc/sysctl.d/99-wazuh.conf
  log_ok "Wazuh désinstallé"
fi

if (( ! KEEP_DATA )) && confirm "Supprimer aussi l'état du déploiement (${DEPLOY_STATE_DIR}, mots de passe) ?" n; then
  rm -rf "$DEPLOY_STATE_DIR"
  log_ok "${DEPLOY_STATE_DIR} supprimé"
fi
log_ok "Désinstallation terminée."
