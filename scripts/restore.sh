#!/usr/bin/env bash
# =============================================================================
#  restore.sh — Restaure une sauvegarde créée par backup.sh
#  Usage : ./scripts/restore.sh /var/backups/wazuh/wazuh-backup-<mode>-<date>.tar.gz
#  Le manager doit être installé dans le même mode (natif/Docker) et la même
#  version. Les agents retrouvent leurs clés : aucune réinscription nécessaire.
# =============================================================================
set -o pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"

ARCHIVE="${1:-}"
[[ -r "$ARCHIVE" ]] || die "Usage : $0 <archive.tar.gz>"
for a in "$@"; do [[ "$a" == "-y" ]] && ASSUME_YES=1; done

require_root
load_config
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
tar -C "$WORK" -xzf "$ARCHIVE" || die "Archive illisible"
# shellcheck disable=SC1091
. "${WORK}/BACKUP_INFO" 2>/dev/null || true
BK_MODE="${mode:-?}"
log_info "Sauvegarde : mode ${BK_MODE}, version ${version:-?}, du ${date:-?} (hôte ${host:-?})"

load_state || true
MODE="$(deploy_mode)"
[[ -n "$MODE" ]] || die "Aucun Wazuh installé : lancez d'abord ./deploy.sh (même mode : ${BK_MODE})."
[[ "$MODE" == "$BK_MODE" ]] || die "Mode différent (installé : ${MODE}, sauvegarde : ${BK_MODE})."
confirm "Restaurer cette sauvegarde (la configuration actuelle sera remplacée) ?" n || exit 0

log_step "Restauration (${MODE})"
mkdir -p "$DEPLOY_STATE_DIR" && chmod 700 "$DEPLOY_STATE_DIR"
cp -a "${WORK}/state/." "$DEPLOY_STATE_DIR/"
log_ok "État du déploiement restauré (${STATE_FILE})"

if [[ "$MODE" == docker ]]; then
  # shellcheck disable=SC2153  # DOCKER_DIR vient de config.env / state.env
  docker_dir="${DOCKER_DIR}"
  tar -C "${WORK}/docker" -cf - . | tar -C "$docker_dir" -xf -
  log_ok "Fichiers de la stack restaurés dans ${docker_dir}"
  tar -C "${WORK}/ossec" -cf - . | docker exec -i wazuh-manager tar -C /var/ossec -xf -
  docker exec wazuh-manager chown -R wazuh:wazuh /var/ossec/etc/shared /var/ossec/etc/rules /var/ossec/etc/decoders
  docker exec wazuh-manager chown root:wazuh /var/ossec/etc/ossec.conf /var/ossec/etc/client.keys /var/ossec/etc/authd.pass 2>/dev/null
  log_ok "Configuration du manager restaurée"
  docker compose --project-directory "$docker_dir" -f "${docker_dir}/docker-compose.yml" up -d --force-recreate >/dev/null 2>&1
  log_ok "Stack redémarrée"
else
  systemctl stop wazuh-manager
  tar -C "${WORK}/ossec" -cf - . | tar -C /var/ossec -xf -
  chown -R wazuh:wazuh /var/ossec/etc/shared /var/ossec/etc/rules /var/ossec/etc/decoders
  chown root:wazuh /var/ossec/etc/ossec.conf /var/ossec/etc/client.keys /var/ossec/etc/authd.pass 2>/dev/null
  systemctl start wazuh-manager
  log_ok "Configuration du manager restaurée et service redémarré"
  log_info "Configurations indexer/dashboard/filebeat disponibles dans l'archive (native/) si besoin."
fi
log_ok "Restauration terminée — vérifiez avec ./scripts/healthcheck.sh"
