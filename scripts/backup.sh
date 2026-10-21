#!/usr/bin/env bash
# =============================================================================
#  backup.sh — Sauvegarde de la configuration Wazuh (natif ou Docker)
#  Contenu : ossec.conf, clés des agents (client.keys), règles/décodeurs,
#  groupes (shared/), authd.pass, configuration API, certificats, état du
#  déploiement. Les données indexées (alertes) ne sont pas incluses : utilisez
#  les snapshots OpenSearch pour celles-ci.
#  Usage : ./scripts/backup.sh [dossier_destination]     (défaut : BACKUP_DIR)
#  Rétention : 14 sauvegardes conservées.
# =============================================================================
set -o pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"

require_root
load_config
load_state || die "Aucun déploiement trouvé (${STATE_FILE})."
MODE="$(deploy_mode)"
DEST="${1:-$BACKUP_DIR}"
STAMP="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
ARCHIVE="${DEST}/wazuh-backup-${MODE}-${STAMP}.tar.gz"
mkdir -p "$DEST" && chmod 700 "$DEST"

OSSEC_ITEMS=(etc/ossec.conf etc/client.keys etc/authd.pass etc/rules etc/decoders etc/lists
             etc/shared etc/sslmanager.cert etc/sslmanager.key etc/internal_options.conf
             etc/local_internal_options.conf api/configuration)

log_step "Sauvegarde Wazuh (${MODE}) → ${ARCHIVE}"

mkdir -p "${WORK}/ossec"
if [[ "$MODE" == docker ]]; then
  docker exec wazuh-manager tar -C /var/ossec -cf - "${OSSEC_ITEMS[@]}" 2>/dev/null | tar -C "${WORK}/ossec" -xf - \
    || die "Lecture de /var/ossec dans le conteneur impossible"
  log_ok "Configuration du manager (conteneur)"
  mkdir -p "${WORK}/docker"
  tar -C "$DOCKER_DIR" -cf - .env docker-compose.yml config | tar -C "${WORK}/docker" -xf -
  log_ok "Stack Docker (${DOCKER_DIR} : .env, compose, certificats, configs)"
else
  tar -C /var/ossec -cf - "${OSSEC_ITEMS[@]}" 2>/dev/null | tar -C "${WORK}/ossec" -xf -
  log_ok "Configuration du manager (/var/ossec)"
  mkdir -p "${WORK}/native"
  for d in /etc/wazuh-indexer /etc/wazuh-dashboard /etc/filebeat; do
    [[ -d "$d" ]] && cp -a "$d" "${WORK}/native/"
  done
  [[ -f "${DEPLOY_STATE_DIR}/native/wazuh-install-files.tar" ]] && cp -a "${DEPLOY_STATE_DIR}/native/wazuh-install-files.tar" "${WORK}/native/"
  log_ok "Configurations indexer / dashboard / filebeat"
fi

mkdir -p "${WORK}/state"
cp -a "$STATE_FILE" "${WORK}/state/"
[[ -f "${DEPLOY_STATE_DIR}/known_hosts" ]] && cp -a "${DEPLOY_STATE_DIR}/known_hosts" "${WORK}/state/"
printf 'mode=%s\nversion=%s\ndate=%s\nhost=%s\n' "$MODE" "$WAZUH_VERSION" "$STAMP" "$(hostname)" > "${WORK}/BACKUP_INFO"

( umask 077; tar -C "$WORK" -czf "$ARCHIVE" . ) || die "Création de l'archive impossible"
log_ok "Archive créée : ${ARCHIVE} ($(du -h "$ARCHIVE" | cut -f1))"
log_warn "L'archive contient des secrets (mots de passe, clés d'agents) : conservez-la en lieu sûr."

# Rétention
mapfile -t old < <(find "$DEST" -maxdepth 1 -name 'wazuh-backup-*.tar.gz' -printf '%T@ %p\n' | sort -rn | tail -n +15 | cut -d' ' -f2-)
if (( ${#old[@]} )); then rm -f "${old[@]}"; log_info "${#old[@]} ancienne(s) sauvegarde(s) supprimée(s)"; fi
