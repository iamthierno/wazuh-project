#!/usr/bin/env bash
# =============================================================================
#  lib/native.sh — Option 1 : installation native (all-in-one) sur Linux
#  Utilise l'assistant officiel wazuh-install.sh (indexer + manager + dashboard)
# =============================================================================

native_is_installed() {
  [[ -x /var/ossec/bin/wazuh-control ]] && /var/ossec/bin/wazuh-control info -t 2>/dev/null | grep -q server
}

native_installed_version() {
  /var/ossec/bin/wazuh-control info -v 2>/dev/null | tr -d 'v'
}

# Extrait un mot de passe de wazuh-passwords.txt : _pw_from_file <fichier> <utilisateur>
_pw_from_file() {
  awk -v u="$2" '
    $0 ~ "(indexer|api)_username: *.?"u".?$" {getline; gsub(/.*_password: *|\x27|"/,""); print; exit}' "$1"
}

native_firewall() {
  [[ "${CONFIGURE_FIREWALL:-yes}" == "yes" ]] || { log_verbose "Pare-feu : configuration désactivée"; return 0; }
  local p ports=("${DASHBOARD_PORT}/tcp" 1514/tcp 1515/tcp 55000/tcp)
  case "${SYSLOG_PROTOCOL}" in
    both) ports+=("${SYSLOG_PORT}/udp" "${SYSLOG_PORT}/tcp") ;;
    *)    ports+=("${SYSLOG_PORT}/${SYSLOG_PROTOCOL}") ;;
  esac
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
    for p in "${ports[@]}"; do run ufw allow "$p"; done
    log_ok "Pare-feu ufw : ports ouverts (${ports[*]})"
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    for p in "${ports[@]}"; do run firewall-cmd --permanent --add-port="$p"; done
    run firewall-cmd --reload
    log_ok "Pare-feu firewalld : ports ouverts (${ports[*]})"
  else
    log_verbose "Aucun pare-feu local actif (ufw/firewalld)"
  fi
}

# Empêche une mise à jour accidentelle de Wazuh via apt/dnf upgrade
native_lock_repo() {
  if [[ -f /etc/apt/sources.list.d/wazuh.list ]]; then
    sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list
    run apt-get update -q
  elif [[ -f /etc/yum.repos.d/wazuh.repo ]]; then
    sed -i 's/^enabled=1/enabled=0/' /etc/yum.repos.d/wazuh.repo
  fi
  log_verbose "Dépôt Wazuh désactivé (mise à jour manuelle et contrôlée uniquement)"
}

native_install() {
  local workdir="${DEPLOY_STATE_DIR}/native" installer opts=() pwfile reinstall=0

  if native_is_installed; then
    log_warn "Wazuh $(native_installed_version) est déjà installé sur ce serveur."
    if confirm "Ne refaire que la configuration (syslog, groupes, règles, enrôlement) ?" o; then
      reinstall=1
    else
      log_info "Pour réinstaller : ./deploy.sh --uninstall puis relancer l'installation."
      return 1
    fi
  fi

  if (( reinstall == 0 )); then
    server_prechecks native || return 1
  fi

  mkdir -p "$workdir" && chmod 700 "$workdir"
  MANAGER_IP="${MANAGER_IP:-$(primary_ip)}"
  [[ -n "$MANAGER_IP" ]] || die "Impossible de déterminer l'IP du serveur : renseignez MANAGER_IP dans config.env"
  ENROLLMENT_PASSWORD="${ENROLLMENT_PASSWORD:-$(gen_password 24)}"
  register_secret "$ENROLLMENT_PASSWORD"

  if (( reinstall == 0 )); then
    log_step "Téléchargement de l'assistant d'installation Wazuh ${WAZUH_MINOR}"
    installer="${workdir}/wazuh-install.sh"
    run curl -fsSL -o "$installer" "https://packages.wazuh.com/${WAZUH_MINOR}/wazuh-install.sh" \
      || die "Téléchargement de wazuh-install.sh impossible"
    log_ok "wazuh-install.sh téléchargé"

    opts=(-a)
    [[ "${IGNORE_CHECKS:-0}" == "1" ]] && opts+=(-i)
    log_step "Installation all-in-one (indexer + manager + dashboard) — 10 à 20 minutes"
    ( cd "$workdir" && run_live bash "$installer" "${opts[@]}" ) \
      || die "L'installation Wazuh a échoué. Voir ${LOG_FILE} et /var/log/wazuh-install.log"
    log_ok "Installation Wazuh terminée"

    # Récupération des mots de passe générés par l'assistant
    pwfile="${workdir}/wazuh-passwords.txt"
    ( umask 077; tar -O -xf "${workdir}/wazuh-install-files.tar" wazuh-install-files/wazuh-passwords.txt > "$pwfile" ) \
      || die "Lecture de wazuh-install-files.tar impossible"
    state_set INDEXER_ADMIN_PASSWORD "$(_pw_from_file "$pwfile" admin)"
    state_set API_USER "wazuh-wui"
    state_set API_PASSWORD "$(_pw_from_file "$pwfile" wazuh-wui)"
    register_secret "$INDEXER_ADMIN_PASSWORD"; register_secret "$API_PASSWORD"
    native_lock_repo

    if [[ "$DASHBOARD_PORT" != "443" ]]; then
      sed -i "s/^server.port:.*/server.port: ${DASHBOARD_PORT}/" /etc/wazuh-dashboard/opensearch_dashboards.yml
      run systemctl restart wazuh-dashboard
      log_ok "Dashboard déplacé sur le port ${DASHBOARD_PORT}"
    fi
  fi

  state_set DEPLOY_MODE native
  state_set MANAGER_IP "$MANAGER_IP"
  state_set WAZUH_VERSION "$(native_installed_version)"
  state_set ENROLLMENT_PASSWORD "$ENROLLMENT_PASSWORD"
  state_set DASHBOARD_URL "https://${MANAGER_IP}$( [[ "$DASHBOARD_PORT" != 443 ]] && echo ":${DASHBOARD_PORT}")"

  log_step "Personnalisation de ossec.conf"
  apply_ossec_conf /var/ossec/etc/ossec.conf
  configure_manager_runtime
  manager_restart
  wait_manager_api 180 || log_warn "Vérifiez : systemctl status wazuh-manager"

  native_firewall
  print_access_summary
}
