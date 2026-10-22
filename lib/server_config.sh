#!/usr/bin/env bash
# =============================================================================
#  lib/server_config.sh — Configuration post-installation du manager
#  Commun aux modes natif et Docker :
#    - réception syslog des équipements réseau
#    - enrôlement des agents protégé par mot de passe
#    - groupes d'agents + configuration centralisée (agent.conf)
#    - règles / décodeurs personnalisés
# =============================================================================

MARK_BEGIN="<!-- WAZUH-DEPLOY:BEGIN (généré par deploy.sh — ne pas éditer) -->"
MARK_END="<!-- WAZUH-DEPLOY:END -->"

# Bloc <ossec_config> ajouté à la fin de ossec.conf
build_ossec_block() {
  local protos=() p ip
  devices_apply_allowed_ips
  case "${SYSLOG_PROTOCOL:-udp}" in
    both) protos=(udp tcp) ;;
    tcp)  protos=(tcp) ;;
    *)    protos=(udp) ;;
  esac
  echo "$MARK_BEGIN"
  echo "<ossec_config>"
  if [[ "${SYSLOG_ENABLED:-yes}" == "yes" ]]; then
    for p in "${protos[@]}"; do
      echo "  <!-- Réception syslog : FortiGate, Palo Alto, Cisco, ... (${p}/${SYSLOG_PORT}) -->"
      echo "  <remote>"
      echo "    <connection>syslog</connection>"
      echo "    <port>${SYSLOG_PORT}</port>"
      echo "    <protocol>${p}</protocol>"
      echo "    <allowed-ips>127.0.0.1</allowed-ips>"
      for ip in ${SYSLOG_ALLOWED_IPS}; do
        echo "    <allowed-ips>${ip}</allowed-ips>"
      done
      echo "  </remote>"
    done
  fi
  # Réponse active (XDR) : blocage temporaire des sources de brute force
  if [[ "${ACTIVE_RESPONSE:-yes}" == "yes" ]]; then
    echo "  <global>"
    # Toutes les IP du serveur (dont les passerelles Docker) : sans cela, un
    # administrateur qui se trompe de mot de passe avec install-agent.sh ferait
    # bloquer le serveur Wazuh lui-même par ses propres agents.
    local wl
    # shellcheck disable=SC2046,SC2086  # découpage en mots voulu
    wl="$(printf '%s\n' 127.0.0.1 ${MANAGER_IP} $(hostname -I 2>/dev/null) ${AR_WHITELIST} \
          | grep -E '^[0-9.]+(/[0-9]+)?$' | sort -u)"
    for ip in $wl; do
      echo "    <white_list>${ip}</white_list>"
    done
    echo "  </global>"
    echo "  <active-response>"
    echo "    <command>firewall-drop</command>"
    echo "    <location>local</location>"
    echo "    <rules_id>${AR_LINUX_RULES}</rules_id>"
    echo "    <timeout>${AR_TIMEOUT}</timeout>"
    echo "  </active-response>"
    echo "  <active-response>"
    echo "    <command>netsh</command>"
    echo "    <location>local</location>"
    echo "    <rules_id>${AR_WINDOWS_RULES}</rules_id>"
    echo "    <timeout>${AR_TIMEOUT}</timeout>"
    echo "  </active-response>"
  fi

  # Notifications et enrichissement
  if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    echo "  <integration>"
    echo "    <name>slack</name>"
    echo "    <hook_url>${SLACK_WEBHOOK_URL}</hook_url>"
    echo "    <level>${ALERT_NOTIFY_LEVEL:-10}</level>"
    echo "    <alert_format>json</alert_format>"
    echo "  </integration>"
  fi
  if [[ -n "${VIRUSTOTAL_API_KEY:-}" ]]; then
    echo "  <integration>"
    echo "    <name>virustotal</name>"
    echo "    <api_key>${VIRUSTOTAL_API_KEY}</api_key>"
    echo "    <group>syscheck</group>"
    echo "    <alert_format>json</alert_format>"
    echo "  </integration>"
  fi
  echo "</ossec_config>"
  echo "$MARK_END"
}

# Applique notre bloc à un fichier ossec.conf (idempotent)
# apply_ossec_conf <fichier>
apply_ossec_conf() {
  local conf="$1" tmp
  [[ -f "$conf" ]] || { log_error "ossec.conf introuvable : $conf"; return 1; }
  cp -p "$conf" "${conf}.bak-$(date +%Y%m%d%H%M%S)"
  tmp="$(mktemp)"
  # Retire un éventuel bloc précédent
  awk -v b="WAZUH-DEPLOY:BEGIN" -v e="WAZUH-DEPLOY:END" '
    index($0,b){skip=1} !skip{print} index($0,e){skip=0}' "$conf" > "$tmp"
  build_ossec_block >> "$tmp"
  # Enrôlement par mot de passe
  sed -i 's#<use_password>no</use_password>#<use_password>yes</use_password>#' "$tmp"
  # Listes CDB du projet, insérées dans le <ruleset> PRINCIPAL : un second bloc
  # <ruleset> désactiverait le chargement de etc/rules et etc/decoders.
  sed -i '/<!-- WAZUH-DEPLOY:list -->/d' "$tmp"
  local lists="" f
  for f in "${PROJECT_DIR}"/manager/lists/*; do
    [[ -f "$f" ]] && lists+="    <list>etc/lists/$(basename "$f")</list> <!-- WAZUH-DEPLOY:list -->\n"
  done
  [[ -n "$lists" ]] && sed -i "0,/<\/ruleset>/s#<\/ruleset>#${lists}  </ruleset>#" "$tmp"
  cat "$tmp" > "$conf"   # conserve propriétaire et droits
  rm -f "$tmp"
  log_ok "ossec.conf mis à jour (syslog ${SYSLOG_PROTOCOL}/${SYSLOG_PORT}, enrôlement par mot de passe)"
}

# Docker : le conteneur ne recopie /wazuh-config-mount qu'au premier démarrage.
# On pousse donc aussi ossec.conf directement dans le conteneur (persisté par
# le volume wazuh_etc), sinon une reconfiguration serait ignorée.
docker_sync_ossec_conf() {
  local src="${DOCKER_DIR}/config/wazuh_cluster/wazuh_manager.conf"
  [[ "$(deploy_mode)" == "docker" && -f "$src" ]] || return 0
  docker inspect "$MANAGER_CONTAINER" >/dev/null 2>&1 || return 0
  mgr_copy "$src" /var/ossec/etc/ossec.conf root:wazuh 660
  log_verbose "  ossec.conf synchronisé dans le conteneur ${MANAGER_CONTAINER}"
}

# Redémarre le manager
manager_restart() {
  log_info "Redémarrage du manager Wazuh..."
  if [[ "$(deploy_mode)" == "docker" ]]; then
    run docker restart "$MANAGER_CONTAINER"
  else
    run systemctl restart wazuh-manager
  fi
}

# Attend que l'API du manager réponde : wait_manager_api [timeout_s]
wait_manager_api() {
  local timeout="${1:-300}" waited=0
  log_info "Attente de l'API Wazuh (55000)..."
  while (( waited < timeout )); do
    if curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:55000/" 2>/dev/null | grep -q '^401$\|^200$'; then
      log_ok "API Wazuh disponible (${waited}s)"
      return 0
    fi
    sleep 5; waited=$((waited + 5))
    (( waited % 30 == 0 )) && log_verbose "  ... toujours en attente (${waited}s)"
  done
  log_error "L'API Wazuh ne répond pas après ${timeout}s"
  return 1
}

# Configuration effectuée une fois le manager démarré
configure_manager_runtime() {
  local g src dest_dir f

  log_step "Configuration du manager"
  docker_sync_ossec_conf

  # 1) Mot de passe d'enrôlement
  printf '%s\n' "$ENROLLMENT_PASSWORD" | mgr_write /var/ossec/etc/authd.pass root:wazuh 640
  log_ok "Mot de passe d'enrôlement installé (/var/ossec/etc/authd.pass)"

  # 2) Règles et décodeurs personnalisés
  for f in "${PROJECT_DIR}"/manager/rules/*.xml; do
    [[ -e "$f" ]] || continue
    mgr_copy "$f" "/var/ossec/etc/rules/$(basename "$f")" wazuh:wazuh 660
    log_verbose "  règle   : $(basename "$f")"
  done
  for f in "${PROJECT_DIR}"/manager/lists/*; do
    [[ -f "$f" ]] || continue
    mgr_copy "$f" "/var/ossec/etc/lists/$(basename "$f")" wazuh:wazuh 660
    log_verbose "  liste   : $(basename "$f")"
  done
  for f in "${PROJECT_DIR}"/manager/decoders/*.xml; do
    [[ -e "$f" ]] || continue
    mgr_copy "$f" "/var/ossec/etc/decoders/$(basename "$f")" wazuh:wazuh 660
    log_verbose "  décodeur: $(basename "$f")"
  done
  if mgr_exec /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    log_ok "Règles et décodeurs personnalisés valides"
  else
    log_error "Erreur dans les règles personnalisées — retrait pour ne pas bloquer le manager"
    for f in "${PROJECT_DIR}"/manager/rules/*.xml "${PROJECT_DIR}"/manager/decoders/*.xml; do
      [[ -e "$f" ]] || continue
      mgr_exec rm -f "/var/ossec/etc/rules/$(basename "$f")" "/var/ossec/etc/decoders/$(basename "$f")"
    done
  fi

  # 3) Groupes d'agents + configuration centralisée
  for g in ${AGENT_GROUPS}; do
    if ! mgr_exec /var/ossec/bin/agent_groups -l 2>/dev/null | grep -Eq "^\s*${g}\b"; then
      if mgr_exec /var/ossec/bin/agent_groups -a -g "$g" -q >/dev/null 2>&1; then
        log_ok "Groupe d'agents créé : ${g}"
      else
        log_warn "Création du groupe ${g} impossible"
      fi
    else
      log_verbose "  groupe ${g} déjà présent"
    fi
    src="${PROJECT_DIR}/manager/shared/${g}/agent.conf"
    dest_dir="/var/ossec/etc/shared/${g}"
    if [[ -f "$src" ]]; then
      mgr_exec mkdir -p "$dest_dir"
      mgr_copy "$src" "${dest_dir}/agent.conf" wazuh:wazuh 660
      if mgr_exec /var/ossec/bin/verify-agent-conf -f "${dest_dir}/agent.conf" >/dev/null 2>&1; then
        log_ok "Configuration centralisée du groupe ${g} déployée"
      else
        log_warn "agent.conf du groupe ${g} invalide (vérifiez ${src})"
      fi
    fi
  done

  # 4) Performances : files d'attente d'analysisd (mesuré en labo : avec les
  #    valeurs par défaut, 13 % d'événements perdus à 10 000 EPS en rafale)
  local lio=/var/ossec/etc/local_internal_options.conf q="${ANALYSISD_QUEUE_SIZE:-131072}"
  { mgr_exec cat "$lio" 2>/dev/null | sed '/WAZUH-DEPLOY/,$d'
    echo "# WAZUH-DEPLOY : réglages de performance (deploy.sh) — ne pas éditer en dessous"
    for k in decode_event decode_winevt decode_output alerts archives firewall statistical; do
      echo "analysisd.${k}_queue_size=${q}"
    done
  } > "${RUN_TMP:-/tmp}/wz-lio.$$"
  mgr_copy "${RUN_TMP:-/tmp}/wz-lio.$$" "$lio" root:wazuh 640
  rm -f "${RUN_TMP:-/tmp}/wz-lio.$$"
  log_ok "Files d'attente d'analysisd dimensionnées (${q} événements)"

  # 5) Indexer : catégorisation des équipements, rétention, tableaux de bord
  devices_install_enrichment || true
  devices_install_retention || true
  if [[ -x "${PROJECT_DIR}/scripts/import-dashboards.sh" ]]; then
    "${PROJECT_DIR}/scripts/import-dashboards.sh" || log_warn "Import des tableaux de bord incomplet"
  fi
}

# Récapitulatif final des accès
print_access_summary() {
  local url="${DASHBOARD_URL:-https://${MANAGER_IP}}"
  echo
  printf '%s\n' "${C_GREEN}${C_BOLD}══════════════════════ WAZUH EST PRÊT ══════════════════════${C_RESET}"
  printf '  %-26s %s\n' "Mode :" "${DEPLOY_MODE}"
  printf '  %-26s %s\n' "Version :" "${WAZUH_VERSION}"
  printf '  %-26s %s\n' "Dashboard :" "${url}"
  printf '  %-26s %s\n' "Utilisateur :" "admin"
  printf '  %-26s %s\n' "Mot de passe admin :" "${INDEXER_ADMIN_PASSWORD:-voir ${STATE_FILE}}"
  printf '  %-26s %s\n' "IP manager (agents) :" "${MANAGER_IP}  (1514/tcp, 1515/tcp)"
  printf '  %-26s %s\n' "Syslog équipements :" "${MANAGER_IP}:${SYSLOG_PORT}/${SYSLOG_PROTOCOL}"
  printf '  %-26s %s\n' "Secrets :" "${STATE_FILE} (root, chmod 600)"
  printf '  %-26s %s\n' "Journal :" "${LOG_FILE}"
  echo
  printf '%s\n' "${C_BOLD}Étapes suivantes :${C_RESET}"
  echo "  1) Découvrir le réseau     : ./agents/install-agent.sh 192.168.1.0/24 -d"
  echo "  2) Installer les agents    : ./agents/install-agent.sh 192.168.1.0/24 -l -u admin -p"
  echo "  3) Équipements réseau      : voir network-devices/*.md"
  echo "  4) Vérifier la plateforme  : ./scripts/healthcheck.sh"
  printf '%s\n' "${C_YELLOW}Le certificat du dashboard est auto-signé : acceptez l'avertissement du navigateur.${C_RESET}"
  echo
}
