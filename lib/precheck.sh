#!/usr/bin/env bash
# =============================================================================
#  lib/precheck.sh — Contrôles préalables du serveur Wazuh
# =============================================================================

SUPPORTED_OS_REGEX='^(ubuntu (20\.04|22\.04|24\.04)|debian (11|12|13)|rhel (8|9|10)(\..*)?|rocky (8|9|10)(\..*)?|almalinux (8|9|10)(\..*)?|centos (8|9|10)|amzn 2023|ol (8|9)(\..*)?)$'

# server_prechecks <native|docker>  -> 0 si OK (ou si l'utilisateur force)
server_prechecks() {
  local mode="$1" errors=0 warns=0
  local cpu ram_mb disk_gb port proto p

  log_step "Contrôles préalables du serveur (mode ${mode})"

  # Système d'exploitation
  detect_os
  if [[ "${OS_ID} ${OS_VERSION}" =~ $SUPPORTED_OS_REGEX ]]; then
    check_line "Système : ${OS_PRETTY}" OK
  else
    check_line "Système : ${OS_PRETTY}" WARN "non validé (Ubuntu 20.04-24.04, Debian 11-13, RHEL/Rocky/Alma 8-10)"
    warns=$((warns + 1))
  fi

  # Architecture
  case "$(uname -m)" in
    x86_64|aarch64) check_line "Architecture : $(uname -m)" OK ;;
    *) check_line "Architecture : $(uname -m)" KO "x86_64 ou aarch64 requis"; errors=$((errors + 1)) ;;
  esac

  # CPU / RAM / disque
  cpu="$(nproc 2>/dev/null || echo 1)"
  ram_mb="$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)"
  if [[ "$mode" == "docker" ]]; then
    disk_gb="$(df -BG --output=avail /var/lib 2>/dev/null | tail -1 | tr -dc '0-9')"
  else
    disk_gb="$(df -BG --output=avail /var 2>/dev/null | tail -1 | tr -dc '0-9')"
  fi
  if (( cpu >= MIN_CPU )); then check_line "CPU : ${cpu} vCPU" OK
  else check_line "CPU : ${cpu} vCPU" WARN "minimum recommandé ${MIN_CPU}"; warns=$((warns + 1)); fi
  if (( ram_mb >= MIN_RAM_MB )); then check_line "RAM : ${ram_mb} Mo" OK
  elif (( ram_mb >= 3800 )); then check_line "RAM : ${ram_mb} Mo" WARN "minimum recommandé ${MIN_RAM_MB} Mo"; warns=$((warns + 1))
  else check_line "RAM : ${ram_mb} Mo" KO "4 Go minimum absolu"; errors=$((errors + 1)); fi
  if (( ${disk_gb:-0} >= MIN_DISK_GB )); then check_line "Disque libre : ${disk_gb} Go" OK
  elif (( ${disk_gb:-0} >= 20 )); then check_line "Disque libre : ${disk_gb} Go" WARN "minimum recommandé ${MIN_DISK_GB} Go"; warns=$((warns + 1))
  else check_line "Disque libre : ${disk_gb:-?} Go" KO "20 Go minimum absolu"; errors=$((errors + 1)); fi

  # Ports
  for p in "${DASHBOARD_PORT}/tcp" 1514/tcp 1515/tcp 55000/tcp 9200/tcp "${SYSLOG_PORT}/udp"; do
    port="${p%/*}"; proto="${p#*/}"
    if port_in_use "$port" "$proto"; then
      # Un port occupé par Wazuh lui-même n'est pas une erreur (réinstallation)
      if ss -lntup 2>/dev/null | grep -E "[:.]${port}\s" | grep -Eqi 'wazuh|ossec|java|node|docker'; then
        check_line "Port ${p}" WARN "déjà utilisé par Wazuh/Docker"
        warns=$((warns + 1))
      else
        check_line "Port ${p}" KO "déjà utilisé par un autre service"
        errors=$((errors + 1))
      fi
    else
      check_line "Port ${p}" OK "libre"
    fi
  done

  # Accès Internet
  if [[ "$mode" == "native" ]]; then
    if https_reachable "https://packages.wazuh.com/${WAZUH_MINOR}/wazuh-install.sh"; then
      check_line "Accès packages.wazuh.com" OK
    else
      check_line "Accès packages.wazuh.com" KO "requis pour l'installation native"
      errors=$((errors + 1))
    fi
  else
    if https_reachable "https://registry-1.docker.io/v2/" || https_reachable "https://hub.docker.com"; then
      check_line "Accès Docker Hub" OK
    else
      check_line "Accès Docker Hub" KO "requis pour télécharger les images"
      errors=$((errors + 1))
    fi
  fi

  # Outils de base
  for p in curl tar awk sed; do
    if have "$p"; then log_verbose "  outil ${p} présent"
    else pkg_install "$p" || { check_line "Outil ${p}" KO; errors=$((errors + 1)); }; fi
  done

  # Synchronisation horaire (importante pour la corrélation des événements)
  if have timedatectl && timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
    check_line "Horloge synchronisée (NTP)" OK
  else
    check_line "Horloge synchronisée (NTP)" WARN "activez chrony/systemd-timesyncd"
    warns=$((warns + 1))
  fi

  echo
  if (( errors > 0 )); then
    log_error "${errors} contrôle(s) bloquant(s), ${warns} avertissement(s)."
    if [[ "${IGNORE_CHECKS:-0}" == "1" ]]; then
      log_warn "--ignore-checks : on continue malgré tout."
      return 0
    fi
    confirm "Continuer malgré les erreurs (déconseillé) ?" n || return 1
  elif (( warns > 0 )); then
    log_warn "${warns} avertissement(s) — installation possible."
    confirm "Continuer ?" o || return 1
  else
    log_ok "Tous les contrôles sont au vert."
  fi
  return 0
}
