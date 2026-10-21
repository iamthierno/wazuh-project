#!/usr/bin/env bash
# =============================================================================
#  agents/lib/actions.sh — Traitement d'un hôte (exécuté en parallèle)
#  install | check | status | log | update | remove | purge
#  Chaque worker écrit son résultat dans ${RUN_DIR}/results/<ip>
# =============================================================================

# ------------------------------------------------------------ Affichage hôte
_hp() { printf '%s[%-15s][%-7s]%s' "$C_BOLD" "$H_IP" "$H_OS" "$C_RESET"; }
h_step()  { log_info  "$(_hp) $*"; }
h_ok()    { log_ok    "$(_hp) ${C_GREEN}✔${C_RESET} $*"; }
h_warn()  { log_warn  "$(_hp) $*"; }
h_err()   { log_error "$(_hp) ${C_RED}✖${C_RESET} $*"; }
h_verb()  { log_verbose "$(_hp) $*"; }
h_check() { # h_check <libellé> <OK|KO|WARN> [détail]
  local label="$1" st="$2" d="${3:-}" color dots len
  len="$(strlen "$label")"
  case "$st" in OK) color="$C_GREEN";; KO) color="$C_RED";; *) color="$C_YELLOW";; esac
  dots="$(printf '%*s' $(( 30 - len > 2 ? 30 - len : 2 )) '' | tr ' ' '.')"
  if [[ "$st" == "OK" ]]; then
    log_verbose "$(_hp) ${label} ${dots} ${color}${st}${C_RESET}${d:+  $d}"
  else
    _log 1 "$C_CYAN" "CHECK" "$(_hp) ${label} ${dots} ${color}${st}${C_RESET}${d:+  $d}"
  fi
}

# Enregistre le résultat : h_result <STATUT> <détail>
h_result() {
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$H_IP" "$H_OS" "${F[OS_NAME]:--}" "$1" \
    "${R_AGENT_ID:--}" "${R_VERSION:--}" "$2" > "${RUN_DIR}/results/${H_IP}"
}

ver_lt() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }

# ---------------------------------------------------------- Appel du payload
# run_payload <action> [CLE=valeur...] : remplit F[...], RES_STATUS, RES_MSG
# Affiche en direct les étapes (STEP|) préfixées par l'hôte.
run_payload() {
  local action="$1"; shift
  local errf="${RUN_DIR}/${H_IP}.${action}.err" line tag rest started=0 rc
  local common=(
    "WAZUH_MANAGER=${MANAGER_IP}" "WAZUH_VERSION=${WAZUH_VERSION}"
    "PKG_BASE_URL=${PKG_BASE_URL}" "LOG_LINES=${LOG_LINES}"
    "CHECK_INTERNET=$( [[ "$OFFLINE" == 1 ]] && echo no || echo yes )"
  )
  RES_STATUS=""; RES_MSG=""
  while IFS= read -r line; do
    line="${line%$'\r'}"
    tag="${line%%|*}"; rest="${line#*|}"
    case "$tag" in
      PAYLOAD_START) started=1 ;;
      STEP)   h_step "$rest" ;;
      INFO)   h_verb "$rest" ;;
      WARN)   h_warn "$rest" ;;
      ERR)    h_err "$rest" ;;
      KV)     F["${rest%%=*}"]="${rest#*=}"; log_debug "$(_hp) ${rest}" ;;
      LOG)    printf '%s %s\n' "$(_hp)" "$rest"; [[ -n "$LOG_FILE" ]] && printf '[%s] %s\n' "$H_IP" "$rest" >> "$LOG_FILE" ;;
      RESULT) RES_STATUS="${rest%%|*}"; RES_MSG="${rest#*|}" ;;
      *)      [[ -n "$line" ]] && log_debug "$(_hp) ${line}" ;;
    esac
  done < <(
    if [[ "$H_OS" == "windows" ]]; then
      win_action "$H_IP" "$H_TRANSPORT" "$action" "${common[@]}" "$@" 2>"$errf"
    else
      unix_action "$H_IP" "$action" "${common[@]}" "$@" 2>"$errf"
    fi
  )
  rc=0
  if [[ -z "$RES_STATUS" ]]; then
    if (( started == 0 )); then
      if [[ "$H_OS" == "windows" ]]; then RES_MSG="$(win_explain "$errf")"; else RES_MSG="$(ssh_explain "$errf")"; fi
    else
      RES_MSG="exécution interrompue ($(tail -1 "$errf" 2>/dev/null))"
    fi
    RES_STATUS="fail"; rc=1
  elif [[ "$RES_STATUS" != "ok" ]]; then
    rc=1
  fi
  [[ -s "$errf" ]] && sed "s/^/[${H_IP}] /" "$errf" | _strip_colors >> "${LOG_FILE:-/dev/null}"
  rm -f "$errf"
  return "$rc"
}

# --------------------------------------------------------- Identifiants hôte
h_load_creds() {
  case "$H_OS" in
    windows) R_USER="$WIN_USER";   R_PASS="$WIN_PASS";   R_KEY="" ;;
    macos)   R_USER="$MAC_USER";   R_PASS="$MAC_PASS";   R_KEY="$MAC_KEY" ;;
    *)       R_USER="$LINUX_USER"; R_PASS="$LINUX_PASS"; R_KEY="$LINUX_KEY" ;;
  esac
  [[ -n "$R_USER" ]]
}

# Nom du paquet selon OS/type/architecture : pkg_name -> "fichier|url"
pkg_name() {
  local arch="${F[ARCH]}" file sub
  case "${F[PKG_TYPE]}" in
    deb)
      case "$arch" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; armv7*|armhf) arch=armhf;; i?86) arch=i386;; *) return 1;; esac
      file="wazuh-agent_${WAZUH_VERSION}-1_${arch}.deb"; sub="apt/pool/main/w/wazuh-agent" ;;
    rpm)
      case "$arch" in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=aarch64;; armv7*) arch=armv7hl;; i?86) arch=i386;; *) return 1;; esac
      file="wazuh-agent-${WAZUH_VERSION}-1.${arch}.rpm"; sub="yum" ;;
    pkg)
      case "$arch" in arm64) arch=arm64;; x86_64) arch=intel64;; *) return 1;; esac
      file="wazuh-agent-${WAZUH_VERSION}-1.${arch}.pkg"; sub="macos" ;;
    msi)
      file="wazuh-agent-${WAZUH_VERSION}-1.msi"; sub="windows" ;;
    *) return 1 ;;
  esac
  printf '%s|%s' "$file" "${PKG_BASE_URL}/${WAZUH_MAJOR_BRANCH}/${sub}/${file}"
}

# Prépare le paquet en mode offline (cache local puis envoi) -> PKG_LOCAL
h_push_package() {
  local file="$1" url="$2" cache lock remote
  cache="${AGENTS_DIR}/packages/${file}"
  lock="${AGENTS_DIR}/packages/.${file}.lock"
  if [[ ! -s "$cache" ]]; then
    (
      flock 9
      if [[ ! -s "$cache" ]]; then
        log_info "Téléchargement de ${file} dans le cache du serveur..."
        curl -fsSL -m 600 -o "${cache}.part" "$url" && mv -f "${cache}.part" "$cache"
      fi
    ) 9>"$lock"
    rm -f "${cache}.part"
  fi
  [[ -s "$cache" ]] || { h_err "paquet ${file} absent du cache (déposez-le dans agents/packages/)"; return 1; }
  h_step "Envoi du paquet ${file} ($(du -h "$cache" | cut -f1)) vers la cible"
  if [[ "$H_OS" == "windows" ]]; then
    remote="C:\\Windows\\Temp\\wazuh-deploy-${file}"
    win_upload "$H_IP" "$H_TRANSPORT" "$cache" "$remote" 2>>"${LOG_FILE:-/dev/null}" || { h_err "envoi du paquet impossible"; return 1; }
  else
    remote="$(unix_upload "$H_IP" "$cache" 2>>"${LOG_FILE:-/dev/null}")" || { h_err "envoi du paquet impossible"; return 1; }
  fi
  PKG_LOCAL="$remote"
}

# ------------------------------------------------------------- Pré-contrôles
# h_prechecks : contrôles avant installation / mise à jour -> 0 si OK
h_prechecks() {
  local bad=0 free="${F[FREE_MB]:-0}"

  h_check "Droits administrateur" OK
  if pkg_name >/dev/null; then
    h_check "Architecture / paquet" OK "${F[ARCH]} / ${F[PKG_TYPE]}"
  else
    h_check "Architecture / paquet" KO "non supporté (${F[ARCH]} / ${F[PKG_TYPE]})"; bad=1
  fi
  if (( free >= 1024 )); then h_check "Espace disque" OK "${free} Mo"
  elif (( free >= 400 )); then h_check "Espace disque" WARN "${free} Mo (faible)"
  else h_check "Espace disque" KO "${free} Mo (400 Mo minimum)"; bad=1; fi
  if [[ "${F[PORT_1514]}" == ok && "${F[PORT_1515]}" == ok ]]; then
    h_check "Accès manager 1514/1515" OK "${MANAGER_IP}"
  else
    h_check "Accès manager 1514/1515" KO "1514=${F[PORT_1514]} 1515=${F[PORT_1515]} → ouvrez ces ports vers ${MANAGER_IP}"; bad=1
  fi
  if [[ "$OFFLINE" == 1 ]]; then
    h_check "Source du paquet" OK "envoi depuis le serveur (--offline)"
  elif [[ "${F[INTERNET]}" == ok ]]; then
    h_check "Accès ${PKG_BASE_URL#https://}" OK
  else
    h_check "Accès ${PKG_BASE_URL#https://}" WARN "indisponible → envoi du paquet depuis le serveur"
    USE_PUSH=1
  fi
  return "$bad"
}

# ----------------------------------------------------------------- Actions
act_check() {
  local api_info api_st="-"
  if [[ "${F[AGENT_INSTALLED]}" != yes ]]; then
    h_warn "agent NON installé"
    h_result "ABSENT" "agent non installé"
    return 0
  fi
  R_VERSION="${F[AGENT_VERSION]:--}"; R_AGENT_ID="${F[AGENT_ID]:--}"
  if api_available && [[ "$R_AGENT_ID" != "-" ]]; then
    api_info="$(api_agent_by_id "$R_AGENT_ID")"
    api_st="$(cut -d'|' -f2 <<<"$api_info")"; api_st="${api_st:-inconnu du manager}"
  fi
  local svc="arrêté" msg
  [[ "${F[AGENT_RUNNING]}" == yes ]] && svc="actif"
  msg="installé v${R_VERSION}, service ${svc}, ID ${R_AGENT_ID}, manager : ${api_st}"
  if ver_lt "$R_VERSION" "$WAZUH_VERSION"; then
    msg+=" — mise à jour disponible (${WAZUH_VERSION}, option -U)"
  fi
  if [[ "${F[AGENT_RUNNING]}" == yes && ( "$api_st" == active || "$api_st" == "-" ) ]]; then
    h_ok "$msg"; h_result "OK" "$msg"
  else
    h_warn "$msg"; h_result "ATTENTION" "$msg"
  fi
}

act_status() {
  local api_info api_st="-" last
  run_payload status || { h_err "$RES_MSG"; h_result "ECHEC" "$RES_MSG"; return 1; }
  if [[ "${F[AGENT_INSTALLED]}" != yes ]]; then
    h_warn "agent non installé"; h_result "ABSENT" "agent non installé"; return 0
  fi
  R_VERSION="${F[AGENT_VERSION]:--}"; R_AGENT_ID="${F[AGENT_ID]:--}"
  if api_available; then
    if [[ "$R_AGENT_ID" != "-" ]]; then api_info="$(api_agent_by_id "$R_AGENT_ID")"
    else api_info="$(api_agent_by_name "${F[AGENT_NAME]:-${F[HOSTNAME]}}")"; fi
    api_st="$(cut -d'|' -f2 <<<"$api_info")"; api_st="${api_st:-inconnu}"
    [[ -n "$api_info" ]] && h_verb "manager : ID $(cut -d'|' -f1 <<<"$api_info"), dernier contact $(cut -d'|' -f5 <<<"$api_info"), groupes $(cut -d'|' -f6 <<<"$api_info")"
  fi
  last="${F[LAST_EVENT]:-}"
  [[ -n "$last" ]] && h_verb "dernier événement : ${last}"
  local svc="ARRÊTÉ" msg
  [[ "${F[AGENT_RUNNING]}" == yes ]] && svc="actif"
  msg="service ${svc} · manager : ${api_st} · v${R_VERSION}"
  if [[ "${F[AGENT_RUNNING]}" == yes && "$api_st" =~ ^(active|-)$ ]]; then
    h_ok "$msg"; h_result "OK" "$msg"
  else
    h_warn "$msg"; h_result "ATTENTION" "$msg"
  fi
}

# Statut côté manager uniquement (sans identifiants)
act_status_manager_only() {
  local lines l id name st ver
  if ! api_available; then
    h_result "ECHEC" "API du manager indisponible et aucun identifiant fourni"; return 1
  fi
  lines="$(api_agents_by_ip "$H_IP")"
  if [[ -z "$lines" ]]; then
    h_warn "aucun agent enregistré avec cette IP sur le manager"
    h_result "ABSENT" "aucun agent enregistré (manager)"; return 0
  fi
  while IFS='|' read -r id name st ver; do
    R_AGENT_ID="$id"; R_VERSION="$ver"
    l="agent ${name} (ID ${id}) : ${st}, v${ver}"
    if [[ "$st" == active ]]; then h_ok "$l"; h_result "OK" "$l (vu du manager)"
    else h_warn "$l"; h_result "ATTENTION" "$l (vu du manager)"; fi
  done <<<"$lines"
}

act_log() {
  h_step "Dernières ${LOG_LINES} lignes de ossec.log :"
  if run_payload log; then h_result "OK" "journal affiché"
  else h_err "$RES_MSG"; h_result "ECHEC" "$RES_MSG"; return 1; fi
}

act_install() {
  local name info old_id pk file url

  if [[ "${F[AGENT_INSTALLED]}" == yes && "$FORCE" != 1 ]]; then
    R_VERSION="${F[AGENT_VERSION]}"; R_AGENT_ID="${F[AGENT_ID]:--}"
    h_warn "agent déjà installé (v${R_VERSION}) — ignoré (utilisez --force pour réinstaller, -U pour mettre à jour)"
    h_result "IGNORE" "déjà installé v${R_VERSION}"
    return 0
  fi

  USE_PUSH=0
  if ! h_prechecks; then
    h_err "pré-contrôles en échec — installation annulée"
    h_result "ECHEC" "pré-contrôles : voir les lignes CHECK"
    return 1
  fi
  [[ "$OFFLINE" == 1 ]] && USE_PUSH=1
  pk="$(pkg_name)"; file="${pk%%|*}"; url="${pk#*|}"

  # Nom de l'agent (hostname) et conflits sur le manager
  name="$(tr -c 'A-Za-z0-9._-' '-' <<<"${F[HOSTNAME]:-$H_IP}" | sed 's/-*$//')"
  [[ -z "$name" || "$name" == "localhost" ]] && name="host-${H_IP//./-}"
  if api_available; then
    info="$(api_agent_by_name "$name")"
    if [[ -n "$info" ]]; then
      old_id="${info%%|*}"
      if [[ "${F[AGENT_INSTALLED]}" == yes || "$(cut -d'|' -f4 <<<"$info")" == "$H_IP" || "$FORCE" == 1 ]]; then
        if [[ "$DRY_RUN" != 1 ]]; then
          api_delete_agent "$old_id" && h_verb "ancien enregistrement ${name} (ID ${old_id}) supprimé du manager"
        fi
      else
        h_warn "le nom ${name} est déjà utilisé par une autre machine (ID ${old_id}) → nom ${name}-${H_IP//./-}"
        name="${name}-${H_IP//./-}"
      fi
    fi
  fi

  if [[ "$DRY_RUN" == 1 ]]; then
    h_ok "[SIMULATION] installerait ${file} — nom ${name}, groupe ${AGENT_GROUP_FOR_HOST}, manager ${MANAGER_IP}$( [[ "$USE_PUSH" == 1 ]] && echo ', paquet envoyé depuis le serveur')"
    h_result "SIMULE" "installerait ${file} (groupe ${AGENT_GROUP_FOR_HOST})"
    return 0
  fi

  if [[ "${F[AGENT_INSTALLED]}" == yes ]]; then
    h_step "--force : désinstallation de l'agent existant"
    run_payload remove || { h_err "$RES_MSG"; h_result "ECHEC" "désinstallation préalable : $RES_MSG"; return 1; }
  fi

  PKG_LOCAL=""
  if [[ "$USE_PUSH" == 1 ]]; then
    h_push_package "$file" "$url" || { h_result "ECHEC" "envoi du paquet impossible"; return 1; }
  fi

  h_step "Installation de wazuh-agent ${WAZUH_VERSION}..."
  if ! run_payload install "PKG_FILE=${file}" "PKG_URL=${url}" "PKG_LOCAL=${PKG_LOCAL}" \
        "ENROLL_PASS=${ENROLLMENT_PASSWORD}" "WAZUH_AGENT_GROUP=${AGENT_GROUP_FOR_HOST}" \
        "WAZUH_AGENT_NAME=${name}"; then
    h_err "$RES_MSG"; h_result "ECHEC" "$RES_MSG"; return 1
  fi
  h_verb "$RES_MSG"

  # Vérification côté manager : l'agent doit être "active" dans son groupe
  if api_available; then
    h_step "Vérification sur le manager (attente statut Active, max ${AGENT_WAIT_TIMEOUT}s)..."
    if info="$(api_wait_active "$name" "$AGENT_WAIT_TIMEOUT")"; then
      R_AGENT_ID="${info%%|*}"; R_VERSION="$(cut -d'|' -f3 <<<"$info")"
      local groups; groups="$(cut -d'|' -f6 <<<"$info")"
      h_ok "Agent actif — ID ${R_AGENT_ID}, nom ${name}, groupe(s) ${groups:-default}"
      h_result "OK" "installé, enrôlé et actif (groupe ${groups:-default})"
    else
      R_AGENT_ID="${info%%|*}"
      h_err "agent installé mais non actif sur le manager (statut : $(cut -d'|' -f2 <<<"$info"))"
      h_result "ECHEC" "installé mais non actif sur le manager — voir --log"
      return 1
    fi
  else
    R_VERSION="$WAZUH_VERSION"; R_AGENT_ID="${F[AGENT_ID]:--}"
    h_ok "$RES_MSG (API manager indisponible : vérification côté agent)"
    h_result "OK" "$RES_MSG"
  fi
}

act_update() {
  local pk file url info
  if [[ "${F[AGENT_INSTALLED]}" != yes ]]; then
    h_warn "aucun agent installé — rien à mettre à jour"
    h_result "IGNORE" "agent non installé"; return 0
  fi
  R_AGENT_ID="${F[AGENT_ID]:--}"; R_VERSION="${F[AGENT_VERSION]:--}"
  if ! ver_lt "$R_VERSION" "$WAZUH_VERSION" && [[ "$FORCE" != 1 ]]; then
    h_ok "déjà à jour (v${R_VERSION})"
    h_result "OK" "déjà à jour v${R_VERSION}"; return 0
  fi
  USE_PUSH=0
  h_prechecks || { h_result "ECHEC" "pré-contrôles en échec"; return 1; }
  [[ "$OFFLINE" == 1 ]] && USE_PUSH=1
  pk="$(pkg_name)"; file="${pk%%|*}"; url="${pk#*|}"
  if [[ "$DRY_RUN" == 1 ]]; then
    h_ok "[SIMULATION] mettrait à jour ${R_VERSION} → ${WAZUH_VERSION} (${file})"
    h_result "SIMULE" "mise à jour ${R_VERSION} → ${WAZUH_VERSION}"; return 0
  fi
  PKG_LOCAL=""
  if [[ "$USE_PUSH" == 1 ]]; then
    h_push_package "$file" "$url" || { h_result "ECHEC" "envoi du paquet impossible"; return 1; }
  fi
  if ! run_payload update "PKG_FILE=${file}" "PKG_URL=${url}" "PKG_LOCAL=${PKG_LOCAL}"; then
    h_err "$RES_MSG"; h_result "ECHEC" "$RES_MSG"; return 1
  fi
  R_VERSION="${F[AGENT_VERSION]:-$WAZUH_VERSION}"
  if api_available && [[ "$R_AGENT_ID" != "-" ]]; then
    sleep 10
    info="$(api_agent_by_id "$R_AGENT_ID")"
    h_verb "manager : statut $(cut -d'|' -f2 <<<"$info"), version $(cut -d'|' -f3 <<<"$info")"
  fi
  h_ok "$RES_MSG"; h_result "OK" "$RES_MSG"
}

act_remove() { # act_remove <remove|purge>
  local mode="$1" id name info
  id="${F[AGENT_ID]:-}"; name="${F[AGENT_NAME]:-${F[HOSTNAME]}}"
  if [[ "${F[AGENT_INSTALLED]}" != yes && "$mode" == remove ]]; then
    h_warn "aucun agent installé"; h_result "IGNORE" "agent non installé"; return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    h_ok "[SIMULATION] désinstallerait l'agent${id:+ (ID ${id})}$( [[ "$mode" == purge ]] && echo ' et purgerait ses fichiers'), puis le supprimerait du manager"
    h_result "SIMULE" "$( [[ "$mode" == purge ]] && echo purge || echo désinstallation )"; return 0
  fi
  if ! run_payload "$mode"; then
    h_err "$RES_MSG"; h_result "ECHEC" "$RES_MSG"; return 1
  fi
  R_AGENT_ID="${id:--}"
  # Suppression de l'enregistrement sur le manager
  if api_available; then
    if [[ -z "$id" && -n "$name" ]]; then info="$(api_agent_by_name "$name")"; id="${info%%|*}"; fi
    if [[ -n "$id" ]] && api_delete_agent "$id"; then
      h_verb "agent ID ${id} supprimé du manager"
      RES_MSG+=" + supprimé du manager"
    elif [[ -n "$id" ]]; then
      h_warn "suppression de l'ID ${id} sur le manager impossible (déjà supprimé ?)"
    fi
  fi
  h_ok "$RES_MSG"; h_result "OK" "$RES_MSG"
}

# ---------------------------------------------------------------- Worker
# host_worker <ip> <os> <ports>   (ACTION est défini par install-agent.sh)
# shellcheck disable=SC2153
host_worker() {
  H_IP="$1"; H_OS="$2"; local ports="$3"
  declare -gA F=()
  R_AGENT_ID=""; R_VERSION=""
  H_TRANSPORT="ssh"
  [[ "$H_OS" == windows ]] && H_TRANSPORT="$(win_transport "$ports")"

  # Statut sans identifiants : vue manager uniquement
  if [[ "$ACTION" == status ]] && ! h_load_creds; then
    act_status_manager_only; return
  fi
  if ! h_load_creds; then
    h_err "identifiants manquants pour ${H_OS} (-u/-p, -k ou --creds)"
    h_result "ECHEC" "identifiants manquants"; return 1
  fi
  if [[ -n "${R_PASS:-}" && -z "${R_KEY:-}" && "$H_TRANSPORT" == ssh ]] && ! have sshpass; then
    h_err "sshpass absent : authentification SSH par mot de passe impossible (utilisez -k)"
    h_result "ECHEC" "sshpass absent"; return 1
  fi

  h_step "Connexion ${H_TRANSPORT} (${R_USER})..."
  if ! run_payload facts; then
    h_err "$RES_MSG"; h_result "ECHEC" "$RES_MSG"; ssh_close "$H_IP"; return 1
  fi

  # Confirmation de l'OS après connexion
  case "${F[OS_KERNEL]}" in
    Linux)   H_OS=linux ;;
    Darwin)  H_OS=macos ;;
    Windows) H_OS=windows ;;
  esac
  if ! os_selected "$H_OS"; then
    h_verb "OS confirmé ${H_OS} hors filtre — ignoré"
    h_result "IGNORE" "OS ${H_OS} hors filtre"; ssh_close "$H_IP"; return 0
  fi
  if [[ "${F[WAZUH_TYPE]}" == server ]]; then
    h_warn "cet hôte est un manager Wazuh — ignoré"
    h_result "IGNORE" "serveur Wazuh (manager)"; ssh_close "$H_IP"; return 0
  fi
  h_ok "Connecté — ${F[OS_NAME]} (${F[ARCH]}), hôte ${F[HOSTNAME]}"

  AGENT_GROUP_FOR_HOST="${AGENT_GROUP:-$H_OS}"
  case "$ACTION" in
    install) act_install ;;
    check)   act_check ;;
    status)  act_status ;;
    log)     act_log ;;
    update)  act_update ;;
    remove)  act_remove remove ;;
    purge)   act_remove purge ;;
  esac
  local rc=$?
  [[ "$H_OS" != windows || "$H_TRANSPORT" == ssh ]] && ssh_close "$H_IP"
  return "$rc"
}
