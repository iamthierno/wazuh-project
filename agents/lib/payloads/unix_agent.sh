# shellcheck shell=bash disable=SC2015,SC1091,SC2329
# =============================================================================
#  agents/lib/payloads/unix_agent.sh — exécuté SUR la cible Linux / macOS
#  (envoyé par SSH, lancé en root via sudo, puis supprimé).
#  Les variables ACTION, WAZUH_MANAGER, ... sont injectées en tête par
#  install-agent.sh. Compatible bash 3.2 (macOS).
#  Protocole de sortie : STEP|msg  INFO|msg  WARN|msg  ERR|msg  KV|cle=valeur
#                        RESULT|ok|msg  ou  RESULT|fail|msg
# =============================================================================
exec </dev/null
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
export PATH LC_ALL=C

say()    { printf 'STEP|%s\n' "$*"; }
info()   { printf 'INFO|%s\n' "$*"; }
warn()   { printf 'WARN|%s\n' "$*"; }
kv()     { printf 'KV|%s=%s\n' "$1" "$2"; }
ok()     { printf 'RESULT|ok|%s\n' "$*"; exit 0; }
fail()   { printf 'RESULT|fail|%s\n' "$*"; exit 1; }
have()   { command -v "$1" >/dev/null 2>&1; }

echo "PAYLOAD_START"
[ "$(id -u)" -eq 0 ] || fail "droits root non obtenus (sudo)"

KERNEL="$(uname -s)"
if [ "$KERNEL" = "Darwin" ]; then
  OSSEC_DIR="/Library/Ossec"
else
  OSSEC_DIR="/var/ossec"
fi
OSSEC_LOG="${OSSEC_DIR}/logs/ossec.log"
WORK_DIR="/tmp/wazuh-deploy.$$"

# --------------------------------------------------------------- Utilitaires
pkg_type() {
  if [ "$KERNEL" = "Darwin" ]; then echo pkg; return; fi
  if have dpkg && have apt-get; then echo deb
  elif have rpm; then echo rpm
  elif have dpkg; then echo deb
  else echo unknown; fi
}

pkg_manager() {
  if [ "$KERNEL" = "Darwin" ]; then echo installer; return; fi
  for m in apt-get dnf yum zypper; do have "$m" && { echo "$m"; return; }; done
  echo none
}

agent_installed() { [ -x "${OSSEC_DIR}/bin/wazuh-control" ] || [ -x "${OSSEC_DIR}/bin/wazuh-agentd" ]; }

agent_type() { "${OSSEC_DIR}/bin/wazuh-control" info -t 2>/dev/null || echo agent; }

agent_version() { "${OSSEC_DIR}/bin/wazuh-control" info -v 2>/dev/null | tr -d 'v'; }

agent_running() {
  if [ "$KERNEL" = "Darwin" ]; then
    pgrep -f wazuh-agentd >/dev/null 2>&1 && echo yes || echo no
  elif have systemctl && systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    echo yes
  elif pgrep -f wazuh-agentd >/dev/null 2>&1; then
    echo yes
  else
    echo no
  fi
}

# Test TCP depuis la cible : tcp_test <hôte> <port>
tcp_test() {
  if [ "$KERNEL" = "Darwin" ] && have nc; then
    nc -z -G 3 "$1" "$2" >/dev/null 2>&1
  elif have timeout; then
    timeout 4 bash -c ">/dev/tcp/$1/$2" >/dev/null 2>&1
  elif have nc; then
    nc -z -w 3 "$1" "$2" >/dev/null 2>&1
  else
    bash -c ">/dev/tcp/$1/$2" >/dev/null 2>&1
  fi
}

download() { # download <url> <fichier>
  if have curl; then curl -fsSL --retry 2 -m 300 -o "$2" "$1"
  elif have wget; then wget -q -T 60 -O "$2" "$1"
  else return 2; fi
}

service_start() {
  if [ "$KERNEL" = "Darwin" ]; then
    "${OSSEC_DIR}/bin/wazuh-control" restart >/dev/null 2>&1
  elif have systemctl && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable wazuh-agent >/dev/null 2>&1
    systemctl restart wazuh-agent
  elif have service; then
    service wazuh-agent restart
  else
    "${OSSEC_DIR}/bin/wazuh-control" restart
  fi
}

service_stop() {
  if [ "$KERNEL" = "Darwin" ]; then
    "${OSSEC_DIR}/bin/wazuh-control" stop >/dev/null 2>&1
  elif have systemctl && [ -d /run/systemd/system ]; then
    systemctl stop wazuh-agent >/dev/null 2>&1
    systemctl disable wazuh-agent >/dev/null 2>&1
  elif have service; then
    service wazuh-agent stop >/dev/null 2>&1
  else
    "${OSSEC_DIR}/bin/wazuh-control" stop >/dev/null 2>&1
  fi
  return 0
}

# Récupère le paquet : fourni (mode offline) ou téléchargé
fetch_package() {
  mkdir -p "$WORK_DIR" && chmod 700 "$WORK_DIR"
  PKG="${WORK_DIR}/${PKG_FILE}"
  if [ -n "${PKG_LOCAL:-}" ] && [ -f "$PKG_LOCAL" ]; then
    mv -f "$PKG_LOCAL" "$PKG"
    say "Paquet reçu du serveur (${PKG_FILE})"
  else
    say "Téléchargement ${PKG_URL}"
    download "$PKG_URL" "$PKG" || fail "téléchargement impossible : ${PKG_URL}"
  fi
  [ -s "$PKG" ] || fail "paquet vide ou absent"
}

cleanup() { rm -rf "$WORK_DIR" /tmp/wazuh_envs 2>/dev/null; }
trap cleanup EXIT

wait_connected() { # attend la connexion au manager (max $1 s)
  i=0
  while [ "$i" -lt "${1:-45}" ]; do
    if grep -q "Connected to the server" "$OSSEC_LOG" 2>/dev/null; then return 0; fi
    sleep 3; i=$((i + 3))
  done
  return 1
}

# ---------------------------------------------------------------- Actions
do_facts() {
  if [ "$KERNEL" = "Darwin" ]; then
    kv OS_NAME "macOS $(sw_vers -productVersion 2>/dev/null)"
    kv HOSTNAME "$(scutil --get LocalHostName 2>/dev/null || hostname -s)"
    kv FREE_MB "$(df -Pk /Library 2>/dev/null | awk 'NR==2{printf "%d", $4/1024}')"
  else
    if [ -r /etc/os-release ]; then
      kv OS_NAME "$(. /etc/os-release; echo "${PRETTY_NAME:-$ID}")"
    else
      kv OS_NAME "Linux $(uname -r)"
    fi
    kv HOSTNAME "$(hostname -s 2>/dev/null || hostname)"
    kv FREE_MB "$(df -Pk /var 2>/dev/null | awk 'NR==2{printf "%d", $4/1024}')"
  fi
  kv OS_KERNEL "$KERNEL"
  kv ARCH "$(uname -m)"
  kv PKG_TYPE "$(pkg_type)"
  kv PKG_MANAGER "$(pkg_manager)"
  kv HAS_SYSTEMD "$( [ -d /run/systemd/system ] && echo yes || echo no )"
  if agent_installed; then
    kv AGENT_INSTALLED yes
    kv WAZUH_TYPE "$(agent_type)"
    kv AGENT_VERSION "$(agent_version)"
    kv AGENT_RUNNING "$(agent_running)"
    if [ -s "${OSSEC_DIR}/etc/client.keys" ]; then
      kv AGENT_ID "$(awk 'NR==1{print $1}' "${OSSEC_DIR}/etc/client.keys")"
      kv AGENT_NAME "$(awk 'NR==1{print $2}' "${OSSEC_DIR}/etc/client.keys")"
    fi
    kv AGENT_MANAGER "$(sed -n 's:.*<address>\(.*\)</address>.*:\1:p' "${OSSEC_DIR}/etc/ossec.conf" 2>/dev/null | head -1)"
  else
    kv AGENT_INSTALLED no
  fi
  tcp_test "$WAZUH_MANAGER" 1514 && kv PORT_1514 ok || kv PORT_1514 ko
  tcp_test "$WAZUH_MANAGER" 1515 && kv PORT_1515 ok || kv PORT_1515 ko
  if [ "${CHECK_INTERNET:-yes}" = "yes" ]; then
    if have curl; then
      curl -fsS -m 8 -o /dev/null -I "${PKG_BASE_URL}/" 2>/dev/null && kv INTERNET ok || kv INTERNET ko
    elif have wget; then
      wget -q -T 8 --spider "${PKG_BASE_URL}/" 2>/dev/null && kv INTERNET ok || kv INTERNET ko
    else
      kv INTERNET ko; kv NO_DOWNLOADER yes
    fi
  fi
  ok "facts"
}

do_install() {
  fetch_package
  WAZUH_REGISTRATION_PASSWORD="$ENROLL_PASS"
  export WAZUH_MANAGER WAZUH_REGISTRATION_PASSWORD WAZUH_AGENT_GROUP WAZUH_AGENT_NAME
  say "Installation du paquet $(basename "$PKG") (manager ${WAZUH_MANAGER}, groupe ${WAZUH_AGENT_GROUP}, nom ${WAZUH_AGENT_NAME})"
  case "$(pkg_type)" in
    deb)
      if have apt-get; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$PKG" >"${WORK_DIR}/install.log" 2>&1 \
          || DEBIAN_FRONTEND=noninteractive dpkg -i "$PKG" >>"${WORK_DIR}/install.log" 2>&1
      else
        dpkg -i "$PKG" >"${WORK_DIR}/install.log" 2>&1
      fi ;;
    rpm)
      case "$(pkg_manager)" in
        dnf|yum) "$(pkg_manager)" install -y "$PKG" >"${WORK_DIR}/install.log" 2>&1 ;;
        zypper)  zypper --non-interactive --no-gpg-checks install "$PKG" >"${WORK_DIR}/install.log" 2>&1 ;;
        *)       rpm -Uvh "$PKG" >"${WORK_DIR}/install.log" 2>&1 ;;
      esac ;;
    pkg)
      printf 'WAZUH_MANAGER="%s"\nWAZUH_REGISTRATION_PASSWORD="%s"\nWAZUH_AGENT_GROUP="%s"\nWAZUH_AGENT_NAME="%s"\n' \
        "$WAZUH_MANAGER" "$WAZUH_REGISTRATION_PASSWORD" "$WAZUH_AGENT_GROUP" "$WAZUH_AGENT_NAME" > /tmp/wazuh_envs
      chmod 600 /tmp/wazuh_envs
      installer -pkg "$PKG" -target / >"${WORK_DIR}/install.log" 2>&1 ;;
    *) fail "type de paquet non supporté" ;;
  esac
  rc=$?
  if [ "$rc" -ne 0 ] || ! agent_installed; then
    tail -5 "${WORK_DIR}/install.log" 2>/dev/null | while IFS= read -r l; do warn "$l"; done
    fail "échec de l'installation du paquet (code ${rc})"
  fi
  info "Paquet installé : wazuh-agent $(agent_version)"
  say "Démarrage du service wazuh-agent"
  service_start >/dev/null 2>&1 || fail "le service wazuh-agent ne démarre pas"
  say "Attente de la connexion au manager..."
  if wait_connected 60; then
    kv AGENT_ID "$(awk 'NR==1{print $1}' "${OSSEC_DIR}/etc/client.keys" 2>/dev/null)"
    ok "agent installé, enrôlé et connecté"
  fi
  grep -E "ERROR|authd|enrollment" "$OSSEC_LOG" 2>/dev/null | tail -3 | while IFS= read -r l; do warn "$l"; done
  ok "agent installé et démarré (connexion non confirmée côté agent)"
}

do_update() {
  agent_installed || fail "aucun agent installé"
  before="$(agent_version)"
  fetch_package
  say "Mise à jour ${before} → ${WAZUH_VERSION}"
  case "$(pkg_type)" in
    deb) DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades "$PKG" >"${WORK_DIR}/install.log" 2>&1 \
           || dpkg -i "$PKG" >>"${WORK_DIR}/install.log" 2>&1 ;;
    rpm) case "$(pkg_manager)" in
           dnf|yum) "$(pkg_manager)" install -y "$PKG" >"${WORK_DIR}/install.log" 2>&1 ;;
           zypper)  zypper --non-interactive --no-gpg-checks install "$PKG" >"${WORK_DIR}/install.log" 2>&1 ;;
           *)       rpm -Uvh "$PKG" >"${WORK_DIR}/install.log" 2>&1 ;;
         esac ;;
    pkg) installer -pkg "$PKG" -target / >"${WORK_DIR}/install.log" 2>&1 ;;
  esac || { tail -5 "${WORK_DIR}/install.log" | while IFS= read -r l; do warn "$l"; done; fail "échec de la mise à jour"; }
  service_start >/dev/null 2>&1
  kv AGENT_VERSION "$(agent_version)"
  ok "agent mis à jour (${before} → $(agent_version))"
}

do_remove() { # do_remove [purge]
  purge="${1:-no}"
  agent_installed || { [ "$purge" = "yes" ] && rm -rf "$OSSEC_DIR"; ok "aucun agent installé"; }
  [ "$(agent_type)" = "server" ] && fail "cet hôte est un manager Wazuh : refus de désinstaller"
  say "Arrêt du service wazuh-agent"
  service_stop
  say "Désinstallation du paquet$( [ "$purge" = yes ] && echo ' + purge des fichiers')"
  case "$(pkg_type)" in
    deb)
      if [ "$purge" = "yes" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -q wazuh-agent >/dev/null 2>&1 || dpkg --purge wazuh-agent >/dev/null 2>&1
      else
        DEBIAN_FRONTEND=noninteractive apt-get remove -y -q wazuh-agent >/dev/null 2>&1 || dpkg -r wazuh-agent >/dev/null 2>&1
      fi ;;
    rpm)
      case "$(pkg_manager)" in
        dnf|yum) "$(pkg_manager)" remove -y wazuh-agent >/dev/null 2>&1 ;;
        zypper)  zypper --non-interactive remove wazuh-agent >/dev/null 2>&1 ;;
        *)       rpm -e wazuh-agent >/dev/null 2>&1 ;;
      esac ;;
    pkg)
      launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist >/dev/null 2>&1
      rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
      rm -rf /Library/StartupItems/WAZUH
      pkgutil --forget com.wazuh.pkg.wazuh-agent >/dev/null 2>&1
      rm -rf "$OSSEC_DIR" ;;
  esac
  if [ "$purge" = "yes" ]; then
    rm -rf "$OSSEC_DIR" /etc/systemd/system/wazuh-agent.service /usr/lib/systemd/system/wazuh-agent.service 2>/dev/null
    if [ "$KERNEL" = "Darwin" ]; then
      dscl . -delete /Users/wazuh >/dev/null 2>&1; dscl . -delete /Groups/wazuh >/dev/null 2>&1
    else
      userdel wazuh >/dev/null 2>&1; groupdel wazuh >/dev/null 2>&1
    fi
    have systemctl && systemctl daemon-reload >/dev/null 2>&1
  fi
  if agent_installed && [ "$purge" = "yes" ]; then fail "des fichiers subsistent dans ${OSSEC_DIR}"; fi
  ok "agent désinstallé$( [ "$purge" = yes ] && echo ' et purgé')"
}

do_status() {
  agent_installed || { kv AGENT_INSTALLED no; ok "aucun agent installé"; }
  kv AGENT_INSTALLED yes
  kv AGENT_VERSION "$(agent_version)"
  kv AGENT_RUNNING "$(agent_running)"
  last="$(grep -E "Connected to the server|Unable to connect|Lost connection|ERROR" "$OSSEC_LOG" 2>/dev/null | tail -1)"
  [ -n "$last" ] && kv LAST_EVENT "$last"
  ok "status"
}

do_log() {
  [ -r "$OSSEC_LOG" ] || fail "journal introuvable (${OSSEC_LOG})"
  tail -n "${LOG_LINES:-40}" "$OSSEC_LOG" | while IFS= read -r l; do printf 'LOG|%s\n' "$l"; done
  ok "log"
}

case "$ACTION" in
  facts)   do_facts ;;
  install) do_install ;;
  update)  do_update ;;
  remove)  do_remove no ;;
  purge)   do_remove yes ;;
  status)  do_status ;;
  log)     do_log ;;
  *)       fail "action inconnue : $ACTION" ;;
esac
