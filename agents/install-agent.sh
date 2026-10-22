#!/usr/bin/env bash
# =============================================================================
#  install-agent.sh — Découverte et déploiement à distance des agents Wazuh
#  (Linux, Windows, macOS) depuis le serveur Wazuh (natif ou Docker).
#  Une seule commande : découverte → contrôles → installation → enrôlement
#  → vérification « Active » sur le manager.   Aide : --help
# =============================================================================
set -o pipefail

AGENTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${AGENTS_DIR}/.." && pwd)"
export PROJECT_DIR AGENTS_DIR

# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"
# shellcheck source=agents/lib/targets.sh
. "${AGENTS_DIR}/lib/targets.sh"
# shellcheck source=agents/lib/discover.sh
. "${AGENTS_DIR}/lib/discover.sh"
# shellcheck source=agents/lib/manager_api.sh
. "${AGENTS_DIR}/lib/manager_api.sh"
# shellcheck source=agents/lib/remote_ssh.sh
. "${AGENTS_DIR}/lib/remote_ssh.sh"
# shellcheck source=agents/lib/remote_win.sh
. "${AGENTS_DIR}/lib/remote_win.sh"
# shellcheck source=agents/lib/actions.sh
. "${AGENTS_DIR}/lib/actions.sh"

DEPLOYER_IMAGE="wazuh-deployer:latest"
VENV_DIR="/opt/wazuh-deploy/venv"

usage() {
  cat <<EOF
${C_BOLD}install-agent.sh${C_RESET} — découverte et déploiement à distance des agents Wazuh

${C_BOLD}USAGE${C_RESET}
  install-agent.sh [options] <cible> [<cible>...]

${C_BOLD}CIBLES${C_RESET}
  192.168.1.10                  une IP
  192.168.1.0/24                un sous-réseau
  192.168.1.10-50               une plage (dernier octet)
  192.168.1.10-192.168.1.50     une plage complète (espaces autour du « - » acceptés)
  srv-web01                     un nom d'hôte
  -f <fichier>                  une cible par ligne (# = commentaire)

${C_BOLD}FILTRES OS${C_RESET} (combinables, ex. -lw ; sans filtre = tous les OS détectés)
  -l                Linux          -w   Windows          -m   macOS

${C_BOLD}ACTIONS${C_RESET} (une seule ; par défaut : installation)
  -d                découverte seule (hôtes actifs + OS détecté), aucune connexion
  -c                vérifier si l'agent est installé (version, service, ID)
  -s                statut de l'agent (service sur la VM + état sur le manager)
                    sans identifiants : statut vu du manager uniquement
  --log             afficher les dernières lignes de ossec.log de l'agent
  -U, --update      mettre à jour l'agent à la version du manager (${WAZUH_VERSION:-config.env})
  -r                désinstaller l'agent et le supprimer du manager
  -rf, --purge      désinstaller + purger tous les fichiers + supprimer du manager

${C_BOLD}CONNEXION${C_RESET}
  -u <user>         utilisateur (SSH et WinRM). Windows domaine : 'CORP\\admin' ou admin@corp.local
  -p [password]     mot de passe ; sans valeur = demandé de façon masquée
                    (ou variable d'environnement WAZUH_DEPLOY_PASS)
  -k <clé>          clé privée SSH (Linux/macOS)
  --creds <fichier> identifiants par OS (chmod 600) — voir agents/credentials.example
  --win-https       WinRM en HTTPS (5986)       --win-auth <ntlm|negotiate|kerberos>

${C_BOLD}EXÉCUTION${C_RESET}
  -n <N>            installations en parallèle (défaut ${INSTALL_PARALLEL:-5})
  -dry, --dry       simulation : découverte + contrôles, aucune modification
  -g <groupe[,...]> groupe(s) Wazuh, ex. -g linux,web-prod (défaut : linux / windows / macos)
  -M <ip>           IP du manager (défaut : celle du déploiement)
  -x <ip,...>       exclure des IP / plages / sous-réseaux
  --force           réinstaller même si l'agent est présent
  --offline         le serveur envoie le paquet (cibles sans Internet)
  --lines <N>       nombre de lignes pour --log (défaut ${LOG_LINES:-40})
  --no-ping         considérer tous les hôtes comme actifs (pare-feu bloquant le ping)
  -y                ne pas demander de confirmation
  -v | -vv | -q     verbeux | debug (commandes exécutées) | silencieux
  -o <fichier.csv>  exporter le rapport final
  --help            cette aide

${C_BOLD}EXEMPLES${C_RESET}
  install-agent.sh 192.168.1.0/24 -d
  install-agent.sh 192.168.1.0/24 -l -u admin -p -n 10
  install-agent.sh 192.168.1.10 - 192.168.1.50 -w -u 'CORP\\admin' -p
  install-agent.sh 192.168.1.30 -m -u admin -p -dry
  install-agent.sh 192.168.1.0/24 -s
  install-agent.sh 192.168.1.20 --log -u admin -k ~/.ssh/id_ed25519
  install-agent.sh 192.168.1.0/24 -l -U -u admin -p
  install-agent.sh 192.168.1.10 -rf -u admin -p
EOF
}

# ------------------------------------------------------------- Arguments ---
set_action() {
  if [[ -n "$ACTION" && "$ACTION" != "$1" ]]; then
    die "Une seule action à la fois (déjà : -${ACTION}, puis : $1)."
  fi
  ACTION="$1"
}

parse_args() {
  ACTION=""; F_LINUX=0; F_WIN=0; F_MAC=0
  CLI_USER=""; CLI_PASS=""; CLI_KEY=""; PASS_PROMPT=0; CREDS_FILE=""
  PARALLEL=""; DRY_RUN=0; AGENT_GROUP=""; CLI_MANAGER=""; EXCLUDES=""
  TARGETS_FILE=""; FORCE=0; OFFLINE=0; CSV_OUT=""; NO_PING=0; CLI_LOG_LINES=""
  WIN_HTTPS="${WIN_HTTPS:-no}"; WIN_AUTH="${WIN_AUTH:-negotiate}"
  TARGET_ARGS=()
  ORIG_ARGS=("$@")

  while (( $# > 0 )); do
    case "$1" in
      -h|--help)   usage; exit 0 ;;
      -l)          F_LINUX=1 ;;
      -w)          F_WIN=1 ;;
      -m)          F_MAC=1 ;;
      -d)          set_action discover ;;
      -c)          set_action check ;;
      -s)          set_action status ;;
      --log)       set_action log ;;
      -U|--update) set_action update ;;
      -r)          set_action remove ;;
      -rf|-fr|--purge) set_action purge ;;
      -dry|--dry|--dry-run) DRY_RUN=1 ;;
      -u)          [[ -n "${2:-}" ]] || die "-u attend un nom d'utilisateur"; CLI_USER="$2"; shift ;;
      -p)
        if [[ -n "${2:-}" && "${2:0:1}" != "-" ]] && ! looks_like_target "$2"; then
          CLI_PASS="$2"; shift
        else
          PASS_PROMPT=1
        fi ;;
      -k)          [[ -r "${2:-}" ]] || die "-k : clé illisible : ${2:-}"; CLI_KEY="$2"; shift ;;
      --creds)     CREDS_FILE="${2:-}"; shift ;;
      -n)          [[ "${2:-}" =~ ^[0-9]+$ ]] && (( $2 >= 1 && $2 <= 64 )) || die "-n attend un nombre entre 1 et 64"
                   PARALLEL="$2"; shift ;;
      -g)          AGENT_GROUP="${2:-}"; [[ "$AGENT_GROUP" =~ ^[A-Za-z0-9_.-]+(,[A-Za-z0-9_.-]+)*$ ]] || die "-g : nom(s) de groupe invalide(s)"; shift ;;
      -M)          is_ipv4 "${2:-}" || die "-M attend une IP"; CLI_MANAGER="$2"; shift ;;
      -x)          EXCLUDES+=" ${2:-}"; shift ;;
      -f)          [[ -r "${2:-}" ]] || die "-f : fichier illisible : ${2:-}"; TARGETS_FILE="$2"; shift ;;
      -o)          CSV_OUT="${2:-}"; [[ -n "$CSV_OUT" ]] || die "-o attend un fichier"; shift ;;
      --lines)     [[ "${2:-}" =~ ^[0-9]+$ ]] || die "--lines attend un nombre"; CLI_LOG_LINES="$2"; shift ;;
      --force)     FORCE=1 ;;
      --offline)   OFFLINE=1 ;;
      --no-ping)   NO_PING=1 ;;
      --win-https) WIN_HTTPS=yes ;;
      --win-auth)  WIN_AUTH="${2:-}"; [[ "$WIN_AUTH" =~ ^(ntlm|negotiate|kerberos|credssp)$ ]] || die "--win-auth invalide"; shift ;;
      -y|--yes)    ASSUME_YES=1 ;;
      -v)          VERBOSITY=2 ;;
      -vv)         VERBOSITY=3 ;;
      -q)          VERBOSITY=0 ;;
      -)           TARGET_ARGS+=("-") ;;
      -[lwm][lwm]*)
        local i ch
        for (( i = 1; i < ${#1}; i++ )); do
          ch="${1:i:1}"
          case "$ch" in l) F_LINUX=1;; w) F_WIN=1;; m) F_MAC=1;; *) die "Option inconnue : $1";; esac
        done ;;
      -*)          die "Option inconnue : $1 (voir --help)" ;;
      *)           TARGET_ARGS+=("$1") ;;
    esac
    shift
  done
  ACTION="${ACTION:-install}"
  export VERBOSITY ASSUME_YES
}

os_selected() { # os_selected <os>
  (( F_LINUX + F_WIN + F_MAC == 0 )) && return 0
  case "$1" in
    linux)   (( F_LINUX )) ;;
    windows) (( F_WIN )) ;;
    macos)   (( F_MAC )) ;;
    unix)    (( F_LINUX || F_MAC )) ;;
    *)       return 1 ;;
  esac
}

filters_label() {
  local f=()
  (( F_LINUX )) && f+=(linux); (( F_WIN )) && f+=(windows); (( F_MAC )) && f+=(macos)
  (( ${#f[@]} )) && (IFS=,; echo "${f[*]}") || echo "tous"
}

# --------------------------------------------------------- Identifiants ----
load_credentials() {
  LINUX_USER=""; LINUX_PASS=""; LINUX_KEY=""; MAC_USER=""; MAC_PASS=""; MAC_KEY=""
  WIN_USER=""; WIN_PASS=""
  local line key val perm

  if [[ -n "$CREDS_FILE" ]]; then
    [[ -r "$CREDS_FILE" ]] || die "--creds : fichier illisible : $CREDS_FILE"
    perm="$(stat -c '%a' "$CREDS_FILE")"
    [[ "$perm" =~ ^[46]00$ ]] || die "--creds : droits ${perm} trop ouverts sur ${CREDS_FILE} (chmod 600 requis)"
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"
      [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
      key="${line%%=*}"; val="${line#*=}"
      key="${key//[[:space:]]/}"
      val="${val#\"}"; val="${val%\"}"; val="${val#\'}"; val="${val%\'}"
      case "$key" in
        SSH_USER)   LINUX_USER="$val"; MAC_USER="${MAC_USER:-$val}" ;;
        SSH_PASS)   LINUX_PASS="$val"; MAC_PASS="${MAC_PASS:-$val}" ;;
        SSH_KEY)    LINUX_KEY="$val";  MAC_KEY="${MAC_KEY:-$val}" ;;
        LINUX_USER|LINUX_PASS|LINUX_KEY|MAC_USER|MAC_PASS|MAC_KEY|WIN_USER|WIN_PASS)
                    printf -v "$key" '%s' "$val" ;;
        WIN_AUTH)   WIN_AUTH="$val" ;;
        WIN_HTTPS)  WIN_HTTPS="$val" ;;
        *)          log_warn "--creds : clé inconnue ignorée : ${key}" ;;
      esac
    done < "$CREDS_FILE"
  fi

  # La ligne de commande s'applique à tous les OS et prime sur le fichier
  [[ -z "$CLI_PASS" && -n "${WAZUH_DEPLOY_PASS:-}" ]] && CLI_PASS="$WAZUH_DEPLOY_PASS"
  if [[ -n "$CLI_USER" ]]; then
    LINUX_USER="$CLI_USER"; MAC_USER="$CLI_USER"; WIN_USER="$CLI_USER"
  fi
  if (( PASS_PROMPT )) && [[ -z "$CLI_PASS" ]]; then
    [[ -n "$CLI_USER$LINUX_USER$WIN_USER" ]] || die "-p : précisez l'utilisateur avec -u"
    read -r -s -p "Mot de passe pour ${CLI_USER:-${LINUX_USER:-$WIN_USER}} : " CLI_PASS </dev/tty || true
    echo >&2
    [[ -n "$CLI_PASS" ]] || die "mot de passe vide"
  fi
  if [[ -n "$CLI_PASS" ]]; then
    LINUX_PASS="$CLI_PASS"; MAC_PASS="$CLI_PASS"; WIN_PASS="$CLI_PASS"
  fi
  if [[ -n "$CLI_KEY" ]]; then
    LINUX_KEY="$CLI_KEY"; MAC_KEY="$CLI_KEY"
  fi
  # Une clé seule sans utilisateur : root par défaut
  [[ -n "$LINUX_KEY" && -z "$LINUX_USER" ]] && LINUX_USER="root"
  [[ -n "$MAC_KEY" && -z "$MAC_USER" ]] && MAC_USER="root"
  for val in "$LINUX_PASS" "$MAC_PASS" "$WIN_PASS"; do register_secret "$val"; done
  export LINUX_USER LINUX_PASS LINUX_KEY MAC_USER MAC_PASS MAC_KEY WIN_USER WIN_PASS WIN_AUTH WIN_HTTPS
}

# ----------------------------------------------------------- Dépendances ---
missing_deps() {
  local m=() c
  for c in ssh scp python3 jq curl timeout flock; do have "$c" || m+=("$c"); done
  have nmap || m+=(nmap)
  if [[ -n "${LINUX_PASS}${MAC_PASS}${WIN_PASS}" ]]; then have sshpass || m+=(sshpass); fi
  if (( F_WIN )) || (( F_LINUX + F_WIN + F_MAC == 0 )); then
    "$PY_WINRM" -c 'import pypsrp' 2>/dev/null || m+=(pypsrp)
  fi
  (( ${#m[@]} )) && printf '%s\n' "${m[@]}"
  return 0
}

install_deps_host() {
  local missing=("$@") pkgs=() d
  detect_os
  for d in "${missing[@]}"; do
    case "$d" in
      ssh|scp) [[ "$OS_FAMILY" == debian ]] && pkgs+=(openssh-client) || pkgs+=(openssh-clients) ;;
      timeout|flock) pkgs+=(coreutils util-linux) ;;
      pypsrp) pkgs+=(python3) ; [[ "$OS_FAMILY" == debian ]] && pkgs+=(python3-venv) ;;
      *) pkgs+=("$d") ;;
    esac
  done
  [[ "$OS_FAMILY" == rhel ]] && [[ " ${pkgs[*]} " == *" sshpass "* ]] && ! "$PKG_MGR" list sshpass >/dev/null 2>&1 \
    && run "$PKG_MGR" install -y epel-release
  mapfile -t pkgs < <(printf '%s\n' "${pkgs[@]}" | sort -u)
  pkg_install "${pkgs[@]}" || log_warn "certains paquets n'ont pas pu être installés"
  if [[ " ${missing[*]} " == *" pypsrp "* ]]; then
    log_info "Création de l'environnement Python ${VENV_DIR} (pypsrp)..."
    python3 -m venv "$VENV_DIR" && "${VENV_DIR}/bin/pip" install -q -r "${AGENTS_DIR}/requirements.txt" \
      && PY_WINRM="${VENV_DIR}/bin/python" || log_warn "installation de pypsrp impossible (Windows indisponible)"
  fi
}

# Relance la commande dans le conteneur deployer (mode Docker)
run_in_deployer() {
  local mounts=(-v "${PROJECT_DIR}:/opt/wazuh-project" -v "${DEPLOY_STATE_DIR}:${DEPLOY_STATE_DIR}"
                -v "${LOG_DIR}:${LOG_DIR}") f d tty=()
  [[ -d /root/.ssh ]] && mounts+=(-v /root/.ssh:/root/.ssh:ro)
  for f in "$CLI_KEY" "$CREDS_FILE" "$TARGETS_FILE"; do
    [[ -n "$f" ]] && { d="$(cd "$(dirname "$f")" && pwd)"; mounts+=(-v "${d}:${d}:ro"); }
  done
  if [[ -n "$CSV_OUT" ]]; then
    d="$(cd "$(dirname "$CSV_OUT")" 2>/dev/null && pwd)" && mounts+=(-v "${d}:${d}")
  fi
  mounts+=(-w "$PWD")
  [[ -d "$PWD" ]] && mounts+=(-v "${PWD}:${PWD}")
  [[ -t 0 && -t 1 ]] && tty=(-t)
  if ! docker image inspect "$DEPLOYER_IMAGE" >/dev/null 2>&1; then
    log_info "Construction de l'image ${DEPLOYER_IMAGE}..."
    if ! docker build -q -t "$DEPLOYER_IMAGE" -f "${PROJECT_DIR}/docker/deployer/Dockerfile" "$PROJECT_DIR" >>"${LOG_FILE:-/dev/null}" 2>&1; then
      log_warn "Construction de ${DEPLOYER_IMAGE} impossible — installation des outils sur l'hôte à la place"
      return 1
    fi
  fi
  # Le mot de passe déjà saisi est transmis au conteneur (pas de nouvelle demande)
  [[ -n "$CLI_PASS" ]] && export WAZUH_DEPLOY_PASS="$CLI_PASS"
  log_info "Exécution dans le conteneur ${DEPLOYER_IMAGE} (réseau de l'hôte)"
  exec docker run --rm -i "${tty[@]}" --network host --cap-add NET_RAW --cap-add NET_ADMIN \
    -e TERM -e NO_COLOR -e WAZUH_DEPLOY_PASS "${mounts[@]}" "$DEPLOYER_IMAGE" "${ORIG_ARGS[@]}"
}

ensure_deps() {
  PY_WINRM="python3"
  [[ -x "${VENV_DIR}/bin/python" ]] && PY_WINRM="${VENV_DIR}/bin/python"
  local missing
  mapfile -t missing < <(missing_deps | sed "/^$/d")
  (( ${#missing[@]} == 0 )) && return 0
  # nmap / pypsrp / sshpass sont facultatifs pour la découverte seule
  if [[ "$ACTION" == discover ]]; then
    mapfile -t missing < <(printf '%s\n' "${missing[@]}" | grep -vxE 'pypsrp|sshpass|nmap|')
    (( ${#missing[@]} == 0 )) && return 0
  fi
  log_warn "Outils manquants sur ce serveur : ${missing[*]}"
  if [[ "${WAZUH_DEPLOYER_INSIDE:-0}" == 1 ]]; then
    die "Outils manquants dans le conteneur deployer : ${missing[*]}"
  fi
  if [[ "$(deploy_mode)" == docker ]] && have docker && [[ "${NO_DEPLOYER:-0}" != 1 ]]; then
    run_in_deployer   # ne revient qu'en cas d'échec de construction de l'image
  fi
  if confirm "Installer les outils manquants sur ce serveur ?" o; then
    install_deps_host "${missing[@]}"
  fi
  mapfile -t missing < <(missing_deps | grep -vxE 'nmap|pypsrp|')
  (( ${#missing[@]} == 0 )) || die "Outils toujours manquants : ${missing[*]}"
}

# ------------------------------------------------------------- Récapitulatif
print_summary() {
  local f ip os osn st id ver det color n_ok=0 n_ko=0 n_skip=0 n_other=0
  echo
  printf '%s══════════════════════════════ RÉSUMÉ (%s) ══════════════════════════════%s\n' "$C_BOLD" "$ACTION" "$C_RESET"
  printf "${C_BOLD}%-15s  %-8s  %-26s  %-10s  %-6s  %-8s  %s${C_RESET}\n" "IP" "OS" "SYSTÈME" "STATUT" "ID" "VERSION" "DÉTAIL"
  [[ -n "$CSV_OUT" ]] && echo "ip;os;systeme;statut;agent_id;version;detail" > "$CSV_OUT"
  for f in $(find "${RUN_DIR}/results/" -maxdepth 1 -type f -printf '%f\n' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n); do
    IFS=$'\t' read -r ip os osn st id ver det < "${RUN_DIR}/results/${f}"
    case "$st" in
      OK)                 color="$C_GREEN";  n_ok=$((n_ok + 1)) ;;
      ECHEC)              color="$C_RED";    n_ko=$((n_ko + 1)) ;;
      IGNORE)             color="$C_YELLOW"; n_skip=$((n_skip + 1)) ;;
      *)                  color="$C_CYAN";   n_other=$((n_other + 1)) ;;
    esac
    printf "%-15s  %-8s  %-26.26s  ${color}%-10s${C_RESET}  %-6s  %-8s  %s\n" "$ip" "$os" "$osn" "$st" "$id" "$ver" "$det"
    [[ -n "$CSV_OUT" ]] && printf '%s;%s;"%s";%s;%s;%s;"%s"\n' "$ip" "$os" "${osn//\"/\'}" "$st" "$id" "$ver" "${det//\"/\'}" >> "$CSV_OUT"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$os" "$osn" "$st" "$id" "$ver" "$det" >> "${LOG_FILE:-/dev/null}"
  done
  echo
  printf "Succès : ${C_GREEN}%d${C_RESET} | Échecs : ${C_RED}%d${C_RESET} | Ignorés : ${C_YELLOW}%d${C_RESET} | Autres : %d   — journal : %s\n" \
    "$n_ok" "$n_ko" "$n_skip" "$n_other" "$LOG_FILE"
  [[ -n "$CSV_OUT" ]] && echo "Rapport CSV : ${CSV_OUT}"
  (( n_ko == 0 ))
}

print_discovery_table() {
  local ip os conf ports ttl why n=0 color
  echo
  printf '%s══════════════════════════ DÉCOUVERTE ══════════════════════════%s\n' "$C_BOLD" "$C_RESET"
  printf "${C_BOLD}%-15s  %-8s  %-12s  %-22s  %-4s  %s${C_RESET}\n" "IP" "OS" "CONFIANCE" "PORTS" "TTL" "INDICES"
  [[ -n "$CSV_OUT" ]] && echo "ip;os;confiance;ports;ttl;indices" > "$CSV_OUT"
  while IFS=$'\t' read -r ip os conf ports ttl why; do
    n=$((n + 1))
    case "$os" in linux) color="$C_GREEN";; windows) color="$C_BLUE";; macos) color="$C_MAGENTA";; *) color="$C_YELLOW";; esac
    printf "%-15s  ${color}%-8s${C_RESET}  %-12s  %-22s  %-4s  %s\n" "$ip" "$os" "$conf" "$ports" "$ttl" "$why"
    [[ -n "$CSV_OUT" ]] && printf '%s;%s;%s;"%s";%s;"%s"\n' "$ip" "$os" "$conf" "$ports" "$ttl" "${why//\"/\'}" >> "$CSV_OUT"
  done < "${RUN_DIR}/discovery.tsv"
  echo
  echo "Hôtes actifs : ${n}   — journal : ${LOG_FILE}"
  [[ -n "$CSV_OUT" ]] && echo "Rapport CSV : ${CSV_OUT}"
}

cleanup() {
  local s
  for s in "${CM_DIR:-/nonexistent}"/*; do
    [[ -S "$s" ]] && ssh -o ControlPath="$s" -O exit dummy >/dev/null 2>&1
  done
  [[ -n "${RUN_DIR:-}" && -d "$RUN_DIR" ]] && rm -rf "$RUN_DIR"
  [[ -n "${CM_DIR:-}" && -d "$CM_DIR" ]] && rm -rf "$CM_DIR"
}

# ------------------------------------------------------------------ Main ---
main() {
  parse_args "$@"
  require_root
  load_config
  load_state || log_verbose "Aucun état de déploiement (${STATE_FILE}) : utilisation de config.env"
  PARALLEL="${PARALLEL:-$INSTALL_PARALLEL}"
  LOG_LINES="${CLI_LOG_LINES:-$LOG_LINES}"
  MANAGER_IP="${CLI_MANAGER:-${MANAGER_IP:-$(primary_ip)}}"
  PKG_BASE_URL="${PKG_BASE_URL:-https://packages.wazuh.com}"
  WAZUH_MAJOR_BRANCH="$(cut -d. -f1 <<<"$WAZUH_VERSION").x"
  KNOWN_HOSTS="${DEPLOY_STATE_DIR}/known_hosts"
  mkdir -p "$DEPLOY_STATE_DIR" "${AGENTS_DIR}/packages" && chmod 700 "$DEPLOY_STATE_DIR"
  touch "$KNOWN_HOSTS" && chmod 600 "$KNOWN_HOSTS"
  export MANAGER_IP WAZUH_VERSION PKG_BASE_URL WAZUH_MAJOR_BRANCH KNOWN_HOSTS DRY_RUN FORCE OFFLINE
  export AGENT_GROUP ACTION F_LINUX F_WIN F_MAC CONNECT_TIMEOUT LOG_LINES AGENT_WAIT_TIMEOUT NO_PING

  load_credentials
  ensure_deps

  RUN_DIR="$(mktemp -d /tmp/wazuh-agents.XXXXXX)"; chmod 700 "$RUN_DIR"
  CM_DIR="$(mktemp -d /tmp/wzcm.XXXX)"; chmod 700 "$CM_DIR"
  mkdir -p "${RUN_DIR}/results"
  export RUN_DIR CM_DIR PY_WINRM
  trap cleanup EXIT
  trap 'echo; log_warn "Interruption — arrêt des tâches en cours"; kill $(jobs -p) 2>/dev/null; exit 130' INT TERM
  log_init "agents-${ACTION}"

  # ---- Cibles
  local raw tok errors=0 ips="${RUN_DIR}/targets.txt" excl="${RUN_DIR}/exclude.txt" n
  raw="${TARGET_ARGS[*]}"
  [[ -n "$TARGETS_FILE" ]] && raw+=" $(grep -vE '^[[:space:]]*(#|$)' "$TARGETS_FILE" | tr '\n' ' ')"
  [[ -n "${raw// /}" ]] || { usage; die "Aucune cible indiquée."; }
  : > "$ips"
  while IFS= read -r tok; do
    if [[ "$tok" == ERR\|* ]]; then log_error "${tok#ERR|}"; errors=$((errors + 1)); else echo "$tok" >> "$ips"; fi
  done < <(expand_targets "$raw")
  (( errors == 0 )) || die "Cible(s) invalide(s)."
  # Exclusions : -x + adresses du serveur lui-même
  { [[ -n "$EXCLUDES" ]] && expand_targets "$EXCLUDES" | grep -v '^ERR|'
    hostname -I 2>/dev/null | tr ' ' '\n'
    ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1
    echo "$MANAGER_IP"; } | grep -E '^[0-9.]+$' | sort -u > "$excl"
  n="$(wc -l < "$ips")"
  grep -vxFf "$excl" "$ips" > "${ips}.f" || true; mv "${ips}.f" "$ips"
  (( n - $(wc -l < "$ips") > 0 )) && log_verbose "$(( n - $(wc -l < "$ips") )) adresse(s) exclue(s) (-x ou serveur Wazuh)"
  n="$(wc -l < "$ips")"
  (( n > 0 )) || die "Aucune adresse à traiter après exclusions."

  # ---- En-tête
  banner
  log_info "Action : ${C_BOLD}${ACTION}${C_RESET}$( (( DRY_RUN )) && echo " ${C_YELLOW}[SIMULATION]${C_RESET}") — cibles : ${n} adresse(s) — filtres OS : $(filters_label)"
  log_info "Manager : ${MANAGER_IP} — version agents : ${WAZUH_VERSION} — parallélisme : ${PARALLEL} — journal : ${LOG_FILE}"
  if (( n > MAX_TARGETS_NO_CONFIRM )); then
    confirm "${n} adresses à analyser. Continuer ?" n || exit 0
  fi

  # ---- Contrôles côté serveur
  if [[ "$ACTION" =~ ^(install|update)$ ]]; then
    log_step "Contrôles côté serveur"
    if tcp_open "$MANAGER_IP" 1514 3 && tcp_open "$MANAGER_IP" 1515 3; then
      check_line "Manager ${MANAGER_IP}:1514/1515" OK
    else
      check_line "Manager ${MANAGER_IP}:1514/1515" KO "le manager n'écoute pas ou l'IP est incorrecte (-M)"
      (( DRY_RUN )) || die "Le manager doit être joignable avant d'installer des agents."
    fi
    if [[ "$ACTION" == install ]] && api_available && api_token >/dev/null 2>&1; then
      local g groups=()
      if [[ -n "$AGENT_GROUP" ]]; then IFS=, read -r -a groups <<<"$AGENT_GROUP"
      else os_selected linux && groups+=(linux); os_selected windows && groups+=(windows); os_selected macos && groups+=(macos); fi
      for g in "${groups[@]}"; do
        if api_ensure_group "$g"; then check_line "Groupe d'agents « ${g} »" OK
        else check_line "Groupe d'agents « ${g} »" KO "absent et création impossible"; (( DRY_RUN )) || die "Groupe ${g} indisponible."; fi
      done
    fi
    if [[ -n "${ENROLLMENT_PASSWORD:-}" ]]; then check_line "Mot de passe d'enrôlement" OK
    else check_line "Mot de passe d'enrôlement" WARN "absent de ${STATE_FILE} : enrôlement sans mot de passe"; fi
  fi
  if [[ "$ACTION" != discover ]]; then
    if api_available && api_token >/dev/null 2>&1; then check_line "API du manager (vérifications)" OK
    else check_line "API du manager (vérifications)" WARN "indisponible : vérification côté agent uniquement"
      API_USER=""; API_PASSWORD=""; fi
  fi
  export API_USER API_PASSWORD ENROLLMENT_PASSWORD

  # ---- Découverte
  discover_hosts "$ips" "${RUN_DIR}/discovery.tsv"
  if [[ "$ACTION" == discover ]]; then
    print_discovery_table
    exit 0
  fi

  # ---- Sélection des hôtes
  local ip os conf ports ttl why selected="${RUN_DIR}/selected.tsv" mgmt
  : > "$selected"
  while IFS=$'\t' read -r ip os conf ports ttl why; do
    if ! os_selected "$os"; then
      log_verbose "[${ip}] ${os} hors filtre — ignoré"
      continue
    fi
    case "$os" in
      windows) mgmt="$(win_transport "$ports")" ;;
      linux|macos|unix) _has_port "$ports" 22 && mgmt=ssh || mgmt=none ;;
      *) mgmt=none ;;
    esac
    if [[ "$mgmt" == none ]]; then
      if [[ "$ACTION" == status ]] && [[ -z "${LINUX_USER}${WIN_USER}${MAC_USER}" ]]; then
        printf '%s\t%s\t%s\n' "$ip" "$os" "$ports" >> "$selected"; continue
      fi
      printf '%s\t%s\t-\tIGNORE\t-\t-\t%s\n' "$ip" "$os" \
        "aucun accès d'administration ouvert ($( [[ "$os" == windows ]] && echo 'WinRM 5985/5986 ou SSH' || echo 'SSH 22'))" \
        > "${RUN_DIR}/results/${ip}"
      log_warn "[${ip}] ${os} : aucun port d'administration ouvert — ignoré"
      continue
    fi
    printf '%s\t%s\t%s\n' "$ip" "$os" "$ports" >> "$selected"
  done < "${RUN_DIR}/discovery.tsv"

  n="$(wc -l < "$selected")"
  if (( n == 0 )); then
    log_warn "Aucun hôte à traiter."
    print_summary; exit 0
  fi

  # ---- Confirmation
  if [[ "$ACTION" =~ ^(install|update|remove|purge)$ ]] && (( ! DRY_RUN )); then
    echo
    log_info "${n} hôte(s) concerné(s) :"
    awk -F'\t' '{printf "    • %-15s %s\n", $1, $2}' "$selected" >&2
    local verb
    case "$ACTION" in install) verb="Installer l'agent sur";; update) verb="Mettre à jour l'agent sur";;
                      remove) verb="Désinstaller l'agent de";; purge) verb="Désinstaller ET purger l'agent de";; esac
    confirm "${verb} ces ${n} hôte(s) ?" n || { log_info "Annulé."; exit 0; }
  fi

  # ---- Traitement parallèle
  log_step "Traitement de ${n} hôte(s) — ${PARALLEL} en parallèle"
  while IFS=$'\t' read -r ip os ports; do
    while (( $(jobs -rp | wc -l) >= PARALLEL )); do wait -n 2>/dev/null || true; done
    ( host_worker "$ip" "$os" "$ports" ) &
  done < "$selected"
  wait

  # Hôtes sans résultat (worker interrompu)
  while IFS=$'\t' read -r ip os ports; do
    [[ -f "${RUN_DIR}/results/${ip}" ]] || printf '%s\t%s\t-\tECHEC\t-\t-\t%s\n' "$ip" "$os" "traitement interrompu" > "${RUN_DIR}/results/${ip}"
  done < "$selected"

  print_summary
}

main "$@"
