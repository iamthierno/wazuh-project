#!/usr/bin/env bash
# =============================================================================
#  lib/common.sh — Fonctions partagées : logs, contrôles, état, utilitaires
#  Sourcé par deploy.sh, lib/*.sh, scripts/*.sh et agents/install-agent.sh
# =============================================================================

# Répertoire racine du projet
PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# ---------------------------------------------------------------- Couleurs ---
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
  C_BLUE=$'\e[34m'; C_MAGENTA=$'\e[35m'; C_CYAN=$'\e[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
  C_BLUE=""; C_MAGENTA=""; C_CYAN=""
fi

# Niveau de verbosité : 0=silencieux 1=normal 2=verbeux(-v) 3=debug(-vv)
VERBOSITY="${VERBOSITY:-1}"
# Fichier de log courant (défini par l'appelant via log_init)
LOG_FILE="${LOG_FILE:-}"
# Secrets à masquer dans toute sortie
declare -a _SECRETS=()

# ------------------------------------------------------------------- Logs ---
_ts() { date '+%H:%M:%S'; }

# Ajoute une valeur à masquer dans les logs
register_secret() { [[ -n "${1:-}" ]] && _SECRETS+=("$1"); return 0; }

_mask() {
  local s="$1" sec
  for sec in "${_SECRETS[@]}"; do
    [[ -n "$sec" ]] && s="${s//"$sec"/********}"
  done
  printf '%s' "$s"
}

_strip_colors() { sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'; }

# _log <niveau_min> <couleur> <TAG> <message...>
_log() {
  local min="$1" color="$2" tag="$3"; shift 3
  local msg; msg="$(_mask "$*")"
  local line
  line="[$(_ts)] [${tag}] ${msg}"
  if (( VERBOSITY >= min )); then
    printf '%s[%s]%s %s[%-5s]%s %s\n' "$C_DIM" "$(_ts)" "$C_RESET" "$color" "$tag" "$C_RESET" "$msg" >&2
  fi
  if [[ -n "$LOG_FILE" ]]; then
    printf '%s\n' "$line" | _strip_colors >> "$LOG_FILE" 2>/dev/null || true
  fi
}

log_info()  { _log 1 "$C_BLUE"    "INFO"  "$@"; }
log_ok()    { _log 1 "$C_GREEN"   " OK "  "$@"; }
log_warn()  { _log 0 "$C_YELLOW"  "WARN"  "$@"; }
log_error() { _log 0 "$C_RED"     "ERREUR" "$@"; }
log_step()  { _log 1 "$C_MAGENTA" "ETAPE" "${C_BOLD}$*${C_RESET}"; }
log_check() { _log 1 "$C_CYAN"    "CHECK" "$@"; }
log_verbose() { _log 2 "$C_DIM"   "INFO"  "$@"; }
log_debug() { _log 3 "$C_DIM"     "DEBUG" "$@"; }

die() { log_error "$*"; exit 1; }

# Initialise un fichier de log : log_init <prefixe>
log_init() {
  local prefix="${1:-deploy}" dir="${LOG_DIR:-/var/log/wazuh-deploy}"
  mkdir -p "$dir" 2>/dev/null || dir="/tmp"
  chmod 750 "$dir" 2>/dev/null || true
  LOG_FILE="${dir}/${prefix}-$(date '+%Y%m%d-%H%M%S').log"
  : > "$LOG_FILE" && chmod 600 "$LOG_FILE"
  export LOG_FILE
}

# Longueur affichée d'une chaîne (caractères UTF-8, pas octets)
strlen() { printf '%s' "$1" | LC_ALL=C.UTF-8 wc -m 2>/dev/null || printf '%s' "${#1}"; }

# Affiche un résultat de contrôle aligné : check_line <libellé> <OK|KO|WARN> [détail]
check_line() {
  local label="$1" status="$2" detail="${3:-}" color dots len
  len="$(strlen "$label")"
  case "$status" in
    OK)   color="$C_GREEN" ;;
    KO)   color="$C_RED" ;;
    *)    color="$C_YELLOW" ;;
  esac
  dots="$(printf '%*s' $(( 42 - len > 2 ? 42 - len : 2 )) '' | tr ' ' '.')"
  log_check "${label} ${dots} ${color}${status}${C_RESET}${detail:+  ${detail}}"
}

# Exécute une commande en l'affichant en mode debug ; sortie dans le log
run() {
  log_debug "\$ $*"
  if [[ -n "$LOG_FILE" ]]; then
    "$@" >> "$LOG_FILE" 2>&1
  else
    "$@" >/dev/null 2>&1
  fi
}

# Exécute une commande et affiche sa sortie en direct (et dans le log)
run_live() {
  log_debug "\$ $*"
  if [[ -n "$LOG_FILE" ]]; then
    "$@" 2>&1 | tee -a "$LOG_FILE"
    return "${PIPESTATUS[0]}"
  else
    "$@"
  fi
}

# --------------------------------------------------------------- Questions ---
ASSUME_YES="${ASSUME_YES:-0}"

# confirm "Question ?" [défaut o|n] -> 0 si oui
confirm() {
  local q="$1" def="${2:-n}" ans prompt
  [[ "$ASSUME_YES" == "1" ]] && return 0
  if [[ "$def" == "o" ]]; then prompt="[O/n]"; else prompt="[o/N]"; fi
  read -r -p "${C_YELLOW}?${C_RESET} ${q} ${prompt} " ans </dev/tty || ans=""
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[oOyY] ]]
}

# ------------------------------------------------------------- Système ------
require_root() {
  [[ $EUID -eq 0 ]] || die "Ce script doit être exécuté en root (sudo $0 ...)."
}

have() { command -v "$1" >/dev/null 2>&1; }

# Charge /etc/os-release dans OS_ID, OS_VERSION, OS_LIKE, OS_PRETTY
detect_os() {
  OS_ID="unknown"; OS_VERSION=""; OS_LIKE=""; OS_PRETTY="inconnu"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"; OS_VERSION="${VERSION_ID:-}"
    OS_LIKE="${ID_LIKE:-}"; OS_PRETTY="${PRETTY_NAME:-$OS_ID}"
  fi
  case "$OS_ID $OS_LIKE" in
    *debian*|*ubuntu*) OS_FAMILY="debian"; PKG_MGR="apt-get" ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*|*amzn*) OS_FAMILY="rhel"
      if have dnf; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi ;;
    *suse*) OS_FAMILY="suse"; PKG_MGR="zypper" ;;
    *) OS_FAMILY="unknown"; PKG_MGR="" ;;
  esac
  export OS_ID OS_VERSION OS_LIKE OS_PRETTY OS_FAMILY PKG_MGR
}

# Installe des paquets système : pkg_install <paquet>...
pkg_install() {
  [[ -n "${PKG_MGR:-}" ]] || detect_os
  log_info "Installation des paquets : $*"
  case "$PKG_MGR" in
    apt-get) run env DEBIAN_FRONTEND=noninteractive apt-get update -q
             run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" ;;
    dnf|yum) run "$PKG_MGR" install -y "$@" ;;
    zypper)  run zypper --non-interactive install "$@" ;;
    *) log_error "Gestionnaire de paquets non supporté, installez manuellement : $*"; return 1 ;;
  esac
}

# IP principale (celle de la route par défaut)
primary_ip() {
  local ip=""
  if have ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  [[ -z "$ip" ]] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "$ip"
}

# Port en écoute localement ? port_in_use <port> [tcp|udp]
port_in_use() {
  local port="$1" proto="${2:-tcp}" flag="-lnt" hex f
  [[ "$proto" == "udp" ]] && flag="-lnu"
  if have ss; then
    ss "$flag" 2>/dev/null | awk 'NR>1{print $4}' | grep -Eq "[:.]${port}\$"
    return
  fi
  # Repli sans iproute2 : lecture de /proc/net (TCP : état 0A = LISTEN)
  hex="$(printf '%04X' "$port")"
  for f in /proc/net/"${proto}" /proc/net/"${proto}6"; do
    [[ -r "$f" ]] || continue
    if [[ "$proto" == tcp ]]; then
      awk -v p=":${hex}" 'NR>1 && substr($2, length($2)-4)==p && $4=="0A"{found=1} END{exit !found}' "$f" && return 0
    else
      awk -v p=":${hex}" 'NR>1 && substr($2, length($2)-4)==p {found=1} END{exit !found}' "$f" && return 0
    fi
  done
  return 1
}

# Test de connexion TCP : tcp_open <hôte> <port> [timeout]
tcp_open() {
  local host="$1" port="$2" t="${3:-3}"
  timeout "$t" bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null
}

# Accès HTTPS sortant : https_reachable <url>
https_reachable() {
  curl -fsS -o /dev/null -m 10 --retry 1 -I "$1" 2>/dev/null \
    || curl -sS -o /dev/null -m 10 -w '%{http_code}' "$1" 2>/dev/null | grep -Eq '^[23]'
}

# Mot de passe robuste compatible avec les politiques Wazuh (maj, min, chiffre, symbole)
# et sûr pour sed/YAML/MSI (pas de / \ & " ' $ ` espace)
gen_password() {
  local len="${1:-20}" core
  core="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$len")"
  printf '%s' "${core:0:$((len/2))}.Wz${RANDOM:0:1}-${core:$((len/2))}"
}

# --------------------------------------------------------- Configuration ----
load_config() {
  local cfg="${CONFIG_FILE:-${PROJECT_DIR}/config.env}"
  [[ -r "$cfg" ]] || die "Fichier de configuration introuvable : $cfg"
  # shellcheck disable=SC1090
  . "$cfg"
  WAZUH_MINOR="$(cut -d. -f1,2 <<<"$WAZUH_VERSION")"     # ex. 4.14
  WAZUH_MAJOR_BRANCH="$(cut -d. -f1 <<<"$WAZUH_VERSION").x"  # ex. 4.x
  STATE_FILE="${DEPLOY_STATE_DIR}/state.env"
  export WAZUH_VERSION WAZUH_MINOR WAZUH_MAJOR_BRANCH STATE_FILE
}

# État du déploiement (mode, IP, mots de passe) : /etc/wazuh-deploy/state.env
load_state() {
  if [[ -r "${STATE_FILE:-}" ]]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
    register_secret "${INDEXER_ADMIN_PASSWORD:-}"
    register_secret "${API_PASSWORD:-}"
    register_secret "${ENROLLMENT_PASSWORD:-}"
    register_secret "${DASHBOARD_PASSWORD:-}"
    return 0
  fi
  return 1
}

# state_set <CLE> <valeur> : écrit/remplace une variable dans state.env
state_set() {
  local key="$1" val="$2" tmp
  mkdir -p "$DEPLOY_STATE_DIR" && chmod 700 "$DEPLOY_STATE_DIR"
  touch "$STATE_FILE" && chmod 600 "$STATE_FILE"
  tmp="$(mktemp "${DEPLOY_STATE_DIR}/.state.XXXXXX")"
  grep -v "^${key}=" "$STATE_FILE" > "$tmp" || true
  printf '%s=%q\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$STATE_FILE" && chmod 600 "$STATE_FILE"
  printf -v "$key" '%s' "$val"
  export "${key?}"
}

# Mode de déploiement actuel : native | docker | (vide)
deploy_mode() {
  if [[ -n "${DEPLOY_MODE:-}" ]]; then printf '%s' "$DEPLOY_MODE"; return; fi
  if [[ -x /var/ossec/bin/wazuh-control ]] && /var/ossec/bin/wazuh-control info -t 2>/dev/null | grep -q server; then
    printf 'native'
  elif have docker && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'wazuh-manager'; then
    printf 'docker'
  fi
}

# ------------------------------------------------- Exécution sur le manager --
# Exécute une commande dans le contexte du manager (natif ou conteneur)
MANAGER_CONTAINER="${MANAGER_CONTAINER:-wazuh-manager}"
mgr_exec() {
  if [[ "$(deploy_mode)" == "docker" ]]; then
    docker exec -i "$MANAGER_CONTAINER" "$@"
  else
    "$@"
  fi
}

# Copie un fichier local vers le manager : mgr_copy <src> <dest> [owner] [mode]
mgr_copy() {
  local src="$1" dest="$2" owner="${3:-root:wazuh}" mode="${4:-660}"
  if [[ "$(deploy_mode)" == "docker" ]]; then
    docker cp "$src" "${MANAGER_CONTAINER}:${dest}" >/dev/null
  else
    cp -f "$src" "$dest"
  fi
  mgr_exec chown "$owner" "$dest"
  mgr_exec chmod "$mode" "$dest"
}

# Écrit stdin dans un fichier du manager : ... | mgr_write <dest> [owner] [mode]
mgr_write() {
  local dest="$1" owner="${2:-root:wazuh}" mode="${3:-640}"
  mgr_exec sh -c "umask 077; cat > '$dest'"
  mgr_exec chown "$owner" "$dest"
  mgr_exec chmod "$mode" "$dest"
}

# ------------------------------------------------------------- Bannière -----
banner() {
  printf '%s' "$C_CYAN"
  cat <<'EOF'
 __        __                _
 \ \      / /_ _ _____   _| |__     Déploiement Wazuh
  \ \ /\ / / _` |_  / | | | '_ \    Serveur · Agents · Équipements réseau
   \ V  V / (_| |/ /| |_| | | | |
    \_/\_/ \__,_/___|\__,_|_| |_|
EOF
  printf '%s\n' "$C_RESET"
}
