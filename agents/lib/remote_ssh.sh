#!/usr/bin/env bash
# =============================================================================
#  agents/lib/remote_ssh.sh — Exécution distante par SSH (Linux, macOS, et
#  Windows avec OpenSSH en secours).
#  Les identifiants de l'hôte courant sont dans R_USER / R_PASS / R_KEY
#  (variables du worker, jamais affichées ni passées en argument).
# =============================================================================

# Options SSH communes (multiplexage : une seule authentification par hôte)
_ssh_opts() {
  SSH_OPTS=(-o "ConnectTimeout=${CONNECT_TIMEOUT}" -o StrictHostKeyChecking=accept-new
            -o "UserKnownHostsFile=${KNOWN_HOSTS}" -o LogLevel=ERROR -o ServerAliveInterval=15
            -o ControlMaster=auto -o "ControlPath=${CM_DIR}/%C" -o ControlPersist=180
            -o NumberOfPasswordPrompts=1)
  if [[ -n "${R_KEY:-}" ]]; then
    SSH_OPTS+=(-i "$R_KEY" -o IdentitiesOnly=yes -o BatchMode=yes)
  elif [[ -n "${R_PASS:-}" ]]; then
    # shellcheck disable=SC2054
    SSH_OPTS+=(-o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no)
  else
    SSH_OPTS+=(-o BatchMode=yes)
  fi
}

# _ssh_wrap <commande...> : préfixe sshpass si authentification par mot de passe
_ssh_wrap() {
  if [[ -z "${R_KEY:-}" && -n "${R_PASS:-}" ]]; then
    SSHPASS="$R_PASS" sshpass -e "$@"
  else
    "$@"
  fi
}

# ssh_exec <ip> <commande distante>   (stdin transmis)
ssh_exec() {
  local ip="$1"; shift
  _ssh_opts
  log_debug "[${ip}] ssh -l ${R_USER} ${ip} $*"
  _ssh_wrap ssh "${SSH_OPTS[@]}" -l "$R_USER" "$ip" "$@"
}

# scp_to <ip> <fichier_local> <chemin_distant>
scp_to() {
  _ssh_opts
  log_debug "[${1}] scp $(basename "$2") -> $3"
  _ssh_wrap scp -q "${SSH_OPTS[@]}" -o "User=${R_USER}" "$2" "${1}:${3}"
}

# Ferme la connexion maître SSH d'un hôte
ssh_close() {
  _ssh_opts
  ssh "${SSH_OPTS[@]}" -O exit -l "${R_USER:-root}" "$1" >/dev/null 2>&1 || true
}

# Écrit l'en-tête de variables (format bash) : _unix_header <action> [CLE=valeur...]
_unix_header() {
  local kv
  printf 'ACTION=%q\n' "$1"; shift
  for kv in "$@"; do
    printf '%s=%q\n' "${kv%%=*}" "${kv#*=}"
  done
}

# unix_upload <ip> <fichier_local> -> affiche le chemin distant
unix_upload() {
  local ip="$1" src="$2" rpath
  rpath="/tmp/.wzd-$(date +%s)-${RANDOM}${RANDOM}-$(basename "$src")"
  ssh_exec "$ip" "umask 077; cat > '${rpath}'" < "$src" || return 1
  printf '%s' "$rpath"
}

# unix_action <ip> <action> [CLE=valeur...]
# Envoie le payload (en-tête + script), l'exécute en root (sudo) et le supprime.
# La sortie du payload (STEP|, KV|, RESULT|...) est écrite sur stdout.
unix_action() {
  local ip="$1" action="$2"; shift 2
  local script rpath runner
  script="$(mktemp "${RUN_DIR}/payload.XXXXXX")"
  { _unix_header "$action" "$@"; cat "${AGENTS_DIR}/lib/payloads/unix_agent.sh"; } > "$script"
  rpath="/tmp/.wzd-$(date +%s)-${RANDOM}${RANDOM}.sh"
  if ! ssh_exec "$ip" "umask 077; cat > '${rpath}'" < "$script"; then
    rm -f "$script"
    return 255
  fi
  rm -f "$script"

  runner="bash '${rpath}'; rc=\$?; rm -f '${rpath}'; exit \$rc"
  if [[ "$R_USER" == "root" ]]; then
    ssh_exec "$ip" "$runner" </dev/null
  elif [[ -n "${R_PASS:-}" ]]; then
    printf '%s\n' "$R_PASS" | ssh_exec "$ip" "sudo -S -p '' bash '${rpath}'; rc=\$?; rm -f '${rpath}'; exit \$rc"
  else
    ssh_exec "$ip" "sudo -n bash '${rpath}'; rc=\$?; rm -f '${rpath}'; exit \$rc" </dev/null
  fi
}

# Traduit les erreurs SSH/sudo en message clair : ssh_explain <fichier_stderr>
ssh_explain() {
  local f="$1"
  if grep -qiE 'permission denied|authentication failed|too many authentication' "$f"; then
    echo "authentification SSH refusée (utilisateur/mot de passe/clé)"
  elif grep -qiE 'a password is required|incorrect password|sorry, try again|no password was provided' "$f"; then
    echo "sudo refusé : mot de passe sudo requis ou incorrect"
  elif grep -qiE 'not in the sudoers|not allowed to (run|execute)' "$f"; then
    echo "l'utilisateur n'a pas les droits sudo"
  elif grep -qiE 'host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED' "$f"; then
    echo "clé d'hôte SSH modifiée (ssh-keygen -R <ip> -f ${KNOWN_HOSTS})"
  elif grep -qiE 'timed out|no route to host' "$f"; then
    echo "délai de connexion SSH dépassé"
  elif grep -qiE 'connection refused' "$f"; then
    echo "connexion SSH refusée (port 22 fermé)"
  elif grep -qiE 'sshpass: command not found|sshpass.*not found' "$f"; then
    echo "sshpass absent sur le serveur (authentification par mot de passe impossible)"
  else
    tr '\n' ' ' < "$f" | cut -c1-160
  fi
}
