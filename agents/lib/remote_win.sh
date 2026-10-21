#!/usr/bin/env bash
# =============================================================================
#  agents/lib/remote_win.sh — Exécution distante sur Windows
#  Transport : WinRM (5985 HTTP / 5986 HTTPS) via winrm_exec.py, ou OpenSSH
#  (port 22) en secours. Identifiants : R_USER / R_PASS.
# =============================================================================

# Choix du transport selon les ports découverts : win_transport <ports>
win_transport() {
  local ports=",$1,"
  if [[ "${WIN_HTTPS:-no}" == "yes" && "$ports" == *",5986,"* ]]; then echo "winrm-https"
  elif [[ "$ports" == *",5985,"* ]]; then echo "winrm"
  elif [[ "$ports" == *",5986,"* ]]; then echo "winrm-https"
  elif [[ "$ports" == *",22,"* ]]; then echo "ssh"
  else echo "none"; fi
}

_winrm() { # _winrm <ip> <transport> <arguments winrm_exec.py...>
  local ip="$1" tr="$2"; shift 2
  local args=(--host "$ip" --user "$R_USER" --auth "${WIN_AUTH:-negotiate}" --timeout "$CONNECT_TIMEOUT")
  [[ "$tr" == "winrm-https" ]] && args+=(--https --no-verify)
  log_debug "[${ip}] winrm_exec.py ${args[*]} $*"
  WZ_WIN_PASS="$R_PASS" "$PY_WINRM" "${AGENTS_DIR}/lib/winrm_exec.py" "${args[@]}" "$@"
}

# Échappe une valeur pour une chaîne PowerShell entre apostrophes
_ps_quote() { local v="${1//\'/\'\'}"; printf "'%s'" "$v"; }

# win_upload <ip> <transport> <fichier_local> <chemin_distant_windows>
win_upload() {
  local ip="$1" tr="$2" src="$3" dst="$4"
  if [[ "$tr" == ssh ]]; then
    scp_to "$ip" "$src" "${dst//\\//}"
  else
    _winrm "$ip" "$tr" --copy "$src" "$dst" >/dev/null
  fi
}

# win_action <ip> <transport> <action> [CLE=valeur...]
win_action() {
  local ip="$1" tr="$2" action="$3"; shift 3
  local script kv rname rc
  script="$(mktemp "${RUN_DIR}/payload.XXXXXX")"
  {
    printf '\xEF\xBB\xBF'   # BOM UTF-8 : accents corrects sous PowerShell 5.1
    # shellcheck disable=SC2016
    printf '$ACTION = %s\n' "$(_ps_quote "$action")"
    for kv in "$@"; do
      printf '$%s = %s\n' "${kv%%=*}" "$(_ps_quote "${kv#*=}")"
    done
    cat "${AGENTS_DIR}/lib/payloads/windows_agent.ps1"
  } > "$script"

  case "$tr" in
    winrm|winrm-https)
      _winrm "$ip" "$tr" --script "$script"; rc=$? ;;
    ssh)
      rname="C:/Windows/Temp/wzd-${RANDOM}${RANDOM}.ps1"
      if scp_to "$ip" "$script" "$rname"; then
        ssh_exec "$ip" "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ${rname//\//\\} & del /f /q ${rname//\//\\}" </dev/null
        rc=$?
      else
        rc=255
      fi ;;
    *) echo "RESULT|fail|aucun accès d'administration (WinRM 5985/5986 ou SSH 22)"; rc=1 ;;
  esac
  rm -f "$script"
  return "$rc"
}

# Traduit les erreurs WinRM : win_explain <fichier_stderr>
win_explain() {
  local f="$1"
  if grep -q 'WINRM_ERROR|' "$f"; then
    grep -m1 'WINRM_ERROR|' "$f" | cut -d'|' -f2-
  elif grep -qiE 'permission denied|access denied' "$f"; then
    echo "authentification refusée"
  else
    ssh_explain "$f"
  fi
}
