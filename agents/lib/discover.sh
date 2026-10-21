#!/usr/bin/env bash
# =============================================================================
#  agents/lib/discover.sh — Découverte des hôtes et détection de l'OS
#  Indices croisés : empreinte nmap (-O), bannière SSH, ports ouverts, TTL,
#  vendeur MAC. Le résultat "unix" (Linux ou macOS) est confirmé après
#  connexion par `uname -s`.
#  Sortie TSV : ip  os  confiance  ports  ttl  détail
# =============================================================================

_has_port() { [[ ",$1," == *",$2,"* ]]; }

# Bannière SSH : ssh_banner <ip> [port]
ssh_banner() {
  local l
  # shellcheck disable=SC2016
  l="$(timeout 4 bash -c 'exec 3<>"/dev/tcp/$0/$1" && IFS= read -r -t 3 l <&3 && printf "%s" "$l"' "$1" "${2:-22}" 2>/dev/null)"
  printf '%s' "${l//$'\r'/}"
}

# classify_host <ports> <ttl> <famille_nmap> <nom_nmap> <vendeur> <bannière>
# -> "os|confiance|raison"
classify_host() {
  local ports="$1" ttl="${2:-0}" fam="$3" name="$4" vendor="$5" banner="$6"
  local b; b="$(tr '[:upper:]' '[:lower:]' <<<"$banner")"

  if [[ "$b" == *windows* ]]; then echo "windows|sûr|bannière SSH (${banner})"; return; fi
  if [[ "$b" =~ ubuntu|debian|raspbian|\.el[0-9]|redhat|centos|rocky|alma|fedora|suse|amzn ]]; then
    echo "linux|sûr|bannière SSH (${banner})"; return
  fi
  case "$fam" in
    Windows)               echo "windows|sûr|empreinte nmap (${name})"; return ;;
    "Mac OS X"|macOS|"OS X"|iOS) echo "macos|probable|empreinte nmap (${name})"; return ;;
    Linux)
      if [[ "$vendor" == *Apple* ]]; then echo "macos|probable|vendeur MAC Apple"; return; fi
      echo "linux|probable|empreinte nmap (${name})"; return ;;
  esac
  if _has_port "$ports" 3389 || _has_port "$ports" 5985 || _has_port "$ports" 5986 || _has_port "$ports" 135; then
    echo "windows|probable|ports Windows (${ports})"; return
  fi
  if _has_port "$ports" 445 && ! _has_port "$ports" 22; then
    echo "windows|probable|SMB sans SSH"; return
  fi
  if [[ "$vendor" == *Apple* ]] || _has_port "$ports" 548 || { _has_port "$ports" 22 && _has_port "$ports" 5900 && _has_port "$ports" 88; }; then
    echo "macos|probable|ports/vendeur Apple"; return
  fi
  if _has_port "$ports" 22; then
    echo "unix|à confirmer|SSH ouvert, TTL ${ttl} (Linux ou macOS)"; return
  fi
  if (( ttl > 64 && ttl <= 128 )); then echo "windows|faible|TTL ${ttl}"; return; fi
  if (( ttl > 0 && ttl <= 64 )); then echo "unix|faible|TTL ${ttl}"; return; fi
  echo "inconnu|-|aucun indice"
}

# Découverte via nmap : _discover_nmap <fichier_ips> <tsv_brut>
_discover_nmap() {
  local ips="$1" raw="$2" xml="${RUN_DIR}/nmap.xml" opts
  opts=(-n -T4 --max-retries 1 --host-timeout 90s -p "$DISCOVERY_PORTS" --reason -oX "$xml" -iL "$ips")
  if [[ $EUID -eq 0 ]]; then
    # shellcheck disable=SC2054
    opts+=(-sS -O --osscan-limit --max-os-tries 1 -PE -PS22,135,445,3389,5985 -PA80)
  else
    opts+=(-sT)
  fi
  [[ "${NO_PING:-0}" == "1" ]] && opts+=(-Pn)
  log_debug "\$ nmap ${opts[*]}"
  if (( VERBOSITY >= 3 )); then
    nmap "${opts[@]}" --stats-every 15s 2>&1 | grep -E 'Stats|Timing|done' | while IFS= read -r l; do log_debug "  nmap: $l"; done
  else
    nmap "${opts[@]}" >>"${LOG_FILE:-/dev/null}" 2>&1
  fi
  python3 "${AGENTS_DIR}/lib/nmap_parse.py" "$xml" > "$raw"
}

# Découverte sans nmap (sondes TCP + ping) : _discover_tcp <fichier_ips> <tsv_brut>
_probe_one() {
  local ip="$1" p open=() ttl=0 pr
  pr="$(ping -c1 -W1 "$ip" 2>/dev/null | grep -o 'ttl=[0-9]*' | head -1)"
  [[ -n "$pr" ]] && ttl="${pr#ttl=}"
  for p in ${DISCOVERY_PORTS//,/ }; do
    timeout 1 bash -c ">/dev/tcp/${ip}/${p}" 2>/dev/null && open+=("$p")
  done
  if (( ${#open[@]} > 0 || ttl > 0 )); then
    printf '%s\t%s\t%s\t\t\t\n' "$ip" "$(IFS=,; echo "${open[*]}")" "$ttl"
  fi
}
_discover_tcp() {
  local ips="$1" raw="$2" ip
  : > "$raw"
  while IFS= read -r ip; do
    while (( $(jobs -rp | wc -l) >= 64 )); do wait -n 2>/dev/null || true; done
    _probe_one "$ip" >> "$raw" &
  done < "$ips"
  wait
}

# discover_hosts <fichier_ips> <tsv_sortie>
discover_hosts() {
  local ips="$1" out="$2" raw="${RUN_DIR}/discovery_raw.tsv" n
  local ip ports ttl fam name vendor banner cls os conf why
  n="$(wc -l < "$ips")"

  if have nmap; then
    log_step "Découverte de ${n} adresse(s) avec nmap (empreinte OS + ports ${DISCOVERY_PORTS})"
    _discover_nmap "$ips" "$raw"
  else
    log_warn "nmap absent : découverte par sondes TCP (moins précise)"
    log_step "Découverte de ${n} adresse(s) (sondes TCP + ping)"
    _discover_tcp "$ips" "$raw"
  fi

  : > "$out"
  while IFS=$'\t' read -r ip ports ttl fam name vendor; do
    [[ -z "$ip" || "$ip" == ERR* ]] && continue
    banner=""
    _has_port "$ports" 22 && banner="$(ssh_banner "$ip")"
    cls="$(classify_host "$ports" "$ttl" "$fam" "$name" "$vendor" "$banner")"
    IFS='|' read -r os conf why <<<"$cls"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$os" "$conf" "${ports:--}" "${ttl:-0}" "$why" >> "$out"
    _log 1 "$C_CYAN" "DISCO" "$(printf '%-15s ▶ actif  ports %-18s TTL %-4s → %s%s%s (%s) %s' \
      "$ip" "${ports:--}" "${ttl:-?}" "$C_BOLD" "$os" "$C_RESET" "$conf" "${C_DIM}${why}${C_RESET}")"
  done < <(sort -t. -k1,1n -k2,2n -k3,3n -k4,4n "$raw")

  log_info "Hôtes actifs : $(wc -l < "$out") / ${n}"
}
