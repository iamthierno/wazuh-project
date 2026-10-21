#!/usr/bin/env bash
# =============================================================================
#  agents/lib/targets.sh — Interprétation des cibles
#  Formats acceptés (séparés par espaces ou virgules) :
#    192.168.1.10              une IP
#    192.168.1.0/24            un sous-réseau (adresses réseau/broadcast exclues)
#    192.168.1.10-50           une plage abrégée (dernier octet)
#    192.168.1.10-192.168.1.50 une plage complète
#    "192.168.1.10 - 192.168.1.50"  plage avec espaces
#    srv-web01                 un nom d'hôte (résolu en IPv4)
# =============================================================================

MAX_EXPAND="${MAX_EXPAND:-65536}"

is_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    (( 10#$o <= 255 )) || return 1
  done
}

ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  echo $(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))
}

int_to_ip() {
  local n="$1"
  echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

# Normalise la saisie : virgules -> espaces, " - " -> "-"
normalize_targets() {
  printf '%s' "$*" | tr ',;' '  ' | sed -E 's/[[:space:]]+-[[:space:]]+/-/g; s/[[:space:]]+-$//; s/^-[[:space:]]+//'
}

# _emit_range <début_int> <fin_int>
_emit_range() {
  local s="$1" e="$2" i
  if (( e < s )); then
    echo "ERR|plage inversée ($(int_to_ip "$s") > $(int_to_ip "$e"))"
    return 1
  fi
  if (( e - s + 1 > MAX_EXPAND )); then
    echo "ERR|plage trop grande ($(( e - s + 1 )) adresses, max ${MAX_EXPAND})"
    return 1
  fi
  for (( i = s; i <= e; i++ )); do int_to_ip "$i"; done
}

# expand_token <cible> : écrit une IP par ligne, ou "ERR|message"
expand_token() {
  local t="$1" ip prefix net mask start end a b
  # CIDR
  if [[ "$t" =~ ^([0-9.]+)/([0-9]{1,2})$ ]]; then
    ip="${BASH_REMATCH[1]}"; prefix="${BASH_REMATCH[2]}"
    is_ipv4 "$ip" || { echo "ERR|adresse invalide : $t"; return 1; }
    (( prefix >= 8 && prefix <= 32 )) || { echo "ERR|masque /${prefix} non supporté (8 à 32) : $t"; return 1; }
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    net=$(( $(ip_to_int "$ip") & mask ))
    if (( prefix >= 31 )); then
      start=$net; end=$(( net + (1 << (32 - prefix)) - 1 ))
    else
      start=$(( net + 1 )); end=$(( net + (1 << (32 - prefix)) - 2 ))
    fi
    _emit_range "$start" "$end"
    return
  fi
  # Plage complète a.b.c.d-w.x.y.z
  if [[ "$t" =~ ^([0-9.]+)-([0-9.]+)$ ]]; then
    a="${BASH_REMATCH[1]}"; b="${BASH_REMATCH[2]}"   # is_ipv4 écrase BASH_REMATCH
    if is_ipv4 "$a" && is_ipv4 "$b"; then
      _emit_range "$(ip_to_int "$a")" "$(ip_to_int "$b")"
      return
    fi
  fi
  # Plage abrégée a.b.c.d-e
  if [[ "$t" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)([0-9]{1,3})-([0-9]{1,3})$ ]]; then
    a="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"; b="${BASH_REMATCH[1]}${BASH_REMATCH[3]}"
    if is_ipv4 "$a" && is_ipv4 "$b"; then
      _emit_range "$(ip_to_int "$a")" "$(ip_to_int "$b")"
      return
    fi
    echo "ERR|plage invalide : $t"; return 1
  fi
  # IP simple
  if is_ipv4 "$t"; then echo "$t"; return 0; fi
  # Ressemble à une IP mais invalide
  if [[ "$t" =~ ^[0-9./-]+$ ]]; then echo "ERR|cible invalide : $t"; return 1; fi
  # Nom d'hôte
  if [[ "$t" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
    ip="$(getent ahostsv4 "$t" 2>/dev/null | awk 'NR==1{print $1}')"
    if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
    echo "ERR|nom d'hôte introuvable : $t"; return 1
  fi
  echo "ERR|cible invalide : $t"
  return 1
}

# expand_targets "<saisie>" : liste d'IP uniques (ordre conservé) + lignes ERR|
expand_targets() {
  local tok
  for tok in $(normalize_targets "$*"); do
    expand_token "$tok"
  done | awk '!seen[$0]++'
}

# Ressemble à une cible ? (sert à l'option -p sans valeur)
looks_like_target() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2}|-[0-9.]+)?$ ]]
}
