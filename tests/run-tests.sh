#!/usr/bin/env bash
# =============================================================================
#  tests/run-tests.sh — Tests automatiques du projet (sans serveur Wazuh)
#    - shellcheck de tous les scripts bash
#    - syntaxe Python / PowerShell / XML / YAML / docker compose
#    - interprétation des cibles (IP, CIDR, plages)
#    - classification OS de la découverte
#    - payload Linux en local (actions facts/status/log sur un faux agent)
#  Option : --with-manager  teste aussi les règles via wazuh-logtest
#           (nécessite un manager déployé : natif ou Docker)
# =============================================================================
set -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS + 1)); printf '  \e[32m✔\e[0m %s\n' "$*"; }
ko()   { FAIL=$((FAIL + 1)); printf '  \e[31m✖ %s\e[0m\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  \e[33m- %s (ignoré)\e[0m\n' "$*"; }
section() { printf '\n\e[1m%s\e[0m\n' "$*"; }
eq() { if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 — attendu [$3], obtenu [$2]"; fi; }

# --------------------------------------------------------------------------
section "1. Analyse statique (shellcheck)"
mapfile -t SH < <(git ls-files '*.sh' 2>/dev/null || find . -name '*.sh' -not -path './.git/*')
if command -v shellcheck >/dev/null; then
  for f in "${SH[@]}"; do
    if shellcheck -x -e SC2015 "$f" >/dev/null 2>&1; then ok "$f"; else ko "$f"; shellcheck -x -e SC2015 "$f" | head -20; fi
  done
else
  skip "shellcheck absent (pip install shellcheck-py)"
fi
for f in "${SH[@]}"; do bash -n "$f" 2>/dev/null || ko "syntaxe bash : $f"; done

# --------------------------------------------------------------------------
section "2. Syntaxe Python / PowerShell / XML / YAML"
for f in agents/lib/*.py lab/agent-sim/*.py lab/devices/*.py dashboards/*.py; do
  python3 -m py_compile "$f" 2>/dev/null && ok "python : $f" || ko "python : $f"
done
if command -v pwsh >/dev/null; then
  for f in agents/active-winRm.ps1 agents/lib/payloads/windows_agent.ps1; do
    r="$(pwsh -NoProfile -Command "\$e=\$null; [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path '$f'), [ref]\$null, [ref]\$e) | Out-Null; \$e.Count")"
    eq "powershell : $f" "$r" "0"
  done
else
  skip "pwsh absent : syntaxe PowerShell non vérifiée"
fi
for f in manager/rules/*.xml manager/decoders/*.xml manager/shared/*/agent.conf; do
  python3 - "$f" <<'EOF' && ok "xml : $f" || ko "xml : $f"
import sys, xml.etree.ElementTree as ET
ET.fromstring("<root>" + open(sys.argv[1], encoding="utf-8").read() + "</root>")
EOF
done
if python3 -c 'import yaml' 2>/dev/null; then
  for f in docker/*.yml docker/config/*.yml docker/config/*/*.yml; do
    python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$f" && ok "yaml : $f" || ko "yaml : $f"
  done
else
  skip "PyYAML absent : YAML non vérifié"
fi
if docker compose version >/dev/null 2>&1; then
  out="$(cd docker && WAZUH_VERSION=4.14.9 INDEXER_PASSWORD=x DASHBOARD_PASSWORD=x API_PASSWORD=x \
        INDEXER_JAVA_HEAP=1g DASHBOARD_PORT=443 SYSLOG_PORT=514 docker compose -f docker-compose.yml config -q 2>&1)"
  [[ -z "$out" ]] && ok "docker compose config" || ko "docker compose config : $out"
else
  skip "docker compose absent"
fi

if python3 dashboards/build_network_dashboard.py | python3 -c '
import json, sys
objs = [json.loads(l) for l in sys.stdin]
ids = {o["id"] for o in objs}
refs = [r["id"] for o in objs for r in o.get("references", []) if r["type"] != "index-pattern"]
assert all(r in ids for r in refs), "référence orpheline"
print(len(objs))' >/dev/null 2>&1; then ok "tableau de bord : objets NDJSON cohérents"; else ko "tableau de bord : objets NDJSON"; fi
for f in manager/lists/*; do
  if grep -vE '^[^:]+:.*$' "$f" | grep -q .; then ko "liste CDB mal formée : $f"; else ok "liste CDB : $f"; fi
done

# --------------------------------------------------------------------------
section "3. Interprétation des cibles"
# shellcheck source=agents/lib/targets.sh
. agents/lib/targets.sh
eq "IP simple"                "$(expand_targets 10.0.0.5 | xargs)"                 "10.0.0.5"
eq "CIDR /30"                 "$(expand_targets 192.168.1.0/30 | xargs)"           "192.168.1.1 192.168.1.2"
eq "CIDR /24 = 254 hôtes"     "$(expand_targets 192.168.1.0/24 | wc -l)"           "254"
eq "CIDR /32"                 "$(expand_targets 10.1.1.1/32 | xargs)"              "10.1.1.1"
eq "plage abrégée"            "$(expand_targets 10.0.0.1-3 | xargs)"               "10.0.0.1 10.0.0.2 10.0.0.3"
eq "plage complète (octets)"  "$(expand_targets 10.0.0.254-10.0.1.1 | xargs)"      "10.0.0.254 10.0.0.255 10.0.1.0 10.0.1.1"
eq "plage avec espaces"       "$(expand_targets '10.0.0.1 - 10.0.0.2' | xargs)"    "10.0.0.1 10.0.0.2"
eq "liste + doublons"         "$(expand_targets '10.0.0.1,10.0.0.1 10.0.0.2' | xargs)" "10.0.0.1 10.0.0.2"
eq "IP invalide"              "$(expand_targets 300.1.1.1 | cut -d'|' -f1)"        "ERR"
eq "plage inversée"           "$(expand_targets 10.0.0.9-2 | cut -d'|' -f1)"       "ERR"
eq "masque refusé (/7)"       "$(expand_targets 10.0.0.0/7 | cut -d'|' -f1)"       "ERR"
eq "plage trop grande"        "$(expand_targets 10.0.0.0/8 | cut -d'|' -f1)"       "ERR"
looks_like_target 10.0.0.0/24 && ok "-p suivi d'une cible : détecté" || ko "-p suivi d'une cible"
looks_like_target 'S3cret!' && ko "-p suivi d'un mot de passe" || ok "-p suivi d'un mot de passe : détecté"

# --------------------------------------------------------------------------
section "4. Classification OS (découverte)"
# shellcheck source=agents/lib/discover.sh
. agents/lib/discover.sh
c() { classify_host "$@" | cut -d'|' -f1; }
eq "bannière Ubuntu → linux"          "$(c 22 64 '' '' '' 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13')" "linux"
eq "bannière Windows → windows"       "$(c 22 128 '' '' '' 'SSH-2.0-OpenSSH_for_Windows_9.5')"       "windows"
eq "nmap Windows → windows"           "$(c 445,3389 128 Windows 'Microsoft Windows 11' '' '')"        "windows"
eq "ports WinRM → windows"            "$(c 135,445,5985 0 '' '' '' '')"                               "windows"
eq "nmap Mac OS X → macos"            "$(c 22 64 'Mac OS X' 'Apple macOS 14' '' 'SSH-2.0-OpenSSH_9.0')" "macos"
eq "vendeur Apple → macos"            "$(c 22 64 '' '' 'Apple' 'SSH-2.0-OpenSSH_9.0')"                "macos"
eq "SSH sans indice → unix"           "$(c 22 64 '' '' '' 'SSH-2.0-OpenSSH_9.0')"                     "unix"
eq "Linux + Samba (22,445) → linux"   "$(c 22,445 64 '' '' '' 'SSH-2.0-OpenSSH_8.9p1 Debian-3')"      "linux"
eq "TTL 128 seul → windows"           "$(c '' 128 '' '' '' '')"                                       "windows"
eq "aucun indice → inconnu"           "$(c '' 0 '' '' '' '')"                                         "inconnu"

# --------------------------------------------------------------------------
section "5. Payload Linux (exécution locale sur un faux agent)"
if [[ $EUID -eq 0 ]] && [[ ! -e /var/ossec ]]; then
  mkdir -p /var/ossec/bin /var/ossec/etc /var/ossec/logs
  # shellcheck disable=SC2016
  printf '#!/bin/sh\ncase "$1 $2" in "info -v") echo v4.14.9;; "info -t") echo agent;; esac\n' > /var/ossec/bin/wazuh-control
  chmod +x /var/ossec/bin/wazuh-control
  echo "007 test-agent any key" > /var/ossec/etc/client.keys
  printf 'l1\nl2 Connected to the server\nl3\n' > /var/ossec/logs/ossec.log
  PL="$(mktemp)"
  # Le payload s'exécute depuis un fichier (comme sur la cible), pas depuis stdin
  run_payload() {
    { printf 'ACTION=%s\nWAZUH_MANAGER=127.0.0.1\nPKG_BASE_URL=http://127.0.0.1:9\nCHECK_INTERNET=no\nLOG_LINES=2\n' "$1"
      cat agents/lib/payloads/unix_agent.sh; } > "$PL"
    bash "$PL"
  }
  out="$(run_payload facts)"
  eq "facts : RESULT ok"           "$(grep -c '^RESULT|ok' <<<"$out")" "1"
  eq "facts : agent détecté"       "$(grep '^KV|AGENT_INSTALLED=' <<<"$out" | cut -d= -f2)" "yes"
  eq "facts : version"             "$(grep '^KV|AGENT_VERSION=' <<<"$out" | cut -d= -f2)" "4.14.9"
  eq "facts : ID depuis client.keys" "$(grep '^KV|AGENT_ID=' <<<"$out" | cut -d= -f2)" "007"
  out="$(run_payload log)"
  eq "log : 2 dernières lignes"    "$(grep -c '^LOG|' <<<"$out")" "2"
  out="$(run_payload bogus)"
  eq "action inconnue → fail"      "$(grep -c '^RESULT|fail' <<<"$out")" "1"
  rm -rf /var/ossec "$PL"
else
  skip "payload Linux (nécessite root et l'absence de /var/ossec)"
fi

# --------------------------------------------------------------------------
section "6. Règles personnalisées (wazuh-logtest)"
if [[ "${1:-}" == "--with-manager" ]]; then
  if out="$(sudo "${ROOT}/scripts/test-device-logs.sh" 2>&1)"; then
    # La nuit / le week-end, 100263-100264 (hors heures) remplacent les règles de configuration
    for id in 100101 100102 100110 100112 100120 100122 100123 100131 100133 100141 100143 100150; do
      if grep -q " ${id} " <<<"$out"; then ok "règle ${id} déclenchée"
      elif [[ "$id" =~ ^1001(01|12|22|33)$ ]] && grep -qE " 10026[34] " <<<"$out"; then ok "règle ${id} (remplacée hors heures par 100263/100264)"
      else ko "règle ${id} non déclenchée"; fi
    done
    if awk '$2=="AUCUN" && $3=="-"' <<<"$out" | grep -q .; then ko "échantillon sans décodeur ni règle"
    else ok "tous les échantillons produisent une règle"; fi
  else
    ko "test-device-logs.sh a échoué"
  fi
else
  skip "règles (utilisez --with-manager sur un serveur déployé)"
fi

printf '\n\e[1mRésultat : %d réussi(s), %d échec(s), %d ignoré(s)\e[0m\n' "$PASS" "$FAIL" "$SKIP"
(( FAIL == 0 ))
