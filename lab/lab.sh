#!/usr/bin/env bash
# =============================================================================
#  lab/lab.sh — Laboratoire de test de la plateforme (sur le serveur Wazuh Docker)
#
#    sudo ./lab/lab.sh up        VMs Linux + agents Windows/macOS simulés +
#                                équipements réseau simulés (IP distinctes)
#    sudo ./lab/lab.sh attack    rejoue les scénarios d'attaque (toutes sources)
#    sudo ./lab/lab.sh load [EPS] [DURÉE]   test de charge syslog + mesures
#    sudo ./lab/lab.sh status    état des composants du labo
#    sudo ./lab/lab.sh down      supprime le labo (VMs, agents, alias IP)
#
#  Composants :
#    - 3 VMs Ubuntu 24.04 (conteneurs SSH) : agents RÉELS via install-agent.sh
#    - WIN-SRV01 (Windows Server 2022), WIN11-PC01, MAC-DIRECTION (macOS 14) :
#      agents SIMULÉS (lab/agent-sim) — protocole agent réel, événements réalistes
#    - 10 équipements réseau (FortiGate x2, Palo Alto, ASA, IOS, pfSense,
#      Sophos, Juniper, FTD, MikroTik) + 1 non inventorié (doit être rejeté)
#  Réservé au test : ne pas lancer sur une plateforme de production.
# =============================================================================
set -o pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${LAB_DIR}/.." && pwd)"
export PROJECT_DIR
# shellcheck source=lib/common.sh
. "${PROJECT_DIR}/lib/common.sh"

LAB_BASE_IMAGE="${LAB_BASE_IMAGE:-ubuntu:24.04}"
VM_IMAGE="wazuh-lab-vm"
VM_PASS="${LAB_VM_PASS:-Labo-Wazuh-2026!}"
VMS=(srv-web01 srv-web02 srv-db01)
RUN="/var/run/wazuh-lab"

mgr_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' wazuh-manager; }
bridge() { local id; id="$(docker network inspect wazuh_default -f '{{.Id}}')"; echo "br-${id:0:12}"; }
vm_ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null; }

build_vm_image() {
  docker image inspect "$VM_IMAGE" >/dev/null 2>&1 && return 0
  log_step "Construction de l'image ${VM_IMAGE} (base ${LAB_BASE_IMAGE})"
  docker build -q -t "$VM_IMAGE" - >/dev/null <<EOF || die "construction de ${VM_IMAGE} impossible"
FROM ${LAB_BASE_IMAGE}
RUN (command -v sshd >/dev/null || (apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      openssh-server sudo rsyslog iptables curl ca-certificates procps)) \
 && useradd -m -s /bin/bash admin && echo 'admin:${VM_PASS}' | chpasswd && usermod -aG sudo admin \
 && mkdir -p /run/sshd && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && (sed -i '/imklog/s/^/#/' /etc/rsyslog.conf || true)
CMD ["/bin/bash", "-c", "rsyslogd; [ -x /var/ossec/bin/wazuh-control ] && /var/ossec/bin/wazuh-control start; exec /usr/sbin/sshd -D"]
EOF
  log_ok "Image ${VM_IMAGE} prête"
}

device_aliases() { # device_aliases add|del
  local br ip
  br="$(bridge)"
  # shellcheck disable=SC2013  # une IP par ligne, sans espace
  for ip in $(grep -vE '^\s*(#|$)' "${LAB_DIR}/devices/devices.csv" | cut -d, -f1); do
    ip addr "$1" "${ip}/32" dev "$br" 2>/dev/null || true
  done
}

start_sims() {
  local scen_win="$1" scen_mac="$2"
  mkdir -p "$RUN"
  pkill -f "[w]azuh_agent_sim.py" 2>/dev/null || true
  export WAZUH_ENROLL_PASS="$ENROLLMENT_PASSWORD"
  local args
  for args in "WIN-SRV01 windows-server-2022 windows 10.10.20.11 ${scen_win}" \
              "WIN11-PC01 windows-11 windows 10.10.30.21 -" \
              "MAC-DIRECTION macos-14 macos 10.10.30.40 ${scen_mac}"; do
    # shellcheck disable=SC2086  # découpage voulu en champs
    set -- $args
    local extra=()
    [[ "$5" != "-" ]] && extra=(--scenario "$5")
    # Réutilise l'enregistrement existant (pas de doublon sur le manager)
    local k; k="$(docker exec wazuh-manager grep " $1 " /var/ossec/etc/client.keys 2>/dev/null | awk '{print $1" "$4}')"
    [[ -n "$k" ]] && extra+=(--id "${k% *}" --key "${k#* }")
    nohup python3 "${LAB_DIR}/agent-sim/wazuh_agent_sim.py" --manager 127.0.0.1 --name "$1" --os "$2" \
      --group "$3" --ip "$4" --duration 86400 "${extra[@]}" > "${RUN}/$1.log" 2>&1 &
    log_info "Agent simulé $1 ($2) lancé — journal ${RUN}/$1.log"
  done
}

cmd_up() {
  require_root; load_config; load_state || die "Déployez d'abord Wazuh (./deploy.sh --docker)."
  [[ "$(deploy_mode)" == docker ]] || die "Le labo s'appuie sur le déploiement Docker."
  have ip || pkg_install iproute2
  build_vm_image

  log_step "Inventaire du labo et configuration du manager"
  INVENTORY_FILE="${LAB_DIR}/inventory.csv" "${PROJECT_DIR}/deploy.sh" --reconfigure -y || die "reconfiguration échouée"

  log_step "VMs Linux"
  local vm ips=()
  for vm in "${VMS[@]}"; do
    docker inspect "$vm" >/dev/null 2>&1 || docker run -d --cap-add NET_ADMIN --name "$vm" --hostname "$vm" "$VM_IMAGE" >/dev/null
    docker start "$vm" >/dev/null
    ips+=("$(vm_ip "$vm")")
  done
  log_ok "VMs : ${VMS[*]} (${ips[*]})"
  sleep 3
  WAZUH_DEPLOY_PASS="$VM_PASS" NO_DEPLOYER=1 "${PROJECT_DIR}/agents/install-agent.sh" "${ips[@]}" -l -u admin -p -n 3 -y

  log_step "Agents Windows / macOS simulés"
  start_sims "${LAB_DIR}/agent-sim/scenarios/windows.json" "${LAB_DIR}/agent-sim/scenarios/macos.json"

  log_step "Équipements réseau simulés"
  device_aliases add
  python3 "${LAB_DIR}/devices/syslog_devices.py" --manager "$(mgr_ip)" --mode samples | tail -1
  log_ok "Labo prêt — dashboard : ${DASHBOARD_URL} (Équipements réseau (SOC), Endpoints, Threat Hunting)"
}

cmd_attack() {
  require_root; load_config; load_state || die "Wazuh non déployé."
  local vm1; vm1="$(vm_ip "${VMS[0]}")"
  log_step "Brute force SSH sur ${VMS[0]} (${vm1}) — réponse active attendue"
  have sshpass || pkg_install sshpass
  local i
  for i in $(seq 1 10); do
    SSHPASS="mauvais-${i}" timeout 5 sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PubkeyAuthentication=no -o ConnectTimeout=3 "admin@${vm1}" true 2>/dev/null
  done
  log_step "Persistance et élévation de privilèges sur ${VMS[1]}"
  docker exec "${VMS[1]}" bash -c 'useradd -m labo-backdoor 2>/dev/null; usermod -aG sudo labo-backdoor;
    mkdir -p /root/.ssh; echo "ssh-ed25519 AAAAlabo labo@test" >> /root/.ssh/authorized_keys;
    echo "*/5 * * * * root /tmp/.labo.sh" > /etc/cron.d/labo; echo "admin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/labo'
  log_step "Scénarios Windows / macOS"
  start_sims "${LAB_DIR}/agent-sim/scenarios/windows.json" "${LAB_DIR}/agent-sim/scenarios/macos.json"
  log_step "Rafales sur les équipements réseau"
  device_aliases add
  python3 "${LAB_DIR}/devices/syslog_devices.py" --manager "$(mgr_ip)" --mode attack | tail -1
  log_ok "Scénarios rejoués. Contrôle : ./lab/lab.sh status"
}

# Lecture des compteurs internes du manager
_stat() { docker exec wazuh-manager grep -E "^$2=" "/var/ossec/var/run/$1.state" 2>/dev/null | cut -d"'" -f2; }

cmd_load() {
  require_root; load_config; load_state || die "Wazuh non déployé."
  local eps="${1:-1000}" dur="${2:-30}" r0 d0 a0 r1 d1 a1 sent
  device_aliases add
  log_step "Charge syslog : ${eps} EPS pendant ${dur} s (11 sources)"
  sleep 6
  r0="$(_stat wazuh-analysisd events_received)"; d0="$(_stat wazuh-analysisd events_dropped)"
  a0="$(_stat wazuh-analysisd alerts_written)"
  sent="$(python3 "${LAB_DIR}/devices/syslog_devices.py" --manager "$(mgr_ip)" --mode load --eps "$eps" --duration "$dur" \
          | awk -F= '/TOTAL_SENT/{print $2}')"
  sleep 12
  r1="$(_stat wazuh-analysisd events_received)"; d1="$(_stat wazuh-analysisd events_dropped)"
  a1="$(_stat wazuh-analysisd alerts_written)"
  printf '%s\n' "envoyés=${sent} décodés=$(( r1 - r0 )) perdus_analysisd=$(( d1 - d0 )) alertes=$(( a1 - a0 ))"
  docker stats --no-stream --format '{{.Name}} CPU={{.CPUPerc}} RAM={{.MemUsage}}' wazuh-manager wazuh-indexer
}

cmd_status() {
  require_root; load_config; load_state || true
  local vm
  for vm in "${VMS[@]}"; do printf '%-12s %s\n' "$vm" "$(docker inspect -f '{{.State.Status}}' "$vm" 2>/dev/null || echo absent)"; done
  pgrep -af "[w]azuh_agent_sim.py" | awk '{print "simulé       " $5" "$6" "$7}' | sed 's/--name //'
  RUN_DIR="$(mktemp -d)"
  # shellcheck source=agents/lib/manager_api.sh
  . "${PROJECT_DIR}/agents/lib/manager_api.sh"
  api_call GET "/agents?select=id,name,status,os.name,group&limit=100" 2>/dev/null \
    | jq -r '.data.affected_items[] | select(.id!="000") | "agent \(.id)  \(.name)\t\(.status)\t\(.os.name // "-")\t\((.group // [])|join(","))"'
  rm -rf "$RUN_DIR"
}

cmd_down() {
  require_root; load_config; load_state || true
  pkill -f "[w]azuh_agent_sim.py" 2>/dev/null || true
  local vm; for vm in "${VMS[@]}"; do docker rm -f "$vm" >/dev/null 2>&1 || true; done
  device_aliases del
  RUN_DIR="$(mktemp -d)"
  # shellcheck source=agents/lib/manager_api.sh
  . "${PROJECT_DIR}/agents/lib/manager_api.sh"
  # Seuls les agents du labo sont supprimés du manager
  local id names
  names="$(printf '%s|' "${VMS[@]}" WIN-SRV01 WIN11-PC01 MAC-DIRECTION)"
  for id in $(api_call GET "/agents?select=id,name&limit=500" 2>/dev/null \
              | jq -r --arg re "^(${names%|})$" '.data.affected_items[] | select(.name | test($re)) | .id'); do
    api_delete_agent "$id" || true
  done
  rm -rf "$RUN_DIR"
  log_ok "Labo supprimé. Pensez à : sudo ./deploy.sh --reconfigure (inventaire de production)."
}

case "${1:-}" in
  up)     cmd_up ;;
  attack) cmd_attack ;;
  load)   shift; cmd_load "$@" ;;
  status) cmd_status ;;
  down)   cmd_down ;;
  *)      sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
