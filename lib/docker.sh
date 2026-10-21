#!/usr/bin/env bash
# =============================================================================
#  lib/docker.sh — Option 2 : déploiement Docker (single-node)
#  Vérifie / installe Docker + Compose v2, prépare ${DOCKER_DIR}, génère
#  certificats et mots de passe, lance la stack puis configure le manager.
# =============================================================================

DEPLOYER_IMAGE="wazuh-deployer:latest"

docker_compose() { docker compose --project-directory "$DOCKER_DIR" -f "${DOCKER_DIR}/docker-compose.yml" "$@"; }

# Installe Docker Engine + plugin compose depuis le dépôt officiel Docker
docker_install_engine() {
  detect_os
  log_step "Installation de Docker Engine (dépôt officiel download.docker.com)"
  case "$OS_FAMILY" in
    debian)
      local distro="$OS_ID"
      [[ "$distro" != "ubuntu" && "$distro" != "debian" ]] && distro="$( [[ "$OS_LIKE" == *ubuntu* ]] && echo ubuntu || echo debian )"
      run env DEBIAN_FRONTEND=noninteractive apt-get update -q
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q ca-certificates curl gnupg
      install -m 0755 -d /etc/apt/keyrings
      run curl -fsSL "https://download.docker.com/linux/${distro}/gpg" -o /etc/apt/keyrings/docker.asc
      chmod a+r /etc/apt/keyrings/docker.asc
      # shellcheck disable=SC1091
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${distro} $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" \
        > /etc/apt/sources.list.d/docker.list
      run env DEBIAN_FRONTEND=noninteractive apt-get update -q
      run env DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      ;;
    rhel)
      local repo="centos"
      [[ "$OS_ID" == "rhel" ]] && repo="rhel"
      [[ "$OS_ID" == "fedora" ]] && repo="fedora"
      run "$PKG_MGR" install -y dnf-plugins-core yum-utils || true
      if have dnf; then
        run dnf config-manager --add-repo "https://download.docker.com/linux/${repo}/docker-ce.repo" \
          || run dnf config-manager addrepo --from-repofile="https://download.docker.com/linux/${repo}/docker-ce.repo"
      else
        run yum-config-manager --add-repo "https://download.docker.com/linux/${repo}/docker-ce.repo"
      fi
      run "$PKG_MGR" install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      ;;
    *)
      die "Installation automatique de Docker non supportée sur ${OS_PRETTY}. Installez Docker puis relancez."
      ;;
  esac
  run systemctl enable --now docker || die "Impossible de démarrer le service docker"
  log_ok "Docker installé : $(docker --version)"
}

# Vérifie Docker, le démon et Compose v2 ; propose l'installation
docker_check() {
  log_step "Vérification de Docker"
  if have docker; then
    check_line "Docker installé" OK "$(docker --version | sed 's/Docker version //')"
  else
    check_line "Docker installé" KO "absent"
    confirm "Docker n'est pas installé. L'installer maintenant ?" o || die "Docker est requis pour l'option 2."
    docker_install_engine
  fi

  if ! docker info >/dev/null 2>&1; then
    log_warn "Le démon Docker ne répond pas, tentative de démarrage..."
    run systemctl enable --now docker
    sleep 3
    docker info >/dev/null 2>&1 || die "Le démon Docker ne démarre pas (systemctl status docker)."
  fi
  check_line "Démon Docker actif" OK

  if docker compose version >/dev/null 2>&1; then
    check_line "Docker Compose v2" OK "$(docker compose version --short 2>/dev/null)"
  else
    check_line "Docker Compose v2" KO "absent"
    confirm "Installer le plugin docker compose ?" o || die "Docker Compose v2 est requis."
    detect_os
    pkg_install docker-compose-plugin || die "Installation de docker-compose-plugin impossible."
  fi
}

# Paramètre noyau requis par l'indexer (OpenSearch)
docker_sysctl() {
  local cur
  cur="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if (( cur < 262144 )); then
    echo "vm.max_map_count=262144" > /etc/sysctl.d/99-wazuh.conf
    run sysctl -w vm.max_map_count=262144 || log_warn "sysctl vm.max_map_count non appliqué"
    log_ok "vm.max_map_count=262144 (persistant : /etc/sysctl.d/99-wazuh.conf)"
  else
    log_verbose "vm.max_map_count déjà à ${cur}"
  fi
}

# Taille de heap Java de l'indexer
docker_heap() {
  if [[ "${INDEXER_JAVA_HEAP}" != "auto" ]]; then printf '%s' "$INDEXER_JAVA_HEAP"; return; fi
  local ram_mb mb
  ram_mb="$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)"
  mb=$(( ram_mb / 4 ))
  (( mb < 1024 )) && mb=1024
  (( mb > 8192 )) && mb=8192
  printf '%sm' "$mb"
}

# Télécharge les images manquantes (avec nouvelles tentatives : limite Docker Hub)
docker_pull_images() {
  local img try
  for img in "wazuh/wazuh-manager:${WAZUH_VERSION}" "wazuh/wazuh-indexer:${WAZUH_VERSION}" \
             "wazuh/wazuh-dashboard:${WAZUH_VERSION}" "wazuh/wazuh-certs-generator:0.0.4"; do
    if docker image inspect "$img" >/dev/null 2>&1; then
      log_verbose "  image ${img} déjà présente"
      continue
    fi
    for try in 1 2 3 4; do
      log_info "Téléchargement ${img} (tentative ${try}/4)..."
      if run_live docker pull "$img"; then log_ok "Image ${img}"; continue 2; fi
      sleep $(( try * 15 ))
    done
    log_error "Impossible de télécharger ${img}"
    return 1
  done
}

# Calcule un hachage bcrypt pour l'indexer : bcrypt_hash <mot_de_passe>
bcrypt_hash() {
  local pw="$1" h=""
  h="$(docker run --rm -e JAVA_HOME=/usr/share/wazuh-indexer/jdk "wazuh/wazuh-indexer:${WAZUH_VERSION}" \
        bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$pw" 2>/dev/null \
        | grep -E '^[$]2[aby][$]' | tail -1)"
  if [[ -z "$h" ]] && have python3 && python3 -c 'import bcrypt' 2>/dev/null; then
    h="$(PW="$pw" python3 -c 'import bcrypt,os;print(bcrypt.hashpw(os.environ["PW"].encode(),bcrypt.gensalt(12)).decode())')"
  fi
  [[ -n "$h" ]] || return 1
  printf '%s' "$h"
}

# Génère les secrets (une seule fois) et les fichiers de configuration
docker_prepare() {
  local admin_hash kib_hash

  log_step "Préparation de ${DOCKER_DIR}"
  mkdir -p "$DOCKER_DIR" && chmod 700 "$DOCKER_DIR"
  cp -f "${PROJECT_DIR}/docker/docker-compose.yml" "${PROJECT_DIR}/docker/generate-indexer-certs.yml" "$DOCKER_DIR/"
  mkdir -p "${DOCKER_DIR}/config"
  # Les configs ne sont copiées que si absentes (préserve les personnalisations)
  local f
  while IFS= read -r f; do
    [[ -e "${DOCKER_DIR}/config/${f}" ]] || install -D -m 644 "${PROJECT_DIR}/docker/config/${f}" "${DOCKER_DIR}/config/${f}"
  done < <(cd "${PROJECT_DIR}/docker/config" && find . -type f | sed 's#^\./##')

  # Secrets : réutilisés s'ils existent déjà (idempotence)
  [[ -n "${INDEXER_ADMIN_PASSWORD:-}" ]] || state_set INDEXER_ADMIN_PASSWORD "$(gen_password 20)"
  [[ -n "${DASHBOARD_PASSWORD:-}" ]]     || state_set DASHBOARD_PASSWORD "$(gen_password 20)"
  [[ -n "${API_PASSWORD:-}" ]]           || state_set API_PASSWORD "$(gen_password 20)"
  [[ -n "${ENROLLMENT_PASSWORD:-}" ]]    || ENROLLMENT_PASSWORD="$(gen_password 24)"
  state_set ENROLLMENT_PASSWORD "$ENROLLMENT_PASSWORD"
  state_set API_USER "wazuh-wui"
  register_secret "$INDEXER_ADMIN_PASSWORD"; register_secret "$DASHBOARD_PASSWORD"
  register_secret "$API_PASSWORD"; register_secret "$ENROLLMENT_PASSWORD"
  log_ok "Mots de passe prêts (stockés dans ${STATE_FILE})"

  # Fichier .env de la stack
  umask 077
  cat > "${DOCKER_DIR}/.env" <<EOF
WAZUH_VERSION=${WAZUH_VERSION}
INDEXER_PASSWORD=${INDEXER_ADMIN_PASSWORD}
DASHBOARD_PASSWORD=${DASHBOARD_PASSWORD}
API_PASSWORD=${API_PASSWORD}
INDEXER_JAVA_HEAP=$(docker_heap)
DASHBOARD_PORT=${DASHBOARD_PORT}
SYSLOG_PORT=${SYSLOG_PORT}
EOF
  umask 022
  log_ok "Fichier .env généré (heap indexer : $(docker_heap))"

  # Téléchargement des images
  log_step "Téléchargement des images Wazuh ${WAZUH_VERSION} (peut prendre plusieurs minutes)"
  docker_pull_images || die "Échec du téléchargement des images"

  # Utilisateurs internes de l'indexer (hachages bcrypt)
  if [[ ! -f "${DOCKER_DIR}/config/wazuh_indexer/internal_users.yml" ]]; then
    log_info "Calcul des hachages bcrypt des mots de passe..."
    admin_hash="$(bcrypt_hash "$INDEXER_ADMIN_PASSWORD")" || die "Hachage du mot de passe admin impossible"
    kib_hash="$(bcrypt_hash "$DASHBOARD_PASSWORD")" || die "Hachage du mot de passe kibanaserver impossible"
    sed -e "s#__ADMIN_HASH__#${admin_hash}#" -e "s#__KIBANASERVER_HASH__#${kib_hash}#" \
      "${DOCKER_DIR}/config/wazuh_indexer/internal_users.yml.tpl" > "${DOCKER_DIR}/config/wazuh_indexer/internal_users.yml"
    chmod 644 "${DOCKER_DIR}/config/wazuh_indexer/internal_users.yml"
    log_ok "internal_users.yml généré (comptes de démonstration supprimés)"
  fi
  sed -e "s#__API_PASSWORD__#${API_PASSWORD}#" "${DOCKER_DIR}/config/wazuh_dashboard/wazuh.yml.tpl" \
    > "${DOCKER_DIR}/config/wazuh_dashboard/wazuh.yml"
  chmod 644 "${DOCKER_DIR}/config/wazuh_dashboard/wazuh.yml"

  # Certificats
  if [[ ! -f "${DOCKER_DIR}/config/wazuh_indexer_ssl_certs/root-ca.pem" ]]; then
    log_info "Génération des certificats TLS..."
    if run docker compose --project-directory "$DOCKER_DIR" -f "${DOCKER_DIR}/generate-indexer-certs.yml" run --rm generator \
       && [[ -f "${DOCKER_DIR}/config/wazuh_indexer_ssl_certs/root-ca.pem" ]]; then
      log_ok "Certificats générés (outil officiel) dans ${DOCKER_DIR}/config/wazuh_indexer_ssl_certs"
    else
      log_warn "Générateur officiel indisponible — génération avec OpenSSL"
      generate_certs_openssl "${DOCKER_DIR}/config/wazuh_indexer_ssl_certs" "$MANAGER_IP" \
        || die "Échec de génération des certificats"
      log_ok "Certificats générés (OpenSSL) dans ${DOCKER_DIR}/config/wazuh_indexer_ssl_certs"
    fi
    docker compose --project-directory "$DOCKER_DIR" -f "${DOCKER_DIR}/generate-indexer-certs.yml" down >/dev/null 2>&1 || true
  else
    log_verbose "Certificats déjà présents"
  fi

  # ossec.conf : syslog + enrôlement par mot de passe
  apply_ossec_conf "${DOCKER_DIR}/config/wazuh_cluster/wazuh_manager.conf"
}

# Attend que les 3 services répondent
docker_wait_healthy() {
  local waited=0 timeout=600 idx=0 api=0 dash=0 code
  log_step "Démarrage des services (indexer → manager → dashboard)"
  while (( waited < timeout )); do
    if (( idx == 0 )) && curl -sk -m 5 -u "admin:${INDEXER_ADMIN_PASSWORD}" "https://127.0.0.1:9200/_cluster/health" 2>/dev/null | grep -q '"status":"\(green\|yellow\)"'; then
      idx=1; log_ok "Indexer opérationnel (${waited}s)"
    fi
    if (( api == 0 )); then
      code="$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:55000/" 2>/dev/null)"
      [[ "$code" == "401" || "$code" == "200" ]] && { api=1; log_ok "Manager / API opérationnels (${waited}s)"; }
    fi
    if (( dash == 0 )); then
      code="$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:${DASHBOARD_PORT}/" 2>/dev/null)"
      [[ "$code" =~ ^(200|302|401)$ ]] && { dash=1; log_ok "Dashboard opérationnel (${waited}s)"; }
    fi
    (( idx && api && dash )) && return 0
    sleep 10; waited=$((waited + 10))
    log_verbose "  ... attente (indexer=${idx} manager=${api} dashboard=${dash}) ${waited}s"
  done
  log_error "Services non prêts après ${timeout}s — voir : docker compose -f ${DOCKER_DIR}/docker-compose.yml logs"
  return 1
}

# Construit l'image du conteneur deployer (agents)
docker_build_deployer() {
  log_info "Construction de l'image ${DEPLOYER_IMAGE} (outils de déploiement des agents)..."
  if run docker build -t "$DEPLOYER_IMAGE" -f "${PROJECT_DIR}/docker/deployer/Dockerfile" "$PROJECT_DIR"; then
    log_ok "Image ${DEPLOYER_IMAGE} prête"
  else
    log_warn "Construction de ${DEPLOYER_IMAGE} impossible (elle sera retentée au premier install-agent.sh)"
  fi
}

docker_install() {
  local existing=0

  docker_check
  if docker ps -a --format '{{.Names}}' | grep -qx 'wazuh-manager'; then
    existing=1
    log_warn "Une stack Wazuh Docker existe déjà."
    confirm "Mettre à jour sa configuration et la redémarrer ?" o || return 1
  fi
  if (( existing == 0 )); then
    server_prechecks docker || return 1
  fi
  docker_sysctl

  MANAGER_IP="${MANAGER_IP:-$(primary_ip)}"
  [[ -n "$MANAGER_IP" ]] || die "Impossible de déterminer l'IP du serveur : renseignez MANAGER_IP dans config.env"
  state_set DEPLOY_MODE docker
  state_set MANAGER_IP "$MANAGER_IP"
  state_set WAZUH_VERSION "$WAZUH_VERSION"
  state_set DOCKER_DIR "$DOCKER_DIR"
  state_set DASHBOARD_URL "https://${MANAGER_IP}$( [[ "$DASHBOARD_PORT" != 443 ]] && echo ":${DASHBOARD_PORT}")"

  docker_prepare

  log_step "Lancement de la stack"
  run_live docker_compose up -d || die "docker compose up a échoué"
  docker_wait_healthy || return 1

  configure_manager_runtime
  manager_restart
  wait_manager_api 300 || log_warn "Vérifiez : docker logs wazuh-manager"

  docker_build_deployer
  print_access_summary
}
