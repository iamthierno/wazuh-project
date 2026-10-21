#!/usr/bin/env bash
# =============================================================================
#  lib/certs.sh — Génération des certificats TLS de la stack Docker avec
#  OpenSSL (secours si le générateur officiel wazuh-certs-generator échoue,
#  par exemple sans accès à packages.wazuh.com).
#  Produit exactement les fichiers attendus par docker-compose.yml.
# =============================================================================

CERT_SUBJ_BASE="/OU=Wazuh/O=Wazuh/L=California/C=US"

# _cert_sign <dir> <nom> <CN> <SAN>
_cert_sign() {
  local dir="$1" name="$2" cn="$3" san="$4" ext
  ext="$(mktemp)"
  cat > "$ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
${san:+subjectAltName = ${san}}
EOF
  openssl genrsa -out "${dir}/${name}-key-temp.pem" 2048 2>/dev/null
  openssl pkcs8 -inform PEM -outform PEM -in "${dir}/${name}-key-temp.pem" -topk8 -nocrypt \
    -v1 PBE-SHA1-3DES -out "${dir}/${name}-key.pem" 2>/dev/null
  openssl req -new -key "${dir}/${name}-key.pem" -subj "/CN=${cn}${CERT_SUBJ_BASE}" \
    -out "${dir}/${name}.csr" 2>/dev/null
  openssl x509 -req -in "${dir}/${name}.csr" -CA "${dir}/root-ca.pem" -CAkey "${dir}/root-ca.key" \
    -CAcreateserial -sha256 -days 3650 -extfile "$ext" -out "${dir}/${name}.pem" 2>/dev/null
  rm -f "${dir}/${name}-key-temp.pem" "${dir}/${name}.csr" "$ext"
  [[ -s "${dir}/${name}.pem" ]]
}

# generate_certs_openssl <dossier_certs> [ip_serveur]
generate_certs_openssl() {
  local dir="$1" ip="${2:-}" n ip_san=""
  have openssl || { log_error "openssl est requis"; return 1; }
  mkdir -p "$dir"
  [[ -n "$ip" ]] && ip_san=",IP:${ip}"

  openssl req -x509 -new -nodes -newkey rsa:2048 -keyout "${dir}/root-ca.key" \
    -sha256 -days 3650 -subj "/CN=root-ca${CERT_SUBJ_BASE}" -out "${dir}/root-ca.pem" 2>/dev/null \
    || return 1
  _cert_sign "$dir" admin          admin           ""                                         || return 1
  _cert_sign "$dir" wazuh.indexer   wazuh.indexer   "DNS:wazuh.indexer,DNS:localhost,IP:127.0.0.1" || return 1
  _cert_sign "$dir" wazuh.manager   wazuh.manager   "DNS:wazuh.manager"                        || return 1
  _cert_sign "$dir" wazuh.dashboard wazuh.dashboard "DNS:wazuh.dashboard,DNS:localhost${ip_san}" || return 1
  cp -f "${dir}/root-ca.pem" "${dir}/root-ca-manager.pem"
  rm -f "${dir}"/*.srl

  # Lisibles par les utilisateurs des conteneurs (le dossier parent est en 700)
  for n in "${dir}"/*.pem; do chmod 644 "$n"; done
  chmod 600 "${dir}/root-ca.key"
  return 0
}
