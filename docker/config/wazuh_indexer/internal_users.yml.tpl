---
# Base des utilisateurs internes de l'indexer (générée par deploy.sh)
# Les hachages bcrypt sont calculés à l'installation à partir des mots de passe
# stockés dans /etc/wazuh-deploy/state.env. Les comptes de démonstration
# (kibanaro, logstash, readall, snapshotrestore) sont volontairement supprimés.
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "__ADMIN_HASH__"
  reserved: true
  backend_roles:
  - "admin"
  description: "Administrateur Wazuh (dashboard + indexer)"

kibanaserver:
  hash: "__KIBANASERVER_HASH__"
  reserved: true
  description: "Compte de service du dashboard"
