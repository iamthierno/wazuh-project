# Décodeurs personnalisés

Déposez ici vos décodeurs (`*.xml`). Ils sont copiés dans
`/var/ossec/etc/decoders/` par `./deploy.sh --reconfigure` puis validés
(`wazuh-analysisd -t`). Un fichier invalide est retiré automatiquement pour ne
pas bloquer le manager.

Les équipements FortiGate, Palo Alto, Cisco ASA et Cisco IOS sont décodés par
le ruleset natif de Wazuh : aucun décodeur supplémentaire n'est nécessaire.
