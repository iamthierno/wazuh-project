# =============================================================================
#  Conteneur "deployer" : outils de découverte et de déploiement des agents
#  (nmap, ssh, sshpass, pypsrp/WinRM). Utilisé automatiquement par
#  agents/install-agent.sh en mode Docker si les outils manquent sur l'hôte.
#  Lancé en --network host pour voir le vrai réseau.
#  Construction (depuis la racine du projet) :
#    docker build -t wazuh-deployer -f docker/deployer/Dockerfile .
# =============================================================================
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap openssh-client sshpass jq curl ca-certificates \
      iputils-ping iproute2 procps bsdextrautils \
 && rm -rf /var/lib/apt/lists/*

COPY agents/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm -f /tmp/requirements.txt

ENV WAZUH_DEPLOYER_INSIDE=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/wazuh-project
ENTRYPOINT ["/opt/wazuh-project/agents/install-agent.sh"]
